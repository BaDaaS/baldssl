//! Deterministic random bit generators: HMAC_DRBG ([NIST SP 800-90A Rev. 1]
//! section 10.1.2).
//!
//! A DRBG expands a seed (entropy input, a nonce, a personalization string)
//! into a stream of bits that cannot be told apart from random without the
//! seed. [`Drbg`] is the interface of section 9 (generate, reseed);
//! [`HmacDrbg`] is the construction of section 10.1.2 over a hash `H`. Its
//! state is two secret strings, the key `K` and the value `V`, each one
//! hash output long, and a counter of the requests since the last seeding.
//!
//! Each input is its own type ([`Entropy`], [`Nonce`], [`Personalization`],
//! [`AdditionalInput`]), so two of them cannot be swapped at a call site,
//! and each limit of section 10.1, table 2, is an error ([`DrbgError`]),
//! never a silent weakening.
//!
//! [NIST SP 800-90A Rev. 1]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final

use crate::{
    hash::{Digest, Sha1, Sha224, Sha256, Sha384, Sha512},
    mac::{Hmac, Mac},
    secret::SecretBytes,
};

/// The most bits one request may return: $2^{19}$ (table 2).
pub const MAX_BITS_PER_REQUEST: usize = 1 << 19;

/// The most requests between two seedings: $2^{48}$ (table 2).
pub const RESEED_INTERVAL: u64 = 1 << 48;

/// A security strength, in bits (SP 800-57 Part 1, as section 8.4 uses it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecurityStrength(pub u32);

impl SecurityStrength {
    /// The strength in bits.
    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }
}

/// The highest security strength HMAC_DRBG supports with a hash (table 2).
pub trait DrbgHash: Digest {
    /// The strength of HMAC_DRBG with this hash.
    const SECURITY_STRENGTH: SecurityStrength;
}

impl DrbgHash for Sha1 {
    const SECURITY_STRENGTH: SecurityStrength = SecurityStrength(128);
}
impl DrbgHash for Sha224 {
    const SECURITY_STRENGTH: SecurityStrength = SecurityStrength(192);
}
impl DrbgHash for Sha256 {
    const SECURITY_STRENGTH: SecurityStrength = SecurityStrength(256);
}
impl DrbgHash for Sha384 {
    const SECURITY_STRENGTH: SecurityStrength = SecurityStrength(256);
}
impl DrbgHash for Sha512 {
    const SECURITY_STRENGTH: SecurityStrength = SecurityStrength(256);
}

/// Entropy input: at least the security strength in bits (section 8.6.3).
#[derive(Clone, Copy)]
pub struct Entropy<'a>(pub &'a [u8]);

/// The nonce of instantiation: at least half the security strength in bits
/// (section 8.6.7).
#[derive(Clone, Copy)]
pub struct Nonce<'a>(pub &'a [u8]);

/// The personalization string of instantiation, possibly empty
/// (section 8.7.1).
#[derive(Clone, Copy)]
pub struct Personalization<'a>(pub &'a [u8]);

/// Additional input to a reseed or a request, possibly empty
/// (section 8.7.2).
#[derive(Clone, Copy)]
pub struct AdditionalInput<'a>(pub &'a [u8]);

impl AdditionalInput<'_> {
    /// No additional input.
    pub const NONE: AdditionalInput<'static> = AdditionalInput(&[]);
}

/// Why the generator refused: each is a limit of SP 800-90A, enforced
/// rather than weakened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrbgError {
    /// Entropy input shorter than the security strength (sections 8.6.3
    /// and 10.1.2.3).
    EntropyTooShort {
        /// Bits given.
        bits: usize,
        /// Bits required.
        required: u32,
    },
    /// A nonce shorter than half the security strength (section 8.6.7).
    NonceTooShort {
        /// Bits given.
        bits: usize,
        /// Bits required.
        required: u32,
    },
    /// More than [`MAX_BITS_PER_REQUEST`] bits requested at once.
    RequestTooLarge,
    /// [`RESEED_INTERVAL`] requests since the last seeding: reseed first
    /// (section 10.1.2.5, step 1).
    ReseedRequired,
}

impl core::fmt::Display for DrbgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DrbgError::EntropyTooShort { bits, required } => write!(
                f,
                "DRBG: entropy input of {bits} bits, {required} required"
            ),
            DrbgError::NonceTooShort { bits, required } => {
                write!(f, "DRBG: nonce of {bits} bits, {required} required")
            }
            DrbgError::RequestTooLarge => {
                write!(f, "DRBG: more than 2^19 bits requested")
            }
            DrbgError::ReseedRequired => {
                write!(f, "DRBG: reseed required")
            }
        }
    }
}

/// A deterministic random bit generator (section 9): seeded once, then
/// asked for bits, and reseeded with fresh entropy.
pub trait Drbg {
    /// Mixes fresh entropy (and optional additional input) into the state,
    /// and restarts the request count (section 9.2).
    ///
    /// # Errors
    ///
    /// [`DrbgError::EntropyTooShort`].
    fn reseed(
        &mut self,
        entropy: Entropy<'_>,
        additional: AdditionalInput<'_>,
    ) -> Result<(), DrbgError>;

    /// Fills `out` with pseudorandom bytes (section 9.3).
    ///
    /// # Errors
    ///
    /// [`DrbgError::RequestTooLarge`] and [`DrbgError::ReseedRequired`]; on
    /// an error `out` is left unchanged.
    fn generate(
        &mut self,
        out: &mut [u8],
        additional: AdditionalInput<'_>,
    ) -> Result<(), DrbgError>;
}

/// HMAC_DRBG over `H` (section 10.1.2).
pub struct HmacDrbg<H>
where
    H: DrbgHash,
{
    /// `K`, one hash output long.
    key: SecretBytes,
    /// `V`, one hash output long.
    value: SecretBytes,
    /// Requests since the last seeding, starting at 1.
    reseed_counter: u64,
    hash: core::marker::PhantomData<H>,
}

impl<H> HmacDrbg<H>
where
    H: DrbgHash,
{
    /// Instantiates the generator (section 10.1.2.3): `K = 0x00...`,
    /// `V = 0x01...`, then the update with `entropy || nonce ||
    /// personalization`.
    ///
    /// # Errors
    ///
    /// [`DrbgError::EntropyTooShort`] and [`DrbgError::NonceTooShort`].
    pub fn new(
        entropy: Entropy<'_>,
        nonce: Nonce<'_>,
        personalization: Personalization<'_>,
    ) -> Result<Self, DrbgError> {
        check_entropy::<H>(entropy)?;
        let required = H::SECURITY_STRENGTH.bits() / 2;
        let bits = nonce.0.len().saturating_mul(8);
        if bits < required as usize {
            return Err(DrbgError::NonceTooShort { bits, required });
        }
        let mut drbg = HmacDrbg {
            key: SecretBytes::filled(0x00, H::OUTPUT_LEN),
            value: SecretBytes::filled(0x01, H::OUTPUT_LEN),
            reseed_counter: 1,
            hash: core::marker::PhantomData,
        };
        drbg.update(&[entropy.0, nonce.0, personalization.0]);
        Ok(drbg)
    }

    /// `HMAC(K, data_1 || data_2 || ...)`.
    fn hmac(&self, data: &[&[u8]]) -> SecretBytes {
        let mut m = Hmac::<H>::new(self.key.expose());
        for d in data {
            m.update(d);
        }
        SecretBytes::new(m.finalize().as_bytes().to_vec())
    }

    /// The update function (section 10.1.2.2), with `provided_data` the
    /// concatenation of `provided`: one round with `0x00`, and a second
    /// with `0x01` when the data is not empty.
    fn update(&mut self, provided: &[&[u8]]) {
        let empty = provided.iter().all(|p| p.is_empty());
        for round in [0x00u8, 0x01] {
            if round == 0x01 && empty {
                break;
            }
            let round = [round];
            let mut data: Vec<&[u8]> = vec![self.value.expose(), &round];
            data.extend_from_slice(provided);
            let key = self.hmac(&data);
            drop(data);
            self.key = key;
            self.value = self.hmac(&[self.value.expose()]);
        }
    }
}

/// Entropy input at least as long as the security strength.
fn check_entropy<H>(entropy: Entropy<'_>) -> Result<(), DrbgError>
where
    H: DrbgHash,
{
    let required = H::SECURITY_STRENGTH.bits();
    let bits = entropy.0.len().saturating_mul(8);
    if bits < required as usize {
        return Err(DrbgError::EntropyTooShort { bits, required });
    }
    Ok(())
}

impl<H> Drbg for HmacDrbg<H>
where
    H: DrbgHash,
{
    /// Section 10.1.2.4: the update with `entropy || additional`.
    fn reseed(
        &mut self,
        entropy: Entropy<'_>,
        additional: AdditionalInput<'_>,
    ) -> Result<(), DrbgError> {
        check_entropy::<H>(entropy)?;
        self.update(&[entropy.0, additional.0]);
        self.reseed_counter = 1;
        Ok(())
    }

    /// Section 10.1.2.5: the update with the additional input when there is
    /// one, `V = HMAC(K, V)` until enough bytes, then the update with the
    /// additional input again.
    fn generate(
        &mut self,
        out: &mut [u8],
        additional: AdditionalInput<'_>,
    ) -> Result<(), DrbgError> {
        if out.len() > MAX_BITS_PER_REQUEST / 8 {
            return Err(DrbgError::RequestTooLarge);
        }
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(DrbgError::ReseedRequired);
        }
        if !additional.0.is_empty() {
            self.update(&[additional.0]);
        }
        for chunk in out.chunks_mut(H::OUTPUT_LEN) {
            self.value = self.hmac(&[self.value.expose()]);
            let block = self.value.expose();
            chunk.copy_from_slice(block.get(..chunk.len()).unwrap_or(block));
        }
        self.update(&[additional.0]);
        self.reseed_counter = self.reseed_counter.saturating_add(1);
        Ok(())
    }
}

impl<H> core::fmt::Debug for HmacDrbg<H>
where
    H: DrbgHash,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "HmacDrbg {{ reseed_counter: {}, .. }}",
            self.reseed_counter
        )
    }
}

#[cfg(test)]
mod tests;
