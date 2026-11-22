//! ECDSA, the Elliptic Curve Digital Signature Algorithm ([FIPS 186-5]
//! section 6), with deterministic nonces ([RFC 6979]).
//!
//! Over a curve with a generator $G$ of prime order $n$ and a hash $H$: a
//! signature of $m$ under the secret scalar $d$ is
//!
//! $$r = x(kG) \bmod n, \qquad s = k^{-1}(e + r d) \bmod n,$$
//!
//! with $e$ the leftmost $\lceil \log_2 n \rceil$ bits of $H(m)$ reduced
//! modulo $n$ (FIPS 186-5 section 6.4.1), and $k$ a nonce. Verification
//! recomputes $x(u_1 G + u_2 Q)$ with $u_1 = e s^{-1}$ and $u_2 = r s^{-1}$
//! for the public key $Q = dG$, and compares it with $r$ (section 6.4.2).
//!
//! The nonce is RFC 6979's, section 3.2: HMAC_DRBG over $H$ instantiated
//! with the secret scalar as entropy input and the reduced hash as nonce,
//! then asked for $n$-sized blocks until one is in $[1, n - 1]$. RFC 6979
//! section 3.3 notes it is exactly that generator, so here it is
//! [`HmacDrbg`] itself. The nonce is thus a function of the key and the
//! message: the same message signed twice gives the same signature, and no
//! randomness from the system is involved. OpenSSL draws random nonces by
//! default, so signatures differ from OpenSSL's; both verify.
//!
//! A signature is [`Signature`], encoded as the DER `ECDSA-Sig-Value` of
//! [RFC 3279 section 2.2.3], `SEQUENCE { r INTEGER, s INTEGER }`, and
//! decoded strictly: canonical DER only, with $r$ and $s$ in $[1, n - 1]$.
//!
//! [FIPS 186-5]: https://csrc.nist.gov/pubs/fips/186-5/final
//! [RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979#section-3.2
//! [RFC 3279 section 2.2.3]: https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3

#![allow(
    clippy::arithmetic_side_effects,
    reason = "the operators here are those of the scalar field and of the \
              curve group, which are modular and cannot overflow"
)]

use core::marker::PhantomData;

use baldssl_core::der::syntax::{Natural, Sequence, Unsigned, decode, encode};

use crate::{
    algebra::{
        curve::ShortWeierstrass,
        encoding::{Decodable, Encodable, InvalidEncoding},
        field::{Field, PrimeField},
        model::{AffineModel, CurveModel, ProjectiveModel},
    },
    drbg::{
        AdditionalInput, Drbg, DrbgError, DrbgHash, Entropy, HmacDrbg, Nonce,
        Personalization,
    },
    keys::EcKeyPair,
    models::weierstrass::{affine::Affine, projective::Projective},
    secret::SecretBytes,
    signature::{SignatureScheme, Signer, Verifier},
};

/// ECDSA over the curve `C` with the hash `H`.
pub struct Ecdsa<C, H>(PhantomData<(C, H)>);

/// An ECDSA signature: the pair $(r, s)$, both in $[1, n - 1]$, which
/// [`Signature::new_opt`] and the decoder enforce. Equality and printing are
/// those of the pair (a signature is public).
#[derive(Clone, Copy)]
pub struct Signature<C>
where
    C: ShortWeierstrass,
{
    r: C::Scalar,
    s: C::Scalar,
}

impl<C> Signature<C>
where
    C: ShortWeierstrass,
{
    /// The signature $(r, s)$; `None` when either is zero.
    #[must_use]
    pub fn new_opt(r: C::Scalar, s: C::Scalar) -> Option<Self> {
        let zero = r.is_zero() | s.is_zero();
        (!zero.to_bool_vartime()).then_some(Signature { r, s })
    }

    /// $r$.
    #[must_use]
    pub fn r(&self) -> &C::Scalar {
        &self.r
    }

    /// $s$.
    #[must_use]
    pub fn s(&self) -> &C::Scalar {
        &self.s
    }
}

impl<C> PartialEq for Signature<C>
where
    C: ShortWeierstrass,
{
    fn eq(&self, other: &Self) -> bool {
        self.r == other.r && self.s == other.s
    }
}

impl<C> Eq for Signature<C> where C: ShortWeierstrass {}

impl<C> core::fmt::Debug for Signature<C>
where
    C: ShortWeierstrass,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field("r", &self.r)
            .field("s", &self.s)
            .finish()
    }
}

/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279
/// section 2.2.3).
type EcdsaSigValue = Sequence<(Unsigned, (Unsigned, ()))>;

/// The description of [`EcdsaSigValue`].
const ECDSA_SIG_VALUE: EcdsaSigValue = Sequence((Unsigned, (Unsigned, ())));

/// The DER `ECDSA-Sig-Value`, each integer minimal and big-endian.
impl<C> Encodable for Signature<C>
where
    C: ShortWeierstrass,
{
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        encode(
            &ECDSA_SIG_VALUE,
            &(
                Natural::from_be_bytes(&self.r.to_bytes_be()),
                (Natural::from_be_bytes(&self.s.to_bytes_be()), ()),
            ),
        )
    }
}

/// Canonical DER only (minimal lengths and integers, no trailing bytes),
/// and $r$, $s$ in $[1, n - 1]$; anything else is [`InvalidEncoding`].
impl<C> Decodable for Signature<C>
where
    C: ShortWeierstrass,
{
    type Error = InvalidEncoding;

    fn decode(der: &[u8]) -> Result<Self, InvalidEncoding> {
        let (r, (s, ())) =
            decode(&ECDSA_SIG_VALUE, der).map_err(|_| InvalidEncoding)?;
        Signature::new_opt(scalar_opt::<C>(&r)?, scalar_opt::<C>(&s)?)
            .ok_or(InvalidEncoding)
    }
}

/// The scalar a natural number is, when it is below $n$.
fn scalar_opt<C>(n: &Natural) -> Result<C::Scalar, InvalidEncoding>
where
    C: ShortWeierstrass,
{
    let digits = n.as_be_bytes();
    let pad = C::Scalar::BYTES
        .checked_sub(digits.len())
        .ok_or(InvalidEncoding)?;
    let mut bytes = vec![0u8; pad];
    bytes.extend_from_slice(digits);
    let (scalar, valid) = C::Scalar::from_bytes_be(&bytes);
    valid
        .to_bool_vartime()
        .then_some(scalar)
        .ok_or(InvalidEncoding)
}

/// `bits2int` (RFC 6979 section 2.3.2; FIPS 186-5 section 6.4.1): the
/// leftmost $\mathrm{qlen}$ bits of `bytes` as an integer, big-endian, on
/// the scalar's byte length. Not reduced: it may be $n$ or more.
pub(crate) fn bits2int<C>(bytes: &[u8]) -> Vec<u8>
where
    C: ShortWeierstrass,
{
    let qlen = C::Scalar::BITS as usize;
    let rlen = C::Scalar::BYTES;
    let blen = bytes.len().saturating_mul(8);
    if blen <= qlen {
        let mut out = vec![0u8; rlen.saturating_sub(bytes.len())];
        out.extend_from_slice(bytes);
        return out;
    }
    // Keep the first rlen bytes, then shift right by the bits beyond qlen.
    let kept = bytes.get(..rlen).unwrap_or(bytes);
    let shift =
        u32::try_from(rlen.saturating_mul(8).saturating_sub(qlen)).unwrap_or(0);
    if shift == 0 {
        return kept.to_vec();
    }
    let mut out = vec![0u8; kept.len()];
    let mut carry = 0u8;
    for (o, &b) in out.iter_mut().zip(kept) {
        *o = b.checked_shr(shift).unwrap_or(0) | carry;
        carry = b.checked_shl(8u32.saturating_sub(shift)).unwrap_or(0);
    }
    out
}

/// The scalar an integer below $2n$ is congruent to: the integer itself, or
/// the integer minus $n$. Variable time, for public values only (a hash, a
/// coordinate of a public point): for the curves here $2^{\mathrm{qlen}} <
/// 2n$ and $p < 2n$, so one subtraction reduces any of them.
pub(crate) fn reduce_once<C>(bytes: &[u8]) -> C::Scalar
where
    C: ShortWeierstrass,
{
    let (scalar, valid) = C::Scalar::from_bytes_be(bytes);
    if valid.to_bool_vartime() {
        return scalar;
    }
    let n = C::Scalar::modulus_be();
    let mut diff = vec![0u8; bytes.len()];
    let mut borrow = 0u16;
    let mut n_padded = vec![0u8; bytes.len().saturating_sub(n.len())];
    n_padded.extend_from_slice(&n);
    for ((out, &minuend), &subtrahend) in
        diff.iter_mut().zip(bytes).zip(&n_padded).rev()
    {
        let sub = u16::from(subtrahend).saturating_add(borrow);
        let (value, under) = u16::from(minuend).overflowing_sub(sub);
        *out = value.to_le_bytes()[0];
        borrow = u16::from(under);
    }
    C::Scalar::from_bytes_be(&diff).0
}

/// $e$: the leftmost bits of the message's hash, reduced modulo $n$.
fn message_scalar<C, H>(message: &[u8]) -> C::Scalar
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    reduce_once::<C>(&bits2int::<C>(&H::digest(message)))
}

/// $x(P) \bmod n$ for a point other than the identity.
fn x_mod_n_opt<C>(point: &Affine<C>) -> Option<C::Scalar>
where
    C: ShortWeierstrass,
{
    point
        .coordinates_opt()
        .map(|(x, _)| reduce_once::<C>(&x.to_bytes_be()))
}

/// The nonces of RFC 6979 section 3.2 for one key and one message: the
/// successive $n$-sized blocks of an HMAC_DRBG seeded with $x$ and
/// $\mathrm{bits2octets}(H(m))$, keeping those in $[1, n - 1]$. An iterator
/// because signing asks for another nonce when $r$ or $s$ is zero.
pub struct Rfc6979<C, H>
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    drbg: HmacDrbg<H>,
    curve: PhantomData<C>,
}

impl<C, H> Rfc6979<C, H>
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    /// The generator for the secret scalar `secret` and the message hash
    /// `hash` (section 3.2, steps a to g).
    ///
    /// # Errors
    ///
    /// [`DrbgError::EntropyTooShort`] when the scalar is shorter than the
    /// hash's security strength (never for P-256, P-384 and P-521 with the
    /// SHA-2 hashes).
    pub fn new(secret: &C::Scalar, hash: &[u8]) -> Result<Self, DrbgError> {
        let x = SecretBytes::new(secret.to_bytes_be());
        let h = reduce_once::<C>(&bits2int::<C>(hash)).to_bytes_be();
        let drbg = HmacDrbg::new(
            Entropy(x.expose()),
            Nonce(&h),
            Personalization(&[]),
        )?;
        Ok(Rfc6979 {
            drbg,
            curve: PhantomData,
        })
    }

    /// The next nonce (section 3.2, step h).
    ///
    /// # Errors
    ///
    /// [`DrbgError::ReseedRequired`], after $2^{48}$ blocks.
    pub fn next_nonce(&mut self) -> Result<C::Scalar, DrbgError> {
        loop {
            let mut block = vec![0u8; C::Scalar::BYTES];
            self.drbg.generate(&mut block, AdditionalInput::NONE)?;
            let t = SecretBytes::new(bits2int::<C>(&block));
            block.fill(0);
            let (k, below_n) = C::Scalar::from_bytes_be(t.expose());
            // A rejected block is public: only how many were rejected leaks.
            if (below_n & !k.is_zero()).to_bool_vartime() {
                return Ok(k);
            }
        }
    }
}

/// Why signing failed: the nonce generator refused (not reachable for the
/// supported curves and hashes, see [`Rfc6979::new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningError(pub DrbgError);

impl<C, H> SignatureScheme for Ecdsa<C, H>
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    type SigningKey = EcKeyPair<C>;
    type VerifyingKey = Affine<C>;
    type Signature = Signature<C>;
}

impl<C, H> Ecdsa<C, H>
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    /// The signature with the nonce $k$, `None` when $r$ or $s$ is zero
    /// (FIPS 186-5 section 6.4.1, steps 4 to 10), for the secret scalar $d$
    /// and the message scalar $e$. Constant time in $d$ and $k$, apart from
    /// the public outcome.
    fn sign_with_opt(
        secret: &C::Scalar,
        digest: &C::Scalar,
        nonce: &C::Scalar,
    ) -> Option<Signature<C>> {
        let point =
            C::scalar_mul(&Projective::<C>::generator(), nonce).to_affine();
        let r = x_mod_n_opt::<C>(&point)?;
        let s = nonce.invert() * (*digest + r * *secret);
        Signature::new_opt(r, s)
    }
}

impl<C, H> Signer for Ecdsa<C, H>
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    type Error = SigningError;

    fn sign(
        key: &EcKeyPair<C>,
        message: &[u8],
    ) -> Result<Signature<C>, SigningError> {
        let hash = H::digest(message);
        let e = reduce_once::<C>(&bits2int::<C>(&hash));
        let mut nonces =
            Rfc6979::<C, H>::new(key.secret(), &hash).map_err(SigningError)?;
        loop {
            let k = nonces.next_nonce().map_err(SigningError)?;
            if let Some(signature) = Self::sign_with_opt(key.secret(), &e, &k) {
                return Ok(signature);
            }
        }
    }
}

impl<C, H> Verifier for Ecdsa<C, H>
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    /// FIPS 186-5 section 6.4.2. The key is on the curve by construction;
    /// the identity is rejected here.
    fn verify(
        key: &Affine<C>,
        message: &[u8],
        signature: &Signature<C>,
    ) -> bool {
        if key.is_identity().to_bool_vartime() {
            return false;
        }
        let digest = message_scalar::<C, H>(message);
        let s_inverse = signature.s.invert();
        let u1 = digest * s_inverse;
        let u2 = signature.r * s_inverse;
        let generator = Projective::<C>::generator();
        let public = Projective::<C>::from(*key);
        let point = (C::scalar_mul(&generator, &u1)
            + C::scalar_mul(&public, &u2))
        .to_affine();
        x_mod_n_opt::<C>(&point).is_some_and(|v| v == signature.r)
    }
}

#[cfg(test)]
mod tests;
