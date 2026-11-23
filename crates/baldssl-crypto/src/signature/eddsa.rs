//! EdDSA ([RFC 8032, section 5][rfc8032-5]), generic over its parameters,
//! and Ed25519, its instance over edwards25519 with SHA-512.
//!
//! RFC 8032 defines EdDSA by a parameter set: the curve, a hash $H$ of
//! $2b$ bits, the length $b$ of encodings, $c = \log_2$ of the cofactor, and
//! $n$, the position of the top bit of secret scalars. [`EddsaParameters`]
//! is that set, [`EdDSA`] the scheme over any of them, and [`Ed25519`] the
//! instance of section 5.1. Adding an instance is adding a parameter set.
//!
//! # Key expansion ([section 5.1.5][rfc8032-5.1.5])
//!
//! A secret key is $b$ random bits, the seed. Its secret scalar is the first
//! $b$ bits of $H(\mathrm{seed})$, as a little-endian integer, *clamped*:
//! the $c$ low bits cleared (so the scalar is a multiple of the cofactor),
//! the bits above $n$ cleared and bit $n$ set. The public key is the encoding
//! of $s B$. The second half of the hash is the nonce prefix of signing,
//! not needed for keys.
//!
//! # Signing ([section 5.1.6][rfc8032-5.1.6])
//!
//! With $h = H(\mathrm{seed})$, $s$ the secret scalar and $A$ the public
//! key: $r = H(h_{b..2b} \,\|\, M) \bmod \ell$, $R = rB$,
//! $k = H(\underline{R} \,\|\, \underline{A} \,\|\, M) \bmod \ell$ and
//! $S = r + k s \bmod \ell$; the signature is $\underline{R} \,\|\,
//! \underline{S}$, each $b$ bits, little-endian. Deterministic: the nonce
//! $r$ is a hash of a secret and the message.
//!
//! # Verifying ([section 5.1.7][rfc8032-5.1.7])
//!
//! $S \geq \ell$ is rejected (against malleability, as the section
//! requires), and so is a public key that is not the encoding of a point,
//! read as OpenSSL reads it ([`PublicKey`]).
//! Then $k$ is recomputed and the signature verifies when the encoding of
//! $S B - k A$ is $\underline{R}$, byte for byte: the *cofactorless*
//! equation, compared on encodings, which rejects a non-canonical
//! $\underline{R}$ (an encoding is canonical). The section allows the
//! cofactored equation $8 S B = 8 R + 8 k A$ instead; the two differ
//! only on signatures built with small-order components, and the
//! cofactorless one is the choice that gives OpenSSL's verdicts (the tests
//! compare them on the edge cases of Chalkias, Garillot and Nikolaenko).
//!
//! [rfc8032-5]: https://www.rfc-editor.org/rfc/rfc8032#section-5
//! [rfc8032-5.1.5]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
//! [rfc8032-5.1.6]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6
//! [rfc8032-5.1.7]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7

#![allow(
    clippy::arithmetic_side_effects,
    reason = "the operators on scalars and points are those of the scalar \
              field and the curve group, which are modular"
)]

use core::marker::PhantomData;

use super::{DigitalSignature, SignatureScheme, Signer, Verifier};
use crate::{
    Digest, Sha512,
    algebra::{
        curve::{Curve, TwistedEdwards},
        encoding::{Decodable, Encodable, InvalidEncoding},
        field::PrimeField,
        model::{CurveModel, ProjectiveModel},
    },
    instances::Edwards25519,
    keys::EdDsaKeyPair,
    models::edwards::{
        affine::{Affine, DecodingRules},
        extended::Extended,
    },
    secret::SecretBytes,
};

/// The parameters of an EdDSA instance ([RFC 8032, section 5][rfc8032-5]).
///
/// [rfc8032-5]: https://www.rfc-editor.org/rfc/rfc8032#section-5
pub trait EddsaParameters: 'static {
    /// The twisted Edwards curve.
    type Curve: TwistedEdwards;
    /// The hash $H$, of $2b$ bits.
    type Hash: Digest;
    /// A secret key: $b$ bits.
    type Seed: AsRef<[u8]>;
    /// $b$, the bit length of encodings and of secret keys.
    const B: usize;
    /// $c$, the base-2 logarithm of the cofactor.
    const C: usize;
    /// $n$, the position of the top bit of secret scalars.
    const N: usize;
}

/// EdDSA over the parameter set `P`.
pub struct EdDSA<P>(PhantomData<P>)
where
    P: EddsaParameters;

/// The secret scalar of section 5.1.5 as $b$ little-endian bytes: the first
/// half of $H(\mathrm{seed})$ with the $c$ low bits and the bits above $n$
/// cleared, and bit $n$ set.
fn clamped_le<P>(seed: &P::Seed) -> Vec<u8>
where
    P: EddsaParameters,
{
    let h = SecretBytes::new(P::Hash::digest(seed.as_ref()));
    let mut s: Vec<u8> = h.expose().iter().take(P::B / 8).copied().collect();
    for bit in 0..P::C {
        set_bit(&mut s, bit, false);
    }
    for bit in P::N..P::B {
        set_bit(&mut s, bit, false);
    }
    set_bit(&mut s, P::N, true);
    s
}

/// Clears, then sets, bit `index` of a little-endian integer.
fn set_bit(le: &mut [u8], index: usize, value: bool) {
    if let Some(byte) = le.get_mut(index / 8) {
        let mask = 1u8 << (index % 8);
        *byte = (*byte & !mask) | if value { mask } else { 0 };
    }
}

impl<P> DigitalSignature for EdDSA<P>
where
    P: EddsaParameters,
{
    type Group = Extended<P::Curve>;
    type SecretKey = P::Seed;
    type Scalar = Vec<u8>;

    /// The clamped first half of $H(\mathrm{seed})$, big-endian.
    fn secret_scalar(seed: &P::Seed) -> Vec<u8> {
        let mut s = clamped_le::<P>(seed);
        s.reverse();
        s
    }
}

/// The scalar field of the parameter set's curve.
type Scalar<P> = <<P as EddsaParameters>::Curve as Curve>::Scalar;

/// A hash of the concatenation of `parts`, read as a little-endian integer
/// modulo $\ell$.
fn hash_scalar<P>(parts: &[&[u8]]) -> Scalar<P>
where
    P: EddsaParameters,
{
    Scalar::<P>::from_le_bytes_mod_order(&P::Hash::digest_parts(parts))
}

/// An EdDSA public key as a verifier holds it: the encoding as given
/// (which the challenge hash covers) and the point it decodes to.
#[derive(Clone)]
pub struct PublicKey<P>
where
    P: EddsaParameters,
{
    encoding: Vec<u8>,
    point: Extended<P::Curve>,
}

impl<P> PublicKey<P>
where
    P: EddsaParameters,
{
    /// The point.
    #[must_use]
    pub fn point(&self) -> &Extended<P::Curve> {
        &self.point
    }
}

/// The key's $b$-bit encoding ([section 5.1.2]), little-endian.
///
/// [section 5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2
impl<P> Encodable for PublicKey<P>
where
    P: EddsaParameters,
{
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        self.encoding.clone()
    }
}

/// Decoded as OpenSSL 3.5 and 4.1 decode an Ed25519 public key
/// ([`DecodingRules::OpenSsl`]): $y$ modulo $p$, and the sign bit ignored
/// when $x = 0$. This deviates from RFC 8032 section 5.1.3, which rejects
/// both, so that baldssl's verdicts are OpenSSL's on every edge case; the
/// challenge hash covers the bytes as given, as in OpenSSL. A $y$ with no
/// point is [`InvalidEncoding`].
impl<P> Decodable for PublicKey<P>
where
    P: EddsaParameters,
{
    type Error = InvalidEncoding;

    fn decode(bytes: &[u8]) -> Result<Self, InvalidEncoding> {
        let point =
            Affine::<P::Curve>::decode_with(bytes, DecodingRules::OpenSsl)?;
        Ok(PublicKey {
            encoding: bytes.to_vec(),
            point: Extended::from(point),
        })
    }
}

/// An EdDSA signature: $\underline{R}$ as given (verification compares
/// encodings, so it is never decoded) and $S$, below $\ell$.
#[derive(Clone)]
pub struct Signature<P>
where
    P: EddsaParameters,
{
    r: Vec<u8>,
    s: Scalar<P>,
}

impl<P> PartialEq for Signature<P>
where
    P: EddsaParameters,
{
    fn eq(&self, other: &Self) -> bool {
        self.r == other.r && self.s == other.s
    }
}

impl<P> Eq for Signature<P> where P: EddsaParameters {}

impl<P> core::fmt::Debug for Signature<P>
where
    P: EddsaParameters,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field("r", &self.r)
            .field("s", &self.s)
            .finish()
    }
}

/// $\underline{R} \,\|\, \underline{S}$, $2b$ bits, each half little-endian.
impl<P> Encodable for Signature<P>
where
    P: EddsaParameters,
{
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        let mut out = self.r.clone();
        // The order l is below 2^b, so a scalar fits in b bits: the resize only appends
        // zeros.
        let mut s = self.s.to_bytes_le();
        s.resize(P::B / 8, 0);
        out.extend(s);
        out
    }
}

/// $2b$ bits; [`InvalidEncoding`] for another length or $S \geq \ell$
/// (section 5.1.7, step 1).
impl<P> Decodable for Signature<P>
where
    P: EddsaParameters,
{
    type Error = InvalidEncoding;

    fn decode(bytes: &[u8]) -> Result<Self, InvalidEncoding> {
        let half = P::B / 8;
        if bytes.len() != 2 * half {
            return Err(InvalidEncoding);
        }
        let (r, s_le) = bytes.split_at(half);
        // The scalar field's encoding may be shorter than b bits: the
        // bytes above it must be zero.
        let (low, high) = s_le
            .split_at_checked(Scalar::<P>::BYTES)
            .ok_or(InvalidEncoding)?;
        let (s, below) = Scalar::<P>::from_bytes_le(low);
        if high.iter().any(|&b| b != 0) || !below.to_bool_vartime() {
            return Err(InvalidEncoding);
        }
        Ok(Signature { r: r.to_vec(), s })
    }
}

impl<P> SignatureScheme for EdDSA<P>
where
    P: EddsaParameters,
    P::Seed: AsMut<[u8]>,
{
    type SigningKey = EdDsaKeyPair<P>;
    type VerifyingKey = PublicKey<P>;
    type Signature = Signature<P>;
}

impl<P> Signer for EdDSA<P>
where
    P: EddsaParameters,
    P::Seed: AsMut<[u8]>,
{
    /// Signing cannot fail.
    type Error = core::convert::Infallible;

    /// Section 5.1.6. Constant time in the seed.
    fn sign(
        key: &EdDsaKeyPair<P>,
        message: &[u8],
    ) -> Result<Signature<P>, core::convert::Infallible> {
        let h = SecretBytes::new(P::Hash::digest(key.seed().as_ref()));
        let prefix = h.expose().get(P::B / 8..).unwrap_or_default();
        let s = SecretBytes::new(clamped_le::<P>(key.seed()));
        let secret = Scalar::<P>::from_le_bytes_mod_order(s.expose());
        let r = hash_scalar::<P>(&[prefix, message]);
        let big_r = <P::Curve as Curve>::scalar_mul(
            &Extended::<P::Curve>::generator(),
            &r,
        )
        .to_affine()
        .encode();
        let k = hash_scalar::<P>(&[&big_r, key.public(), message]);
        Ok(Signature {
            r: big_r,
            s: r + k * secret,
        })
    }
}

impl<P> Verifier for EdDSA<P>
where
    P: EddsaParameters,
    P::Seed: AsMut<[u8]>,
{
    /// Section 5.1.7, cofactorless, comparing encodings (see the module
    /// documentation).
    fn verify(
        key: &PublicKey<P>,
        message: &[u8],
        signature: &Signature<P>,
    ) -> bool {
        let k = hash_scalar::<P>(&[&signature.r, &key.encoding, message]);
        let generator = Extended::<P::Curve>::generator();
        let check = <P::Curve as Curve>::scalar_mul(&generator, &signature.s)
            - <P::Curve as Curve>::scalar_mul(&key.point, &k);
        check.to_affine().encode() == signature.r
    }
}

/// The parameters of Ed25519 ([RFC 8032, section 5.1][rfc8032-5.1]):
/// edwards25519, SHA-512, $b = 256$, $c = 3$, $n = 254$.
///
/// [rfc8032-5.1]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1
pub enum Ed25519Parameters {}

impl EddsaParameters for Ed25519Parameters {
    type Curve = Edwards25519;
    type Hash = Sha512;
    type Seed = [u8; 32];
    const B: usize = 256;
    const C: usize = 3;
    const N: usize = 254;
}

/// Ed25519.
pub type Ed25519 = EdDSA<Ed25519Parameters>;

#[cfg(test)]
mod tests;
