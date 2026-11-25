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
//! compare them on the edge cases of Chalkias, Garillot and Nikolaenko,
//! [*Taming the many EdDSAs*][taming], IACR ePrint 2020/1244).
//!
//! [rfc8032-5]: https://www.rfc-editor.org/rfc/rfc8032#section-5
//! [rfc8032-5.1.5]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
//! [rfc8032-5.1.6]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6
//! [rfc8032-5.1.7]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7
//! [taming]: https://eprint.iacr.org/2020/1244

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
    secret::{SecretBytes, SecretScalar},
};

/// The parameters of an EdDSA instance ([RFC 8032, section 5][rfc8032-5]).
///
/// Laws, asserted at compile time for every parameter set signing or key
/// expansion is instantiated with: $b$ is a whole number of bytes, $H$
/// outputs exactly $2b$ bits, and $c < n < b$. Each is what makes the
/// expansion well defined: the secret scalar is the first $b$ bits of the
/// hash, the nonce prefix the other $b$, and the bits cleared and set are
/// inside the scalar. Sealed, so that no parameter set outside this crate
/// can break them.
///
/// [rfc8032-5]: https://www.rfc-editor.org/rfc/rfc8032#section-5
pub trait EddsaParameters: crate::sealed::Sealed + 'static {
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

/// The laws of [`EddsaParameters`], checked when the constant is
/// evaluated: after monomorphisation, so at compile time, for each parameter
/// set [`halves`] is used with.
struct Laws<P>(PhantomData<P>);

impl<P> Laws<P>
where
    P: EddsaParameters,
{
    /// Compiles only when the laws hold.
    const HOLD: () = {
        assert!(P::B.is_multiple_of(8), "EdDSA: b is not a number of bytes");
        assert!(
            P::Hash::OUTPUT_LEN * 8 == 2 * P::B,
            "EdDSA: the hash does not output 2b bits"
        );
        assert!(P::N < P::B, "EdDSA: n is not below b");
        assert!(P::C < P::N, "EdDSA: c is not below n");
    };
}

/// $H(\mathrm{seed})$, wiped when dropped.
fn expand<P>(seed: &P::Seed) -> SecretBytes
where
    P: EddsaParameters,
{
    SecretBytes::new(P::Hash::digest(seed.as_ref()))
}

/// The two halves of $h = H(\mathrm{seed})$, $b$ bits each: the one the
/// secret scalar is made of, and the nonce prefix of signing.
fn halves<P>(h: &SecretBytes) -> (&[u8], &[u8])
where
    P: EddsaParameters,
{
    let () = Laws::<P>::HOLD;
    // By Laws::HOLD, h is 2b / 8 bytes long, so b / 8 is inside it and
    // split_at cannot panic.
    h.expose().split_at(P::B / 8)
}

/// The secret scalar of section 5.1.5 as $b$ little-endian bytes: the first
/// half of $H(\mathrm{seed})$ with the $c$ low bits and the bits above $n$
/// cleared, and bit $n$ set.
fn clamp<P>(low_half: &[u8]) -> SecretBytes
where
    P: EddsaParameters,
{
    let mut s = SecretBytes::new(low_half.to_vec());
    let le = s.expose_mut();
    for bit in 0..P::C {
        clear_bit(le, bit);
    }
    for bit in P::N..P::B {
        clear_bit(le, bit);
    }
    set_bit(le, P::N);
    s
}

/// Clears bit `index` of a little-endian integer. The callers' indices are
/// below $b$ and their integers $b / 8$ bytes long ([`Laws::HOLD`]), so the
/// byte is always there.
fn clear_bit(le: &mut [u8], index: usize) {
    if let Some(byte) = le.get_mut(index / 8) {
        *byte &= !(1u8 << (index % 8));
    }
}

/// Sets bit `index` of a little-endian integer; the byte is always there,
/// as for [`clear_bit`].
fn set_bit(le: &mut [u8], index: usize) {
    if let Some(byte) = le.get_mut(index / 8) {
        *byte |= 1u8 << (index % 8);
    }
}

impl<P> crate::sealed::Sealed for EdDSA<P> where P: EddsaParameters {}

impl<P> DigitalSignature for EdDSA<P>
where
    P: EddsaParameters,
{
    type Group = Extended<P::Curve>;
    type SecretKey = P::Seed;

    /// The clamped first half of $H(\mathrm{seed})$, big-endian.
    fn secret_scalar(seed: &P::Seed) -> SecretBytes {
        let h = expand::<P>(seed);
        let (low, _) = halves::<P>(&h);
        let mut s = clamp::<P>(low);
        s.expose_mut().reverse();
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
/// (which the challenge hash covers) and the point it decodes to. Equality
/// and printing are those of the encoding (a public key is public).
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
    /// The public key of a point, with its canonical encoding: what a key
    /// pair derives from its secret scalar.
    pub(crate) fn from_point(point: &Affine<P::Curve>) -> Self {
        PublicKey {
            encoding: point.encode(),
            point: Extended::from(*point),
        }
    }

    /// The point.
    #[must_use]
    pub fn point(&self) -> &Extended<P::Curve> {
        &self.point
    }

    /// The encoding, as given (little-endian, [section 5.1.2]): what the
    /// challenge hash covers, and what a SubjectPublicKeyInfo carries.
    ///
    /// [section 5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoding
    }
}

impl<P> PartialEq for PublicKey<P>
where
    P: EddsaParameters,
{
    fn eq(&self, other: &Self) -> bool {
        self.encoding == other.encoding
    }
}

impl<P> Eq for PublicKey<P> where P: EddsaParameters {}

impl<P> core::fmt::Debug for PublicKey<P>
where
    P: EddsaParameters,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey(")?;
        for b in &self.encoding {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
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
        if high.iter().any(|&b| b != 0) {
            return Err(InvalidEncoding);
        }
        let s = Scalar::<P>::from_bytes_le(low)
            .into_vartime_opt()
            .ok_or(InvalidEncoding)?;
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

    /// Section 5.1.6. Constant time in the seed. The secret scalar, the
    /// nonce $r$ and the product $k s$ are each a [`SecretScalar`], wiped
    /// when dropped.
    fn sign(
        key: &EdDsaKeyPair<P>,
        message: &[u8],
    ) -> Result<Signature<P>, core::convert::Infallible> {
        let h = expand::<P>(key.seed());
        let (low, prefix) = halves::<P>(&h);
        let s = clamp::<P>(low);
        let secret =
            SecretScalar::new(Scalar::<P>::from_le_bytes_mod_order(s.expose()));
        let r = SecretScalar::new(hash_scalar::<P>(&[prefix, message]));
        let big_r = <P::Curve as Curve>::scalar_mul(
            &Extended::<P::Curve>::generator(),
            r.expose(),
        )
        .to_affine()
        .encode();
        let k = hash_scalar::<P>(&[&big_r, key.public().as_bytes(), message]);
        let ks = SecretScalar::new(k * *secret.expose());
        Ok(Signature {
            r: big_r,
            s: *r.expose() + *ks.expose(),
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

impl crate::sealed::Sealed for Ed25519Parameters {}

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
