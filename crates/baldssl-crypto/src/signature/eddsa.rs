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
//! [rfc8032-5]: https://www.rfc-editor.org/rfc/rfc8032#section-5
//! [rfc8032-5.1.5]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5

use core::marker::PhantomData;

use super::DigitalSignature;
use crate::{
    Digest, Sha512, algebra::curve::TwistedEdwards, instances::Edwards25519,
    models::edwards::extended::Extended,
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
        let h = P::Hash::digest(seed.as_ref());
        let mut s: Vec<u8> = h.iter().take(P::B / 8).copied().collect();
        for bit in 0..P::C {
            set_bit(&mut s, bit, false);
        }
        for bit in P::N..P::B {
            set_bit(&mut s, bit, false);
        }
        set_bit(&mut s, P::N, true);
        s.reverse();
        s
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
