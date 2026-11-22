//! Ed25519 keys ([RFC 8032, section 5.1.5][rfc8032-5.1.5]).
//!
//! A private key is 32 random bytes, the seed. The secret scalar is derived
//! from it: hash the seed with SHA-512, keep the first 32 bytes, clear the
//! three low bits (so the scalar is a multiple of the cofactor 8), clear the
//! top bit and set the second-highest ("clamping"). The public key is the
//! encoding of $s B$. The second half of the hash is the nonce prefix used
//! by signing, not needed here.
//!
//! [rfc8032-5.1.5]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5

use crate::{
    Digest, Sha512,
    edwards::{affine::Affine, extended::Extended},
};

/// The secret scalar of [RFC 8032, section 5.1.5][rfc8032-5.1.5], as 32 little-endian bytes.
///
/// [rfc8032-5.1.5]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
#[must_use]
pub fn secret_scalar(seed: &[u8; 32]) -> [u8; 32] {
    let h = Sha512::digest(seed);
    let mut s = [0u8; 32];
    for (o, b) in s.iter_mut().zip(&h) {
        *o = *b;
    }
    s[0] &= 0b1111_1000;
    s[31] &= 0b0111_1111;
    s[31] |= 0b0100_0000;
    s
}

/// The public key of a private key (seed): the encoding of $s B$.
#[must_use]
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let s = secret_scalar(seed);
    Affine::from(Extended::base().mul_bytes_le(&s)).encode()
}
