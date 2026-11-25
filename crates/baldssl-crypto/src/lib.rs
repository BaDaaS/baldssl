//! Cryptographic primitives for baldssl, implemented from their
//! specifications with no third-party code.
//!
//! # Layers
//!
//! Each layer depends only on the ones before it:
//!
//! 1. [`algebra`], the formal definitions: fields, curves, models, the group
//!    law and encodings as traits, and $\mathbb{Z}/p\mathbb{Z}$ in Montgomery
//!    form, the one construction every prime field shares.
//! 2. [`models`], the forms of a curve, each generic over the curve: affine,
//!    projective and Jacobian for short Weierstrass curves; affine and
//!    extended for twisted Edwards curves.
//! 3. [`instances`], the curves as data: P-256, P-384, P-521 and
//!    edwards25519.
//! 4. The primitives built on them: [`signature`] (EdDSA and ECDSA),
//!    [`keys`] (key pairs whose public part is derived from the secret),
//!    [`hash`] (SHA-1, SHA-2, [FIPS 180-4][fips180]), [`mac`] (HMAC, [RFC
//!    2104][rfc2104]) and [`drbg`] (HMAC_DRBG, [NIST SP
//!    800-90A][sp800-90a]).
//!
//! [`ct`] (constant-time building blocks), [`secret`] (byte strings
//! overwritten on drop) and [`os_rng`] (randomness from the operating
//! system, the only module allowed to use `unsafe`) support all of them.
//!
//! # Terms
//!
//! - **SHA**, Secure Hash Algorithm; **FIPS**, Federal Information
//!   Processing Standard; **NIST**, the US National Institute of Standards
//!   and Technology, which publishes both.
//! - **MAC**, message authentication code; **HMAC**, the keyed-hash MAC of
//!   [RFC 2104][rfc2104].
//! - **DRBG**, deterministic random bit generator; **HMAC_DRBG**, the one
//!   built on HMAC in [NIST SP 800-90A][sp800-90a] (SP, Special
//!   Publication); **CAVP**, NIST's Cryptographic Algorithm Validation
//!   Program, whose test vectors the tests use.
//! - **EdDSA**, the Edwards-curve Digital Signature Algorithm ([RFC
//!   8032][rfc8032]); **ECDSA**, the Elliptic Curve Digital Signature
//!   Algorithm ([FIPS 186-5][fips186]), with the deterministic nonces of
//!   [RFC 6979][rfc6979].
//! - **EC**, elliptic curve; **RFC**, Request for Comments, the IETF's
//!   (Internet Engineering Task Force) standards series, published by the
//!   [RFC Editor][rfc-editor].
//! - **SEC 1** and **SEC 2**, Standards for Efficient Cryptography: [SEC
//!   1][sec1] (Elliptic Curve Cryptography: the point encodings) and [SEC
//!   2][sec2] (Recommended Elliptic Curve Domain Parameters: the curves),
//!   with [NIST SP 800-186][sp800-186], which gives the same curves.
//! - **DER**, Distinguished Encoding Rules, the canonical encoding of ASN.1
//!   (Abstract Syntax Notation One) values ([ITU-T X.690][x690]), in which
//!   ECDSA signatures are encoded.
//! - **PKCS#8**, Public-Key Cryptography Standards #8, the format of
//!   private keys ([RFC 5958][rfc5958]), which stores both the secret and
//!   the public key of a pair.
//!
//! [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
//! [rfc2104]: https://www.rfc-editor.org/rfc/rfc2104
//! [sp800-90a]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final
//! [rfc8032]: https://www.rfc-editor.org/rfc/rfc8032
//! [fips186]: https://csrc.nist.gov/pubs/fips/186-5/final
//! [rfc6979]: https://www.rfc-editor.org/rfc/rfc6979
//! [rfc-editor]: https://www.rfc-editor.org/
//! [sec1]: https://www.secg.org/sec1-v2.pdf
//! [sec2]: https://www.secg.org/sec2-v2.pdf
//! [sp800-186]: https://csrc.nist.gov/pubs/sp/800/186/final
//! [x690]: https://www.itu.int/rec/T-REC-X.690
//! [rfc5958]: https://www.rfc-editor.org/rfc/rfc5958

#![deny(clippy::arithmetic_side_effects)]
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

pub mod algebra;
pub mod ct;
pub mod drbg;
pub mod hash;
pub mod instances;
pub mod keys;
pub mod mac;
pub mod models;
pub mod os_rng;
pub mod secret;
pub mod signature;

pub use hash::{
    Algorithm, Digest, Sha1, Sha224, Sha256, Sha384, Sha512, WithHash,
};

/// The seal of the traits whose laws baldssl relies on to sign, verify and
/// encode: fields and moduli, curves, models and groups, constant-time
/// equality and selection, hashes, MACs, DRBGs, the EdDSA parameter sets
/// and the signature schemes. Each of them has [`sealed::Sealed`] as a
/// supertrait, which no crate outside this one can name, so no
/// implementation outside this crate can break the laws the tests check
/// here (a trait refining a sealed one, as `ShortWeierstrass` refines
/// `Curve`, is sealed with it).
mod sealed {
    /// Implemented by every type of this crate that implements a sealed
    /// trait.
    #[allow(
        unreachable_pub,
        reason = "public so that public traits can have it as a supertrait, \
                  in a private module so that no other crate can name it"
    )]
    pub trait Sealed {}
}
