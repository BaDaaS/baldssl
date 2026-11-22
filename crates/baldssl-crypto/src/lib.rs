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
//!
//! [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
//! [rfc2104]: https://www.rfc-editor.org/rfc/rfc2104
//! [sp800-90a]: https://csrc.nist.gov/pubs/sp/800/90/a/r1/final
//! [rfc8032]: https://www.rfc-editor.org/rfc/rfc8032
//! [fips186]: https://csrc.nist.gov/pubs/fips/186-5/final
//! [rfc6979]: https://www.rfc-editor.org/rfc/rfc6979

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
