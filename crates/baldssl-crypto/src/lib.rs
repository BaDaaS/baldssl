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
//! 4. The primitives built on them: [`signature`] (EdDSA), [`keys`] (key
//!    pairs whose public part is derived from the secret), and [`hash`]
//!    (SHA-1, SHA-2, [FIPS 180-4][fips180]).
//!
//! [`ct`] (constant-time building blocks) and [`os_rng`] (randomness from
//! the operating system, the only module allowed to use `unsafe`) support
//! all of them.
//!
//! [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final

#![deny(clippy::arithmetic_side_effects)]
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

pub mod algebra;
pub mod ct;
pub mod hash;
pub mod instances;
pub mod keys;
pub mod models;
pub mod os_rng;
pub mod signature;

pub use hash::{Algorithm, Digest, Sha1, Sha224, Sha256, Sha384, Sha512};
