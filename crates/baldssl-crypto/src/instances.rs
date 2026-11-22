//! The curves, as data: each instance is a type implementing a curve trait
//! of [`crate::algebra::curve`] ([`crate::algebra::curve::ShortWeierstrass`]
//! or [`crate::algebra::curve::TwistedEdwards`]), with its base and scalar
//! fields. The models of [`crate::models`] are generic over these traits, so
//! adding a curve of a supported family adds data, not code.

pub mod edwards25519;
pub mod p256;
pub mod p384;
pub mod p521;

pub use edwards25519::Edwards25519;
pub use p256::P256;
pub use p384::P384;
pub use p521::P521;
