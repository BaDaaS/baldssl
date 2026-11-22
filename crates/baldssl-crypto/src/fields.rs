//! The prime fields of Curve25519 and Ed25519. The NIST fields are defined
//! with their curves, in `curves::p256`, `curves::p384` and `curves::p521`.
//!
//! The Curve25519 prime and the Ed25519 group order are from [RFC 7748] and
//! [RFC 8032], section 5.1. The tests recompute each from its defining
//! formula.
//!
//! [RFC 7748]: https://www.rfc-editor.org/rfc/rfc7748
//! [RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032

use crate::algebra::fp::{Fp, Modulus};

/// The base field of Curve25519 and Ed25519, $p = 2^{255} - 19$.
pub enum Curve25519Base {}
impl Modulus<4> for Curve25519Base {
    const HEX: &'static str =
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
    const NAME: &'static str = "Curve25519 base";
}
/// An element of the Curve25519 base field.
pub type Field25519 = Fp<Curve25519Base, 4>;

/// The scalar field of Ed25519, the order of its prime subgroup,
/// $\ell = 2^{252} + 27742317777372353535851937790883648493$.
pub enum Ed25519Scalar {}
impl Modulus<4> for Ed25519Scalar {
    const HEX: &'static str =
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
    const NAME: &'static str = "Ed25519 scalar";
}
/// An Ed25519 scalar.
pub type ScalarEd25519 = Fp<Ed25519Scalar, 4>;
