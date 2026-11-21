//! The prime fields baldssl uses: the base field and the scalar field (the
//! group order) of each curve.
//!
//! The NIST values are copied from `openssl ecparam -name <curve>
//! -param_enc explicit -noout -text` (OpenSSL 3.5.9), the source the output
//! of baldssl is compared against; they are those of FIPS 186-5 and SEC 2.
//! The Curve25519 prime and the Ed25519 group order are from RFC 7748 and
//! RFC 8032, section 5.1. The tests recompute each from its defining
//! formula.

use crate::field::{Fp, Modulus};

/// The base field of P-256, $p = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1$.
pub enum P256Base {}
impl Modulus<4> for P256Base {
    const HEX: &'static str =
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
    const NAME: &'static str = "P-256 base";
}
/// An element of the P-256 base field.
pub type FieldP256 = Fp<P256Base, 4>;

/// The scalar field of P-256, its group order $n$.
pub enum P256Scalar {}
impl Modulus<4> for P256Scalar {
    const HEX: &'static str =
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const NAME: &'static str = "P-256 scalar";
}
/// A P-256 scalar.
pub type ScalarP256 = Fp<P256Scalar, 4>;

/// The base field of P-384, $p = 2^{384} - 2^{128} - 2^{96} + 2^{32} - 1$.
pub enum P384Base {}
impl Modulus<6> for P384Base {
    const HEX: &'static str = "fffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffeffffffff0000000000000000ffffffff";
    const NAME: &'static str = "P-384 base";
}
/// An element of the P-384 base field.
pub type FieldP384 = Fp<P384Base, 6>;

/// The scalar field of P-384.
pub enum P384Scalar {}
impl Modulus<6> for P384Scalar {
    const HEX: &'static str = "fffffffffffffffffffffffffffffffffffffffffffff\
        fffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
    const NAME: &'static str = "P-384 scalar";
}
/// A P-384 scalar.
pub type ScalarP384 = Fp<P384Scalar, 6>;

/// The base field of P-521, the Mersenne prime $p = 2^{521} - 1$.
pub enum P521Base {}
impl Modulus<9> for P521Base {
    const HEX: &'static str = "01ffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffff";
    const NAME: &'static str = "P-521 base";
}
/// An element of the P-521 base field.
pub type FieldP521 = Fp<P521Base, 9>;

/// The scalar field of P-521.
pub enum P521Scalar {}
impl Modulus<9> for P521Scalar {
    const HEX: &'static str = "01ffffffffffffffffffffffffffffffffffffffffffff\
        fffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47ae\
        bb6fb71e91386409";
    const NAME: &'static str = "P-521 scalar";
}
/// A P-521 scalar.
pub type ScalarP521 = Fp<P521Scalar, 9>;

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
