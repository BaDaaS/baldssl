//! NIST P-384 (`secp384r1`): its base field, its scalar field (the group
//! order $n$), and its parameters.
//!
//! The values are those of `openssl ecparam -name secp384r1 -param_enc explicit
//! -noout -text` (OpenSSL 3.5.9), the source the output of baldssl is compared
//! against; they are those of [FIPS 186-5] and [SEC 2]. The tests recompute
//! each modulus from its defining formula, and check that the generator is on
//! the curve and has order $n$.
//!
//! [FIPS 186-5]: https://csrc.nist.gov/pubs/fips/186-5/final
//! [SEC 2]: https://www.secg.org/sec2-v2.pdf

use super::params::CurveParams;
use crate::algebra::fp::{Fp, Modulus};

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

/// NIST P-384 (`secp384r1`).
pub enum P384 {}

impl CurveParams for P384 {
    type Base = FieldP384;
    type Scalar = ScalarP384;
    const NAME: &'static str = "secp384r1";
    const B: &'static str = "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112\
        0314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef";
    const GX: &'static str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98\
        59f741e082542a385502f25dbf55296c3a545e3872760ab7";
    const GY: &'static str = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c\
        e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
}
