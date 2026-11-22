//! NIST P-256 (`prime256v1`, `secp256r1`): its base field, its scalar field
//! (the group order $n$), and its parameters, as a [`ShortWeierstrass`] curve.
//!
//! The values are those of `openssl ecparam -name prime256v1 -param_enc
//! explicit -noout -text` (OpenSSL 3.5.9), the source the output of baldssl is
//! compared against; they are those of [FIPS 186-5] and [SEC 2]. The tests
//! recompute each modulus from its defining formula, and check that the
//! generator is on the curve and has order $n$.
//!
//! [FIPS 186-5]: https://csrc.nist.gov/pubs/fips/186-5/final
//! [SEC 2]: https://www.secg.org/sec2-v2.pdf

use crate::{
    algebra::{
        curve::{Curve, ShortWeierstrass},
        field::Sqrt,
        fp::{Fp, Modulus},
        model::ProjectiveModel,
    },
    ct::Choice,
};

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

/// NIST P-256 (`prime256v1`, `secp256r1`).
pub enum P256 {}

/// Its group of points has prime order: the cofactor is 1 ([SEC 2]).
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
impl Curve for P256 {
    type Base = FieldP256;
    type Scalar = ScalarP256;
    const NAME: &'static str = "prime256v1";
    const COFACTOR: u64 = 1;
    const GX: &'static str =
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const GY: &'static str =
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    /// The cofactor is 1: by Lagrange every point on the curve has an order
    /// dividing the prime $n$, so being on the curve is being in $G$.
    fn is_in_prime_subgroup<P>(point: &P) -> Choice
    where
        P: ProjectiveModel<Curve = Self>,
    {
        point.is_on_curve()
    }
}

impl ShortWeierstrass for P256 {
    const B: &'static str =
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
}

/// $p \equiv 3 \pmod 4$: the root is $a^{(p + 1)/4}$.
impl Sqrt for FieldP256 {
    fn sqrt(&self) -> (Self, Choice) {
        self.sqrt_3_mod_4()
    }
}
