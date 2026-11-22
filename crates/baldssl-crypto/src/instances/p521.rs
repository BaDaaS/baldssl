//! NIST P-521 (`secp521r1`): its base field, its scalar field (the group
//! order $n$), and its parameters, as a [`ShortWeierstrass`] curve.
//!
//! The values are those of `openssl ecparam -name secp521r1 -param_enc explicit
//! -noout -text` (OpenSSL 3.5.9), the source the output of baldssl is compared
//! against; they are those of [FIPS 186-5] and [SEC 2]. The tests recompute
//! each modulus from its defining formula, and check that the generator is on
//! the curve and has order $n$.
//!
//! [FIPS 186-5]: https://csrc.nist.gov/pubs/fips/186-5/final
//! [SEC 2]: https://www.secg.org/sec2-v2.pdf

use crate::{
    algebra::{
        curve::{Curve, ShortWeierstrass},
        fp::{Fp, Modulus},
        model::ProjectiveModel,
    },
    ct::Choice,
};

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

/// NIST P-521 (`secp521r1`).
pub enum P521 {}

/// Its group of points has prime order: the cofactor is 1 ([SEC 2]).
///
/// [SEC 2]: https://www.secg.org/sec2-v2.pdf
impl Curve for P521 {
    type Base = FieldP521;
    type Scalar = ScalarP521;
    const NAME: &'static str = "secp521r1";
    const COFACTOR: u64 = 1;
    const GX: &'static str = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053f\
        b521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf9\
        7e7e31c2e5bd66";
    const GY: &'static str = "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b\
        446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088\
        be94769fd16650";

    /// The cofactor is 1: by Lagrange every point on the curve has an order
    /// dividing the prime $n$, so being on the curve is being in $G$.
    fn is_in_prime_subgroup<P>(point: &P) -> Choice
    where
        P: ProjectiveModel<Curve = Self>,
    {
        point.is_on_curve()
    }
}

impl ShortWeierstrass for P521 {
    const B: &'static str = "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b3\
        15f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef\
        451fd46b503f00";
}
