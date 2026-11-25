//! edwards25519, the twisted Edwards curve of Ed25519 ([RFC 8032, section
//! 5.1][rfc8032-5.1]): $-x^2 + y^2 = 1 + d x^2 y^2$ over $\mathbb{F}_p$, $p =
//! 2^{255} - 19$, $d = -121665 / 121666$, birationally equivalent to Curve25519
//! ([RFC 7748, section 4.1][rfc7748-4.1]); it is also Edwards25519 of [NIST SP
//! 800-186][sp800-186], section 3.2.3.1. Its group of points has order $8
//! \ell$: the cofactor is 8, and the base point $B$, with $y = 4/5$ and $x$
//! even, generates the subgroup of prime order $\ell$.
//!
//! The base field, the scalar field (of order $\ell$) and the curve
//! constants are defined here. The tests recompute each from its defining
//! formula.
//!
//! [rfc8032-5.1]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1
//! [rfc7748-4.1]: https://www.rfc-editor.org/rfc/rfc7748#section-4.1
//! [sp800-186]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf

use crate::{
    algebra::{
        curve::{Curve, TwistedEdwards},
        field::{PrimeField, Sqrt},
        fp::{Fp, Modulus},
        model::ProjectiveModel,
    },
    ct::{Choice, CtOption},
};

/// The base field of Curve25519 and Ed25519, $p = 2^{255} - 19$.
pub enum Curve25519Base {}
impl crate::sealed::Sealed for Curve25519Base {}
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
impl crate::sealed::Sealed for Ed25519Scalar {}
impl Modulus<4> for Ed25519Scalar {
    const HEX: &'static str =
        "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
    const NAME: &'static str = "Ed25519 scalar";
}
/// An Ed25519 scalar.
pub type ScalarEd25519 = Fp<Ed25519Scalar, 4>;

/// edwards25519.
pub enum Edwards25519 {}
impl crate::sealed::Sealed for Edwards25519 {}

impl Curve for Edwards25519 {
    type Base = Field25519;
    type Scalar = ScalarEd25519;
    const NAME: &'static str = "edwards25519";
    const COFACTOR: u64 = 8;
    /// The base point's $x$ ([RFC 8032, section 5.1][rfc8032-5.1]).
    ///
    /// [rfc8032-5.1]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1
    const GX: &'static str =
        "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
    /// The base point's $y = 4/5$.
    const GY: &'static str =
        "6666666666666666666666666666666666666666666666666666666666666658";

    /// On the curve, and $[\ell] P = O$: the cofactor is 8, so
    /// $E(\mathbb{F}_p) = G \oplus T$ with $T$ of order 8, and the points
    /// with a component in $T$ satisfy the equation without being in $G$.
    fn is_in_prime_subgroup<P>(point: &P) -> Choice
    where
        P: ProjectiveModel<Curve = Self>,
    {
        let order = ScalarEd25519::modulus_be();
        point.is_on_curve()
            & Self::scalar_mul_bytes(point, &order).is_identity()
    }
}

/// $p = 2^{255} - 19 \equiv 5 \pmod 8$: Atkin's square root.
impl Sqrt for Field25519 {
    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt_5_mod_8()
    }
}

impl TwistedEdwards for Edwards25519 {
    /// $d = -121665 / 121666$ ([RFC 8032, section 5.1][rfc8032-5.1]; the
    /// tests recompute it).
    ///
    /// [rfc8032-5.1]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1
    const D: &'static str =
        "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";
}
