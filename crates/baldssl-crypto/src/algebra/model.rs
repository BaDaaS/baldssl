//! What a model of a curve is: a representation of its points, with the
//! operations that do not depend on the representation chosen.
//!
//! # Variety and group
//!
//! A point satisfies a model's equations when it lies on the *variety*
//! $V(f)$, the zero set of the curve's equation: [`CurveModel::is_on_curve`].
//! That is not membership of the cryptographic group: when the cofactor $h$
//! is above one, the variety's points form $E(\mathbb{F}_p) = G \oplus T$,
//! and those with a component in the small torsion $T$ satisfy the equation
//! without being in $G$. [`CurveModel::is_in_prime_subgroup`] decides
//! membership of $G = \ker [\ell]$ (Lagrange, since $\gcd(h, \ell) = 1$).
//!
//! # The hierarchy
//!
//! ```text
//!        CtEq + CtSelect + Neg + Encodable + Decodable
//!                        |
//!                   CurveModel            G, -P, is_on_curve,
//!                  /     |     \          is_in_prime_subgroup
//!       AffineModel      |      \
//!    (O, coordinates)    |       \
//!          CurveModel + Group     CurveModel + GroupVartime
//!                 |                        |
//!          ProjectiveModel           JacobianModel
//! ```
//!
//! [`Group`] and [`GroupVartime`] are the group law alone, independent of
//! curves; a model trait combines [`CurveModel`] with the group it needs, so
//! a type cannot be a projective model without being a constant-time group,
//! nor a Jacobian model without being a variable-time one. The affine chart
//! carries no group law (the formulas live in the other models), so it has
//! its own identity. Every model is encodable and decodable: the affine chart
//! in the standard point formats, the other models as their coordinates.
//!
//! # The models form a groupoid
//!
//! All models of one curve represent the same group $E(\mathbb{F}_p)$: an
//! elliptic curve is a group object in the category of varieties, the group
//! law being a morphism (Silverman, [*The Arithmetic of Elliptic
//! Curves*][silverman], III.3.6), and each model is a chart or an
//! embedding of that one object. The maps between models, `from_affine` and
//! `to_affine` (and the `From` impls built on them), are isomorphisms of
//! groups: they commute with the operations and preserve both predicates,
//! which the tests check.
//!
//! [silverman]: https://doi.org/10.1007/978-0-387-09494-6

use core::ops::Neg;

use crate::{
    algebra::{
        curve::Curve,
        encoding::{Decodable, Encodable},
        group::{Group, GroupVartime},
    },
    ct::{Choice, CtEq, CtOption, CtSelect},
};

/// The coordinate field of a model.
pub type Base<P> = <<P as CurveModel>::Curve as Curve>::Base;

/// The points of a curve in one representation, with its distinguished
/// points and the predicates every model has.
pub trait CurveModel:
    crate::sealed::Sealed
    + Copy
    + CtEq
    + CtSelect
    + Neg<Output = Self>
    + Encodable
    + Decodable
{
    /// The curve the points are on.
    type Curve: Curve;

    /// The base point, generator of the subgroup $G$ of prime order.
    #[must_use]
    fn generator() -> Self;

    /// Whether the point lies on the variety: the model's equations hold.
    fn is_on_curve(&self) -> Choice;

    /// Whether the point is on the curve and in the subgroup $G$ of prime
    /// order $\ell$, as the instance decides
    /// ([`Curve::is_in_prime_subgroup`]).
    fn is_in_prime_subgroup(&self) -> Choice;
}

/// The affine chart: points as coordinates $(x, y)$. No group law: the
/// formulas live in the other models.
pub trait AffineModel: CurveModel {
    /// The neutral element $O$ of the curve's group.
    #[must_use]
    fn identity() -> Self;

    /// Whether this is $O$.
    fn is_identity(&self) -> Choice;

    /// The point $(x, y)$, present when it is on the curve.
    fn from_coordinates(x: Base<Self>, y: Base<Self>) -> CtOption<Self>;

    /// The coordinates $(x, y)$, `None` for a point at infinity.
    fn coordinates_opt(&self) -> Option<(Base<Self>, Base<Self>)>;
}

/// A projective model with complete formulas: a constant-time group, and an
/// isomorphism with the affine chart.
pub trait ProjectiveModel: CurveModel + Group {
    /// The affine chart of the same curve.
    type Affine: AffineModel<Curve = Self::Curve>;

    /// The point of the affine chart, as a point of this model.
    #[must_use]
    fn from_affine(point: &Self::Affine) -> Self;

    /// The point as a point of the affine chart (one inversion).
    #[must_use]
    fn to_affine(&self) -> Self::Affine;
}

/// A Jacobian model, with faster but incomplete formulas: a variable-time
/// group, and an isomorphism with the affine chart.
pub trait JacobianModel: CurveModel + GroupVartime {
    /// The affine chart of the same curve.
    type Affine: AffineModel<Curve = Self::Curve>;

    /// The point of the affine chart, as a point of this model.
    #[must_use]
    fn from_affine(point: &Self::Affine) -> Self;

    /// The point as a point of the affine chart (one inversion).
    #[must_use]
    fn to_affine(&self) -> Self::Affine;
}
