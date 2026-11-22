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
//!                 CtEq + CtSelect
//!                        |
//!                   CurveModel          the pointed variety: O, G, -P,
//!                  /     |     \        is_on_curve, is_in_prime_subgroup
//!        AffineModel   Group   GroupVartime
//!        (+ Encodable)   |          |
//!                ProjectiveModel  JacobianModel
//! ```
//!
//! A model trait has the group trait it needs as a supertrait, so a type
//! cannot be a projective model without being a constant-time group, nor a
//! Jacobian model without being a variable-time one. The affine model is
//! where points are encoded, and it carries no group law: the formulas live
//! in the other models.
//!
//! # The models form a groupoid
//!
//! All models of one curve represent the same group $E(\mathbb{F}_p)$: an
//! elliptic curve is a group object in the category of varieties, the group
//! law being a morphism (Silverman, III.3.6), and each model is a chart or an
//! embedding of that one object. The maps between models, `from_affine` and
//! `to_affine` (and the `From` impls built on them), are isomorphisms of
//! groups: they commute with the operations and preserve both predicates,
//! which the tests check.

use crate::{
    algebra::{
        curve::Curve,
        encoding::Encodable,
        field::PrimeField,
        group::{Group, GroupVartime, scalar_mul},
    },
    ct::{Choice, CtEq, CtSelect},
};

/// The coordinate field of a model.
pub type Base<P> = <<P as CurveModel>::Curve as Curve>::Base;

/// The points of a curve in one representation, with its distinguished
/// points and the predicates every model has.
pub trait CurveModel: Copy + CtEq + CtSelect {
    /// The curve the points are on.
    type Curve: Curve;

    /// The neutral element $O$.
    #[must_use]
    fn identity() -> Self;

    /// The base point, generator of the subgroup $G$ of prime order.
    #[must_use]
    fn generator() -> Self;

    /// Whether this is $O$.
    fn is_identity(&self) -> Choice;

    /// $-P$, the curve automorphism $[-1]$; every model has it, including
    /// those without a group law.
    #[must_use]
    fn neg(&self) -> Self;

    /// Whether the point lies on the variety: the model's equations hold.
    fn is_on_curve(&self) -> Choice;

    /// Whether the point is on the curve and in the subgroup $G$ of prime
    /// order $\ell$.
    fn is_in_prime_subgroup(&self) -> Choice;
}

/// The affine chart: points as coordinates $(x, y)$, where they are
/// encoded. No group law: the formulas live in the other models.
pub trait AffineModel: CurveModel + Encodable {
    /// The point $(x, y)$, and whether it is on the curve.
    fn from_coordinates(x: Base<Self>, y: Base<Self>) -> (Self, Choice);

    /// The coordinates $(x, y)$, `None` for a point at infinity.
    fn coordinates(&self) -> Option<(Base<Self>, Base<Self>)>;
}

/// A projective model with complete formulas: a constant-time group, and an
/// isomorphism with the affine chart.
pub trait ProjectiveModel: Group {
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
pub trait JacobianModel: GroupVartime {
    /// The affine chart of the same curve.
    type Affine: AffineModel<Curve = Self::Curve>;

    /// The point of the affine chart, as a point of this model.
    #[must_use]
    fn from_affine(point: &Self::Affine) -> Self;

    /// The point as a point of the affine chart (one inversion).
    #[must_use]
    fn to_affine(&self) -> Self::Affine;
}

/// [`CurveModel::is_in_prime_subgroup`] for a projective model: on the
/// curve, and $[\ell] P = O$. With cofactor 1 the second test is implied
/// (Lagrange: $|E(\mathbb{F}_p)| = \ell$ is prime, so every point's order
/// divides $\ell$) and skipped; the branch is on a constant of the curve, not
/// on the point.
pub(crate) fn prime_subgroup<P>(point: &P) -> Choice
where
    P: ProjectiveModel,
{
    let on_curve = point.is_on_curve();
    if <P::Curve as Curve>::COFACTOR == 1 {
        return on_curve;
    }
    let order = <<P::Curve as Curve>::Scalar as PrimeField>::modulus_be();
    on_curve & scalar_mul(point, &order).is_identity()
}
