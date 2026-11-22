//! The laws of the algebra traits, as generic checks the tests of every model
//! and instance call: each trait is a theory, each implementation a structure
//! that must satisfy it, and a failing check is a countermodel.

use core::fmt::Debug;

use crate::algebra::{
    curve::Curve,
    encoding::{Decodable, Encodable},
    group::{Group, GroupVartime},
    model::{AffineModel, CurveModel, JacobianModel, ProjectiveModel},
};

/// The abelian group axioms for the constant-time group law, on three
/// points: associativity, commutativity, the identity, inverses,
/// `double = P + P`, `P - Q = P + (-Q)` and $-(-P) = P$.
#[expect(clippy::eq_op, reason = "P - P = O is one of the laws")]
pub(crate) fn group<G>(p: G, q: G, r: G)
where
    G: Group + PartialEq + Debug,
{
    let o = G::identity();
    assert_eq!((p + q) + r, p + (q + r), "associativity");
    assert_eq!(p + q, q + p, "commutativity");
    assert_eq!(p + o, p, "right identity");
    assert_eq!(o + p, p, "left identity");
    assert!((p + -p).is_identity().to_bool_vartime(), "inverse");
    assert!((p - p).is_identity().to_bool_vartime(), "p - p");
    assert_eq!(p.double(), p + p, "doubling");
    assert_eq!(p - q, p + -q, "subtraction");
    assert_eq!(-(-p), p, "involution");
    assert!(o.is_identity().to_bool_vartime(), "identity");
    assert_eq!(-o, o, "-O = O");
}

/// The same axioms for a variable-time group law.
pub(crate) fn group_vartime<G>(p: &G, q: &G, r: &G)
where
    G: GroupVartime + PartialEq + Debug,
{
    let o = G::identity();
    assert_eq!(
        p.add_vartime(q).add_vartime(r),
        p.add_vartime(&q.add_vartime(r)),
        "associativity"
    );
    assert_eq!(p.add_vartime(q), q.add_vartime(p), "commutativity");
    assert_eq!(p.add_vartime(&o), *p, "right identity");
    assert_eq!(o.add_vartime(p), *p, "left identity");
    assert!(p.sub_vartime(p).is_identity().to_bool_vartime(), "inverse");
    assert_eq!(p.double_vartime(), p.add_vartime(p), "doubling");
    assert_eq!(p.sub_vartime(q), p.add_vartime(&-*q), "subtraction");
}

/// The group of a model is closed on the curve: sums of points on the curve
/// are on the curve, and stay in the subgroup when both terms are in it.
pub(crate) fn closed<P>(p: P, q: P)
where
    P: ProjectiveModel + Debug,
{
    assert!((p + q).is_on_curve().to_bool_vartime(), "closure");
    if (p.is_in_prime_subgroup() & q.is_in_prime_subgroup()).to_bool_vartime() {
        assert!((p + q).is_in_prime_subgroup().to_bool_vartime(), "G closed");
    }
}

/// A projective model is isomorphic to the affine chart: the two maps are
/// mutually inverse on points, homomorphisms for the identity, the
/// generator and the opposite, and preserve both predicates.
pub(crate) fn projective_model<P>(p: &P)
where
    P: ProjectiveModel + PartialEq + Debug,
    P::Affine: PartialEq + Debug,
{
    let a = p.to_affine();
    assert_eq!(P::from_affine(&a), *p, "from_affine . to_affine");
    assert_eq!(P::from_affine(&a).to_affine(), a, "to_affine . from_affine");
    assert_eq!(P::identity().to_affine(), P::Affine::identity(), "identity");
    assert_eq!(
        P::generator().to_affine(),
        P::Affine::generator(),
        "generator"
    );
    assert_eq!((-*p).to_affine(), -a, "opposite");
    assert_eq!(
        p.is_on_curve().to_bool_vartime(),
        a.is_on_curve().to_bool_vartime(),
        "on the curve"
    );
    assert_eq!(
        p.is_in_prime_subgroup().to_bool_vartime(),
        a.is_in_prime_subgroup().to_bool_vartime(),
        "in the subgroup"
    );
}

/// The same for a Jacobian model.
pub(crate) fn jacobian_model<J>(p: &J)
where
    J: JacobianModel + PartialEq + Debug,
    J::Affine: PartialEq + Debug,
{
    let a = p.to_affine();
    assert_eq!(J::from_affine(&a), *p, "from_affine . to_affine");
    assert_eq!(J::from_affine(&a).to_affine(), a, "to_affine . from_affine");
    assert_eq!(J::identity().to_affine(), J::Affine::identity(), "identity");
    assert_eq!(
        J::generator().to_affine(),
        J::Affine::generator(),
        "generator"
    );
    assert_eq!((-*p).to_affine(), -a, "opposite");
    assert_eq!(
        p.is_in_prime_subgroup().to_bool_vartime(),
        a.is_in_prime_subgroup().to_bool_vartime(),
        "in the subgroup"
    );
}

/// The scalar multiplication is the $\mathbb{Z}$-module structure: it is a
/// homomorphism in the scalar, $(a + b) P = a P + b P$, compatible with the
/// product, $(a b) P = a (b P)$, and $1 P = P$, $0 P = O$.
pub(crate) fn module<P>(
    p: &P,
    a: &<P::Curve as Curve>::Scalar,
    b: &<P::Curve as Curve>::Scalar,
) where
    P: ProjectiveModel + PartialEq + Debug,
{
    use crate::algebra::field::Field;
    type S<P> = <<P as CurveModel>::Curve as Curve>::Scalar;
    let mul = |k: &S<P>, x: &P| <P::Curve as Curve>::scalar_mul(x, k);
    assert_eq!(mul(&(*a + *b), p), mul(a, p) + mul(b, p), "additive");
    assert_eq!(mul(&(*a * *b), p), mul(a, &mul(b, p)), "compatible");
    assert_eq!(mul(&S::<P>::ONE, p), *p, "unit");
    assert!(
        mul(&S::<P>::ZERO, p).is_identity().to_bool_vartime(),
        "zero"
    );
}

/// `decode . encode` is the identity: `encode` is a section, `decode` a
/// retraction.
pub(crate) fn round_trip<E>(x: &E)
where
    E: Encodable + Decodable + PartialEq + Debug,
{
    assert_eq!(
        E::decode(x.encode().as_ref()).as_ref(),
        Some(x),
        "round trip"
    );
}

/// Canonicity: whatever `decode` accepts, `encode` gives back byte for byte,
/// so every value has exactly one accepted encoding. Stronger than the round
/// trip, which says nothing about the bytes `decode` accepts.
pub(crate) fn canonical<E>(bytes: &[u8])
where
    E: Encodable + Decodable,
{
    if let Some(x) = E::decode(bytes) {
        assert_eq!(
            x.encode().as_ref(),
            bytes,
            "non-canonical encoding accepted"
        );
    }
}

/// Every model's encoding round-trips and is canonical, and every point it
/// decodes is on the curve.
pub(crate) fn encodings<P>(p: &P)
where
    P: CurveModel + PartialEq + Debug,
{
    round_trip(p);
    let bytes = p.encode();
    canonical::<P>(bytes.as_ref());
    let decoded = P::decode(bytes.as_ref());
    assert!(decoded.is_some_and(|d| d.is_on_curve().to_bool_vartime()));
}
