//! The laws of the algebra traits, as generic checks the tests of every model
//! and instance call: each trait is a theory, each implementation a structure
//! that must satisfy it, and a failing check is a countermodel.

use core::fmt::Debug;

use crate::algebra::{
    encoding::{Decodable, Encodable},
    group::{Group, GroupVartime},
    model::{CurveModel, JacobianModel, ProjectiveModel},
};

/// The abelian group axioms for the constant-time group law, on three points:
/// associativity, commutativity, the identity, inverses, `double = add(x, x)`
/// and `sub = add . neg`. The group is closed: the results are on the curve.
pub(crate) fn group<G>(p: &G, q: &G, r: &G)
where
    G: Group + PartialEq + Debug,
{
    let o = G::identity();
    assert_eq!(p.add(q).add(r), p.add(&q.add(r)), "associativity");
    assert_eq!(p.add(q), q.add(p), "commutativity");
    assert_eq!(p.add(&o), *p, "right identity");
    assert_eq!(o.add(p), *p, "left identity");
    assert!(p.add(&p.neg()).is_identity().to_bool_vartime(), "inverse");
    assert_eq!(p.double(), p.add(p), "doubling");
    assert_eq!(p.sub(q), p.add(&q.neg()), "subtraction");
    assert_eq!(p.neg().neg(), *p, "involution");
    assert!(p.add(q).is_on_curve().to_bool_vartime(), "closure");
    assert!(
        o.is_identity().to_bool_vartime() && o.is_on_curve().to_bool_vartime()
    );
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
    assert!(
        p.add_vartime(&p.neg()).is_identity().to_bool_vartime(),
        "inverse"
    );
    assert_eq!(p.double_vartime(), p.add_vartime(p), "doubling");
    assert!(p.add_vartime(q).is_on_curve().to_bool_vartime(), "closure");
}

/// A projective model is isomorphic to the affine chart: the two maps are
/// mutually inverse on points, preserve the identity, are homomorphisms for
/// the opposite, and preserve both predicates.
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
    assert_eq!(p.neg().to_affine(), a.neg(), "opposite");
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
    assert_eq!(p.neg().to_affine(), a.neg(), "opposite");
    assert_eq!(
        p.is_in_prime_subgroup().to_bool_vartime(),
        a.is_in_prime_subgroup().to_bool_vartime(),
        "in the subgroup"
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
