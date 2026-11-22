//! The formal definitions: what a field, a group, a curve and a point
//! encoding are, as traits, independent of any representation or instance.
//!
//! The crate is layered so that each layer only depends on the ones above
//! it in this list:
//!
//! 1. [`crate::algebra`] (this module): the signatures, and the one generic
//!    construction every prime field shares, $\mathbb{Z}/p\mathbb{Z}$ in
//!    Montgomery form ([`fp`]).
//! 2. `crate::models`: the forms of a curve (affine, projective, Jacobian,
//!    twisted Edwards), each generic over the curve.
//! 3. `crate::instances`: P-256, P-384, P-521 and edwards25519, as data.
//! 4. The primitives built on them: signatures, hashes.
//!
//! # The categorical reading
//!
//! A trait here is a signature in the sense of universal algebra: a carrier
//! (the implementing type), operations, and laws the property tests check.
//! An implementation is a structure satisfying it, and code generic over the
//! trait is a construction valid in every such structure, which is why each
//! algorithm is written once.
//!
//! The structures relate as follows: a field $K$ is an object of the
//! category of fields; an elliptic curve $E$ over $K$ is a group object in
//! the category of varieties over $K$ (the group law is a morphism, Silverman
//! III.3.6), so its rational points $E(K)$ form an abelian group; the models
//! of $E$ (affine, projective, Jacobian) are isomorphic representations of
//! that one group object, and the maps between them form a groupoid; and an
//! abelian group is a $\mathbb{Z}$-module in exactly one way, since
//! $\mathbb{Z}$ is the initial ring, which is why scalar multiplication is
//! defined once for every group.

pub mod field;
pub mod fp;
