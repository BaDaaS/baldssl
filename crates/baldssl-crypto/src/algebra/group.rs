//! The group law of a curve, as traits, and the one scalar multiplication
//! every group shares.
//!
//! [`Group`] is the signature of an abelian group $(G, O, +, -)$ on the
//! points of a model, with constant-time operations; its laws are the
//! abelian group axioms (associativity, commutativity, $O$ neutral,
//! $P + (-P) = O$) and `double(P) = P + P`. [`GroupVartime`] is the same
//! group with variable-time operations, for public points only.
//!
//! Constant time is a property of the algorithm, not of the abstract group:
//! the same group can be implemented both ways. That is why it is in the
//! *type* of the implementation, as two traits, rather than a comment: code
//! that handles secrets takes a [`Group`], so a variable-time implementation
//! cannot reach a secret.
//!
//! # Scalar multiplication
//!
//! An abelian group is a $\mathbb{Z}$-module in exactly one way, since
//! $\mathbb{Z}$ is the initial ring: $k P = P + \dots + P$. So
//! [`scalar_mul`] is defined once, for every [`Group`]. For a group of prime
//! order $\ell$ the action factors through $\mathbb{F}_\ell$, and
//! $k \mapsto k G$ is a group isomorphism $\mathbb{F}_\ell \to G$ whose inverse
//! is the discrete logarithm: its hardness is the security assumption.

use crate::{algebra::model::CurveModel, ct::Choice};

/// An abelian group on the points of a model, with constant-time
/// operations. See the module documentation for the laws.
pub trait Group: CurveModel {
    /// $P + Q$, constant time.
    #[must_use]
    fn add(&self, rhs: &Self) -> Self;

    /// $2P$, constant time.
    #[must_use]
    fn double(&self) -> Self;

    /// $P - Q$.
    #[must_use]
    fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.neg())
    }
}

/// The group law with variable-time operations: correct for every input,
/// but its running time depends on the points, so only for public ones
/// (signature verification, decoding).
pub trait GroupVartime: CurveModel {
    /// $P + Q$, variable time.
    #[must_use]
    fn add_vartime(&self, rhs: &Self) -> Self;

    /// $2P$, variable time.
    #[must_use]
    fn double_vartime(&self) -> Self;
}

/// $k P$, for the integer $k$ given big-endian, constant time in $k$ and $P$:
/// a double-and-add-always ladder over the bits of $k$, most significant
/// first, that always computes the sum and keeps it or not by a
/// constant-time selection. The bytes of $k$ are read in a fixed order, never
/// used as an index.
#[must_use]
pub fn scalar_mul<G>(point: &G, k_be: &[u8]) -> G
where
    G: Group,
{
    let mut acc = G::identity();
    for &byte in k_be {
        for bit in (0..8).rev() {
            acc = acc.double();
            let sum = acc.add(point);
            acc =
                G::select(&acc, &sum, Choice::from_bit(u64::from(byte >> bit)));
        }
    }
    acc
}
