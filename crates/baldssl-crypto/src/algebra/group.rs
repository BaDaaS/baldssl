//! The group law, as traits, independent of any curve.
//!
//! [`Group`] is the signature of an abelian group $(G, O, +, -)$ with
//! constant-time operations, written with the operators of [`core::ops`].
//! Its laws are the abelian group axioms (associativity, commutativity, $O$
//! neutral, $P + (-P) = O$), `double(P) = P + P` and $P - Q = P + (-Q)$.
//! [`GroupVartime`] is the same signature with variable-time operations, for
//! public points only.
//!
//! Constant time is a property of the algorithm, not of the abstract group:
//! the same group can be implemented both ways. That is why it is in the
//! *type* of the implementation, as two traits: code that handles secrets
//! takes a [`Group`], so a variable-time implementation cannot reach a
//! secret.
//!
//! # Scalar multiplication
//!
//! An abelian group is a $\mathbb{Z}$-module in exactly one way, since
//! $\mathbb{Z}$ is the initial ring: $k P = P + \dots + P$. [`ladder`]
//! computes that action for every [`Group`]; the curves expose it as
//! [`crate::algebra::curve::Curve::scalar_mul`], which an instance may
//! replace with a faster algorithm computing the same map. For a group of
//! prime order $\ell$ the action factors through $\mathbb{F}_\ell$, and
//! $k \mapsto k G$ is a group isomorphism $\mathbb{F}_\ell \to G$ whose
//! inverse is the discrete logarithm: its hardness is the security
//! assumption.

// `+` and `-` here are group operations, which cannot overflow.
#![allow(
    clippy::arithmetic_side_effects,
    reason = "group operations, not integer arithmetic"
)]

use core::ops::{Add, Neg, Sub};

use crate::ct::{Choice, CtEq, CtSelect};

/// An abelian group with constant-time operations. See the module
/// documentation for the laws.
pub trait Group:
    crate::sealed::Sealed
    + Copy
    + CtEq
    + CtSelect
    + Add<Output = Self>
    + Sub<Output = Self>
    + Neg<Output = Self>
{
    /// The neutral element $O$.
    #[must_use]
    fn identity() -> Self;

    /// Whether this is $O$, constant time.
    fn is_identity(&self) -> Choice;

    /// $2P$, constant time.
    #[must_use]
    fn double(&self) -> Self;
}

/// An abelian group with variable-time operations: correct for every input,
/// but the running time depends on the points, so only for public ones
/// (signature verification, decoding).
pub trait GroupVartime:
    crate::sealed::Sealed + Copy + CtEq + Neg<Output = Self>
{
    /// The neutral element $O$.
    #[must_use]
    fn identity() -> Self;

    /// Whether this is $O$.
    fn is_identity(&self) -> Choice;

    /// $P + Q$, variable time.
    #[must_use]
    fn add_vartime(&self, rhs: &Self) -> Self;

    /// $2P$, variable time.
    #[must_use]
    fn double_vartime(&self) -> Self;

    /// $P - Q$, variable time.
    #[must_use]
    fn sub_vartime(&self, rhs: &Self) -> Self {
        self.add_vartime(&-*rhs)
    }
}

/// $k P$, for the integer $k$ given big-endian, constant time in $k$ and $P$:
/// a double-and-add-always ladder over the bits of $k$, most significant
/// first, that always computes the sum and keeps it or not by a
/// constant-time selection. The bytes of $k$ are read in a fixed order, never
/// used as an index.
#[must_use]
pub fn ladder<G>(point: &G, k_be: &[u8]) -> G
where
    G: Group,
{
    let mut acc = G::identity();
    for &byte in k_be {
        for bit in (0..8).rev() {
            acc = acc.double();
            let sum = acc + *point;
            acc =
                G::select(&acc, &sum, Choice::from_bit(u64::from(byte >> bit)));
        }
    }
    acc
}
