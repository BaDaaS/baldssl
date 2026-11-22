//! Fields, as signatures: what the curve code may assume of its coordinates
//! and scalars.
//!
//! [`Field`] is the signature of a commutative field $(K, 0, 1, +, \cdot)$:
//! the carrier is the implementing type, the operations are the operator
//! traits and the methods below, and the laws are the field axioms
//! (associativity, commutativity and distributivity of $+$ and $\cdot$, the
//! neutral elements, additive inverses, and multiplicative inverses of every
//! nonzero element). Nothing in the signature states the laws; the property
//! tests of each implementation check them.
//!
//! [`PrimeField`] refines it for $\mathbb{F}_p$: a prime field has a
//! canonical representative in $[0, p)$ for each element, hence a canonical
//! encoding, which a general field does not. Keeping the two apart is what
//! lets extension fields ($\mathbb{F}_{p^k}$, for pairings or for curves
//! over extensions) implement [`Field`] later without inventing an encoding.
//!
//! Every operation here is constant time in the values: [`Choice`] carries
//! the result of every predicate, never a `bool`.

// The operators are those of the field, modular by definition: they cannot
// overflow.
#![allow(clippy::arithmetic_side_effects)]

use core::{
    fmt,
    ops::{Add, Mul, Neg, Sub},
};

use crate::ct::Choice;

/// The signature of a field. See the module documentation for the laws.
pub trait Field:
    Copy
    + Eq
    + fmt::Debug
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
{
    /// The additive neutral element.
    const ZERO: Self;
    /// The multiplicative neutral element.
    const ONE: Self;

    /// $2a$.
    #[must_use]
    fn double(&self) -> Self {
        *self + *self
    }

    /// $a^2$.
    #[must_use]
    fn square(&self) -> Self {
        *self * *self
    }

    /// $a^{-1}$ for $a \neq 0$, and $0$ for $a = 0$ (so the map is total and
    /// branch-free; callers that need the inverse to exist check
    /// [`Field::is_zero`] first).
    #[must_use]
    fn invert(&self) -> Self;

    /// Whether $a = 0$.
    fn is_zero(&self) -> Choice;

    /// Whether $a = b$, without branching on the values.
    fn ct_eq(&self, other: &Self) -> Choice;

    /// `a` if `choice` is false, `b` if it is true, without branching.
    #[must_use]
    fn select(a: &Self, b: &Self, choice: Choice) -> Self;
}

/// A prime field $\mathbb{F}_p$, with its canonical big-endian encoding.
pub trait PrimeField: Field {
    /// The number of bits of $p$.
    const BITS: u32;
    /// The length of the canonical encoding, $\lceil \mathrm{BITS} / 8
    /// \rceil$ bytes.
    const BYTES: usize;

    /// The element $v \bmod p$.
    #[must_use]
    fn from_u64(v: u64) -> Self;

    /// Decodes the canonical big-endian encoding of [`PrimeField::BYTES`]
    /// bytes. The [`Choice`] is false, and the element zero, when the length
    /// is wrong or the value is not below $p$; the check does not branch on
    /// the value.
    fn from_bytes_be(bytes: &[u8]) -> (Self, Choice);

    /// The canonical big-endian encoding, [`PrimeField::BYTES`] bytes.
    fn to_bytes_be(&self) -> Vec<u8>;
}
