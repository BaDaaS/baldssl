//! The models of a twisted Edwards curve with $a = -1$, generic over the
//! curve ([`crate::algebra::curve::TwistedEdwards`]); edwards25519 is an
//! instance ([`crate::instances::edwards25519`]).
//!
//! # The curves
//!
//! $-x^2 + y^2 = 1 + d x^2 y^2$ over $\mathbb{F}_p$. The identity is the
//! affine point $(0, 1)$: unlike the Weierstrass curves, the Edwards model
//! has no point at infinity to add.
//!
//! # Models
//!
//! | Model    | Type                   | Equation                                | Affine point     | Identity          |
//! | -------- | ---------------------- | --------------------------------------- | ---------------- | ----------------- |
//! | Affine   | [`affine::Affine`]     | $-x^2 + y^2 = 1 + d x^2 y^2$            | $(x, y)$         | $(0, 1)$          |
//! | Extended | [`extended::Extended`] | $-X^2 + Y^2 = Z^2 + d T^2$, $X Y = T Z$ | $(X / Z, Y / Z)$ | $(0 : 1 : 1 : 0)$ |
//!
//! Extended coordinates ([Hisil, Wong, Carter and Dawson][hwcd], *Twisted
//! Edwards curves revisited*, ASIACRYPT 2008) add $T = x y$ to the
//! projective coordinates, which makes addition cheaper. For $a = -1$ and
//! $d$ not a square in $\mathbb{F}_p$, which holds for edwards25519, the
//! addition is complete: no case for the identity, doubling or opposite
//! points, so the extended model is a constant-time group.
//!
//! # Maps
//!
//! In [`maps`]: affine to extended, $(x, y) \mapsto (x : y : 1 : x y)$;
//! extended to affine, $(X / Z, Y / Z)$, one inversion ($Z$ is never zero on
//! the curve).
//!
//! [hwcd]: https://eprint.iacr.org/2008/522

// Arithmetic here is on field elements, whose operators are modular and
// cannot overflow; the one-letter names are the formulas' notation.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::similar_names
)]

pub mod affine;
pub mod extended;
pub mod maps;

use crate::algebra::curve::{TwistedEdwards, constant};

/// The curve constant $d$.
pub(crate) fn d<C>() -> C::Base
where
    C: TwistedEdwards,
{
    constant(C::D)
}

#[cfg(test)]
mod tests;
