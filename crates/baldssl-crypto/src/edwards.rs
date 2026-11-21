//! The twisted Edwards curve of Ed25519.
//!
//! # The curve
//!
//! Ed25519's curve is $-x^2 + y^2 = 1 + d x^2 y^2$ over $\mathbb{F}_p$,
//! $p = 2^{255} - 19$, $d = -121665 / 121666$ (RFC 8032, section 5.1), a
//! twisted Edwards curve with $a = -1$, birationally equivalent to
//! Curve25519. Its group has order $8 \ell$; the base point $B$, with
//! $y = 4/5$ and $x$ even, generates the subgroup of prime order $\ell$.
//! The identity is the affine point $(0, 1)$: unlike the Weierstrass
//! curves, the Edwards model has no point at infinity to add.
//!
//! # Models
//!
//! | Model    | Type                   | Equation                                         | Affine point     | Identity        |
//! | -------- | ---------------------- | ------------------------------------------------ | ---------------- | --------------- |
//! | Affine   | [`affine::Affine`]     | $-x^2 + y^2 = 1 + d x^2 y^2$                     | $(x, y)$         | $(0, 1)$        |
//! | Extended | [`extended::Extended`] | $-X^2 + Y^2 = Z^2 + d T^2$, $X Y = T Z$          | $(X / Z, Y / Z)$ | $(0 : 1 : 1 : 0)$ |
//!
//! Extended coordinates (Hisil, Wong, Carter and Dawson, *Twisted Edwards
//! curves revisited*, ASIACRYPT 2008) add $T = x y$ to the projective
//! coordinates, which makes addition cheaper. For $a = -1$ and $d$ not a
//! square in $\mathbb{F}_p$, which holds for Ed25519, the addition is
//! complete: no case for the identity, doubling or opposite points, so the
//! scalar multiplication in [`extended`] is constant time.
//!
//! # Maps
//!
//! Affine to extended: $(x, y) \mapsto (x : y : 1 : x y)$. Extended to
//! affine: $(X / Z, Y / Z)$, one inversion; $Z$ is never zero on the curve.

// Arithmetic here is on field elements, whose operators are modular and
// cannot overflow; the one-letter names are the formulas' notation.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::similar_names
)]

pub mod affine;
pub mod extended;

use crate::fields::Field25519;

/// $d = -121665 / 121666$, big-endian hexadecimal (RFC 8032, section 5.1;
/// the tests recompute it).
const D: &str =
    "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";

/// The base point's $x$ (RFC 8032, section 5.1).
const BX: &str =
    "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";

/// The base point's $y = 4/5$.
const BY: &str =
    "6666666666666666666666666666666666666666666666666666666666666658";

/// Decodes one of the constants above; the tests check each is canonical.
fn constant(hex: &str) -> Field25519 {
    crate::curves::params::element(hex).unwrap_or(Field25519::ZERO)
}

/// The curve constant $d$.
pub(crate) fn d() -> Field25519 {
    constant(D)
}

#[cfg(test)]
mod tests;
