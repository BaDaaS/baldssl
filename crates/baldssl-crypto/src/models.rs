//! The forms of a curve: representations of its points, each generic over
//! the curve and implementing the model traits of
//! [`crate::algebra::model`].
//!
//! - [`weierstrass`]: affine, projective (complete formulas, a constant-time
//!   group) and Jacobian (incomplete formulas, a variable-time group), for
//!   short Weierstrass curves with $a = -3$.
//! - [`edwards`]: affine and extended (complete formulas, a constant-time
//!   group), for twisted Edwards curves with $a = -1$.
//!
//! The models of one curve represent the same group, and the maps between
//! them are isomorphisms: see [`crate::algebra::model`] for the hierarchy of
//! traits and the groupoid of models.

pub mod edwards;
pub mod weierstrass;
