//! Constant-time scalar multiplication.
//!
//! A double-and-add-always ladder over the bits of the scalar, most
//! significant first, in the projective model: each step doubles, adds the
//! point, and keeps the sum or not by a constant-time selection on the bit.
//! The formulas are complete, so the same operations run for every scalar
//! and point; the number of steps is the bit length of the scalar field,
//! not of the scalar. The scalar's bytes are read in a fixed order, never
//! used as an index.

use super::{params::CurveParams, projective::Projective};
use crate::{ct::Choice, field::PrimeField};

/// $k P$, constant time in $k$ and $P$.
#[must_use]
pub fn mul<C>(point: &Projective<C>, scalar: &C::Scalar) -> Projective<C>
where
    C: CurveParams,
{
    let mut acc = Projective::identity();
    for byte in scalar.to_bytes_be() {
        for bit in (0..8).rev() {
            acc = acc.double();
            let sum = acc.add(point);
            acc = Projective::select(
                &acc,
                &sum,
                Choice::from_bit(u64::from(byte >> bit)),
            );
        }
    }
    acc
}

/// $k G$, the public key of the private key $k$.
#[must_use]
pub fn mul_generator<C>(scalar: &C::Scalar) -> Projective<C>
where
    C: CurveParams,
{
    mul(&Projective::generator(), scalar)
}
