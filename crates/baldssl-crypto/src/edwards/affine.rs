//! The affine model: points $(x, y)$ with $-x^2 + y^2 = 1 + d x^2 y^2$,
//! the identity being $(0, 1)$. Affine points are what is encoded and
//! decoded ([RFC 8032, section 5.1.2][rfc8032-5.1.2]).
//!
//! [rfc8032-5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2

use super::{BX, BY, constant, d};
use crate::{
    algebra::field::{Field, PrimeField},
    ct::Choice,
    fields::Field25519,
};

/// A point of the Ed25519 curve in affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Affine {
    pub(crate) x: Field25519,
    pub(crate) y: Field25519,
}

impl Affine {
    /// The identity $(0, 1)$.
    #[must_use]
    pub fn identity() -> Self {
        Affine {
            x: Field25519::ZERO,
            y: Field25519::ONE,
        }
    }

    /// The base point $B$.
    #[must_use]
    pub fn base() -> Self {
        Affine {
            x: constant(BX),
            y: constant(BY),
        }
    }

    /// The point $(x, y)$, and whether it is on the curve.
    #[must_use]
    pub fn from_coordinates(x: Field25519, y: Field25519) -> (Self, Choice) {
        let p = Affine { x, y };
        (p, p.is_on_curve())
    }

    /// Whether $-x^2 + y^2 = 1 + d x^2 y^2$.
    #[must_use]
    pub fn is_on_curve(&self) -> Choice {
        let (x2, y2) = (self.x.square(), self.y.square());
        (y2 - x2).ct_eq(&(Field25519::ONE + d() * x2 * y2))
    }

    /// The coordinates $(x, y)$.
    #[must_use]
    pub fn coordinates(&self) -> (Field25519, Field25519) {
        (self.x, self.y)
    }

    /// The opposite point $(-x, y)$.
    #[must_use]
    pub fn neg(&self) -> Self {
        Affine {
            x: -self.x,
            y: self.y,
        }
    }

    /// The 32-byte encoding of [RFC 8032, section 5.1.2][rfc8032-5.1.2]: $y$ in
    /// little-endian, with the least significant bit of $x$ in the most
    /// significant bit of the last byte (free, since $y < 2^{255}$).
    ///
    /// [rfc8032-5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2
    #[must_use]
    pub fn encode(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (o, b) in out.iter_mut().zip(self.y.to_bytes_be().iter().rev()) {
            *o = *b;
        }
        let x_parity = self.x.to_bytes_be().last().map_or(0, |b| b & 1);
        if let Some(last) = out.last_mut() {
            *last |= x_parity << 7;
        }
        out
    }
}
