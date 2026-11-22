//! Extended twisted Edwards coordinates $(X : Y : Z : T)$, with
//! $x = X / Z$, $y = Y / Z$ and $T = X Y / Z$ (so $x y = T / Z$), on
//! $-X^2 + Y^2 = Z^2 + d T^2$.
//!
//! The formulas are from the Explicit-Formulas Database for $a = -1$
//! (<https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html>):
//! [`add-2008-hwcd-3`][add-2008-hwcd-3] for addition, complete since $d$ is not a square, and
//! [`dbl-2008-hwcd`][dbl-2008-hwcd] for doubling. The scalar multiplication is a
//! double-and-add-always ladder with constant-time selection, as for the
//! Weierstrass curves.
//!
//! [add-2008-hwcd-3]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
//! [dbl-2008-hwcd]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd

use super::{affine::Affine, d};
use crate::{ct::Choice, fields::Field25519};

/// A point of the Ed25519 curve in extended coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Extended {
    pub(crate) x: Field25519,
    pub(crate) y: Field25519,
    pub(crate) z: Field25519,
    pub(crate) t: Field25519,
}

impl Extended {
    /// The identity $(0 : 1 : 1 : 0)$.
    #[must_use]
    pub fn identity() -> Self {
        Self::from(Affine::identity())
    }

    /// The base point.
    #[must_use]
    pub fn base() -> Self {
        Self::from(Affine::base())
    }

    /// $P + Q$ by [`add-2008-hwcd-3`][add-2008-hwcd-3] ($a = -1$, $k = 2d$): $A = (Y_1 - X_1)(Y_2 - X_2)$,
    /// $B = (Y_1 + X_1)(Y_2 + X_2)$, $C = k T_1 T_2$, $D = 2 Z_1 Z_2$,
    /// $E = B - A$, $F = D - C$, $G = D + C$, $H = B + A$,
    /// $X_3 = E F$, $Y_3 = G H$, $T_3 = E H$, $Z_3 = F G$.
    ///
    /// [add-2008-hwcd-3]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let k = d().double();
        let a = (self.y - self.x) * (rhs.y - rhs.x);
        let b = (self.y + self.x) * (rhs.y + rhs.x);
        let c = k * self.t * rhs.t;
        let dd = (self.z * rhs.z).double();
        let e = b - a;
        let f = dd - c;
        let g = dd + c;
        let h = b + a;
        Extended {
            x: e * f,
            y: g * h,
            z: f * g,
            t: e * h,
        }
    }

    /// $2P$ by [`dbl-2008-hwcd`][dbl-2008-hwcd] ($a = -1$): $A = X^2$, $B = Y^2$,
    /// $C = 2 Z^2$, $D = -A$, $E = (X + Y)^2 - A - B$, $G = D + B$,
    /// $F = G - C$, $H = D - B$, $X_3 = E F$, $Y_3 = G H$, $T_3 = E H$,
    /// $Z_3 = F G$.
    ///
    /// [dbl-2008-hwcd]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
    #[must_use]
    pub fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().double();
        let dd = -a;
        let e = (self.x + self.y).square() - a - b;
        let g = dd + b;
        let f = g - c;
        let h = dd - b;
        Extended {
            x: e * f,
            y: g * h,
            z: f * g,
            t: e * h,
        }
    }

    /// `a` if `choice` is false, `b` if it is true.
    #[must_use]
    pub fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        Extended {
            x: Field25519::select(&a.x, &b.x, choice),
            y: Field25519::select(&a.y, &b.y, choice),
            z: Field25519::select(&a.z, &b.z, choice),
            t: Field25519::select(&a.t, &b.t, choice),
        }
    }

    /// $k P$ for a scalar given as little-endian bytes (an Ed25519 secret
    /// scalar is an integer below $2^{255}$, not reduced modulo $\ell$):
    /// double-and-add-always from the most significant bit, constant time.
    #[must_use]
    pub fn mul_bytes_le(&self, scalar: &[u8]) -> Self {
        let mut acc = Self::identity();
        for &byte in scalar.iter().rev() {
            for bit in (0..8).rev() {
                acc = acc.double();
                let sum = acc.add(self);
                acc = Self::select(
                    &acc,
                    &sum,
                    Choice::from_bit(u64::from(byte >> bit)),
                );
            }
        }
        acc
    }

    /// Whether two points are equal: $X_1 Z_2 = X_2 Z_1$ and
    /// $Y_1 Z_2 = Y_2 Z_1$.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> Choice {
        (self.x * other.z).ct_eq(&(other.x * self.z))
            & (self.y * other.z).ct_eq(&(other.y * self.z))
    }
}

impl PartialEq for Extended {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool_vartime()
    }
}

impl Eq for Extended {}

impl From<Affine> for Extended {
    fn from(p: Affine) -> Self {
        Extended {
            x: p.x,
            y: p.y,
            z: Field25519::ONE,
            t: p.x * p.y,
        }
    }
}

impl From<Extended> for Affine {
    fn from(p: Extended) -> Self {
        let zinv = p.z.invert();
        Affine {
            x: p.x * zinv,
            y: p.y * zinv,
        }
    }
}
