//! Jacobian coordinates: the weighted projective plane $\mathbb{P}(2, 3, 1)$.
//!
//! A point is a class $(X : Y : Z)$ under
//! $(X, Y, Z) \sim (\lambda^2 X, \lambda^3 Y, \lambda Z)$, on the curve
//!
//! $$Y^2 = X^3 - 3 X Z^4 + b Z^6,$$
//!
//! the affine equation made homogeneous for the weights $(2, 3, 1)$, which
//! are the orders of the poles of $x$ and $y$ at the identity. Where
//! $Z \neq 0$ the point is $(X / Z^2, Y / Z^3)$; every $Z = 0$ is the
//! identity, stored as $(0, 0, 0)$.
//!
//! The formulas are faster than the projective ones but not complete: the
//! identity, doubling and opposite points are separate cases, so the
//! addition branches. It is therefore *variable time* and only for public
//! points (signature verification, decoding); secret scalars go through the
//! projective model. Formulas from the Explicit-Formulas Database
//! (Bernstein and Lange, <https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html>):
//! [`dbl-2001-b`][dbl-2001-b] (Bernstein) for doubling with $a = -3$, and [`add-2007-bl`][add-2007-bl]
//! for addition.
//!
//! [dbl-2001-b]: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
//! [add-2007-bl]: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl

use core::marker::PhantomData;

use super::params::CurveParams;
use crate::{ct::Choice, field::PrimeField};

/// A point $(X : Y : Z)$ of the curve `C` in Jacobian coordinates.
pub struct Jacobian<C>
where
    C: CurveParams,
{
    pub(crate) x: C::Base,
    pub(crate) y: C::Base,
    pub(crate) z: C::Base,
    pub(crate) _curve: PhantomData<C>,
}

impl<C> Clone for Jacobian<C>
where
    C: CurveParams,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Jacobian<C> where C: CurveParams {}

impl<C> core::fmt::Debug for Jacobian<C>
where
    C: CurveParams,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}[{:?}, {:?}, {:?}]", C::NAME, self.x, self.y, self.z)
    }
}

impl<C> Jacobian<C>
where
    C: CurveParams,
{
    pub(crate) fn new(x: C::Base, y: C::Base, z: C::Base) -> Self {
        Jacobian {
            x,
            y,
            z,
            _curve: PhantomData,
        }
    }

    /// The identity, stored as $(0, 0, 0)$.
    #[must_use]
    pub fn identity() -> Self {
        Self::new(C::Base::ZERO, C::Base::ZERO, C::Base::ZERO)
    }

    /// Whether this is the identity, $Z = 0$.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// $2P$ by [`dbl-2001-b`][dbl-2001-b] ($a = -3$): $\delta = Z^2$, $\gamma = Y^2$,
    /// $\beta = X \gamma$, $\alpha = 3 (X - \delta)(X + \delta)$,
    /// $X_3 = \alpha^2 - 8 \beta$, $Z_3 = (Y + Z)^2 - \gamma - \delta$,
    /// $Y_3 = \alpha (4 \beta - X_3) - 8 \gamma^2$. The identity maps to
    /// $Z_3 = 0$, and there is no point of order two on a curve of odd
    /// order, so no other case.
    ///
    /// [dbl-2001-b]: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    #[must_use]
    pub fn double(&self) -> Self {
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x * gamma;
        let t = (self.x - delta) * (self.x + delta);
        let alpha = t.double() + t;
        let beta4 = beta.double().double();
        let x3 = alpha.square() - beta4.double();
        let z3 = (self.y + self.z).square() - gamma - delta;
        let gamma2 = gamma.square();
        let y3 = alpha * (beta4 - x3) - gamma2.double().double().double();
        Self::new(x3, y3, z3)
    }

    /// $P + Q$ by [`add-2007-bl`][add-2007-bl], with the cases it does not cover handled
    /// first: either input the identity, $P = Q$ (doubling) and $P = -Q$.
    /// Variable time.
    ///
    /// [add-2007-bl]: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
    #[must_use]
    pub fn add_vartime(&self, rhs: &Self) -> Self {
        if self.is_identity().to_bool_vartime() {
            return *rhs;
        }
        if rhs.is_identity().to_bool_vartime() {
            return *self;
        }
        let z1z1 = self.z.square();
        let z2z2 = rhs.z.square();
        let u1 = self.x * z2z2;
        let u2 = rhs.x * z1z1;
        let s1 = self.y * rhs.z * z2z2;
        let s2 = rhs.y * self.z * z1z1;
        let h = u2 - u1;
        let r = (s2 - s1).double();
        if h.is_zero().to_bool_vartime() {
            return if r.is_zero().to_bool_vartime() {
                self.double()
            } else {
                Self::identity()
            };
        }
        let i = h.double().square();
        let j = h * i;
        let v = u1 * i;
        let x3 = r.square() - j - v.double();
        let y3 = r * (v - x3) - (s1 * j).double();
        let z3 = ((self.z + rhs.z).square() - z1z1 - z2z2) * h;
        Self::new(x3, y3, z3)
    }

    /// The opposite point $(X, -Y, Z)$.
    #[must_use]
    pub fn neg(&self) -> Self {
        Self::new(self.x, -self.y, self.z)
    }
}
