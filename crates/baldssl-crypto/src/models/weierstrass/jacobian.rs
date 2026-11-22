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

use core::{marker::PhantomData, ops::Neg};

use super::{
    affine::{Affine, b},
    projective::Projective,
};
use crate::{
    algebra::{
        curve::ShortWeierstrass,
        encoding::{Decodable, Encodable},
        field::{Field, PrimeField},
        group::GroupVartime,
        model::{CurveModel, JacobianModel},
    },
    ct::{Choice, CtEq, CtSelect},
};

/// A point $(X : Y : Z)$ of the curve `C` in Jacobian coordinates.
pub struct Jacobian<C>
where
    C: ShortWeierstrass,
{
    pub(crate) x: C::Base,
    pub(crate) y: C::Base,
    pub(crate) z: C::Base,
    pub(crate) _curve: PhantomData<C>,
}

impl<C> Clone for Jacobian<C>
where
    C: ShortWeierstrass,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Jacobian<C> where C: ShortWeierstrass {}

impl<C> core::fmt::Debug for Jacobian<C>
where
    C: ShortWeierstrass,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}[{:?}, {:?}, {:?}]", C::NAME, self.x, self.y, self.z)
    }
}

/// What is specific to this model: its constructor.
impl<C> Jacobian<C>
where
    C: ShortWeierstrass,
{
    pub(crate) fn new(x: C::Base, y: C::Base, z: C::Base) -> Self {
        Jacobian {
            x,
            y,
            z,
            _curve: PhantomData,
        }
    }
}

/// Equality of classes: $X_1 Z_2^2 = X_2 Z_1^2$ and $Y_1 Z_2^3 = Y_2 Z_1^3$.
/// Those equations hold trivially when one side is the identity (stored as
/// $(0, 0, 0)$), so the identity is compared on its own: two points are
/// equal when both are the identity, or neither is and the equations hold.
impl<C> CtEq for Jacobian<C>
where
    C: ShortWeierstrass,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        let (z1z1, z2z2) = (self.z.square(), other.z.square());
        let same_x = (self.x * z2z2).ct_eq(&(other.x * z1z1));
        let same_y =
            (self.y * z2z2 * other.z).ct_eq(&(other.y * z1z1 * self.z));
        let (o1, o2) = (self.is_identity(), other.is_identity());
        (o1 & o2) | (!o1 & !o2 & same_x & same_y)
    }
}

impl<C> CtSelect for Jacobian<C>
where
    C: ShortWeierstrass,
{
    fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(
            C::Base::select(&a.x, &b.x, choice),
            C::Base::select(&a.y, &b.y, choice),
            C::Base::select(&a.z, &b.z, choice),
        )
    }
}

/// For tests and public values; secret comparisons use [`CtEq`].
impl<C> PartialEq for Jacobian<C>
where
    C: ShortWeierstrass,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool_vartime()
    }
}

impl<C> Eq for Jacobian<C> where C: ShortWeierstrass {}

/// $(X, -Y, Z)$.
impl<C> Neg for Jacobian<C>
where
    C: ShortWeierstrass,
{
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(self.x, -self.y, self.z)
    }
}

impl<C> CurveModel for Jacobian<C>
where
    C: ShortWeierstrass,
{
    type Curve = C;

    fn generator() -> Self {
        Self::from(Affine::<C>::generator())
    }

    /// $Y^2 = X^3 - 3 X Z^4 + b Z^6$; the stored identity satisfies it.
    fn is_on_curve(&self) -> Choice {
        let (x, y, z) = (self.x, self.y, self.z);
        let z2 = z.square();
        let z4 = z2.square();
        let rhs =
            x.square() * x - (x * z4).double() - x * z4 + b::<C>() * z4 * z2;
        y.square().ct_eq(&rhs)
    }

    /// Through the projective model, the one with a constant-time group.
    fn is_in_prime_subgroup(&self) -> Choice {
        Projective::<C>::from(*self).is_in_prime_subgroup()
    }
}

/// The incomplete Jacobian formulas: a variable-time group, for public
/// points only.
impl<C> GroupVartime for Jacobian<C>
where
    C: ShortWeierstrass,
{
    /// Stored as $(0, 0, 0)$.
    fn identity() -> Self {
        Self::new(C::Base::ZERO, C::Base::ZERO, C::Base::ZERO)
    }

    /// $Z = 0$.
    fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// $P + Q$ by [`add-2007-bl`][add-2007-bl], with the cases it does not cover handled
    /// first: either input the identity, $P = Q$ (doubling) and $P = -Q$.
    /// Variable time.
    ///
    /// [add-2007-bl]: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
    fn add_vartime(&self, rhs: &Self) -> Self {
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
                self.double_vartime()
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

    /// $2P$ by [`dbl-2001-b`][dbl-2001-b] ($a = -3$): $\delta = Z^2$, $\gamma = Y^2$,
    /// $\beta = X \gamma$, $\alpha = 3 (X - \delta)(X + \delta)$,
    /// $X_3 = \alpha^2 - 8 \beta$, $Z_3 = (Y + Z)^2 - \gamma - \delta$,
    /// $Y_3 = \alpha (4 \beta - X_3) - 8 \gamma^2$. The identity maps to
    /// $Z_3 = 0$, and there is no point of order two on a curve of odd
    /// order, so no other case.
    ///
    /// [dbl-2001-b]: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    fn double_vartime(&self) -> Self {
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
}

impl<C> JacobianModel for Jacobian<C>
where
    C: ShortWeierstrass,
{
    type Affine = Affine<C>;

    fn from_affine(point: &Affine<C>) -> Self {
        Self::from(*point)
    }

    fn to_affine(&self) -> Affine<C> {
        Affine::from(*self)
    }
}

/// The representation itself, not the point it denotes: the 3 coordinates
/// $X, Y, Z$ as canonical **big-endian** field elements, each on the field's byte
/// length, concatenated in that order. Two
/// representatives of one point have different encodings; the affine chart
/// carries the standard encoding of points.
impl<C> Encodable for Jacobian<C>
where
    C: ShortWeierstrass,
{
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 * C::Base::BYTES);
        out.extend(self.x.to_bytes_be());
        out.extend(self.y.to_bytes_be());
        out.extend(self.z.to_bytes_be());
        out
    }
}

/// The inverse of the encoding: 3 canonical field elements (each below
/// $p$) that satisfy the model's equations; anything else is rejected.
impl<C> Decodable for Jacobian<C>
where
    C: ShortWeierstrass,
{
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 3 * C::Base::BYTES {
            return None;
        }
        let mut chunks = bytes.chunks(C::Base::BYTES);
        let (x, x_ok) = C::Base::from_bytes_be(chunks.next()?);
        let (y, y_ok) = C::Base::from_bytes_be(chunks.next()?);
        let (z, z_ok) = C::Base::from_bytes_be(chunks.next()?);
        let candidate = Self::new(x, y, z);
        (x_ok & y_ok & z_ok & candidate.is_on_curve())
            .to_bool_vartime()
            .then_some(candidate)
    }
}
