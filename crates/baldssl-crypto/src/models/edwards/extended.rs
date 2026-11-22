//! Extended twisted Edwards coordinates $(X : Y : Z : T)$, with
//! $x = X / Z$, $y = Y / Z$ and $T = X Y / Z$ (so $x y = T / Z$), on
//! $-X^2 + Y^2 = Z^2 + d T^2$.
//!
//! The formulas are from the Explicit-Formulas Database for $a = -1$
//! (<https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html>):
//! [`add-2008-hwcd-3`][add-2008-hwcd-3] for addition, complete since $d$ is not a square, and
//! [`dbl-2008-hwcd`][dbl-2008-hwcd] for doubling. The scalar multiplication is a
//! double-and-add-always ladder with constant-time selection
//! ([`crate::algebra::curve::Curve::scalar_mul`]), as for the Weierstrass curves.
//!
//! [add-2008-hwcd-3]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
//! [dbl-2008-hwcd]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd

use core::{
    marker::PhantomData,
    ops::{Add, Neg, Sub},
};

use super::{affine::Affine, d};
use crate::{
    algebra::{
        curve::TwistedEdwards,
        encoding::{Decodable, Encodable, InvalidEncoding},
        field::{Field, PrimeField},
        group::Group,
        model::{AffineModel, CurveModel, ProjectiveModel},
    },
    ct::{Choice, CtEq, CtSelect},
};

/// A point of the curve `C` in extended coordinates.
pub struct Extended<C>
where
    C: TwistedEdwards,
{
    pub(crate) x: C::Base,
    pub(crate) y: C::Base,
    pub(crate) z: C::Base,
    pub(crate) t: C::Base,
    pub(crate) _curve: PhantomData<C>,
}

impl<C> Clone for Extended<C>
where
    C: TwistedEdwards,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Extended<C> where C: TwistedEdwards {}

impl<C> core::fmt::Debug for Extended<C>
where
    C: TwistedEdwards,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}({:?} : {:?} : {:?} : {:?})",
            C::NAME,
            self.x,
            self.y,
            self.z,
            self.t
        )
    }
}

/// What is specific to this model: its constructor.
impl<C> Extended<C>
where
    C: TwistedEdwards,
{
    pub(crate) fn new(x: C::Base, y: C::Base, z: C::Base, t: C::Base) -> Self {
        Extended {
            x,
            y,
            z,
            t,
            _curve: PhantomData,
        }
    }
}

/// Whether two points are equal: $X_1 Z_2 = X_2 Z_1$ and
/// $Y_1 Z_2 = Y_2 Z_1$ ($Z$ is never zero on the curve).
impl<C> CtEq for Extended<C>
where
    C: TwistedEdwards,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        (self.x * other.z).ct_eq(&(other.x * self.z))
            & (self.y * other.z).ct_eq(&(other.y * self.z))
    }
}

impl<C> CtSelect for Extended<C>
where
    C: TwistedEdwards,
{
    fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(
            C::Base::select(&a.x, &b.x, choice),
            C::Base::select(&a.y, &b.y, choice),
            C::Base::select(&a.z, &b.z, choice),
            C::Base::select(&a.t, &b.t, choice),
        )
    }
}

/// For tests and public values; secret comparisons use [`CtEq`].
impl<C> PartialEq for Extended<C>
where
    C: TwistedEdwards,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool_vartime()
    }
}

impl<C> Eq for Extended<C> where C: TwistedEdwards {}

/// $(-X : Y : Z : -T)$.
impl<C> Neg for Extended<C>
where
    C: TwistedEdwards,
{
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(-self.x, self.y, self.z, -self.t)
    }
}

impl<C> CurveModel for Extended<C>
where
    C: TwistedEdwards,
{
    type Curve = C;

    fn generator() -> Self {
        Self::from(Affine::<C>::generator())
    }

    /// $-X^2 + Y^2 = Z^2 + d T^2$ and $X Y = T Z$, with $Z \neq 0$.
    fn is_on_curve(&self) -> Choice {
        let (x2, y2, z2, t2) = (
            self.x.square(),
            self.y.square(),
            self.z.square(),
            self.t.square(),
        );
        (y2 - x2).ct_eq(&(z2 + d::<C>() * t2))
            & (self.x * self.y).ct_eq(&(self.t * self.z))
            & !self.z.is_zero()
    }

    fn is_in_prime_subgroup(&self) -> Choice {
        C::is_in_prime_subgroup(self)
    }
}

/// $P + Q$ by [`add-2008-hwcd-3`][add-2008-hwcd-3] ($a = -1$, $k = 2d$): $A = (Y_1 - X_1)(Y_2 - X_2)$,
/// $B = (Y_1 + X_1)(Y_2 + X_2)$, $C = k T_1 T_2$, $D = 2 Z_1 Z_2$,
/// $E = B - A$, $F = D - C$, $G = D + C$, $H = B + A$,
/// $X_3 = E F$, $Y_3 = G H$, $T_3 = E H$, $Z_3 = F G$.
///
/// [add-2008-hwcd-3]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
impl<C> Add for Extended<C>
where
    C: TwistedEdwards,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let k = d::<C>().double();
        let a = (self.y - self.x) * (rhs.y - rhs.x);
        let b = (self.y + self.x) * (rhs.y + rhs.x);
        let c = k * self.t * rhs.t;
        let dd = (self.z * rhs.z).double();
        let e = b - a;
        let f = dd - c;
        let g = dd + c;
        let h = b + a;
        Self::new(e * f, g * h, f * g, e * h)
    }
}

/// $P - Q = P + (-Q)$.
impl<C> Sub for Extended<C>
where
    C: TwistedEdwards,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self + -rhs
    }
}

/// The complete formulas for $a = -1$: a constant-time group.
impl<C> Group for Extended<C>
where
    C: TwistedEdwards,
{
    /// $(0 : 1 : 1 : 0)$.
    fn identity() -> Self {
        Self::from(Affine::<C>::identity())
    }

    /// $X = 0$ and $Y = Z$.
    fn is_identity(&self) -> Choice {
        self.x.is_zero() & self.y.ct_eq(&self.z)
    }

    /// $2P$ by [`dbl-2008-hwcd`][dbl-2008-hwcd] ($a = -1$): $A = X^2$, $B = Y^2$,
    /// $C = 2 Z^2$, $D = -A$, $E = (X + Y)^2 - A - B$, $G = D + B$,
    /// $F = G - C$, $H = D - B$, $X_3 = E F$, $Y_3 = G H$, $T_3 = E H$,
    /// $Z_3 = F G$.
    ///
    /// [dbl-2008-hwcd]: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
    fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().double();
        let dd = -a;
        let e = (self.x + self.y).square() - a - b;
        let g = dd + b;
        let f = g - c;
        let h = dd - b;
        Self::new(e * f, g * h, f * g, e * h)
    }
}

impl<C> ProjectiveModel for Extended<C>
where
    C: TwistedEdwards,
{
    type Affine = Affine<C>;

    fn from_affine(point: &Affine<C>) -> Self {
        Self::from(*point)
    }

    fn to_affine(&self) -> Affine<C> {
        Affine::from(*self)
    }
}

/// The representation itself, not the point it denotes: the 4 coordinates
/// $X, Y, Z, T$ as canonical **big-endian** field elements, each on the field's byte
/// length, concatenated in that order. Two
/// representatives of one point have different encodings; the affine chart
/// carries the standard encoding of points.
impl<C> Encodable for Extended<C>
where
    C: TwistedEdwards,
{
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 * C::Base::BYTES);
        out.extend(self.x.to_bytes_be());
        out.extend(self.y.to_bytes_be());
        out.extend(self.z.to_bytes_be());
        out.extend(self.t.to_bytes_be());
        out
    }
}

/// The inverse of the encoding: 4 canonical field elements (each below
/// $p$) that satisfy the model's equations; anything else is rejected.
impl<C> Decodable for Extended<C>
where
    C: TwistedEdwards,
{
    type Error = InvalidEncoding;

    fn decode(bytes: &[u8]) -> Result<Self, InvalidEncoding> {
        decode_option::<C>(bytes).ok_or(InvalidEncoding)
    }
}

/// [`Decodable::decode`], with `None` for a rejection.
fn decode_option<C>(bytes: &[u8]) -> Option<Extended<C>>
where
    C: TwistedEdwards,
{
    if bytes.len() != 4 * C::Base::BYTES {
        return None;
    }
    let mut chunks = bytes.chunks(C::Base::BYTES);
    let (x, x_ok) = C::Base::from_bytes_be(chunks.next()?);
    let (y, y_ok) = C::Base::from_bytes_be(chunks.next()?);
    let (z, z_ok) = C::Base::from_bytes_be(chunks.next()?);
    let (t, t_ok) = C::Base::from_bytes_be(chunks.next()?);
    let candidate = Extended::<C>::new(x, y, z, t);
    (x_ok & y_ok & z_ok & t_ok & candidate.is_on_curve())
        .to_bool_vartime()
        .then_some(candidate)
}
