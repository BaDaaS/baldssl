//! The affine chart: points $(x, y)$ with $y^2 = x^3 - 3x + b$.
//!
//! The chart misses the identity $O$, the point at infinity, so a point
//! carries a flag for it; the coordinates of the identity are stored as
//! $(0, 0)$, which is not on the curve since $b \neq 0$. Affine points are
//! what is encoded and decoded ([SEC 1, section 2.3.3][sec1]); the group law lives
//! in the projective and Jacobian models.
//!
//! [sec1]: https://www.secg.org/sec1-v2.pdf

use core::marker::PhantomData;

use super::params::{self, CurveParams};
use crate::{ct::Choice, field::PrimeField};

/// A point of the curve `C` in affine coordinates, or the identity.
pub struct Affine<C>
where
    C: CurveParams,
{
    pub(crate) x: C::Base,
    pub(crate) y: C::Base,
    pub(crate) infinity: Choice,
    pub(crate) _curve: PhantomData<C>,
}

impl<C> Clone for Affine<C>
where
    C: CurveParams,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Affine<C> where C: CurveParams {}

impl<C> core::fmt::Debug for Affine<C>
where
    C: CurveParams,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.infinity.to_bool_vartime() {
            write!(f, "{}(identity)", C::NAME)
        } else {
            write!(f, "{}({:?}, {:?})", C::NAME, self.x, self.y)
        }
    }
}

/// The constant $b$ of the curve.
pub(crate) fn b<C>() -> C::Base
where
    C: CurveParams,
{
    params::element(C::B).unwrap_or(C::Base::ZERO)
}

/// $x^3 - 3x + b$, the right-hand side of the equation.
pub(crate) fn rhs<C>(x: C::Base) -> C::Base
where
    C: CurveParams,
{
    x.square() * x - (x.double() + x) + b::<C>()
}

impl<C> Affine<C>
where
    C: CurveParams,
{
    /// The identity, the point at infinity.
    #[must_use]
    pub fn identity() -> Self {
        Affine {
            x: C::Base::ZERO,
            y: C::Base::ZERO,
            infinity: Choice::TRUE,
            _curve: PhantomData,
        }
    }

    /// The standard generator.
    #[must_use]
    pub fn generator() -> Self {
        Affine {
            x: params::element(C::GX).unwrap_or(C::Base::ZERO),
            y: params::element(C::GY).unwrap_or(C::Base::ZERO),
            infinity: Choice::FALSE,
            _curve: PhantomData,
        }
    }

    /// The point $(x, y)$, and whether it is on the curve. When it is not,
    /// the identity is returned with a false [`Choice`].
    #[must_use]
    pub fn from_coordinates(x: C::Base, y: C::Base) -> (Self, Choice) {
        let on_curve = y.square().ct_eq(&rhs::<C>(x));
        let point = Affine {
            x,
            y,
            infinity: Choice::FALSE,
            _curve: PhantomData,
        };
        (Self::select(&Self::identity(), &point, on_curve), on_curve)
    }

    /// Whether the point satisfies the curve equation (the identity does).
    #[must_use]
    pub fn is_on_curve(&self) -> Choice {
        self.y.square().ct_eq(&rhs::<C>(self.x)) | self.infinity
    }

    /// Whether this is the identity.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        self.infinity
    }

    /// The coordinates, `None` for the identity.
    #[must_use]
    pub fn coordinates(&self) -> Option<(C::Base, C::Base)> {
        (!self.infinity.to_bool_vartime()).then_some((self.x, self.y))
    }

    /// The opposite point $(x, -y)$.
    #[must_use]
    pub fn neg(&self) -> Self {
        Affine {
            y: C::Base::select(&-self.y, &self.y, self.infinity),
            ..*self
        }
    }

    /// `a` if `choice` is false, `b` if it is true.
    #[must_use]
    pub fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        Affine {
            x: C::Base::select(&a.x, &b.x, choice),
            y: C::Base::select(&a.y, &b.y, choice),
            infinity: Choice::from_bit(
                crate::ct::select(a.infinity.mask(), b.infinity.mask(), choice)
                    & 1,
            ),
            _curve: PhantomData,
        }
    }

    /// The [SEC 1][sec1] uncompressed encoding: `04 || x || y`, or the single byte
    /// `00` for the identity (section 2.3.3).
    ///
    /// [sec1]: https://www.secg.org/sec1-v2.pdf
    #[must_use]
    pub fn to_uncompressed(&self) -> Vec<u8> {
        if self.infinity.to_bool_vartime() {
            return vec![0x00];
        }
        let mut out = Vec::with_capacity(1 + 2 * C::Base::BYTES);
        out.push(0x04);
        out.extend(self.x.to_bytes_be());
        out.extend(self.y.to_bytes_be());
        out
    }

    /// Decodes the [SEC 1][sec1] uncompressed encoding of a point other than the
    /// identity. Rejects a wrong length or prefix, a non-canonical
    /// coordinate, and a point not on the curve.
    ///
    /// [sec1]: https://www.secg.org/sec1-v2.pdf
    #[must_use]
    pub fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        let len = C::Base::BYTES;
        if bytes.len() != 1 + 2 * len || bytes.first() != Some(&0x04) {
            return None;
        }
        let (x, x_ok) = C::Base::from_bytes_be(bytes.get(1..=len)?);
        let (y, y_ok) = C::Base::from_bytes_be(bytes.get(1 + len..)?);
        let (point, on_curve) = Self::from_coordinates(x, y);
        (x_ok & y_ok & on_curve).to_bool_vartime().then_some(point)
    }
}

/// Equality of points; both identities are equal whatever the stored
/// coordinates.
impl<C> PartialEq for Affine<C>
where
    C: CurveParams,
{
    fn eq(&self, other: &Self) -> bool {
        let both = self.infinity & other.infinity;
        let same = !self.infinity
            & !other.infinity
            & self.x.ct_eq(&other.x)
            & self.y.ct_eq(&other.y);
        (both | same).to_bool_vartime()
    }
}

impl<C> Eq for Affine<C> where C: CurveParams {}
