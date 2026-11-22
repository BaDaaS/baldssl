//! The affine model: points $(x, y)$ with $-x^2 + y^2 = 1 + d x^2 y^2$,
//! the identity being $(0, 1)$. Affine points are what is encoded
//! ([RFC 8032, section 5.1.2][rfc8032-5.1.2]).
//!
//! [rfc8032-5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2

use core::marker::PhantomData;

use super::{d, extended::Extended};
use crate::{
    algebra::{
        curve::{TwistedEdwards, constant},
        encoding::Encodable,
        field::{Field, PrimeField},
        model::{AffineModel, Base, CurveModel},
    },
    ct::{Choice, CtEq, CtSelect},
};

/// A point of the curve `C` in affine coordinates.
pub struct Affine<C>
where
    C: TwistedEdwards,
{
    pub(crate) x: C::Base,
    pub(crate) y: C::Base,
    pub(crate) _curve: PhantomData<C>,
}

impl<C> Clone for Affine<C>
where
    C: TwistedEdwards,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Affine<C> where C: TwistedEdwards {}

impl<C> core::fmt::Debug for Affine<C>
where
    C: TwistedEdwards,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({:?}, {:?})", C::NAME, self.x, self.y)
    }
}

/// The point $(x, y)$, without checking it.
pub(crate) fn point<C>(x: C::Base, y: C::Base) -> Affine<C>
where
    C: TwistedEdwards,
{
    Affine {
        x,
        y,
        _curve: PhantomData,
    }
}

impl<C> CtEq for Affine<C>
where
    C: TwistedEdwards,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl<C> CtSelect for Affine<C>
where
    C: TwistedEdwards,
{
    fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        point(
            C::Base::select(&a.x, &b.x, choice),
            C::Base::select(&a.y, &b.y, choice),
        )
    }
}

/// For tests and public values; secret comparisons use [`CtEq`].
impl<C> PartialEq for Affine<C>
where
    C: TwistedEdwards,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool_vartime()
    }
}

impl<C> Eq for Affine<C> where C: TwistedEdwards {}

impl<C> CurveModel for Affine<C>
where
    C: TwistedEdwards,
{
    type Curve = C;

    /// $(0, 1)$.
    fn identity() -> Self {
        point(C::Base::ZERO, C::Base::ONE)
    }

    fn generator() -> Self {
        point(constant(C::GX), constant(C::GY))
    }

    fn is_identity(&self) -> Choice {
        self.x.is_zero() & self.y.ct_eq(&C::Base::ONE)
    }

    /// $(-x, y)$.
    fn neg(&self) -> Self {
        point(-self.x, self.y)
    }

    /// $-x^2 + y^2 = 1 + d x^2 y^2$.
    fn is_on_curve(&self) -> Choice {
        let (x2, y2) = (self.x.square(), self.y.square());
        (y2 - x2).ct_eq(&(C::Base::ONE + d::<C>() * x2 * y2))
    }

    /// Through the extended model: on the curve and $[\ell] P = O$.
    fn is_in_prime_subgroup(&self) -> Choice {
        Extended::<C>::from(*self).is_in_prime_subgroup()
    }
}

impl<C> AffineModel for Affine<C>
where
    C: TwistedEdwards,
{
    /// The point $(x, y)$, and whether it is on the curve. When it is not,
    /// the identity is returned with a false [`Choice`].
    fn from_coordinates(x: Base<Self>, y: Base<Self>) -> (Self, Choice) {
        let candidate = point(x, y);
        let on_curve = candidate.is_on_curve();
        (
            Self::select(&Self::identity(), &candidate, on_curve),
            on_curve,
        )
    }

    /// Every point is affine: the model has no point at infinity.
    fn coordinates(&self) -> Option<(Base<Self>, Base<Self>)> {
        Some((self.x, self.y))
    }
}

/// The encoding of [RFC 8032, section 5.1.2][rfc8032-5.1.2]: $y$ in
/// little-endian over $b$ bits, with the least significant bit of $x$ in
/// the top bit, where $b - 1$ is at least the bit length of $p$ (for
/// edwards25519, 32 bytes; the top bit is free since $y < 2^{255}$).
///
/// [rfc8032-5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2
impl<C> Encodable for Affine<C>
where
    C: TwistedEdwards,
{
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        let len = (C::Base::BITS as usize + 1).div_ceil(8);
        let mut out = vec![0u8; len];
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
