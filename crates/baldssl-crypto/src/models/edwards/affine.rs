//! The affine model: points $(x, y)$ with $-x^2 + y^2 = 1 + d x^2 y^2$,
//! the identity being $(0, 1)$. Affine points are what is encoded and
//! decoded ([RFC 8032, sections 5.1.2 and 5.1.3][rfc8032-5.1.2]).
//!
//! [rfc8032-5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2

use core::{marker::PhantomData, ops::Neg};

use super::{d, extended::Extended};
use crate::{
    algebra::{
        curve::{TwistedEdwards, constant},
        encoding::{Decodable, Encodable, InvalidEncoding},
        field::{Field, PrimeField, Sqrt},
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

/// $(-x, y)$.
impl<C> Neg for Affine<C>
where
    C: TwistedEdwards,
{
    type Output = Self;

    fn neg(self) -> Self {
        point(-self.x, self.y)
    }
}

impl<C> CurveModel for Affine<C>
where
    C: TwistedEdwards,
{
    type Curve = C;

    fn generator() -> Self {
        point(constant(C::GX), constant(C::GY))
    }

    /// $-x^2 + y^2 = 1 + d x^2 y^2$.
    fn is_on_curve(&self) -> Choice {
        let (x2, y2) = (self.x.square(), self.y.square());
        (y2 - x2).ct_eq(&(C::Base::ONE + d::<C>() * x2 * y2))
    }

    fn is_in_prime_subgroup(&self) -> Choice {
        C::is_in_prime_subgroup(&Extended::<C>::from(*self))
    }
}

impl<C> AffineModel for Affine<C>
where
    C: TwistedEdwards,
{
    /// $(0, 1)$.
    fn identity() -> Self {
        point(C::Base::ZERO, C::Base::ONE)
    }

    fn is_identity(&self) -> Choice {
        self.x.is_zero() & self.y.ct_eq(&C::Base::ONE)
    }

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

/// $b / 8$, the length of an encoding: the bits of $y$ and one sign bit.
fn encoding_len<C>() -> usize
where
    C: TwistedEdwards,
{
    (C::Base::BITS as usize + 1).div_ceil(8)
}

/// The encoding of [RFC 8032, section 5.1.2][rfc8032-5.1.2], **little-endian**
/// (unlike SEC 1): $y$ over $b$ bits, with the least significant bit of $x$ in
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
        let len = encoding_len::<C>();
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

/// The decoding of [RFC 8032, section 5.1.3][rfc8032-5.1.3], from the
/// **little-endian** encoding: read $y$ and the sign bit $x_0$; solve $x^2 = (y^2 - 1) / (d y^2 + 1)$ (the
/// denominator is never zero, $d$ not being a square); pick the root of
/// parity $x_0$. Rejected: a wrong length, $y \geq p$, no square root, and
/// $x = 0$ with $x_0 = 1$ (the one non-canonical sign). Every accepted point
/// is on the curve, including the small-order ones, which RFC 8032 accepts;
/// subgroup membership is a separate check
/// ([`CurveModel::is_in_prime_subgroup`]).
///
/// [rfc8032-5.1.3]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3
impl<C> Decodable for Affine<C>
where
    C: TwistedEdwards,
{
    type Error = InvalidEncoding;

    fn decode(bytes: &[u8]) -> Result<Self, InvalidEncoding> {
        decode_opt::<C>(bytes).ok_or(InvalidEncoding)
    }
}

/// [`Decodable::decode`], with `None` for a rejection.
fn decode_opt<C>(bytes: &[u8]) -> Option<Affine<C>>
where
    C: TwistedEdwards,
{
    if bytes.len() != encoding_len::<C>() {
        return None;
    }
    let mut be: Vec<u8> = bytes.iter().rev().copied().collect();
    let top = be.first_mut()?;
    let x_0 = *top >> 7;
    *top &= 0x7f;
    // The bytes above the field's width, if any, must be zero.
    let extra = be.len().checked_sub(C::Base::BYTES)?;
    let (high, low) = be.split_at(extra);
    if high.iter().any(|&b| b != 0) {
        return None;
    }
    let (y, canonical) = C::Base::from_bytes_be(low);
    let y2 = y.square();
    let u = y2 - C::Base::ONE;
    let v = d::<C>() * y2 + C::Base::ONE;
    let (x, is_square) = (u * v.invert()).sqrt();
    let parity = x.to_bytes_be().last().map_or(0, |b| b & 1);
    let flip = Choice::from_bit(u64::from(parity ^ x_0));
    let x = C::Base::select(&x, &-x, flip);
    let bad_sign = x.is_zero() & Choice::from_bit(u64::from(x_0));
    (canonical & is_square & !bad_sign)
        .to_bool_vartime()
        .then_some(point(x, y))
}
