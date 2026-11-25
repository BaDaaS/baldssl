//! The affine model: points $(x, y)$ with $-x^2 + y^2 = 1 + d x^2 y^2$,
//! the identity being $(0, 1)$. Affine points are what is encoded and
//! decoded ([RFC 8032, sections 5.1.2 and 5.1.3][rfc8032-5.1.2]).
//!
//! [rfc8032-5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2

use core::{marker::PhantomData, ops::Neg};

use baldssl_core::num::u32_to_usize;

use super::{d, extended::Extended};
use crate::{
    algebra::{
        curve::{TwistedEdwards, constant},
        encoding::{Decodable, Encodable, InvalidEncoding},
        field::{Field, PrimeField, Sqrt},
        model::{AffineModel, Base, CurveModel},
    },
    ct::{Choice, CtEq, CtOption, CtSelect},
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

impl<C> crate::sealed::Sealed for Affine<C> where C: TwistedEdwards {}

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

    /// The point $(x, y)$, present when it is on the curve; the
    /// placeholder is the identity.
    fn from_coordinates(x: Base<Self>, y: Base<Self>) -> CtOption<Self> {
        let candidate = point(x, y);
        let on_curve = candidate.is_on_curve();
        CtOption::new(
            Self::select(&Self::identity(), &candidate, on_curve),
            on_curve,
        )
    }

    /// Every point is affine: the model has no point at infinity.
    fn coordinates_opt(&self) -> Option<(Base<Self>, Base<Self>)> {
        Some((self.x, self.y))
    }
}

/// The top bit of the last byte of an encoding, which holds the least
/// significant bit of $x$ ([RFC 8032, section 5.1.2][rfc8032-5.1.2]); the
/// bits below it hold $y$.
///
/// [rfc8032-5.1.2]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2
const SIGN_BIT: u8 = 0x80;

/// $b / 8$, the length of an encoding: the bits of $y$ and one sign bit.
fn encoding_len<C>() -> usize
where
    C: TwistedEdwards,
{
    (u32_to_usize(C::Base::BITS) + 1).div_ceil(8)
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
        // The encoding has room for BITS + 1 bits, so at least BYTES bytes:
        // the resize only appends zeros.
        let mut out = self.y.to_bytes_le();
        out.resize(encoding_len::<C>(), 0);
        // The mask is all ones or all zeros: its low byte, masked, is the
        // sign bit or nothing, without a branch.
        let [mask, ..] = self.x.is_odd().mask().to_le_bytes();
        // The encoding is at least one byte long, so there is a last byte.
        if let Some(last) = out.last_mut() {
            *last |= mask & SIGN_BIT;
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
        Self::decode_with(bytes, DecodingRules::Rfc8032)
    }
}

/// Which encodings of a point [`Affine::decode_with`] accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodingRules {
    /// RFC 8032 section 5.1.3: $y < p$, and not $x = 0$ with the sign bit
    /// set. The canonical encodings only, so decoding inverts encoding.
    Rfc8032,
    /// What OpenSSL 3.5 and 4.1 accept for an Ed25519 public key: $y$ is
    /// read modulo $p$ (so $y \geq p$ is accepted), and the sign bit is
    /// ignored when $x = 0$. A $y$ with no point is still rejected. Several
    /// encodings then denote one point; only verification uses it, to give
    /// OpenSSL's verdicts.
    OpenSsl,
}

impl<C> Affine<C>
where
    C: TwistedEdwards,
{
    /// The point `bytes` encodes under `rules` (RFC 8032 section 5.1.3,
    /// with the relaxations of [`DecodingRules::OpenSsl`] when asked).
    ///
    /// # Errors
    ///
    /// [`InvalidEncoding`] for a wrong length, bytes above the field's
    /// width, a $y$ with no point, and, under [`DecodingRules::Rfc8032`], a
    /// non-canonical $y$ or $x = 0$ with the sign bit set.
    pub fn decode_with(
        bytes: &[u8],
        rules: DecodingRules,
    ) -> Result<Self, InvalidEncoding> {
        if bytes.len() != encoding_len::<C>() {
            return Err(InvalidEncoding);
        }
        let mut le = bytes.to_vec();
        let top = le.last_mut().ok_or(InvalidEncoding)?;
        let x_0 = Choice::from_bit(u64::from((*top & SIGN_BIT) != 0));
        *top &= !SIGN_BIT;
        // The bytes above the field's width, if any, must be zero.
        let (low, high) =
            le.split_at_checked(C::Base::BYTES).ok_or(InvalidEncoding)?;
        if high.iter().any(|&b| b != 0) {
            return Err(InvalidEncoding);
        }
        let canonical = C::Base::from_bytes_le(low).is_some();
        let y = C::Base::from_le_bytes_mod_order(low);
        let y2 = y.square();
        let u = y2 - C::Base::ONE;
        let v = d::<C>() * y2 + C::Base::ONE;
        let root = (u * v.invert()).sqrt();
        let is_square = root.is_some();
        // The placeholder of a non-square is never used: is_square is in
        // both rules below.
        let x = root.unwrap_or_ct(&C::Base::ZERO);
        let flip = x.is_odd() ^ x_0;
        let x = C::Base::select(&x, &-x, flip);
        let bad_sign = x.is_zero() & x_0;
        let valid = match rules {
            DecodingRules::Rfc8032 => canonical & is_square & !bad_sign,
            DecodingRules::OpenSsl => is_square,
        };
        valid
            .to_bool_vartime()
            .then_some(point(x, y))
            .ok_or(InvalidEncoding)
    }
}
