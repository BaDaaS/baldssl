//! The affine chart: points $(x, y)$ with $y^2 = x^3 - 3x + b$.
//!
//! The chart misses the identity $O$, the point at infinity, so a point
//! carries a flag for it; the coordinates of the identity are stored as
//! $(0, 0)$, which is not on the curve since $b \neq 0$. Affine points are
//! what is encoded and decoded ([SEC 1][sec1], sections 2.3.3 and 2.3.4); the
//! group law lives in the projective and Jacobian models.
//!
//! [sec1]: https://www.secg.org/sec1-v2.pdf

use core::{marker::PhantomData, ops::Neg};

use super::projective::Projective;

use crate::{
    algebra::{
        curve::{ShortWeierstrass, constant},
        encoding::{Decodable, Encodable, InvalidEncoding},
        field::{Field, PrimeField},
        model::{AffineModel, Base, CurveModel},
    },
    ct::{Choice, CtEq, CtSelect},
};

/// A point of the curve `C` in affine coordinates, or the identity.
pub struct Affine<C>
where
    C: ShortWeierstrass,
{
    pub(crate) x: C::Base,
    pub(crate) y: C::Base,
    pub(crate) infinity: Choice,
    pub(crate) _curve: PhantomData<C>,
}

impl<C> Clone for Affine<C>
where
    C: ShortWeierstrass,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Affine<C> where C: ShortWeierstrass {}

impl<C> core::fmt::Debug for Affine<C>
where
    C: ShortWeierstrass,
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
    C: ShortWeierstrass,
{
    constant(C::B)
}

/// $x^3 - 3x + b$, the right-hand side of the equation.
pub(crate) fn rhs<C>(x: C::Base) -> C::Base
where
    C: ShortWeierstrass,
{
    x.square() * x - (x.double() + x) + b::<C>()
}

/// The affine point $(x, y)$, not the identity, without checking it.
fn point<C>(x: C::Base, y: C::Base) -> Affine<C>
where
    C: ShortWeierstrass,
{
    Affine {
        x,
        y,
        infinity: Choice::FALSE,
        _curve: PhantomData,
    }
}

/// Equality of points: both identities are equal whatever the stored
/// coordinates, and otherwise the coordinates are compared.
impl<C> CtEq for Affine<C>
where
    C: ShortWeierstrass,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        let both = self.infinity & other.infinity;
        let same = !self.infinity
            & !other.infinity
            & self.x.ct_eq(&other.x)
            & self.y.ct_eq(&other.y);
        both | same
    }
}

impl<C> CtSelect for Affine<C>
where
    C: ShortWeierstrass,
{
    fn select(a: &Self, b: &Self, choice: Choice) -> Self {
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
}

/// For tests and public values; secret comparisons use [`CtEq`].
impl<C> PartialEq for Affine<C>
where
    C: ShortWeierstrass,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool_vartime()
    }
}

impl<C> Eq for Affine<C> where C: ShortWeierstrass {}

/// $(x, -y)$; the identity is its own opposite.
impl<C> Neg for Affine<C>
where
    C: ShortWeierstrass,
{
    type Output = Self;

    fn neg(self) -> Self {
        Affine {
            y: C::Base::select(&-self.y, &self.y, self.infinity),
            ..self
        }
    }
}

impl<C> CurveModel for Affine<C>
where
    C: ShortWeierstrass,
{
    type Curve = C;

    fn generator() -> Self {
        point(constant(C::GX), constant(C::GY))
    }

    /// $y^2 = x^3 - 3x + b$, or the identity.
    fn is_on_curve(&self) -> Choice {
        self.y.square().ct_eq(&rhs::<C>(self.x)) | self.infinity
    }

    fn is_in_prime_subgroup(&self) -> Choice {
        C::is_in_prime_subgroup(&Projective::<C>::from(*self))
    }
}

impl<C> AffineModel for Affine<C>
where
    C: ShortWeierstrass,
{
    /// The point at infinity.
    fn identity() -> Self {
        Affine {
            x: C::Base::ZERO,
            y: C::Base::ZERO,
            infinity: Choice::TRUE,
            _curve: PhantomData,
        }
    }

    fn is_identity(&self) -> Choice {
        self.infinity
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

    fn coordinates(&self) -> Option<(Base<Self>, Base<Self>)> {
        (!self.infinity.to_bool_vartime()).then_some((self.x, self.y))
    }
}

/// The [SEC 1][sec1] uncompressed encoding (section 2.3.3): `04 || x || y`,
/// with $x$ and $y$ **big-endian**, each on the field's byte length (32
/// bytes for P-256, 48 for P-384, 66 for P-521), and the single byte `00`
/// for the identity.
///
/// [sec1]: https://www.secg.org/sec1-v2.pdf
impl<C> Encodable for Affine<C>
where
    C: ShortWeierstrass,
{
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        if self.infinity.to_bool_vartime() {
            return vec![0x00];
        }
        let mut out = Vec::with_capacity(1 + 2 * C::Base::BYTES);
        out.push(0x04);
        out.extend(self.x.to_bytes_be());
        out.extend(self.y.to_bytes_be());
        out
    }
}

/// Decodes the uncompressed encoding ([SEC 1][sec1], section 2.3.4): `00`
/// is the identity, and `04 || x || y` (each coordinate **big-endian**) a
/// point on the curve with canonical coordinates. Anything else is rejected, including the compressed forms
/// (`02`, `03`) and the hybrid ones (`06`, `07`), which are other encodings.
///
/// [sec1]: https://www.secg.org/sec1-v2.pdf
impl<C> Decodable for Affine<C>
where
    C: ShortWeierstrass,
{
    type Error = InvalidEncoding;

    fn decode(bytes: &[u8]) -> Result<Self, InvalidEncoding> {
        decode_opt::<C>(bytes).ok_or(InvalidEncoding)
    }
}

/// [`Decodable::decode`], with `None` for a rejection.
fn decode_opt<C>(bytes: &[u8]) -> Option<Affine<C>>
where
    C: ShortWeierstrass,
{
    if bytes == [0x00] {
        return Some(Affine::<C>::identity());
    }
    let len = C::Base::BYTES;
    if bytes.len() != 1 + 2 * len || bytes.first() != Some(&0x04) {
        return None;
    }
    let (x, x_ok) = C::Base::from_bytes_be(bytes.get(1..=len)?);
    let (y, y_ok) = C::Base::from_bytes_be(bytes.get(1 + len..)?);
    let (point, on_curve) = Affine::<C>::from_coordinates(x, y);
    (x_ok & y_ok & on_curve).to_bool_vartime().then_some(point)
}
