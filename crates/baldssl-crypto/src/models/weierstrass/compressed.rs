//! The SEC 1 compressed encoding of points, as a newtype.
//!
//! A type has one [`Encodable`] implementation, and the affine chart's is the
//! uncompressed form. The compressed form encodes the same points, so it
//! lives on a newtype, [`Compressed`]: a second section of the same set,
//! with its own idempotent `encode . decode` on byte strings.
//!
//! The encoding ([SEC 1][sec1], section 2.3.3): `02 || x` when $y$ is even,
//! `03 || x` when it is odd, with $x$ **big-endian** on the field's byte
//! length; the identity is the single byte `00`. Decoding (section 2.3.4)
//! recovers $y$ as the square root of $x^3 - 3x + b$ of the given parity.
//!
//! [sec1]: https://www.secg.org/sec1-v2.pdf

use super::{
    COMPRESSED_EVEN, COMPRESSED_ODD, IDENTITY,
    affine::{Affine, rhs},
};
use crate::algebra::{
    curve::ShortWeierstrass,
    encoding::{Decodable, Encodable, InvalidEncoding},
    field::{PrimeField, Sqrt},
    model::AffineModel,
};

/// A point of the curve `C`, encoded and decoded in the SEC 1 compressed
/// form.
pub struct Compressed<C>(pub Affine<C>)
where
    C: ShortWeierstrass;

impl<C> Clone for Compressed<C>
where
    C: ShortWeierstrass,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Compressed<C> where C: ShortWeierstrass {}

impl<C> core::fmt::Debug for Compressed<C>
where
    C: ShortWeierstrass,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Compressed({:?})", self.0)
    }
}

impl<C> PartialEq for Compressed<C>
where
    C: ShortWeierstrass,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<C> Eq for Compressed<C> where C: ShortWeierstrass {}

/// `00` for the identity, otherwise `02 || x` or `03 || x` by the parity of
/// $y$, $x$ big-endian.
impl<C> Encodable for Compressed<C>
where
    C: ShortWeierstrass,
{
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        let Some((x, y)) = self.0.coordinates_opt() else {
            return vec![IDENTITY];
        };
        let mut out = Vec::with_capacity(1 + C::Base::BYTES);
        out.push(if y.is_odd().to_bool_vartime() {
            COMPRESSED_ODD
        } else {
            COMPRESSED_EVEN
        });
        out.extend(x.to_bytes_be());
        out
    }
}

/// Decodes `00` as the identity and `02 || x` or `03 || x` as the point with
/// that $x$ and a $y$ of that parity. Rejected: a wrong length or prefix
/// (including the uncompressed `04` and the hybrid `06`, `07`), $x \geq p$,
/// an $x$ with no point ($x^3 - 3x + b$ not a square), and `03` when $y = 0$
/// (its only root is even). Variable time: for public points.
impl<C> Decodable for Compressed<C>
where
    C: ShortWeierstrass,
{
    type Error = InvalidEncoding;

    fn decode(bytes: &[u8]) -> Result<Self, InvalidEncoding> {
        if bytes == [IDENTITY] {
            return Ok(Compressed(Affine::identity()));
        }
        let prefix = *bytes.first().ok_or(InvalidEncoding)?;
        let want_odd = match prefix {
            COMPRESSED_EVEN => false,
            COMPRESSED_ODD => true,
            _ => return Err(InvalidEncoding),
        };
        if bytes.len() != 1 + C::Base::BYTES {
            return Err(InvalidEncoding);
        }
        let x = C::Base::from_bytes_be(bytes.get(1..).ok_or(InvalidEncoding)?)
            .into_vartime_opt()
            .ok_or(InvalidEncoding)?;
        let root = rhs::<C>(x)
            .sqrt()
            .into_vartime_opt()
            .ok_or(InvalidEncoding)?;
        let y = if root.is_odd().to_bool_vartime() == want_odd {
            root
        } else {
            -root
        };
        if y.is_odd().to_bool_vartime() != want_odd {
            // y = 0 = -0 is even, so 03 has no point.
            return Err(InvalidEncoding);
        }
        Affine::<C>::from_coordinates(x, y)
            .into_vartime_opt()
            .map(Compressed)
            .ok_or(InvalidEncoding)
    }
}
