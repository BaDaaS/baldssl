//! Projective coordinates, with complete formulas.
//!
//! A point is a class $(X : Y : Z)$ of the projective plane, in which
//! $(X : Y : Z)$ and $(\lambda X : \lambda Y : \lambda Z)$ are the same point
//! for every nonzero $\lambda$ (weights $(1, 1, 1)$). The curve is the affine
//! equation made homogeneous of degree three:
//!
//! $$Y^2 Z = X^3 - 3 X Z^2 + b Z^3.$$
//!
//! Where $Z \neq 0$ the point is the affine point $(X / Z, Y / Z)$. Where
//! $Z = 0$ the equation forces $X = 0$, which leaves the single point
//! $(0 : 1 : 0)$, the identity.
//!
//! The formulas need no case for the identity, for doubling or for opposite
//! points: they are complete on curves of odd order (Renes, Costello and
//! Batina, *Complete addition formulas for prime order elliptic curves*,
//! <https://eprint.iacr.org/2015/1060>, Algorithms 4, 5 and 6 for $a = -3$),
//! and the NIST curves have prime order. Completeness is what makes the
//! scalar multiplication of [`super::mul`] constant time: the same
//! operations run whatever the inputs. The step numbers of the paper are in
//! the comments; the arrangement follows RustCrypto's `primeorder`.

use core::marker::PhantomData;

use super::{
    affine::{Affine, b},
    params::CurveParams,
};
use crate::{algebra::field::Field, ct::Choice};

/// A point $(X : Y : Z)$ of the curve `C`; see the module documentation.
pub struct Projective<C>
where
    C: CurveParams,
{
    pub(crate) x: C::Base,
    pub(crate) y: C::Base,
    pub(crate) z: C::Base,
    pub(crate) _curve: PhantomData<C>,
}

impl<C> Clone for Projective<C>
where
    C: CurveParams,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Projective<C> where C: CurveParams {}

impl<C> core::fmt::Debug for Projective<C>
where
    C: CurveParams,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({:?} : {:?} : {:?})", C::NAME, self.x, self.y, self.z)
    }
}

impl<C> Projective<C>
where
    C: CurveParams,
{
    pub(crate) fn new(x: C::Base, y: C::Base, z: C::Base) -> Self {
        Projective {
            x,
            y,
            z,
            _curve: PhantomData,
        }
    }

    /// The identity $(0 : 1 : 0)$.
    #[must_use]
    pub fn identity() -> Self {
        Self::new(C::Base::ZERO, C::Base::ONE, C::Base::ZERO)
    }

    /// The standard generator.
    #[must_use]
    pub fn generator() -> Self {
        Self::from(Affine::<C>::generator())
    }

    /// Whether this is the identity, $Z = 0$.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// $P + Q$ ([Algorithm 4][rcb]); complete.
    ///
    /// [rcb]: https://eprint.iacr.org/2015/1060
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let b = b::<C>();
        let xx = self.x * rhs.x; // 1
        let yy = self.y * rhs.y; // 2
        let zz = self.z * rhs.z; // 3
        let xy_pairs = ((self.x + self.y) * (rhs.x + rhs.y)) - (xx + yy); // 4-8
        let yz_pairs = ((self.y + self.z) * (rhs.y + rhs.z)) - (yy + zz); // 9-13
        let xz_pairs = ((self.x + self.z) * (rhs.x + rhs.z)) - (xx + zz); // 14-18

        let bzz_part = xz_pairs - (b * zz); // 19, 20
        let bzz3_part = bzz_part.double() + bzz_part; // 21, 22
        let yy_m_bzz3 = yy - bzz3_part; // 23
        let yy_p_bzz3 = yy + bzz3_part; // 24

        let zz3 = zz.double() + zz; // 26, 27
        let bxz_part = (b * xz_pairs) - (zz3 + xx); // 25, 28, 29
        let bxz3_part = bxz_part.double() + bxz_part; // 30, 31
        let xx3_m_zz3 = xx.double() + xx - zz3; // 32, 33, 34

        Self::new(
            (yy_p_bzz3 * xy_pairs) - (yz_pairs * bxz3_part), // 35, 39, 40
            (yy_p_bzz3 * yy_m_bzz3) + (xx3_m_zz3 * bxz3_part), // 36, 37, 38
            (yy_m_bzz3 * yz_pairs) + (xy_pairs * xx3_m_zz3), // 41, 42, 43
        )
    }

    /// $P + Q$ with $Q$ affine ([Algorithm 5][rcb]): complete for every projective
    /// $P$; the formula assumes $Z_Q = 1$, so the identity $Q$ is handled by
    /// a constant-time selection.
    ///
    /// [rcb]: https://eprint.iacr.org/2015/1060
    #[must_use]
    pub fn add_affine(&self, rhs: &Affine<C>) -> Self {
        let b = b::<C>();
        let xx = self.x * rhs.x; // 1
        let yy = self.y * rhs.y; // 2
        let xy_pairs = ((self.x + self.y) * (rhs.x + rhs.y)) - (xx + yy); // 3-7
        let yz_pairs = (rhs.y * self.z) + self.y; // 8, 9
        let xz_pairs = (rhs.x * self.z) + self.x; // 10, 11

        let bz_part = xz_pairs - (b * self.z); // 12, 13
        let bz3_part = bz_part.double() + bz_part; // 14, 15
        let yy_m_bzz3 = yy - bz3_part; // 16
        let yy_p_bzz3 = yy + bz3_part; // 17

        let z3 = self.z.double() + self.z; // 19, 20
        let bxz_part = (b * xz_pairs) - (z3 + xx); // 18, 21, 22
        let bxz3_part = bxz_part.double() + bxz_part; // 23, 24
        let xx3_m_zz3 = xx.double() + xx - z3; // 25, 26, 27

        let sum = Self::new(
            (yy_p_bzz3 * xy_pairs) - (yz_pairs * bxz3_part), // 28, 32, 33
            (yy_p_bzz3 * yy_m_bzz3) + (xx3_m_zz3 * bxz3_part), // 29, 30, 31
            (yy_m_bzz3 * yz_pairs) + (xy_pairs * xx3_m_zz3), // 34, 35, 36
        );
        Self::select(&sum, self, rhs.infinity)
    }

    /// $2P$ ([Algorithm 6][rcb]); complete.
    ///
    /// [rcb]: https://eprint.iacr.org/2015/1060
    #[must_use]
    pub fn double(&self) -> Self {
        let b = b::<C>();
        let xx = self.x.square(); // 1
        let yy = self.y.square(); // 2
        let zz = self.z.square(); // 3
        let xy2 = (self.x * self.y).double(); // 4, 5
        let xz2 = (self.x * self.z).double(); // 6, 7

        let bzz_part = (b * zz) - xz2; // 8, 9
        let bzz3_part = bzz_part.double() + bzz_part; // 10, 11
        let yy_m_bzz3 = yy - bzz3_part; // 12
        let yy_p_bzz3 = yy + bzz3_part; // 13
        let y_frag = yy_p_bzz3 * yy_m_bzz3; // 14
        let x_frag = yy_m_bzz3 * xy2; // 15

        let zz3 = zz.double() + zz; // 16, 17
        let bxz2_part = (b * xz2) - (zz3 + xx); // 18, 19, 20
        let bxz6_part = bxz2_part.double() + bxz2_part; // 21, 22
        let xx3_m_zz3 = xx.double() + xx - zz3; // 23, 24, 25

        let y = y_frag + (xx3_m_zz3 * bxz6_part); // 26, 27
        let yz2 = (self.y * self.z).double(); // 28, 29
        let x = x_frag - (bxz6_part * yz2); // 30, 31
        let z = (yz2 * yy).double().double(); // 32, 33, 34
        Self::new(x, y, z)
    }

    /// The opposite point $(X : -Y : Z)$; it fixes the identity as a class.
    #[must_use]
    pub fn neg(&self) -> Self {
        Self::new(self.x, -self.y, self.z)
    }

    /// Whether two points are equal: $X_1 Z_2 = X_2 Z_1$ and
    /// $Y_1 Z_2 = Y_2 Z_1$, which compares the classes.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> Choice {
        (self.x * other.z).ct_eq(&(other.x * self.z))
            & (self.y * other.z).ct_eq(&(other.y * self.z))
    }

    /// `a` if `choice` is false, `b` if it is true.
    #[must_use]
    pub fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(
            C::Base::select(&a.x, &b.x, choice),
            C::Base::select(&a.y, &b.y, choice),
            C::Base::select(&a.z, &b.z, choice),
        )
    }
}

impl<C> PartialEq for Projective<C>
where
    C: CurveParams,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool_vartime()
    }
}

impl<C> Eq for Projective<C> where C: CurveParams {}
