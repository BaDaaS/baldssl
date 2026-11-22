//! The maps between the two models, as `From` impls: affine to extended,
//! $(x, y) \mapsto (x : y : 1 : x y)$, and extended to affine,
//! $(X / Z, Y / Z)$, one inversion ($Z$ is never zero on the curve). They are
//! mutually inverse isomorphisms of groups; the tests check that they commute
//! with the operations. Each is constant time.

use super::{
    affine::{Affine, point},
    extended::Extended,
};
use crate::algebra::{curve::TwistedEdwards, field::Field};

impl<C> From<Affine<C>> for Extended<C>
where
    C: TwistedEdwards,
{
    fn from(p: Affine<C>) -> Self {
        Extended::new(p.x, p.y, C::Base::ONE, p.x * p.y)
    }
}

impl<C> From<Extended<C>> for Affine<C>
where
    C: TwistedEdwards,
{
    fn from(p: Extended<C>) -> Self {
        let zinv = p.z.invert();
        point(p.x * zinv, p.y * zinv)
    }
}
