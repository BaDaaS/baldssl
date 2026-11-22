//! The maps between the models, as `From` impls:
//!
//! - affine to projective: $(x, y) \mapsto (x : y : 1)$, the identity to
//!   $(0 : 1 : 0)$;
//! - projective to affine: $(X / Z, Y / Z)$, one inversion;
//! - affine to Jacobian: $(x, y) \mapsto (x, y, 1)$, the identity to
//!   $(0, 0, 0)$;
//! - Jacobian to affine: $(X / Z^2, Y / Z^3)$, one inversion;
//! - Jacobian to projective: $(X : Y : Z) \mapsto (X Z : Y : Z^3)$, the three
//!   monomials of weighted degree 3. It is defined at the identity, which it
//!   sends to $(0 : 1 : 0)$; the stored $(0, 0, 0)$ is mapped there too.
//! - projective to Jacobian: $(X : Y : Z) \mapsto (X Z : Y Z^2 : Z)$, which
//!   sends the identity to $(0, 0, 0)$.
//!
//! Each map is constant time: the identity cases are selections, and the
//! inverse of $Z = 0$ is $0$.

use core::marker::PhantomData;

use super::{
    affine::Affine, jacobian::Jacobian, params::CurveParams,
    projective::Projective,
};
use crate::field::PrimeField;

impl<C> From<Affine<C>> for Projective<C>
where
    C: CurveParams,
{
    fn from(p: Affine<C>) -> Self {
        let point = Projective::new(p.x, p.y, C::Base::ONE);
        Projective::select(&point, &Projective::identity(), p.infinity)
    }
}

impl<C> From<Projective<C>> for Affine<C>
where
    C: CurveParams,
{
    fn from(p: Projective<C>) -> Self {
        let zinv = p.z.invert();
        let point = Affine {
            x: p.x * zinv,
            y: p.y * zinv,
            infinity: crate::ct::Choice::FALSE,
            _curve: PhantomData,
        };
        Affine::select(&point, &Affine::identity(), p.is_identity())
    }
}

impl<C> From<Affine<C>> for Jacobian<C>
where
    C: CurveParams,
{
    fn from(p: Affine<C>) -> Self {
        let point = Jacobian::<C>::new(p.x, p.y, C::Base::ONE);
        let identity = Jacobian::<C>::identity();
        Jacobian::new(
            C::Base::select(&point.x, &identity.x, p.infinity),
            C::Base::select(&point.y, &identity.y, p.infinity),
            C::Base::select(&point.z, &identity.z, p.infinity),
        )
    }
}

impl<C> From<Jacobian<C>> for Affine<C>
where
    C: CurveParams,
{
    fn from(p: Jacobian<C>) -> Self {
        let zinv = p.z.invert();
        let zinv2 = zinv.square();
        let point = Affine {
            x: p.x * zinv2,
            y: p.y * zinv2 * zinv,
            infinity: crate::ct::Choice::FALSE,
            _curve: PhantomData,
        };
        Affine::select(&point, &Affine::identity(), p.is_identity())
    }
}

impl<C> From<Jacobian<C>> for Projective<C>
where
    C: CurveParams,
{
    fn from(p: Jacobian<C>) -> Self {
        let point = Projective::new(p.x * p.z, p.y, p.z.square() * p.z);
        Projective::select(&point, &Projective::identity(), p.is_identity())
    }
}

impl<C> From<Projective<C>> for Jacobian<C>
where
    C: CurveParams,
{
    fn from(p: Projective<C>) -> Self {
        Jacobian::new(p.x * p.z, p.y * p.z.square(), p.z)
    }
}
