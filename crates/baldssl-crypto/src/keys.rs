//! Key pairs, as typed values whose invariants hold by construction.
//!
//! # The structure
//!
//! For a curve with generator $G$ of prime order $\ell$, an EC key pair is
//! an element of the graph of the exponential map
//! $\mathbb{F}_\ell^* \to E, \; d \mapsto d G$:
//!
//! $$\{ (d, Q) : d \in \mathbb{F}_\ell^*, \; Q = d G \}.$$
//!
//! [`EcKeyPair`] is that set, not the product $\mathbb{F}_\ell \times E$: its
//! only constructors take $d$ and compute $Q$, so a pair with $Q \neq d G$,
//! or with $d = 0$, cannot be built. Formats that store both $d$ and $Q$
//! (PKCS#8, SEC 1) are redundant on purpose; reading one is where the graph
//! condition is checked again.
//!
//! An EdDSA key pair ([`EdDsaKeyPair`]) is a seed and the public key it
//! determines, through the key expansion of [`DigitalSignature`]; its only
//! constructors take the seed.
//!
//! Generation draws the secret uniformly: $d$ by
//! [`PrimeField::random_nonzero`], the seed as random bytes.
//!
//! # Secrets
//!
//! The secret is never printed (`Debug` shows the public part only) and is
//! overwritten when the pair is dropped. That is best effort: without
//! `unsafe` (volatile writes) the compiler may elide the writes, and copies
//! made earlier (by moves, or in registers) are not reached.

use crate::{
    algebra::{
        curve::ShortWeierstrass,
        field::{Field, PrimeField},
        model::{CurveModel, ProjectiveModel},
    },
    models::weierstrass::{affine::Affine, projective::Projective},
    signature::{
        DigitalSignature,
        eddsa::{EdDSA, EddsaParameters},
    },
};

/// An EC key pair on the curve `C`: a nonzero secret scalar $d$ and its
/// public point $Q = d G$.
pub struct EcKeyPair<C>
where
    C: ShortWeierstrass,
{
    secret: C::Scalar,
    public: Affine<C>,
}

impl<C> EcKeyPair<C>
where
    C: ShortWeierstrass,
{
    /// The pair of the secret scalar `d`, or `None` when `d` is zero.
    #[must_use]
    pub fn from_secret(d: C::Scalar) -> Option<Self> {
        (!d.is_zero().to_bool_vartime()).then(|| Self::of_nonzero(d))
    }

    /// The pair of a nonzero `d`: $Q = d G$.
    fn of_nonzero(d: C::Scalar) -> Self {
        let public =
            C::scalar_mul(&Projective::<C>::generator(), &d).to_affine();
        EcKeyPair { secret: d, public }
    }

    /// A pair with a uniformly random secret, drawn from `fill`.
    ///
    /// # Errors
    ///
    /// The error of `fill`.
    pub fn generate<F, E>(fill: F) -> Result<Self, E>
    where
        F: FnMut(&mut [u8]) -> Result<(), E>,
    {
        Ok(Self::of_nonzero(C::Scalar::random_nonzero(fill)?))
    }

    /// The secret scalar $d$.
    #[must_use]
    pub fn secret(&self) -> &C::Scalar {
        &self.secret
    }

    /// The public point $Q = d G$.
    #[must_use]
    pub fn public(&self) -> &Affine<C> {
        &self.public
    }
}

/// Shows the curve and the public point, never the secret.
impl<C> core::fmt::Debug for EcKeyPair<C>
where
    C: ShortWeierstrass,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcKeyPair")
            .field("curve", &C::NAME)
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Overwrites the secret (best effort; see the module documentation).
impl<C> Drop for EcKeyPair<C>
where
    C: ShortWeierstrass,
{
    fn drop(&mut self) {
        self.secret = C::Scalar::ZERO;
        core::hint::black_box(&self.secret);
    }
}

/// An EdDSA key pair for the parameters `P`: a seed and its public key.
pub struct EdDsaKeyPair<P>
where
    P: EddsaParameters,
    P::Seed: AsMut<[u8]>,
{
    seed: P::Seed,
    public: Vec<u8>,
}

impl<P> EdDsaKeyPair<P>
where
    P: EddsaParameters,
    P::Seed: AsMut<[u8]>,
{
    /// The pair of a seed. Every seed is a secret key.
    #[must_use]
    pub fn from_seed(seed: P::Seed) -> Self {
        let public = EdDSA::<P>::public_key(&seed);
        EdDsaKeyPair { seed, public }
    }

    /// A pair with a uniformly random seed, drawn from `fill`.
    ///
    /// # Errors
    ///
    /// The error of `fill`.
    pub fn generate<F, E>(mut fill: F) -> Result<Self, E>
    where
        F: FnMut(&mut [u8]) -> Result<(), E>,
        P::Seed: Default,
    {
        let mut seed = P::Seed::default();
        fill(seed.as_mut())?;
        Ok(Self::from_seed(seed))
    }

    /// The seed, the secret key.
    #[must_use]
    pub fn seed(&self) -> &P::Seed {
        &self.seed
    }

    /// The public key, as RFC 8032 encodes it (little-endian).
    #[must_use]
    pub fn public(&self) -> &[u8] {
        &self.public
    }
}

/// Shows the public key, never the seed.
impl<P> core::fmt::Debug for EdDsaKeyPair<P>
where
    P: EddsaParameters,
    P::Seed: AsMut<[u8]>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EdDsaKeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Overwrites the seed (best effort; see the module documentation).
impl<P> Drop for EdDsaKeyPair<P>
where
    P: EddsaParameters,
    P::Seed: AsMut<[u8]>,
{
    fn drop(&mut self) {
        self.seed.as_mut().fill(0);
        core::hint::black_box(&self.seed);
    }
}

#[cfg(test)]
mod tests;
