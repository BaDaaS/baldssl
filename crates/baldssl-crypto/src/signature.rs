//! Digital signature schemes, as a trait, and their instances.
//!
//! A signature scheme is a triple of algorithms $\Sigma = (\mathrm{Gen},
//! \mathrm{Sign}, \mathrm{Vrfy})$ with the correctness law
//! $\mathrm{Vrfy}(pk, m, \mathrm{Sign}(sk, m)) = 1$ (Goldwasser, Micali and
//! Rivest; Katz and Lindell, *Introduction to Modern Cryptography*,
//! definition 12.1). The schemes here are discrete-logarithm schemes over a
//! group $G$ of prime order: a secret key determines a scalar $s$, and the
//! public key is $s G$, so key generation is the composition of a key
//! expansion with the exponential map $s \mapsto s G$, an isomorphism
//! $\mathbb{F}_\ell \to G$ whose inverse is the discrete logarithm.
//!
//! [`DigitalSignature`] is that structure: the group, the secret key, the
//! expansion ([`DigitalSignature::secret_scalar`]), and the public key it
//! determines. Signing and verification are separate traits, to come with
//! the signing algorithms, so that a scheme states only what it implements;
//! their correctness law will be their test.
//!
//! The group must be a [`ProjectiveModel`], a constant-time group: the
//! exponential map is computed on the secret scalar.

pub mod eddsa;

use crate::algebra::{
    encoding::Encodable,
    group::scalar_mul,
    model::{CurveModel, ProjectiveModel},
};

/// A discrete-logarithm signature scheme over a group of prime order.
pub trait DigitalSignature {
    /// The group of the public keys, in a model with complete formulas.
    type Group: ProjectiveModel + Encodable;
    /// A secret key.
    type SecretKey;
    /// The secret scalar, as a big-endian integer.
    type Scalar: AsRef<[u8]>;

    /// The secret scalar $s$ of a secret key: the discrete logarithm of its
    /// public key. Secret.
    fn secret_scalar(secret_key: &Self::SecretKey) -> Self::Scalar;

    /// The public key, the encoding of $s G$.
    fn public_key(
        secret_key: &Self::SecretKey,
    ) -> <Self::Group as Encodable>::Bytes {
        let s = Self::secret_scalar(secret_key);
        scalar_mul(&Self::Group::generator(), s.as_ref()).encode()
    }
}
