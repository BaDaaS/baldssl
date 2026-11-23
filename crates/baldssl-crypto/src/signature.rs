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
//! determines.
//!
//! The group must be a [`ProjectiveModel`], a constant-time group: the
//! exponential map is computed on the secret scalar.
//!
//! Signing and verifying are separate traits over a [`SignatureScheme`]
//! that names the key and signature types: [`Signer`] holds the secret
//! operation, [`Verifier`] the public one, with the correctness law
//! `verify(pk, m, sign(sk, m))` for the public key `pk` of `sk`.

pub mod ecdsa;
pub mod eddsa;

use crate::{
    Algorithm,
    algebra::{
        curve::Curve,
        encoding::{Decodable, Encodable},
        model::{CurveModel, ProjectiveModel},
    },
};

/// A discrete-logarithm signature scheme over a group of prime order.
pub trait DigitalSignature {
    /// The group of the public keys, in a model with complete formulas.
    type Group: ProjectiveModel;
    /// A secret key.
    type SecretKey;
    /// The secret scalar, as a big-endian integer.
    type Scalar: AsRef<[u8]>;

    /// The secret scalar $s$ of a secret key: the discrete logarithm of its
    /// public key. Secret.
    fn secret_scalar(secret_key: &Self::SecretKey) -> Self::Scalar;

    /// The public key: $s G$ in the standard encoding of points, the affine
    /// chart's (not the projective coordinates). Its byte order is the
    /// scheme's: little-endian for EdDSA (RFC 8032), big-endian for SEC 1.
    fn public_key(
        secret_key: &Self::SecretKey,
    ) -> <<Self::Group as ProjectiveModel>::Affine as Encodable>::Bytes {
        let s = Self::secret_scalar(secret_key);
        <<Self::Group as CurveModel>::Curve as Curve>::scalar_mul_bytes(
            &Self::Group::generator(),
            s.as_ref(),
        )
        .to_affine()
        .encode()
    }
}

/// The types of a signature scheme: what signs, what verifies, and what a
/// signature is.
pub trait SignatureScheme {
    /// What signs: a secret key, with its public key.
    type SigningKey;
    /// What verifies: a public key, valid by construction.
    type VerifyingKey;
    /// A signature.
    type Signature;
}

/// The signing algorithm of a scheme. Constant time in the secret key and
/// in any secret derived from it.
pub trait Signer: SignatureScheme {
    /// Why signing failed.
    type Error;

    /// A signature of `message` under `key`.
    ///
    /// # Errors
    ///
    /// [`Signer::Error`], when the scheme cannot produce a signature.
    fn sign(
        key: &Self::SigningKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error>;
}

/// The verification algorithm of a scheme. Its inputs are public, so it
/// may run in variable time.
pub trait Verifier: SignatureScheme {
    /// Whether `signature` is a signature of `message` under `key`.
    #[must_use]
    fn verify(
        key: &Self::VerifyingKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool;
}

/// Signing to the encoding of the signature: the bytes certificates and
/// requests carry (a DER `ECDSA-Sig-Value`, the 64 bytes of Ed25519). One
/// blanket implementation covers every scheme whose signatures encode.
pub trait SignEncoded: Signer {
    /// The encoded signature of `message`.
    ///
    /// # Errors
    ///
    /// The scheme's signing error.
    fn sign_encoded(
        key: &Self::SigningKey,
        message: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

impl<S> SignEncoded for S
where
    S: Signer,
    S::Signature: Encodable,
    <S::Signature as Encodable>::Bytes: AsRef<[u8]>,
{
    fn sign_encoded(
        key: &S::SigningKey,
        message: &[u8],
    ) -> Result<Vec<u8>, S::Error> {
        S::sign(key, message).map(|s| s.encode().as_ref().to_vec())
    }
}

/// Verifying an encoded signature: false when the bytes do not decode
/// ([`Decodable`] is canonical, so a signature has one encoding), and
/// [`Verifier::verify`] otherwise. One blanket implementation covers every
/// scheme whose signatures decode.
pub trait VerifyEncoded: Verifier {
    /// Whether `signature` decodes and verifies.
    #[must_use]
    fn verify_encoded(
        key: &Self::VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

impl<S> VerifyEncoded for S
where
    S: Verifier,
    S::Signature: Decodable,
{
    fn verify_encoded(
        key: &S::VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        S::Signature::decode(signature)
            .is_ok_and(|s| S::verify(key, message, &s))
    }
}

/// A signature scheme named at run time: ECDSA with a hash, or Ed25519.
/// The hash is a parameter of ECDSA only, so this is a sum, not a product
/// of a family and a hash: there is no Ed25519 with a hash to reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA ([FIPS 186-5] section 6) with the hash.
    ///
    /// [FIPS 186-5]: https://csrc.nist.gov/pubs/fips/186-5/final
    Ecdsa(Algorithm),
    /// Ed25519 ([RFC 8032] section 5.1), which fixes its hash.
    ///
    /// [RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1
    Ed25519,
}
