//! Signing with a key, and verifying under one.
//!
//! A run-time [`SignatureAlgorithm`] and a run-time key type do not form a
//! product: the pairs that sign are a dependent sum, a key type with the
//! choice it leaves open (an ECDSA hash for an EC key, nothing for
//! Ed25519). [`Signing`] states that sum at the type level: `Choice` is
//! the fibre over each key type, [`Signing::algorithm`] embeds it in
//! [`SignatureAlgorithm`], and [`Signing::choice_opt`] is its left inverse,
//! the only place a key and an algorithm can fail to match. Typed keys
//! ([`PrivateKey::sign`]) take a choice, so a mismatch does not type-check;
//! the run-time keys ([`AnyPrivateKey::sign`], [`PublicKey::verify`]) go
//! through `choice_opt` once.
//!
//! Signing is deterministic: ECDSA nonces follow [RFC 6979], and Ed25519
//! ([RFC 8032] section 5.1.6) has no nonce to draw.
//!
//! [RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979
//! [RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6

use baldssl_core::{Error, Result};
use baldssl_crypto::{
    algebra::encoding::Decodable as _,
    hash::Algorithm as Hash,
    instances::{P256, P384, P521},
    signature::{
        SignEncoded, SignatureAlgorithm, VerifyEncoded,
        ecdsa::{sign_with_hash, verify_with_hash},
        eddsa::{Ed25519, Ed25519Parameters, PublicKey as EddsaPublicKey},
    },
};

use crate::{AnyPrivateKey, KeyAlgorithm, NamedCurve, PrivateKey, PublicKey};

/// How keys of an algorithm sign: the choice a key leaves open, and the
/// signature algorithms it signs with.
///
/// Laws, tested for every implementation: `choice_opt(algorithm(c)) ==
/// Some(c)` (so `algorithm` is injective), and what `sign` gives verifies
/// under the same choice and no other.
pub trait Signing: KeyAlgorithm {
    /// What is left to choose once the key is known: the hash of ECDSA, or
    /// nothing for Ed25519.
    type Choice: Copy + Eq + core::fmt::Debug;

    /// What OpenSSL signs with when told nothing: SHA-256 on every EC
    /// curve.
    const DEFAULT: Self::Choice;

    /// The signature algorithm a choice gives.
    fn algorithm(choice: Self::Choice) -> SignatureAlgorithm;

    /// The choice an algorithm is, when it is one for this key type.
    fn choice_opt(algorithm: SignatureAlgorithm) -> Option<Self::Choice>;

    /// The encoded signature of `message`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when ECDSA finds no nonce, which RFC 6979 makes
    /// a probability-zero event.
    fn sign(
        pair: &Self::KeyPair,
        choice: Self::Choice,
        message: &[u8],
    ) -> Result<Vec<u8>>;

    /// Whether the encoded `signature` of `message` verifies under `key`.
    fn verify(
        key: &Self::PublicKey,
        choice: Self::Choice,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

/// ECDSA with any hash, on every named curve.
impl<C> Signing for C
where
    C: NamedCurve,
{
    type Choice = Hash;

    const DEFAULT: Hash = Hash::Sha256;

    fn algorithm(hash: Hash) -> SignatureAlgorithm {
        SignatureAlgorithm::Ecdsa(hash)
    }

    fn choice_opt(algorithm: SignatureAlgorithm) -> Option<Hash> {
        match algorithm {
            SignatureAlgorithm::Ecdsa(hash) => Some(hash),
            SignatureAlgorithm::Ed25519 => None,
        }
    }

    fn sign(
        pair: &Self::KeyPair,
        hash: Hash,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        sign_with_hash(hash, pair, message)
            .map_err(|_| Error::invalid("ECDSA: no nonce"))
    }

    fn verify(
        key: &Self::PublicKey,
        hash: Hash,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        verify_with_hash(hash, key, message, signature)
    }
}

/// Ed25519, which leaves nothing to choose.
impl Signing for Ed25519 {
    type Choice = ();

    const DEFAULT: () = ();

    fn algorithm((): ()) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn choice_opt(algorithm: SignatureAlgorithm) -> Option<()> {
        (algorithm == SignatureAlgorithm::Ed25519).then_some(())
    }

    fn sign(pair: &Self::KeyPair, (): (), message: &[u8]) -> Result<Vec<u8>> {
        match Ed25519::sign_encoded(pair, message) {
            Ok(signature) => Ok(signature),
            Err(never) => match never {},
        }
    }

    fn verify(key: &[u8], (): (), message: &[u8], signature: &[u8]) -> bool {
        EddsaPublicKey::<Ed25519Parameters>::decode(key)
            .is_ok_and(|key| Ed25519::verify_encoded(&key, message, signature))
    }
}

impl<A> PrivateKey<A>
where
    A: Signing,
{
    /// The encoded signature of `message`, with what `choice` leaves open.
    ///
    /// # Errors
    ///
    /// See [`Signing::sign`].
    pub fn sign(&self, choice: A::Choice, message: &[u8]) -> Result<Vec<u8>> {
        A::sign(self.key_pair(), choice, message)
    }

    /// The signature of a run-time algorithm, when it is one of this key.
    fn sign_as(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.sign(A::choice_opt(algorithm).ok_or_else(mismatch)?, message)
    }
}

/// A key and an algorithm that do not go together.
fn mismatch() -> Error {
    Error::invalid("the signature algorithm does not match the key")
}

/// Whether `signature` verifies under a typed key and a run-time
/// algorithm: false when the algorithm is not one of the key's.
fn verify_as<A>(
    key: &A::PublicKey,
    algorithm: SignatureAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> bool
where
    A: Signing,
{
    A::choice_opt(algorithm)
        .is_some_and(|choice| A::verify(key, choice, message, signature))
}

impl AnyPrivateKey {
    /// What OpenSSL signs with by default: ECDSA with SHA-256 on every
    /// curve, Ed25519 for an Ed25519 key.
    #[must_use]
    pub fn default_signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            AnyPrivateKey::P256(_) => P256::algorithm(P256::DEFAULT),
            AnyPrivateKey::P384(_) => P384::algorithm(P384::DEFAULT),
            AnyPrivateKey::P521(_) => P521::algorithm(P521::DEFAULT),
            AnyPrivateKey::Ed25519(_) => Ed25519::algorithm(Ed25519::DEFAULT),
        }
    }

    /// The encoded signature of `message` with `algorithm`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `algorithm` is not one of the key's (ECDSA
    /// for an Ed25519 key, or Ed25519 for an EC key), and see
    /// [`Signing::sign`].
    pub fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        match self {
            AnyPrivateKey::P256(k) => k.sign_as(algorithm, message),
            AnyPrivateKey::P384(k) => k.sign_as(algorithm, message),
            AnyPrivateKey::P521(k) => k.sign_as(algorithm, message),
            AnyPrivateKey::Ed25519(k) => k.sign_as(algorithm, message),
        }
    }
}

impl PublicKey {
    /// Whether the encoded `signature` of `message` verifies under this key
    /// with `algorithm`: false when the algorithm is not one of the key's.
    #[must_use]
    pub fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        match self {
            PublicKey::P256(q) => {
                verify_as::<P256>(q, algorithm, message, signature)
            }
            PublicKey::P384(q) => {
                verify_as::<P384>(q, algorithm, message, signature)
            }
            PublicKey::P521(q) => {
                verify_as::<P521>(q, algorithm, message, signature)
            }
            PublicKey::Ed25519(bytes) => {
                verify_as::<Ed25519>(bytes, algorithm, message, signature)
            }
        }
    }
}

#[cfg(test)]
mod tests;
