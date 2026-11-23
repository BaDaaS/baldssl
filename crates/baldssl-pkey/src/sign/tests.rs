//! The laws of [`Signing`], for every key type, and the run-time keys.

use baldssl_crypto::{
    hash::Algorithm as Hash,
    instances::{P256, P384, P521},
    signature::{SignatureAlgorithm, eddsa::Ed25519},
};
use proptest::prelude::*;

use super::Signing;
use crate::{Algorithm, AnyPrivateKey, PrivateKey, PublicKey};

/// Every run-time signature algorithm.
fn all_algorithms() -> Vec<SignatureAlgorithm> {
    Hash::ALL
        .into_iter()
        .map(SignatureAlgorithm::Ecdsa)
        .chain([SignatureAlgorithm::Ed25519])
        .collect()
}

/// `choice_opt` is a left inverse of `algorithm` on the key's choices, and
/// is `None` exactly off the image of `algorithm`.
fn retraction<A>(choices: &[A::Choice])
where
    A: Signing,
{
    for &c in choices {
        assert_eq!(A::choice_opt(A::algorithm(c)), Some(c));
    }
    for a in all_algorithms() {
        let in_image = choices.iter().any(|&c| A::algorithm(c) == a);
        assert_eq!(A::choice_opt(a).is_some(), in_image, "{a:?}");
    }
}

#[test]
fn choice_is_a_retraction() {
    retraction::<P256>(&Hash::ALL);
    retraction::<P384>(&Hash::ALL);
    retraction::<P521>(&Hash::ALL);
    retraction::<Ed25519>(&[()]);
}

/// A typed signature verifies under its choice and under no other
/// algorithm, and the run-time key signs the same bytes.
fn signs<A>(key: &PrivateKey<A>, any: &AnyPrivateKey, message: &[u8])
where
    A: Signing,
{
    let public = PublicKey::from(any);
    for a in all_algorithms() {
        match A::choice_opt(a) {
            Some(choice) => {
                let typed = key.sign(choice, message).unwrap();
                assert_eq!(any.sign(a, message).unwrap(), typed, "{a:?}");
                for b in all_algorithms() {
                    assert_eq!(
                        public.verify(b, message, &typed),
                        a == b,
                        "{a:?} as {b:?}"
                    );
                }
            }
            None => assert!(any.sign(a, message).is_err(), "{a:?}"),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn signing_laws(message in prop::collection::vec(any::<u8>(), 0..64)) {
        let p256 = PrivateKey::<P256>::from_secret(&[7; 32]).unwrap();
        signs(&p256, &AnyPrivateKey::from_secret(Algorithm::P256, &[7; 32]).unwrap(), &message);
        let p384 = PrivateKey::<P384>::from_secret(&[7; 48]).unwrap();
        signs(&p384, &AnyPrivateKey::from_secret(Algorithm::P384, &[7; 48]).unwrap(), &message);
        let mut d = [7u8; 66];
        d[0] = 0;
        let p521 = PrivateKey::<P521>::from_secret(&d).unwrap();
        signs(&p521, &AnyPrivateKey::from_secret(Algorithm::P521, &d).unwrap(), &message);
        let ed = PrivateKey::<Ed25519>::from_secret(&[7; 32]).unwrap();
        signs(&ed, &AnyPrivateKey::from_secret(Algorithm::Ed25519, &[7; 32]).unwrap(), &message);
    }
}

/// OpenSSL's defaults: ECDSA with SHA-256 on every curve, Ed25519 alone.
#[test]
fn defaults() {
    for (algorithm, len) in [(Algorithm::P256, 32), (Algorithm::P384, 48)] {
        let key = AnyPrivateKey::from_secret(algorithm, &vec![1; len]).unwrap();
        assert_eq!(
            key.default_signature_algorithm(),
            SignatureAlgorithm::Ecdsa(Hash::Sha256)
        );
    }
    let key = AnyPrivateKey::from_secret(Algorithm::Ed25519, &[1; 32]).unwrap();
    assert_eq!(
        key.default_signature_algorithm(),
        SignatureAlgorithm::Ed25519
    );
}
