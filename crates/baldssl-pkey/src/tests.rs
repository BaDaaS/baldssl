//! PKCS#8 against the keys OpenSSL wrote, and key generation.

use baldssl_core::{
    der::syntax::{ObjectId, decode, encode},
    encoding::Encodable,
    pem::Pem,
};
use baldssl_test_utils::{fixture, hex};

use super::{Algorithm, PrivateKey};
use crate::asn1::{
    CURVE_PRIVATE_KEY, EC_PRIVATE_KEY, ID_EC_PUBLIC_KEY, ID_ED25519,
    PRIME256V1, PRIVATE_KEY_INFO, SECP384R1, SECP521R1,
};

fn algorithm(name: &str) -> Option<Algorithm> {
    match name {
        "P-256" => Some(Algorithm::P256),
        "P-384" => Some(Algorithm::P384),
        "P-521" => Some(Algorithm::P521),
        "ED25519" => Some(Algorithm::Ed25519),
        _ => None,
    }
}

/// The scalar as OpenSSL printed it (possibly with a leading `00`), at the
/// full length of the group order.
fn secret(alg: Algorithm, printed: &str) -> Vec<u8> {
    let bytes = hex(printed);
    let skip = bytes.len().saturating_sub(alg.secret_len());
    let mut out = vec![0u8; alg.secret_len().saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// Same public key and byte-identical PKCS#8 for the twenty keys OpenSSL
/// generated (`scripts/gen-ec-vectors.sh`).
#[test]
fn pkcs8_matches_openssl() {
    let mut seen = 0;
    for line in fixture("keys/keypairs.txt").lines() {
        let [name, private, public, der] =
            line.split_whitespace().collect::<Vec<_>>()[..]
        else {
            continue;
        };
        let Some(alg) = algorithm(name) else { continue };
        let key = PrivateKey::from_secret(alg, &secret(alg, private)).unwrap();
        assert_eq!(key.public_key(), hex(public), "{name} public key");
        assert_eq!(key.encode(), hex(der), "{name} PKCS#8");
        records_round_trip(&key.encode());
        seen += 1;
    }
    assert_eq!(seen, 16);
}

#[test]
fn generated_keys_are_valid_and_distinct() {
    for alg in [
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::P521,
        Algorithm::Ed25519,
    ] {
        let a = PrivateKey::generate(alg).unwrap();
        let b = PrivateKey::generate(alg).unwrap();
        assert_ne!(a.public_key(), b.public_key(), "{alg:?}");
        // Re-deriving from the secret gives the same key.
        let again = PrivateKey::from_secret(alg, &a.secret_bytes()).unwrap();
        assert_eq!(again.encode(), a.encode());
        records_round_trip(&a.encode());
        assert!(a.to_pem().starts_with("-----BEGIN PRIVATE KEY-----\n"));
        // The Debug output is fixed: it cannot contain the secret.
        assert_eq!(
            format!("{a:?}"),
            format!("PrivateKey {{ algorithm: {alg:?}, .. }}")
        );
    }
}

#[test]
fn invalid_secrets() {
    assert!(
        PrivateKey::from_secret(Algorithm::P256, &[0u8; 32]).is_err(),
        "zero"
    );
    assert!(
        PrivateKey::from_secret(Algorithm::P256, &[0xffu8; 32]).is_err(),
        ">= n"
    );
    assert!(
        PrivateKey::from_secret(Algorithm::P256, &[1u8; 31]).is_err(),
        "length"
    );
    assert!(
        PrivateKey::from_secret(Algorithm::Ed25519, &[1u8; 31]).is_err(),
        "length"
    );
    let mut one = vec![0u8; 66];
    one[65] = 1;
    assert!(
        PrivateKey::from_secret(Algorithm::P521, &one).is_ok(),
        "d = 1"
    );
}

/// The PKCS#8 written reads back, with the descriptions, to records that
/// write the same bytes: the outer PrivateKeyInfo, and the ECPrivateKey or
/// CurvePrivateKey inside it.
fn records_round_trip(der: &[u8]) {
    let (version, ((oid, (params, ())), (inner, ()))) =
        decode(&PRIVATE_KEY_INFO, der).expect("PrivateKeyInfo");
    assert_eq!(version, 0);
    let record = (
        version,
        ((oid.clone(), (params.clone(), ())), (inner.clone(), ())),
    );
    assert_eq!(encode(&PRIVATE_KEY_INFO, &record), der);
    if oid == ID_EC_PUBLIC_KEY {
        let ec = decode(&EC_PRIVATE_KEY, &inner).expect("ECPrivateKey");
        assert_eq!(ec.0, 1, "ECPrivateKey version");
        assert!(ec.1.1.0.is_none(), "no [0] parameters");
        assert!(ec.1.1.1.0.is_some(), "[1] public key");
        assert_eq!(encode(&EC_PRIVATE_KEY, &ec), inner);
    } else {
        assert_eq!(oid, ID_ED25519);
        assert!(params.is_none(), "Ed25519 has no parameters");
        let seed = decode(&CURVE_PRIVATE_KEY, &inner).expect("CurvePrivateKey");
        assert_eq!(seed.len(), 32);
    }
}

/// The identifiers, written as contents octets, are the ones their dotted
/// forms name.
#[test]
fn object_identifiers() {
    for (id, dotted) in [
        (ID_EC_PUBLIC_KEY, "1.2.840.10045.2.1"),
        (ID_ED25519, "1.3.101.112"),
        (PRIME256V1, "1.2.840.10045.3.1.7"),
        (SECP384R1, "1.3.132.0.34"),
        (SECP521R1, "1.3.132.0.35"),
    ] {
        assert_eq!(Some(id), ObjectId::from_dotted(dotted), "{dotted}");
    }
}
