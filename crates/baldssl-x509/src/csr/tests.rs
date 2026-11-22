//! Certificate requests against the ones OpenSSL writes.
//!
//! Known answers: `req/requests.txt` of the fixtures
//! (`scripts/gen-requests.py`): the request `openssl req -new` writes for
//! every fixture key and three subjects. Ed25519 signing is deterministic,
//! so baldssl's Ed25519 requests are OpenSSL's byte for byte; ECDSA nonces
//! are random in OpenSSL, so an ECDSA request matches everywhere but in the
//! signature, and OpenSSL's verifies under baldssl.

use baldssl_core::{
    Error,
    encoding::{Decodable, Encodable},
};
use baldssl_crypto::hash::Algorithm as Hash;
use baldssl_pkey::{Algorithm, AnyPrivateKey};
use baldssl_test_utils::{fixture, hex};

use super::{CertificationRequest, SignatureAlgorithm};
use crate::{
    dn::{DistinguishedName, InputEncoding, UTF8_ONLY},
    extension::Extensions,
};

/// One fixture line: the key, the subject argument, OpenSSL's request.
struct Case {
    key: AnyPrivateKey,
    subject: Vec<u8>,
    openssl: Vec<u8>,
}

fn cases() -> Vec<Case> {
    fixture("req/requests.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            let algorithm = match f[0] {
                "P-256" => Algorithm::P256,
                "P-384" => Algorithm::P384,
                "P-521" => Algorithm::P521,
                _ => Algorithm::Ed25519,
            };
            Case {
                key: AnyPrivateKey::from_secret(algorithm, &hex(f[1])).unwrap(),
                subject: hex(f[2]),
                openssl: hex(f[3]),
            }
        })
        .collect()
}

fn subject(arg: &[u8]) -> DistinguishedName {
    DistinguishedName::from_subj(arg, InputEncoding::Latin1, true, UTF8_ONLY)
        .unwrap()
        .0
}

/// baldssl's request against OpenSSL's, for every key and subject.
#[test]
fn matches_openssl() {
    let all = cases();
    assert_eq!(all.len(), 48);
    for case in &all {
        let what = format!(
            "{:?} {}",
            case.key.algorithm(),
            String::from_utf8_lossy(&case.subject)
        );
        let algorithm = case.key.default_signature_algorithm();
        let ours = CertificationRequest::sign(
            &subject(&case.subject),
            &case.key,
            algorithm,
            &Extensions::new(),
        )
        .unwrap();
        assert!(ours.verify(), "{what}: ours verifies");
        let theirs = CertificationRequest::decode(&case.openssl).unwrap();
        assert!(theirs.verify(), "{what}: OpenSSL's verifies");
        assert_eq!(theirs.encode(), case.openssl, "{what}: re-encodes");
        assert_eq!(theirs.algorithm(), algorithm, "{what}: algorithm");
        if algorithm == SignatureAlgorithm::Ed25519 {
            assert_eq!(ours.encode(), case.openssl, "{what}: byte for byte");
        } else {
            assert_eq!(ours.info, theirs.info, "{what}: the signed part");
            assert_eq!(
                CertificationRequest::decode(&ours.encode()),
                Ok(ours.clone())
            );
        }
    }
}

/// A request does not verify once any byte of what was signed changes, or
/// under another key's signature.
#[test]
fn tampering() {
    let all = cases();
    for case in all.iter().step_by(7) {
        let request = CertificationRequest::decode(&case.openssl).unwrap();
        let mut changed = request.clone();
        let mut info = changed.info.as_bytes().to_vec();
        let last = info.len() - 1;
        info[last] ^= 1;
        changed.info = baldssl_core::der::syntax::RawTlv::parse(&info).unwrap();
        assert!(!changed.verify());
        let mut other = request.clone();
        let middle = other.signature.len() / 2;
        other.signature[middle] ^= 1;
        assert!(!other.verify());
    }
}

/// The algorithm must match the key, and decoding refuses what OpenSSL
/// would not write: another version, signature parameters.
#[test]
fn rejections() {
    let all = cases();
    let ec = all
        .iter()
        .find(|c| c.key.algorithm() == Algorithm::P256)
        .unwrap();
    let ed = all
        .iter()
        .find(|c| c.key.algorithm() == Algorithm::Ed25519)
        .unwrap();
    let name = subject(b"/CN=x");
    let mismatch = Some(Error::invalid(
        "the signature algorithm does not match the key",
    ));
    assert_eq!(
        CertificationRequest::sign(
            &name,
            &ec.key,
            SignatureAlgorithm::Ed25519,
            &Extensions::new()
        )
        .err(),
        mismatch
    );
    assert_eq!(
        CertificationRequest::sign(
            &name,
            &ed.key,
            SignatureAlgorithm::Ecdsa(Hash::Sha256),
            &Extensions::new(),
        )
        .err(),
        mismatch
    );
    for algorithm in [
        SignatureAlgorithm::Ecdsa(Hash::Sha224),
        SignatureAlgorithm::Ecdsa(Hash::Sha384),
        SignatureAlgorithm::Ecdsa(Hash::Sha512),
    ] {
        let request = CertificationRequest::sign(
            &name,
            &ec.key,
            algorithm,
            &Extensions::new(),
        )
        .unwrap();
        assert!(request.verify(), "{algorithm:?}");
        assert_eq!(
            CertificationRequest::decode(&request.encode())
                .map(|r| r.algorithm()),
            Ok(algorithm)
        );
    }

    // Version 1: the INTEGER after the info's header is 01.
    let mut v1 = ed.openssl.clone();
    let at = v1.windows(3).position(|w| w == [0x02, 0x01, 0x00]).unwrap();
    v1[at + 2] = 1;
    assert_eq!(
        CertificationRequest::decode(&v1).err(),
        Some(Error::invalid("certificate request: version 1"))
    );
}
