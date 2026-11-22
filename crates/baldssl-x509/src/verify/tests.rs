//! Verification of chains baldssl builds itself, with fixed keys and
//! dates: each error as OpenSSL reports it (the interop tests compare with
//! OpenSSL), and the law that a chain verifies exactly at the times every
//! certificate is valid.

use baldssl_pkey::{Algorithm, AnyPrivateKey, PublicKey};
use proptest::prelude::*;

use super::{VerifyError, verify};
use crate::{
    Certificate, CertificateTemplate, CertificationRequest, Compat, Extension,
    ExtensionValue, Extensions, IssuedExtensions, SerialNumber,
    SignatureAlgorithm, Validity,
    dn::{DistinguishedName, InputEncoding, UTF8_ONLY},
};

fn key(seed: u8) -> AnyPrivateKey {
    AnyPrivateKey::from_secret(Algorithm::Ed25519, &[seed; 32]).unwrap()
}

fn name(subj: &str) -> DistinguishedName {
    DistinguishedName::from_subj(
        subj.as_bytes(),
        InputEncoding::Latin1,
        true,
        UTF8_ONLY,
    )
    .unwrap()
    .0
}

/// A root valid over `[from, to]`.
fn root(k: &AnyPrivateKey, from: u64, to: u64) -> Vec<u8> {
    CertificateTemplate::self_signed(
        &name("/CN=Root"),
        &PublicKey::from(k),
        SerialNumber::new_opt(&[1]).unwrap(),
        Validity::from_unix_seconds(from, to),
        Compat::V3,
    )
    .sign(k, SignatureAlgorithm::Ed25519)
    .unwrap()
}

/// A certificate for `subject` issued by `ca` over `[from, to]`, a CA or
/// not.
fn issue(
    subject: &str,
    k: &AnyPrivateKey,
    ca: &[u8],
    ca_key: &AnyPrivateKey,
    (from, to): (u64, u64),
    is_ca: bool,
) -> Vec<u8> {
    let request = CertificationRequest::sign(
        &name(subject),
        k,
        SignatureAlgorithm::Ed25519,
        &[],
    )
    .unwrap();
    let extensions: Extensions =
        [Extension::critical(ExtensionValue::BasicConstraints {
            ca: is_ca,
            path_length: None,
        })]
        .into_iter()
        .collect();
    CertificateTemplate::issued(
        &request,
        &Certificate::from_der(ca).unwrap(),
        ca_key,
        SerialNumber::new_opt(&[2]).unwrap(),
        Validity::from_unix_seconds(from, to),
        &IssuedExtensions {
            extensions,
            from_file: true,
        },
        Compat::V3,
    )
    .unwrap()
    .sign(ca_key, SignatureAlgorithm::Ed25519)
    .unwrap()
}

/// Parses DER certificates, each borrowing its bytes.
fn parse<'a>(ders: &[&'a [u8]]) -> Vec<Certificate<'a>> {
    ders.iter()
        .map(|d| Certificate::from_der(d).unwrap())
        .collect()
}

/// The errors of verifying `target` at `now`, or none.
fn errors(
    target: &[u8],
    trusted: &[&[u8]],
    untrusted: &[&[u8]],
    now: i64,
) -> Vec<(u32, usize)> {
    let (trusted, untrusted) = (parse(trusted), parse(untrusted));
    let target = Certificate::from_der(target).unwrap();
    match verify(&target, &trusted, &untrusted, now).unwrap() {
        Ok(_) => Vec::new(),
        Err(f) => f.errors.iter().map(|(e, d)| (e.code(), *d)).collect(),
    }
}

const DAY: u64 = 86_400;

#[test]
fn outcomes() {
    let (rk, mk, lk) = (key(1), key(2), key(3));
    let span = (DAY, 100 * DAY);
    let root = root(&rk, span.0, span.1);
    let mid = issue("/CN=Mid", &mk, &root, &rk, span, true);
    let leaf = issue("/CN=Leaf", &lk, &mid, &mk, span, false);
    let now = i64::try_from(10 * DAY).unwrap();
    assert_eq!(errors(&leaf, &[&root], &[&mid], now), []);
    // The issuer missing: OpenSSL's 20 at the top of what was built.
    assert_eq!(errors(&leaf, &[&root], &[], now), [(20, 0)]);
    // A trusted intermediate without its root: 2.
    assert_eq!(errors(&leaf, &[&mid], &[], now), [(2, 1)]);
    // Self-signed and untrusted: 18 at depth 0 (which goes on), 19 above.
    assert_eq!(errors(&root, &[], &[], now), [(18, 0)]);
    assert_eq!(errors(&leaf, &[], &[&mid, &root], now), [(19, 2)]);
    // Issued by a certificate that is not a CA: 79, which goes on.
    let not_ca = issue("/CN=NotCA", &mk, &root, &rk, span, false);
    let under = issue("/CN=Leaf", &lk, &not_ca, &mk, span, false);
    assert_eq!(errors(&under, &[&root], &[&not_ca], now), [(79, 1)]);
    // A signature that does not verify: 7, where it is.
    let mut bad = leaf.clone();
    if let Some(last) = bad.last_mut() {
        *last ^= 1;
    }
    assert_eq!(errors(&bad, &[&root], &[&mid], now), [(7, 0)]);
    let _ = VerifyError::KeyUsageNoCertSign.message(Compat::V3);
}

/// The bounds of the validity period are in it: valid at notBefore and at
/// notAfter, as OpenSSL 3.0, 3.5 and 4.1 verify with `-attime`, and not one
/// second outside.
#[test]
fn validity_bounds() {
    let (rk, lk) = (key(1), key(3));
    let (from, to) = (DAY, 2 * DAY);
    let root = root(&rk, 0, 3 * DAY);
    let leaf = issue("/CN=Leaf", &lk, &root, &rk, (from, to), false);
    let at = |t: u64| errors(&leaf, &[&root], &[], i64::try_from(t).unwrap());
    assert_eq!(at(from - 1), [(9, 0)]);
    assert_eq!(at(from), []);
    assert_eq!(at(to), []);
    assert_eq!(at(to + 1), [(10, 0)]);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// A chain verifies exactly at the times in the intersection of its
    /// validity intervals, closed at both ends, and otherwise fails with "not yet valid" or
    /// "expired" at the topmost certificate not valid then.
    #[test]
    fn valid_exactly_on_the_intersection(
        starts in prop::array::uniform3(0u64..50),
        lengths in prop::array::uniform3(1u64..50),
        now in 0i64..120,
    ) {
        let interval = |i: usize| (starts[i] * DAY, (starts[i] + lengths[i]) * DAY);
        let (rk, mk, lk) = (key(1), key(2), key(3));
        let root = root(&rk, interval(2).0, interval(2).1);
        let mid = issue("/CN=Mid", &mk, &root, &rk, interval(1), true);
        let leaf = issue("/CN=Leaf", &lk, &mid, &mk, interval(0), false);
        let now = now * i64::try_from(DAY).unwrap();
        let valid = |i: usize| {
            let (from, to) = interval(i);
            i64::try_from(from).unwrap() <= now && now <= i64::try_from(to).unwrap()
        };
        let found = errors(&leaf, &[&root], &[&mid], now);
        if valid(0) && valid(1) && valid(2) {
            prop_assert!(found.is_empty(), "{found:?}");
        } else {
            // Top down, as OpenSSL checks; expiry goes on, so later expiries
            // follow, and "not yet valid" ends it.
            let first = (0..3).rev().find(|&i| !valid(i)).unwrap();
            prop_assert!(matches!(found.first(), Some(&(9 | 10, d)) if d == first), "{found:?}");
        }
    }
}
