//! Verification of chains baldssl builds itself, with fixed keys and
//! dates: each error as OpenSSL reports it (the interop tests compare with
//! OpenSSL), and the law that a chain verifies exactly at the times every
//! certificate is valid.

use baldssl_pkey::{Algorithm, AnyPrivateKey, PublicKey};
use proptest::prelude::*;

use super::{
    HANDLED_CRITICAL, Reported, TrustStore, Verification, VerifyError,
};
use crate::{
    Certificate, CertificateTemplate, CertificateTimes, CertificationRequest,
    Compat, Extension, ExtensionFile, ExtensionValue, Extensions,
    IssuedExtensions, Profile, SerialNumber, SignatureAlgorithm, Validity,
    WithProfile,
    dn::{DistinguishedName, InputEncoding, RdnMode, UTF8_ONLY},
};

/// What a profile says: how it compares times, and its message for a
/// verification error.
struct Says(VerifyError);

impl WithProfile for Says {
    type Output = (CertificateTimes, &'static str);

    fn call<P>(self) -> Self::Output
    where
        P: Profile,
    {
        (P::CERTIFICATE_TIMES, self.0.message::<P>())
    }
}

/// The release lines compiled in.
fn lines() -> Vec<Compat> {
    Compat::ALL
        .into_iter()
        .filter(|c| c.run(Says(VerifyError::CertHasExpired)).is_ok())
        .collect()
}

/// How the line `compat` compares times.
fn times(compat: Compat) -> CertificateTimes {
    compat.run(Says(VerifyError::CertHasExpired)).unwrap().0
}

/// The line `compat`'s message for `error`.
fn message(error: VerifyError, compat: Compat) -> &'static str {
    compat.run(Says(error)).unwrap().1
}

fn key(seed: u8) -> AnyPrivateKey {
    AnyPrivateKey::from_secret(Algorithm::Ed25519, &[seed; 32]).unwrap()
}

fn name(subj: &str) -> DistinguishedName {
    DistinguishedName::from_subj(
        subj.as_bytes(),
        InputEncoding::Latin1,
        RdnMode::MultiValued,
        UTF8_ONLY,
    )
    .unwrap()
    .name
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
        &Extensions::new(),
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
            extension_file: ExtensionFile::Given,
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

/// The errors of verifying `target` at `now` as OpenSSL 3.5 does, or none.
fn errors(
    target: &[u8],
    trusted: &[&[u8]],
    untrusted: &[&[u8]],
    now: i64,
) -> Vec<(u32, usize)> {
    errors_as(target, trusted, untrusted, now, Compat::default())
}

/// The errors of verifying `target` at `now` as the release line `compat`
/// does, or none.
fn errors_as(
    target: &[u8],
    trusted: &[&[u8]],
    untrusted: &[&[u8]],
    now: i64,
    compat: Compat,
) -> Vec<(u32, usize)> {
    compat
        .run(ErrorsAt {
            target,
            trusted,
            untrusted,
            now,
        })
        .unwrap()
}

/// The errors of a verification, for the profile it is applied to.
struct ErrorsAt<'x> {
    target: &'x [u8],
    trusted: &'x [&'x [u8]],
    untrusted: &'x [&'x [u8]],
    now: i64,
}

impl WithProfile for ErrorsAt<'_> {
    type Output = Vec<(u32, usize)>;

    fn call<P>(self) -> Self::Output
    where
        P: Profile,
    {
        let (trusted, untrusted) = (parse(self.trusted), parse(self.untrusted));
        let target = Certificate::from_der(self.target).unwrap();
        let store = TrustStore::new(&trusted, &untrusted).unwrap();
        match store.verify::<P>(&target, self.now).unwrap() {
            Verification::Verified(_) => Vec::new(),
            Verification::Failed(f) => f
                .errors
                .iter()
                .map(|Reported { error, depth }| (error.code(), *depth))
                .collect(),
        }
    }
}

const DAY: u64 = 86_400;

/// The errors a verification reports, as `(code, depth)`.
type Errors = &'static [(u32, usize)];

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
    let _ = message(VerifyError::KeyUsageNoCertSign, Compat::default());
}

/// The bounds of the validity period, by release line, as OpenSSL 3.5.9 and
/// 4.1.0 verify with `-attime`: valid at notBefore and not one second
/// before; through notAfter in OpenSSL 4, and only to the second before it
/// in 3.0 to 3.6, whose `X509_cmp_time` compares with `<=`.
#[test]
fn validity_bounds() {
    let (rk, lk) = (key(1), key(3));
    let (from, to) = (DAY, 2 * DAY);
    let root = root(&rk, 0, 3 * DAY);
    let leaf = issue("/CN=Leaf", &lk, &root, &rk, (from, to), false);
    for compat in lines() {
        let at = |t: u64| {
            errors_as(&leaf, &[&root], &[], i64::try_from(t).unwrap(), compat)
        };
        assert_eq!(at(from - 1), [(9, 0)], "{compat:?}");
        assert_eq!(at(from), [], "{compat:?}");
        assert_eq!(at(to - 1), [], "{compat:?}");
        assert_eq!(at(to + 1), [(10, 0)], "{compat:?}");
        let expected: Errors = match times(compat) {
            CertificateTimes::Asn1Compared => &[(10, 0)],
            CertificateTimes::PosixCompared => &[],
        };
        assert_eq!(at(to), expected, "{compat:?}");
    }
}

/// OpenSSL 3.0 to 3.6 at a time outside the years 0 to 9999: error 13 at
/// the top of the chain, and nothing after it. At the ends of that range,
/// and in OpenSSL 4 at any time, the times are compared (as OpenSSL 3.5.9
/// and 4.1.0 verify with `-attime`).
#[test]
fn times_outside_asn1() {
    let (rk, mk, lk) = (key(1), key(2), key(3));
    let span = (DAY, 100 * DAY);
    let root = root(&rk, span.0, span.1);
    let mid = issue("/CN=Mid", &mk, &root, &rk, span, true);
    let leaf = issue("/CN=Leaf", &lk, &mid, &mk, span, false);
    let (first, last) = (-62_167_219_200, 253_402_300_799);
    for compat in lines() {
        let at = |now: i64| errors_as(&leaf, &[&root], &[&mid], now, compat);
        assert_eq!(at(first), [(9, 2)], "{compat:?}");
        assert_eq!(at(last), [(10, 2), (10, 1), (10, 0)], "{compat:?}");
        for now in [first - 1, last + 1, i64::MIN, i64::MAX] {
            let expected: Errors = match times(compat) {
                CertificateTimes::Asn1Compared => &[(13, 2)],
                CertificateTimes::PosixCompared if now < first => &[(9, 2)],
                CertificateTimes::PosixCompared => &[(10, 2), (10, 1), (10, 0)],
            };
            assert_eq!(at(now), expected, "{compat:?} at {now}");
        }
    }
}

/// A notAfter of 99991231235959Z, RFC 5280's "no well-defined expiration
/// date": OpenSSL 4 never expires it; OpenSSL 3.0 to 3.6 expire it at that
/// second, and cannot compare a later time (as OpenSSL 3.5.9 and 4.1.0
/// verify with `-attime`).
#[test]
fn no_well_defined_expiration() {
    let rk = key(1);
    let forever = root(&rk, DAY, 253_402_300_799);
    for compat in lines() {
        let at = |now: i64| errors_as(&forever, &[&forever], &[], now, compat);
        let (at_end, after): (Errors, Errors) = match times(compat) {
            CertificateTimes::Asn1Compared => (&[(10, 0)], &[(13, 0)]),
            CertificateTimes::PosixCompared => (&[], &[]),
        };
        assert_eq!(at(253_402_300_798), [], "{compat:?}");
        assert_eq!(at(253_402_300_799), at_end, "{compat:?}");
        assert_eq!(at(253_402_300_800), after, "{compat:?}");
        assert_eq!(at(i64::MAX), after, "{compat:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// A chain verifies exactly at the times in the intersection of its
    /// validity intervals, and otherwise fails with "not yet valid" or
    /// "expired" at the topmost certificate not valid then. Each interval
    /// is closed at both ends in OpenSSL 4, and open at notAfter in 3.0 to
    /// 3.6.
    #[test]
    fn valid_exactly_on_the_intersection(
        starts in prop::array::uniform3(0u64..50),
        lengths in prop::array::uniform3(1u64..50),
        now in 0i64..120,
        compat in prop::sample::select(lines()),
    ) {
        let interval = |i: usize| (starts[i] * DAY, (starts[i] + lengths[i]) * DAY);
        let (rk, mk, lk) = (key(1), key(2), key(3));
        let root = root(&rk, interval(2).0, interval(2).1);
        let mid = issue("/CN=Mid", &mk, &root, &rk, interval(1), true);
        let leaf = issue("/CN=Leaf", &lk, &mid, &mk, interval(0), false);
        let now = now * i64::try_from(DAY).unwrap();
        let valid = |i: usize| {
            let (from, to) = interval(i);
            let (from, to) = (i64::try_from(from).unwrap(), i64::try_from(to).unwrap());
            from <= now
                && match times(compat) {
                    CertificateTimes::Asn1Compared => now < to,
                    CertificateTimes::PosixCompared => now <= to,
                }
        };
        let found = errors_as(&leaf, &[&root], &[&mid], now, compat);
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

/// The critical extensions OpenSSL handles, by the dotted OIDs of
/// `X509_supported_extension` (`crypto/x509/v3_purp.c`).
#[test]
fn handled_critical_extensions() {
    let dotted: Vec<String> = HANDLED_CRITICAL
        .iter()
        .map(|id| id.to_dotted().unwrap())
        .collect();
    assert_eq!(
        dotted,
        [
            "2.16.840.1.113730.1.1",
            "2.5.29.15",
            "2.5.29.17",
            "2.5.29.19",
            "2.5.29.32",
            "2.5.29.37",
            "2.5.29.36",
            "1.3.6.1.5.5.7.1.14",
            "2.5.29.30",
            "2.5.29.33",
            "2.5.29.54",
            "1.3.6.1.5.5.7.1.7",
            "1.3.6.1.5.5.7.1.8",
        ]
    );
}

/// The error numbers are OpenSSL's (`include/openssl/x509_vfy.h.in`).
#[test]
fn error_numbers() {
    for (error, code) in [
        (VerifyError::UnableToGetIssuerCert, 2),
        (VerifyError::CertSignatureFailure, 7),
        (VerifyError::CertNotYetValid, 9),
        (VerifyError::CertHasExpired, 10),
        (VerifyError::ErrorInCertNotBeforeField, 13),
        (VerifyError::DepthZeroSelfSignedCert, 18),
        (VerifyError::SelfSignedCertInChain, 19),
        (VerifyError::UnableToGetIssuerCertLocally, 20),
        (VerifyError::PathLengthExceeded, 25),
        (VerifyError::KeyUsageNoCertSign, 32),
        (VerifyError::UnhandledCriticalExtension, 34),
        (VerifyError::InvalidCa, 79),
    ] {
        assert_eq!(error.code(), code, "{error:?}");
    }
}

/// Error 9's message gained "or the system clock is incorrect" in OpenSSL
/// 3.6 (`crypto/x509/x509_txt.c`).
#[test]
fn not_yet_valid_message() {
    let short = "certificate is not yet valid";
    let long = "certificate is not yet valid or the system clock is incorrect";
    for compat in lines() {
        let expected = match compat {
            Compat::V30 | Compat::V3 => short,
            Compat::V36 | Compat::V4 => long,
        };
        assert_eq!(
            message(VerifyError::CertNotYetValid, compat),
            expected,
            "{compat:?}"
        );
    }
}
