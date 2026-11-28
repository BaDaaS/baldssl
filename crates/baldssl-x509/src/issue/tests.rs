//! Issued certificates against the ones OpenSSL writes.
//!
//! Known answers: `req/certificates.txt` of the fixtures
//! (`scripts/gen-certificates.py`): the self-signed certificate `openssl
//! req -x509` writes for every fixture key, three subjects and three
//! (serial, validity) cases. Ed25519 signing is deterministic, so baldssl's
//! Ed25519 certificates are OpenSSL's byte for byte; ECDSA nonces are
//! random in OpenSSL, so an ECDSA certificate matches in its
//! `TBSCertificate`, and each side's signature verifies.

use baldssl_core::{
    Error,
    der::syntax::{Any, BitString, RawTlv, Sequence, decode},
    encoding::Decodable,
};
use baldssl_pkey::{Algorithm, AnyPrivateKey, PublicKey};
use baldssl_test_utils::{fixture, hex};

use super::{
    CertificateTemplate, CopyExtensions, IssuedExtensions, SerialNumber,
};
#[cfg(feature = "openssl-4")]
use crate::OpenSsl4;
#[cfg(feature = "openssl-3-0")]
use crate::OpenSsl30;
#[cfg(feature = "openssl-3-5")]
use crate::OpenSsl35;
#[cfg(feature = "openssl-3-6")]
use crate::OpenSsl36;
use crate::{
    Certificate, CertificationRequest, Profile, SignatureAlgorithm,
    cert::Validity,
    dn::{DistinguishedName, InputEncoding, RdnMode, UTF8_ONLY},
    extension::{ExtensionValue, Extensions},
    profile::AnyProfile,
};

/// The parts of a DER certificate: what is signed, and the signature.
fn split(der: &[u8]) -> (RawTlv, Vec<u8>) {
    let syntax = Sequence((Any, (Any, (BitString, ()))));
    let (tbs, (_, (signature, ()))) = decode(&syntax, der).unwrap();
    (tbs, signature)
}

/// baldssl's certificate against OpenSSL 3.5's, for every fixture line.
#[cfg(feature = "openssl-3-5")]
#[test]
fn matches_openssl() {
    let mut count = 0;
    for line in fixture("req/certificates.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let f: Vec<&str> = line.split(' ').collect();
        let algorithm = match f[0] {
            "P-256" => Algorithm::P256,
            "P-384" => Algorithm::P384,
            "P-521" => Algorithm::P521,
            _ => Algorithm::Ed25519,
        };
        let key = AnyPrivateKey::from_secret(algorithm, &hex(f[1])).unwrap();
        let subject = DistinguishedName::from_subj(
            &hex(f[2]),
            InputEncoding::Latin1,
            RdnMode::MultiValued,
            UTF8_ONLY,
        )
        .unwrap()
        .name;
        let serial = SerialNumber::new_opt(&hex(f[3])).unwrap();
        let validity = Validity::from_unix_seconds(
            f[4].parse().unwrap(),
            f[5].parse().unwrap(),
        );
        let theirs = hex(f[6]);
        let public = PublicKey::from(&key);
        let signature_algorithm = key.default_signature_algorithm();
        let ours = CertificateTemplate::self_signed::<OpenSsl35>(
            &subject, &public, serial, validity,
        )
        .sign(&key, signature_algorithm)
        .unwrap();
        let what = format!("{line:.60}");
        if signature_algorithm == SignatureAlgorithm::Ed25519 {
            assert_eq!(ours, theirs, "{what}: byte for byte");
        }
        let (our_tbs, our_signature) = split(&ours);
        let (their_tbs, their_signature) = split(&theirs);
        assert_eq!(our_tbs, their_tbs, "{what}: TBSCertificate");
        for signature in [our_signature, their_signature] {
            assert!(
                public.verify(
                    signature_algorithm,
                    our_tbs.as_bytes(),
                    &signature
                ),
                "{what}: signature"
            );
        }
        count += 1;
    }
    assert_eq!(count, 144);
}

/// OpenSSL 4's default `v3_ca` leaves the authority key identifier out of
/// a self-signed certificate; OpenSSL 3's (and 3.0's) puts it in.
#[test]
fn authority_key_identifier_by_release() {
    let key = AnyPrivateKey::from_secret(Algorithm::Ed25519, &[7; 32]).unwrap();
    let public = PublicKey::from(&key);
    let subject = DistinguishedName::from_subj(
        b"/CN=x",
        InputEncoding::Latin1,
        RdnMode::MultiValued,
        UTF8_ONLY,
    )
    .unwrap()
    .name;
    let has_authority = |template: CertificateTemplate| {
        template.extensions.as_slice().iter().any(|e| {
            matches!(e.value, ExtensionValue::AuthorityKeyIdentifier(_))
        })
    };
    let serial = || SerialNumber::new_opt(&[1]).unwrap();
    let validity = || Validity::from_unix_seconds(0, 1);
    #[cfg(feature = "openssl-3-0")]
    assert!(has_authority(
        CertificateTemplate::self_signed::<OpenSsl30>(
            &subject,
            &public,
            serial(),
            validity(),
        )
    ));
    #[cfg(feature = "openssl-3-5")]
    assert!(has_authority(
        CertificateTemplate::self_signed::<OpenSsl35>(
            &subject,
            &public,
            serial(),
            validity(),
        )
    ));
    #[cfg(feature = "openssl-3-6")]
    assert!(has_authority(
        CertificateTemplate::self_signed::<OpenSsl36>(
            &subject,
            &public,
            serial(),
            validity(),
        )
    ));
    #[cfg(feature = "openssl-4")]
    assert!(!has_authority(
        CertificateTemplate::self_signed::<OpenSsl4>(
            &subject,
            &public,
            serial(),
            validity(),
        )
    ));
}

/// baldssl's certificate for a request against the one `openssl x509 -req`
/// of each release line issues: `x509-req/issued-<line>.txt` of the
/// fixtures (`scripts/gen-issued.py`), one CA per curve and every fixture
/// key as the subject, the CA's own key included.
#[test]
fn issued_matches_openssl() {
    #[cfg(feature = "openssl-3-0")]
    issued_matches::<OpenSsl30>("x509-req/issued-v30.txt");
    #[cfg(feature = "openssl-3-5")]
    issued_matches::<OpenSsl35>("x509-req/issued-v3.txt");
    #[cfg(feature = "openssl-4")]
    issued_matches::<OpenSsl4>("x509-req/issued-v4.txt");
}

/// The certificates of the fixture `file`, recorded from the release line
/// `P`, against baldssl's.
#[allow(
    dead_code,
    reason = "unused when none of the lines with a fixture is compiled in"
)]
fn issued_matches<P>(file: &str)
where
    P: Profile,
{
    {
        let mut count = 0;
        for line in fixture(file).lines().filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = line.split(' ').collect();
            let algorithm = match f[0] {
                "P-256" => Algorithm::P256,
                "P-384" => Algorithm::P384,
                "P-521" => Algorithm::P521,
                _ => Algorithm::Ed25519,
            };
            let ca_key =
                AnyPrivateKey::from_secret(algorithm, &hex(f[1])).unwrap();
            let ca_der = hex(f[2]);
            let ca = Certificate::from_der(&ca_der).unwrap();
            let request = CertificationRequest::decode(&hex(f[3])).unwrap();
            let theirs = hex(f[4]);
            let validity = Certificate::from_der(&theirs).unwrap().validity;
            let signature_algorithm = ca_key.default_signature_algorithm();
            let ours = CertificateTemplate::issued::<P>(
                &request,
                &ca,
                &ca_key,
                SerialNumber::new_opt(&[1, 2]).unwrap(),
                validity,
                &IssuedExtensions::default(),
            )
            .unwrap()
            .sign(&ca_key, signature_algorithm)
            .unwrap();
            let what = format!("{file} {count}");
            if signature_algorithm == SignatureAlgorithm::Ed25519 {
                assert_eq!(ours, theirs, "{what}: byte for byte");
            }
            let (our_tbs, our_signature) = split(&ours);
            let (their_tbs, their_signature) = split(&theirs);
            assert_eq!(our_tbs, their_tbs, "{what}: TBSCertificate");
            let ca_public = PublicKey::from(&ca_key);
            for signature in [our_signature, their_signature] {
                assert!(
                    ca_public.verify(
                        signature_algorithm,
                        our_tbs.as_bytes(),
                        &signature
                    ),
                    "{what}: signature"
                );
            }
            count += 1;
        }
        assert_eq!(count, 64, "{file}");
    }
}

/// A CA key that is not the CA certificate's is refused, as OpenSSL does.
#[test]
fn issued_needs_the_ca_key() {
    let line = fixture("x509-req/issued-v3.txt")
        .lines()
        .find(|l| !l.starts_with('#'))
        .unwrap()
        .to_owned();
    let f: Vec<&str> = line.split(' ').collect();
    let ca_der = hex(f[2]);
    let ca = Certificate::from_der(&ca_der).unwrap();
    let request = CertificationRequest::decode(&hex(f[3])).unwrap();
    let other =
        AnyPrivateKey::from_secret(Algorithm::Ed25519, &[9; 32]).unwrap();
    assert!(
        CertificateTemplate::issued::<AnyProfile>(
            &request,
            &ca,
            &other,
            SerialNumber::new_opt(&[1]).unwrap(),
            Validity::from_unix_seconds(0, 1),
            &IssuedExtensions::default(),
        )
        .is_err()
    );
}

/// A CA certificate without a subject key identifier is refused: OpenSSL
/// would name the issuer and serial in the authority key identifier.
#[test]
fn issued_needs_a_ca_key_identifier() {
    let ca_key =
        AnyPrivateKey::from_secret(Algorithm::Ed25519, &[5; 32]).unwrap();
    let name = |subj: &[u8]| {
        DistinguishedName::from_subj(
            subj,
            InputEncoding::Latin1,
            RdnMode::MultiValued,
            UTF8_ONLY,
        )
        .unwrap()
        .name
    };
    let mut ca = CertificateTemplate::self_signed::<AnyProfile>(
        &name(b"/CN=CA"),
        &PublicKey::from(&ca_key),
        SerialNumber::new_opt(&[1]).unwrap(),
        Validity::from_unix_seconds(0, 1),
    );
    ca.extensions = crate::extension::Extensions::new();
    let ca_der = ca.sign(&ca_key, SignatureAlgorithm::Ed25519).unwrap();
    let ca = Certificate::from_der(&ca_der).unwrap();
    let leaf =
        AnyPrivateKey::from_secret(Algorithm::Ed25519, &[6; 32]).unwrap();
    let request = CertificationRequest::sign(
        &name(b"/CN=leaf"),
        &leaf,
        SignatureAlgorithm::Ed25519,
        &Extensions::new(),
    )
    .unwrap();
    let refused = |issued: Result<CertificateTemplate, Error>| {
        matches!(issued, Err(Error::Unsupported(_)))
    };
    let serial = || SerialNumber::new_opt(&[2]).unwrap();
    let validity = || Validity::from_unix_seconds(0, 1);
    let extensions = IssuedExtensions::default();
    // At signing (3.2 to 3.6) and from the configuration (4) alike. 3.0
    // adds no key identifier to a certificate without extensions, so it
    // has none to look for.
    #[cfg(feature = "openssl-3-0")]
    assert!(!refused(CertificateTemplate::issued::<OpenSsl30>(
        &request,
        &ca,
        &ca_key,
        serial(),
        validity(),
        &extensions,
    )));
    #[cfg(feature = "openssl-3-5")]
    assert!(refused(CertificateTemplate::issued::<OpenSsl35>(
        &request,
        &ca,
        &ca_key,
        serial(),
        validity(),
        &extensions,
    )));
    #[cfg(feature = "openssl-3-6")]
    assert!(refused(CertificateTemplate::issued::<OpenSsl36>(
        &request,
        &ca,
        &ca_key,
        serial(),
        validity(),
        &extensions,
    )));
    #[cfg(feature = "openssl-4")]
    assert!(refused(CertificateTemplate::issued::<OpenSsl4>(
        &request,
        &ca,
        &ca_key,
        serial(),
        validity(),
        &extensions,
    )));
}

#[test]
fn serial_numbers() {
    assert_eq!(SerialNumber::new_opt(&[]), None);
    assert_eq!(SerialNumber::new_opt(&[0, 0]), None);
    assert_eq!(SerialNumber::new_opt(&[0, 1]).unwrap().as_be_bytes(), [1]);
    // 20 octets once encoded: 0x7f.. fits, 0x80.. needs a 21st.
    assert!(SerialNumber::new_opt(&[0x7f; 20]).is_some());
    assert!(SerialNumber::new_opt(&[0x80; 20]).is_none());
    assert!(SerialNumber::new_opt(&[1; 21]).is_none());
}

/// Random serials are positive and at most 20 octets, as RFC 5280
/// section 4.1.2.2 requires.
#[test]
fn random_serials() {
    for _ in 0..64 {
        let serial = SerialNumber::random().unwrap();
        let bytes = serial.as_be_bytes();
        assert!(!bytes.is_empty() && bytes.len() <= 20);
        assert_ne!(bytes[0], 0);
        assert!(bytes.len() < 20 || bytes[0] < 0x80);
    }
}

/// `-copy_extensions` names, in any case, as OpenSSL's `set_ext_copy`.
#[test]
fn copy_extension_modes() {
    for (name, mode) in [
        ("none", CopyExtensions::None),
        ("COPY", CopyExtensions::Copy),
        ("CopyAll", CopyExtensions::CopyAll),
    ] {
        assert_eq!(name.parse::<CopyExtensions>(), Ok(mode), "{name}");
    }
    assert!(matches!(
        "all".parse::<CopyExtensions>(),
        Err(baldssl_core::Error::Usage(_))
    ));
}

/// `-set_serial`: decimal, or hexadecimal after `0x`, positive and at most
/// 20 octets once encoded.
#[test]
fn set_serial_values() {
    let s = |v: &str| v.parse::<SerialNumber>();
    assert_eq!(s("258").unwrap().as_be_bytes(), [1, 2]);
    assert_eq!(s("0x0102").unwrap().as_be_bytes(), [1, 2]);
    assert_eq!(s("0XfF").unwrap().as_be_bytes(), [0xff]);
    for bad in ["", "0x", "12a", "0xg", "-1"] {
        assert!(matches!(s(bad), Err(Error::Usage(_))), "{bad}");
    }
    // Zero, and 20 bytes with the top bit set: 21 octets once encoded.
    for refused in ["0", "0x00", "0x8000000000000000000000000000000000000000"] {
        assert!(
            matches!(s(refused), Err(Error::Unsupported(_))),
            "{refused}"
        );
    }
}

/// A serial file's number is read, incremented, and written back as
/// `save_serial` writes it: `0A` gives `0B`, `ff` gives `0100`.
#[test]
fn serial_files() {
    for (held, written) in [("0A\n", "0B\n"), ("ff", "0100\n")] {
        let next = SerialNumber::following_file(held).unwrap();
        assert_eq!(next.to_serial_file(), written);
    }
    for bad in ["", "\n", "xyz"] {
        assert!(
            matches!(SerialNumber::following_file(bad), Err(Error::Usage(_))),
            "{bad:?}"
        );
    }
}
