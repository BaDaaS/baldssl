//! Robustness of the certificate decoder on corrupted real certificates.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::{fs, path::Path};

use baldssl_x509::{
    Certificate, Format, certificate_der,
    text::{Compat, print_text},
};
use proptest::prelude::*;

fn fixture_ders() -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/certs");
    let mut out = Vec::new();
    for entry in
        fs::read_dir(dir).expect("tests/fixtures/certs (run `make fixtures`)")
    {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "crt") {
            out.push(certificate_der(&fs::read(path).unwrap(), None).unwrap());
        }
    }
    out.sort();
    out
}

#[test]
fn fixtures_parse_and_keep_their_encoding() {
    for der in fixture_ders() {
        let cert = Certificate::from_der(&der).unwrap();
        assert_eq!(cert.der, &der[..]);
        print_text(&cert, Compat::V3).unwrap();
        print_text(&cert, Compat::V4).unwrap();
    }
}

/// A strict prefix of a certificate is never a certificate: the outer TLV
/// fixes the length. Likewise trailing bytes are rejected.
#[test]
fn truncation_and_trailing_data_rejected() {
    for der in fixture_ders() {
        for cut in 0..der.len() {
            assert!(
                Certificate::from_der(&der[..cut]).is_err(),
                "prefix {cut}"
            );
        }
        let mut longer = der.clone();
        longer.push(0);
        assert!(Certificate::from_der(&longer).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Totality: flipping bytes anywhere never panics, and when the mutant
    /// still decodes, printing it never panics either.
    #[test]
    fn mutations_never_panic(
        which in 0usize..64,
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
    ) {
        let ders = fixture_ders();
        let mut der = ders[which % ders.len()].clone();
        for (at, byte) in edits {
            let i = at.index(der.len());
            der[i] = byte;
        }
        if let Ok(cert) = Certificate::from_der(&der) {
            let _ = print_text(&cert, Compat::V3);
            let _ = print_text(&cert, Compat::V4);
            let _ = cert.subject.to_openssl(baldssl_x509::name::NameStyle::Utf8);
        }
        let _ = certificate_der(&der, Some(Format::Pem));
    }
}
