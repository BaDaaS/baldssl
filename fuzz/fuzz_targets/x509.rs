//! Certificate decoding and every printer, in both compatibility profiles.
#![no_main]

use baldssl_x509::{
    Certificate,
    Compat, print_text,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(cert) = Certificate::from_der(data) {
        assert_eq!(cert.der, data);
        let _ = print_text(&cert, Compat::V3);
        let _ = print_text(&cert, Compat::V4);
        let _ = cert.issuer.to_openssl(baldssl_x509::NameStyle::Oneline);
        let _ = cert.subject.to_openssl(baldssl_x509::NameStyle::Utf8);
    }
});
