//! Certificate decoding and every printer, in every compatibility profile.
#![no_main]

use baldssl_core::text::Text;
use baldssl_x509::{Certificate, Compat, NameStyle};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(cert) = Certificate::from_der(data) {
        assert_eq!(cert.der, data);
        for compat in [Compat::V30, Compat::V3, Compat::V36, Compat::V4] {
            let _ = cert.to_text(compat);
        }
        let _ = cert.issuer.to_openssl(NameStyle::Oneline);
        let _ = cert.subject.to_openssl(NameStyle::Utf8);
    }
});
