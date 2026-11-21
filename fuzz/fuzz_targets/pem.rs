//! The PEM reader never panics, and its output re-encodes and re-reads.
#![no_main]

use baldssl_core::pem;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = pem::decode_first(data, &["CERTIFICATE"]) {
        let again = pem::encode(&block.label, &block.contents);
        let back = pem::decode_first(again.as_bytes(), &["CERTIFICATE"]);
        assert_eq!(back.map(|b| b.contents).ok(), Some(block.contents));
    }
});
