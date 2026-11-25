//! The DER reader is total and every accepted TLV is a prefix of the input.
#![no_main]

use baldssl_core::der::{self, Integer, Oid};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = der::Reader::new(data);
    while let Ok(tlv) = reader.read() {
        assert!(data.windows(tlv.encoded().len()).any(|w| w == tlv.encoded()));
        assert!(tlv.encoded().ends_with(tlv.value()));
        let _ = Integer::parse(tlv.value());
        if let Ok(oid) = Oid::parse(tlv.value()) {
            let _ = oid.to_dotted();
        }
    }
});
