//! Totality and canonicity of the base64 decoder.
#![no_main]

use baldssl_core::base64;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bytes) = base64::decode(data) {
        // Canonicity: only the encoder's image is accepted.
        assert_eq!(base64::encode(&bytes).as_bytes(), data);
    }
});
