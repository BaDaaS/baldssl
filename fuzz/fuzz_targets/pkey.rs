//! Reading keys: never panics on any input, any private key read back
//! re-encodes to PKCS#8 and reads again to the same key, and any public key
//! read back writes a SubjectPublicKeyInfo that reads again to the same key.
#![no_main]

use baldssl_core::encoding::Encodable;
use baldssl_pkey::{AnyPrivateKey, PublicKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for key in [AnyPrivateKey::from_der(data), AnyPrivateKey::from_pem(data)]
        .into_iter()
        .flatten()
    {
        let der = key.encode();
        let again = AnyPrivateKey::from_der(&der).expect("re-read PKCS#8");
        assert_eq!(again.encode(), der);
    }
    for public in [PublicKey::from_der(data), PublicKey::from_pem(data)]
        .into_iter()
        .flatten()
    {
        assert!(!public.as_bytes().is_empty());
        let der = public.encode();
        let again = PublicKey::from_der(&der).expect("re-read SPKI");
        assert_eq!(again, public);
    }
});
