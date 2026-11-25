//! Message digests as the command line names them: the `-<digest>` options
//! OpenSSL accepts, implemented or not.

use baldssl_crypto::hash::Algorithm;

/// The digests OpenSSL 3.5 lists that baldssl does not implement
/// (`openssl list -digest-algorithms`), by the names `-<digest>` takes.
const UNIMPLEMENTED_DIGESTS: [&str; 14] = [
    "md5",
    "md4",
    "sha512-224",
    "sha512-256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "shake128",
    "shake256",
    "sm3",
    "ripemd160",
    "blake2b512",
    "blake2s256",
];

/// Whether `name` is a digest OpenSSL accepts that baldssl does not
/// implement, ignoring ASCII case.
pub(crate) fn is_unimplemented_digest(name: &str) -> bool {
    UNIMPLEMENTED_DIGESTS
        .iter()
        .any(|d| d.eq_ignore_ascii_case(name))
}

/// Whether `-<name>` is a digest option: one baldssl implements, or one it
/// refuses as unsupported.
pub(crate) fn is_digest_option(name: &str) -> bool {
    Algorithm::from_name_opt(name).is_some() || is_unimplemented_digest(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_digests_are_named() {
        assert!(is_unimplemented_digest("MD5"));
        assert!(is_unimplemented_digest("sha3-256"));
        assert!(!is_unimplemented_digest("sha256"));
        assert!(!is_unimplemented_digest("text"));
    }
}
