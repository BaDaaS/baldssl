//! Message digests as the command line names them: the `-<digest>` options
//! OpenSSL accepts, and the names it prints.

use baldssl_crypto::hash::Algorithm;

/// Digest names OpenSSL accepts that baldssl does not implement.
pub(crate) fn is_unimplemented_digest(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "md5"
            | "md4"
            | "sha512-224"
            | "sha512-256"
            | "sha3-224"
            | "sha3-256"
            | "sha3-384"
            | "sha3-512"
            | "shake128"
            | "shake256"
            | "sm3"
            | "ripemd160"
            | "blake2b512"
            | "blake2s256"
    )
}

/// The name OpenSSL 3 prints for a digest it fetched by name
/// (`EVP_MD_get0_name`): `-sha256` prints as `SHA2-256`.
pub(crate) fn fetched_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha224 => "SHA2-224",
        Algorithm::Sha256 => "SHA2-256",
        Algorithm::Sha384 => "SHA2-384",
        Algorithm::Sha512 => "SHA2-512",
    }
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

    #[test]
    fn fetched_names() {
        let names: Vec<_> =
            Algorithm::ALL.into_iter().map(fetched_name).collect();
        assert_eq!(
            names,
            ["SHA1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512"]
        );
    }
}
