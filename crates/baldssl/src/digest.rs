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

/// What a `-<digest>` option names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestName {
    /// A digest baldssl implements.
    Implemented(Algorithm),
    /// A digest OpenSSL has and baldssl does not, which is refused as
    /// unsupported.
    Unimplemented,
}

impl DigestName {
    /// The digest `-<name>` names, ignoring ASCII case, if it names one.
    pub(crate) fn from_option_opt(name: &str) -> Option<DigestName> {
        match Algorithm::from_name_opt(name) {
            Some(algorithm) => Some(DigestName::Implemented(algorithm)),
            None => UNIMPLEMENTED_DIGESTS
                .iter()
                .any(|d| d.eq_ignore_ascii_case(name))
                .then_some(DigestName::Unimplemented),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_names() {
        assert_eq!(
            DigestName::from_option_opt("MD5"),
            Some(DigestName::Unimplemented)
        );
        assert_eq!(
            DigestName::from_option_opt("sha3-256"),
            Some(DigestName::Unimplemented)
        );
        assert_eq!(
            DigestName::from_option_opt("SHA256"),
            Some(DigestName::Implemented(Algorithm::Sha256))
        );
        assert_eq!(DigestName::from_option_opt("text"), None);
        for algorithm in Algorithm::ALL {
            assert_eq!(
                DigestName::from_option_opt(algorithm.name()),
                Some(DigestName::Implemented(algorithm))
            );
        }
    }
}
