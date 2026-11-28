//! The loader's lines for certificates. The keys' lines are tested with
//! `dgst`, which loads them.

use baldssl_x509::Compat;

use super::{Credential, LoadFailure, load_line};
use crate::line::{Apps as _, Line, LoadMessage, compat};

/// `verify`'s description of a certificate to verify (`apps/verify.c`).
const TARGET: &str = "certificate file";
/// `verify`'s description of `-untrusted` (`apps/verify.c`).
const UNTRUSTED: &str = "untrusted certificates";

/// The cases of [`certificate_lines`]: a credential, its description, the
/// failure, the release line, and the line.
const CASES: &[(Credential, &str, LoadFailure, Compat, &str)] = &[
    (
        Credential::Certificate,
        TARGET,
        LoadFailure::Missing,
        Compat::V30,
        "Could not open file or uri for loading certificate file from f",
    ),
    (
        Credential::Certificate,
        TARGET,
        LoadFailure::Undecoded,
        Compat::V30,
        "Could not read certificate file from f",
    ),
    (
        Credential::Certificates,
        UNTRUSTED,
        LoadFailure::Missing,
        Compat::V30,
        "Could not open file or uri for loading certs of untrusted \
             certificates from f",
    ),
    (
        Credential::Certificates,
        UNTRUSTED,
        LoadFailure::Undecoded,
        Compat::V30,
        "Could not read any untrusted certificates from f",
    ),
    (
        Credential::Certificate,
        TARGET,
        LoadFailure::Missing,
        Compat::V3,
        "Could not open file or uri for loading certificate file from f: \
             No such file or directory",
    ),
    (
        Credential::Certificate,
        TARGET,
        LoadFailure::Undecoded,
        Compat::V3,
        "Could not find certificate file from f",
    ),
    (
        Credential::Certificates,
        UNTRUSTED,
        LoadFailure::Missing,
        Compat::V3,
        "Could not open file or uri for loading untrusted certificates \
             from f: No such file or directory",
    ),
    (
        Credential::Certificates,
        UNTRUSTED,
        LoadFailure::Undecoded,
        Compat::V3,
        "Could not find untrusted certificates from f",
    ),
    (
        Credential::Certificate,
        TARGET,
        LoadFailure::Undecoded,
        Compat::V36,
        "Could not find certificate file from f",
    ),
    (
        Credential::Certificates,
        UNTRUSTED,
        LoadFailure::Undecoded,
        Compat::V36,
        "Could not find untrusted certificates from f",
    ),
    (
        Credential::Certificate,
        TARGET,
        LoadFailure::Missing,
        Compat::V4,
        "Could not open file or uri for loading certificate file from f: \
             No such file or directory",
    ),
    (
        Credential::Certificate,
        TARGET,
        LoadFailure::Undecoded,
        Compat::V4,
        "Could not find or decode certificate file from f",
    ),
    (
        Credential::Certificates,
        UNTRUSTED,
        LoadFailure::Missing,
        Compat::V4,
        "Could not open file or uri for loading untrusted certificates \
             from f: No such file or directory",
    ),
    (
        Credential::Certificates,
        UNTRUSTED,
        LoadFailure::Undecoded,
        Compat::V4,
        "Could not find or decode untrusted certificates from f",
    ),
];

/// OpenSSL's lines for files that do not load: 3.0.22, 3.5.9 and 4.1.0 as
/// they print them; 3.6 as `load_key_certs_crls` in its `apps/lib/apps.c`
/// builds them, the same as 3.5's ("Could not find"). A build checks the
/// cases of the line it imitates (`make check-profiles` builds each).
#[test]
fn certificate_lines() {
    for &(credential, desc, failure, line, expected) in CASES {
        if line == compat() {
            assert_eq!(
                load_line(credential, desc, "f", failure),
                expected,
                "{credential:?} {failure:?} {line:?}"
            );
        }
    }
}

/// A description that names the credential is printed alone, and one that
/// does not follows the name: the rule `load_key_certs_crls` applies with
/// `strstr`, in every release line. 3.0 calls a private key "key", which
/// "public key" contains; later lines call it "private key".
#[test]
fn noun_rule() {
    let line = load_line(
        Credential::PrivateKey,
        "public key",
        "f",
        LoadFailure::Undecoded,
    );
    let expected = match Line::LOAD_MESSAGE {
        LoadMessage::Read => "public key",
        LoadMessage::Find | LoadMessage::FindOrDecode => {
            "private key of public key"
        }
    };
    assert!(line.contains(&format!(" {expected} from f")), "{line}");
}
