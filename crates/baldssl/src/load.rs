//! The line OpenSSL's applications print for a file of keys or certificates
//! that does not load: the message of `load_key_certs_crls` in
//! `apps/lib/apps.c`, in the form of the release line
//! ([`Apps::LOAD_MESSAGE`](crate::line::Apps::LOAD_MESSAGE)).
//!
//! The line is `<verb> <noun> from <file>`, and from OpenSSL 3.2 a file
//! that does not open adds `: <reason>`. The noun is the description the
//! caller gives (`desc`, "certificate file") when it contains the name of
//! the credential asked for ([`Credential`]), and `<name> of <desc>`
//! otherwise ("certs of untrusted certificates" in 3.0, "private key of
//! public key" for the private key `dgst -verify` falls back to).

#[cfg(test)]
mod tests;

use crate::line::{Apps as _, Line, LoadMessage};

/// The verb for a file that does not open, in every release line.
const COULD_NOT_OPEN: &str = "Could not open file or uri for loading";
/// The verb for a file with nothing that decodes, in OpenSSL 3.0.
const COULD_NOT_READ: &str = "Could not read";
/// What OpenSSL 3.0 adds to [`COULD_NOT_READ`] for a list of certificates
/// (`any` in `load_key_certs_crls`).
const ANY: &str = "any";
/// The verb for a file with nothing that decodes, in OpenSSL 3.2 to 3.6.
const COULD_NOT_FIND: &str = "Could not find";
/// The verb for a file with nothing that decodes, in OpenSSL 4.
const COULD_NOT_FIND_OR_DECODE: &str = "Could not find or decode";
/// The system's reason for a missing file (`strerror(ENOENT)`), which
/// OpenSSL 3.2 and later print after a file that does not open.
const NO_SUCH_FILE: &str = "No such file or directory";

/// What `load_key_certs_crls` is asked to load, which its message names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Credential {
    /// A private key (`ppkey`).
    PrivateKey,
    /// A public key (`ppubkey`).
    PublicKey,
    /// One certificate (`pcert`, as `load_cert` asks).
    Certificate,
    /// A list of certificates (`pcerts`, as `load_certs` asks).
    Certificates,
}

/// Why a file did not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadFailure {
    /// The file does not exist.
    Missing,
    /// Nothing in it decodes as the credential.
    Undecoded,
}

impl Credential {
    /// The name the loader gives the credential. OpenSSL 3.0 names it
    /// twice: as it starts (`failed`: "key", "public key", "cert", "certs"),
    /// which a file that does not open keeps, and once the file is read,
    /// from what is missing ("key" for either key, "cert" for one
    /// certificate or a list). From 3.2, `FAIL_NAME` names it in full.
    fn name(self, failure: LoadFailure, message: LoadMessage) -> &'static str {
        match (message, failure, self) {
            (LoadMessage::Read, _, Credential::PrivateKey)
            | (
                LoadMessage::Read,
                LoadFailure::Undecoded,
                Credential::PublicKey,
            ) => "key",
            (
                LoadMessage::Read,
                LoadFailure::Missing,
                Credential::PublicKey,
            )
            | (
                LoadMessage::Find | LoadMessage::FindOrDecode,
                _,
                Credential::PublicKey,
            ) => "public key",
            (LoadMessage::Read, _, Credential::Certificate)
            | (
                LoadMessage::Read,
                LoadFailure::Undecoded,
                Credential::Certificates,
            ) => "cert",
            (
                LoadMessage::Read,
                LoadFailure::Missing,
                Credential::Certificates,
            ) => "certs",
            (
                LoadMessage::Find | LoadMessage::FindOrDecode,
                _,
                Credential::PrivateKey,
            ) => "private key",
            (
                LoadMessage::Find | LoadMessage::FindOrDecode,
                _,
                Credential::Certificate,
            ) => "certificate",
            (
                LoadMessage::Find | LoadMessage::FindOrDecode,
                _,
                Credential::Certificates,
            ) => "certificates",
        }
    }
}

/// The line, without its newline, for `credential` described as `desc`
/// that did not load from `file`, in the form of the release line this
/// build imitates.
pub(crate) fn load_line(
    credential: Credential,
    desc: &str,
    file: &str,
    failure: LoadFailure,
) -> String {
    let message = Line::LOAD_MESSAGE;
    let name = credential.name(failure, message);
    let noun = if desc.contains(name) {
        desc.to_owned()
    } else {
        format!("{name} of {desc}")
    };
    match (failure, message) {
        (LoadFailure::Missing, LoadMessage::Read) => {
            format!("{COULD_NOT_OPEN} {noun} from {file}")
        }
        (
            LoadFailure::Missing,
            LoadMessage::Find | LoadMessage::FindOrDecode,
        ) => {
            format!("{COULD_NOT_OPEN} {noun} from {file}: {NO_SUCH_FILE}")
        }
        (LoadFailure::Undecoded, LoadMessage::Read) => match credential {
            Credential::Certificates => {
                format!("{COULD_NOT_READ} {ANY} {noun} from {file}")
            }
            Credential::PrivateKey
            | Credential::PublicKey
            | Credential::Certificate => {
                format!("{COULD_NOT_READ} {noun} from {file}")
            }
        },
        (LoadFailure::Undecoded, LoadMessage::Find) => {
            format!("{COULD_NOT_FIND} {noun} from {file}")
        }
        (LoadFailure::Undecoded, LoadMessage::FindOrDecode) => {
            format!("{COULD_NOT_FIND_OR_DECODE} {noun} from {file}")
        }
    }
}
