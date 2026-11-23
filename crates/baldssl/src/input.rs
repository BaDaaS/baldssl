//! Reading a command's input, and the `-inform`/`-outform` values, shared
//! by the commands.

use std::{
    ffi::OsStr,
    fs,
    io::{self, Read},
};

use baldssl_core::{
    Error, Result,
    encoding::Decodable,
    pem::{self, Pem},
};
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{CertificationRequest, Format};

/// The bytes of `path`, or of standard input without one.
///
/// # Errors
///
/// [`Error::NotFound`] for a missing file, [`Error::Io`] otherwise.
pub(crate) fn read_input(path: Option<&OsStr>) -> Result<Vec<u8>> {
    match path {
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).map_err(|e| Error::Io {
                context: "reading stdin".into(),
                message: e.to_string(),
            })?;
            Ok(buf)
        }
        Some(p) => fs::read(p).map_err(|e| {
            let shown = p.to_string_lossy().into_owned();
            if e.kind() == io::ErrorKind::NotFound {
                Error::NotFound { path: shown }
            } else {
                Error::Io {
                    context: format!("reading {shown}"),
                    message: e.to_string(),
                }
            }
        }),
    }
}

/// The value of `-inform` or `-outform` for `command`: `PEM` or `DER`, in
/// any case, as OpenSSL accepts them.
///
/// # Errors
///
/// [`Error::Usage`] for anything else, with OpenSSL's message.
pub(crate) fn parse_format(
    value: &OsStr,
    command: &str,
    option: &str,
) -> Result<Format> {
    match value.to_str().map(str::to_ascii_uppercase).as_deref() {
        Some("PEM") => Ok(Format::Pem),
        Some("DER") => Ok(Format::Der),
        // OpenSSL's two lines; the command name in front of the first is
        // the one every usage error gets.
        _ => {
            let value = value.to_string_lossy();
            Err(Error::Usage(format!(
                "Bad format \"{value}\"\n{command}: Invalid format \"{value}\" \
                 for option -{option}"
            )))
        }
    }
}

/// Whether the bytes are PEM: a `-----BEGIN` boundary, as OpenSSL 3 detects
/// it when no format is given.
pub(crate) fn is_pem(bytes: &[u8]) -> bool {
    bytes.windows(10).any(|w| w == b"-----BEGIN")
}

/// A private key file, PEM or DER (`-key`, `-CAkey`).
///
/// # Errors
///
/// An unreadable file or key.
pub(crate) fn read_key(
    path: &OsStr,
    form: Option<Format>,
) -> Result<AnyPrivateKey> {
    let bytes = read_input(Some(path))?;
    let pem = form.map_or_else(|| is_pem(&bytes), |f| f == Format::Pem);
    if pem {
        AnyPrivateKey::from_pem(&bytes)
    } else {
        AnyPrivateKey::decode(&bytes)
    }
}

/// A certificate request file, or standard input, PEM or DER.
///
/// # Errors
///
/// An unreadable file or request.
pub(crate) fn read_request(
    path: Option<&OsStr>,
    form: Option<Format>,
) -> Result<CertificationRequest> {
    let bytes = read_input(path)?;
    let pem = form.map_or_else(|| is_pem(&bytes), |f| f == Format::Pem);
    if pem {
        let block = pem::decode_first(&bytes, &[CertificationRequest::LABEL])?;
        CertificationRequest::decode(&block.contents)
    } else {
        CertificationRequest::decode(&bytes)
    }
}
