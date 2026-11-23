//! Reading a command's input, and the `-inform`/`-outform` values, shared
//! by the commands.

use std::{
    ffi::OsStr,
    fs,
    io::{self, Read},
};

use baldssl_core::{Error, Result};
use baldssl_x509::Format;

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
        _ => Err(Error::Usage(format!(
            "{command}: Invalid format \"{}\" for option -{option}",
            value.to_string_lossy()
        ))),
    }
}
