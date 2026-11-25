//! Reading a command's input, the `-inform`/`-outform` values, and the
//! release line to imitate, shared by the commands.

use std::{
    env::{self, VarError},
    ffi::OsStr,
    path::Path,
};

use baldssl_core::{
    Error, Result,
    encoding::Decodable,
    pem::{self, Pem},
};
use baldssl_fs::read_input as read_fs;
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{CertificationRequest, Compat, Format};

/// The environment variable selecting the OpenSSL release line to imitate.
pub(crate) const COMPAT_ENV: &str = "BALDSSL_OPENSSL_COMPAT";

/// The release line [`COMPAT_ENV`] names (see the `FromStr` of
/// [`Compat`]), or the default without it.
///
/// # Errors
///
/// [`Error::Usage`] for a value that names no profile, or is not UTF-8.
pub(crate) fn compat() -> Result<Compat> {
    match env::var(COMPAT_ENV) {
        Err(VarError::NotPresent) => Ok(Compat::default()),
        Err(VarError::NotUnicode(v)) => Err(Error::Usage(format!(
            "{COMPAT_ENV}: not UTF-8: {}",
            v.display()
        ))),
        Ok(v) => v
            .parse()
            .map_err(|e| Error::Usage(format!("{COMPAT_ENV}: {e}"))),
    }
}

/// The bytes of the file `path`, or of standard input without one.
///
/// # Errors
///
/// [`Error::NotFound`] for a missing file, [`Error::Io`] otherwise.
pub(crate) fn read_input(path: Option<&OsStr>) -> Result<Vec<u8>> {
    read_fs(path.map(Path::new))
}

/// What `opt_format` in OpenSSL's `apps/lib/opt.c` prints before a format
/// value it does not know.
const BAD_FORMAT: &str = "Bad format";
/// What `opt_next` in `apps/lib/opt.c` prints, after the command name,
/// before a format value it does not know.
const INVALID_FORMAT: &str = "Invalid format";

/// The value of `-inform`, `-outform` or another format option of
/// `command` (see the `FromStr` of [`Format`]).
///
/// # Errors
///
/// [`Error::Usage`] for anything else, with OpenSSL's two lines: `Bad
/// format "<value>"` from `opt_format`, then `<command>: Invalid format
/// "<value>" for option -<option>` from `opt_next` (`apps/lib/opt.c`).
pub(crate) fn format_value(
    value: &OsStr,
    command: &str,
    option: &str,
) -> Result<Format> {
    value.to_str().and_then(|v| v.parse().ok()).ok_or_else(|| {
        // OpenSSL's two lines; the command name in front of the first is
        // the one every usage error gets.
        let value = value.to_string_lossy();
        Error::Usage(format!(
            "{BAD_FORMAT} \"{value}\"\n{command}: {INVALID_FORMAT} \
             \"{value}\" for option -{option}"
        ))
    })
}

/// How a command writes what it produces: in `-outform`, unless `-noout`,
/// which wins wherever it comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum OutputForm {
    /// PEM.
    #[default]
    Pem,
    /// DER.
    Der,
    /// Nothing (`-noout`).
    Nothing,
}

impl OutputForm {
    /// After `-outform <format>`: that format, unless `-noout` came first.
    #[must_use]
    pub(crate) fn with_format(self, format: Format) -> OutputForm {
        match (self, format) {
            (OutputForm::Nothing, _) => OutputForm::Nothing,
            (OutputForm::Pem | OutputForm::Der, Format::Pem) => OutputForm::Pem,
            (OutputForm::Pem | OutputForm::Der, Format::Der) => OutputForm::Der,
        }
    }
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
    match Format::given_or_detected(form, &bytes) {
        Format::Pem => AnyPrivateKey::from_pem(&bytes),
        Format::Der => AnyPrivateKey::decode(&bytes),
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
    match Format::given_or_detected(form, &bytes) {
        Format::Pem => {
            let block =
                pem::decode_first(&bytes, &[CertificationRequest::LABEL])?;
            CertificationRequest::decode(&block.contents)
        }
        Format::Der => CertificationRequest::decode(&bytes),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use baldssl_core::Error;
    use baldssl_x509::Format;

    use super::{OutputForm, format_value};

    /// A format value in any case, and OpenSSL's two lines for any other.
    #[test]
    fn format_values() {
        let value = |v: &str| format_value(OsStr::new(v), "x509", "inform");
        assert_eq!(value("der").unwrap(), Format::Der);
        assert_eq!(value("Pem").unwrap(), Format::Pem);
        assert_eq!(
            value("xyz").err(),
            Some(Error::Usage(
                "Bad format \"xyz\"\nx509: Invalid format \"xyz\" for option \
                 -inform"
                    .into()
            ))
        );
    }

    /// `-noout` wins over `-outform`, in either order; the last
    /// `-outform` wins over the ones before.
    #[test]
    fn noout_is_sticky() {
        let after = |steps: &[Option<Format>]| {
            steps
                .iter()
                .fold(OutputForm::default(), |form, step| match step {
                    Some(f) => form.with_format(*f),
                    None => OutputForm::Nothing,
                })
        };
        assert_eq!(after(&[]), OutputForm::Pem);
        assert_eq!(after(&[Some(Format::Der)]), OutputForm::Der);
        assert_eq!(
            after(&[Some(Format::Der), Some(Format::Pem)]),
            OutputForm::Pem
        );
        assert_eq!(after(&[None, Some(Format::Der)]), OutputForm::Nothing);
        assert_eq!(after(&[Some(Format::Der), None]), OutputForm::Nothing);
    }
}
