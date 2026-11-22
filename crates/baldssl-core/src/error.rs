//! The workspace-wide error type.
//!
//! Hand-written rather than derived with `thiserror`: the project has no
//! third-party dependencies.

use crate::{base64::Base64Error, der::DerError, pem::PemError};

/// Every failure baldssl can report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The command reported the failure on standard error itself, in
    /// OpenSSL's words, and exits with this code: nothing is to be added.
    Reported(u8),
    /// An input file does not exist (exit code 2).
    NotFound {
        /// The path as given on the command line.
        path: String,
    },
    /// Any other I/O failure.
    Io {
        /// What was being done, e.g. `reading cert.pem`.
        context: String,
        /// The operating system message.
        message: String,
    },
    /// Malformed base64.
    Base64(Base64Error),
    /// Malformed PEM framing.
    Pem(PemError),
    /// Malformed or non-canonical DER.
    Der(DerError),
    /// Well-formed DER that is not a valid structure of the expected type.
    Invalid(String),
    /// A valid input that baldssl does not handle yet. The message names the
    /// feature; the status of every command is on the website.
    Unsupported(String),
    /// Bad command-line usage.
    Usage(String),
}

impl Error {
    /// The process exit code: 2 when an input file is missing, 1 otherwise.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::NotFound { .. } => 2,
            Error::Reported(code) => *code,
            _ => 1,
        }
    }

    /// Shorthand for [`Error::Unsupported`].
    pub fn unsupported(what: impl Into<String>) -> Self {
        Error::Unsupported(what.into())
    }

    /// Shorthand for [`Error::Invalid`].
    pub fn invalid(what: impl Into<String>) -> Self {
        Error::Invalid(what.into())
    }
}

impl From<Base64Error> for Error {
    fn from(e: Base64Error) -> Self {
        Error::Base64(e)
    }
}

impl From<PemError> for Error {
    fn from(e: PemError) -> Self {
        Error::Pem(e)
    }
}

impl From<DerError> for Error {
    fn from(e: DerError) -> Self {
        Error::Der(e)
    }
}

#[cfg(not(aeneas))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotFound { path } => {
                write!(f, "{path}: No such file or directory")
            }
            Error::Reported(code) => write!(f, "failed (exit code {code})"),
            Error::Io { context, message } => write!(f, "{context}: {message}"),
            Error::Base64(e) => write!(f, "base64: {e:?}"),
            Error::Pem(PemError::Base64(e)) => write!(f, "PEM: base64: {e:?}"),
            Error::Pem(e) => write!(f, "PEM: {e:?}"),
            Error::Der(e) => write!(f, "DER: {e:?}"),
            Error::Invalid(m) => write!(f, "invalid: {m}"),
            Error::Unsupported(m) => {
                write!(
                    f,
                    "unsupported: {m} (not implemented yet, see \
                     https://badaas.be/baldssl/#commands)"
                )
            }
            Error::Usage(m) => write!(f, "{m}"),
        }
    }
}

#[cfg(not(aeneas))]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        let nf = Error::NotFound { path: "x".into() };
        assert_eq!(nf.exit_code(), 2);
        assert_eq!(Error::invalid("x").exit_code(), 1);
        assert_eq!(Error::unsupported("x").exit_code(), 1);
        assert_eq!(Error::Der(DerError::UnexpectedEnd).exit_code(), 1);
        assert_eq!(Error::Reported(2).exit_code(), 2);
    }
}
