//! The options that set the fields of a certificate baldssl signs, shared
//! by `req -x509` and `x509 -req`: the serial number (`-set_serial`, or a
//! serial file), the validity (`-days`, `-not_before`, `-not_after`), and
//! the digest it is signed with.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use baldssl_core::{
    Error, Result,
    der::{Time, TimeKind},
};
use baldssl_crypto::Algorithm as Digest;
use baldssl_fs::{Access, read_if_present};
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{SerialNumber, SignatureAlgorithm, Validity};

use crate::outputs::Outputs;

/// The validity in days without `-days`: `DEFAULT_DAYS` in OpenSSL's
/// `apps/req.c` and `apps/x509.c`.
pub(crate) const DEFAULT_DAYS: u64 = 30;

/// Seconds in a day: the unit `-days` is counted in.
const SECONDS_PER_DAY: u64 = 86_400;

/// The value of `-not_before` and `-not_after` that means now
/// (`ASN1_TIME_set_string_X509` is skipped for it in OpenSSL's
/// `set_cert_times`, `apps/lib/apps.c`).
const TODAY: &str = "today";

/// The length of a UTCTime written `YYMMDDHHMMSSZ` ([RFC 5280 section
/// 4.1.2.5.1]).
///
/// [RFC 5280 section 4.1.2.5.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1
const UTC_TIME_LEN: usize = 13;

/// The length of a GeneralizedTime written `YYYYMMDDHHMMSSZ` ([RFC 5280
/// section 4.1.2.5.2]).
///
/// [RFC 5280 section 4.1.2.5.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.2
const GENERALIZED_TIME_LEN: usize = 15;

/// `error` with `prefix` before its message, for the errors of the
/// `FromStr` impls, which do not know the command or the option.
fn prefixed(prefix: &str, error: Error) -> Error {
    match error {
        Error::Usage(m) => Error::Usage(format!("{prefix}: {m}")),
        Error::Unsupported(m) => Error::Unsupported(format!("{prefix}: {m}")),
        Error::Invalid(m) => Error::Invalid(format!("{prefix}: {m}")),
        e @ (Error::Reported { .. }
        | Error::NotFound { .. }
        | Error::Io { .. }
        | Error::Base64(_)
        | Error::Pem(_)
        | Error::Der(_)) => e,
    }
}

/// The serial number of `-set_serial` (see the `FromStr` of
/// [`SerialNumber`]).
///
/// # Errors
///
/// A usage error on what is not a number; unsupported for zero, negative
/// numbers and serials longer than 20 octets.
pub(crate) fn set_serial(value: &OsStr) -> Result<SerialNumber> {
    value
        .to_str()
        .ok_or_else(|| {
            Error::Usage(format!("invalid serial number {}", value.display()))
        })?
        .parse()
}

/// Seconds since the Unix epoch, now.
///
/// # Errors
///
/// [`Error::Invalid`] when the clock is before 1970, which no certificate
/// time baldssl writes can start from.
pub(crate) fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::invalid("the system clock is before 1970"))
}

/// A `-not_before` or `-not_after` time: now, or a given time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidityTime {
    /// `today`: the time the certificate is made.
    Today,
    /// A UTCTime or GeneralizedTime.
    At(Time),
}

/// `today`, or a UTCTime or GeneralizedTime without fraction, written as
/// RFC 5280 requires (UTCTime through 2049), as OpenSSL's
/// `ASN1_TIME_set_string_X509` does.
///
/// # Errors
///
/// [`Error::Usage`] on any other text.
impl FromStr for ValidityTime {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let invalid = || Error::Usage(format!("invalid time {text}"));
        if text == TODAY {
            return Ok(ValidityTime::Today);
        }
        let kind = match text.len() {
            UTC_TIME_LEN => TimeKind::Utc,
            GENERALIZED_TIME_LEN => TimeKind::Generalized,
            _ => return Err(invalid()),
        };
        let time = Time::parse(kind, text.as_bytes()).map_err(|_| invalid())?;
        if !time.fraction().is_empty() {
            return Err(invalid());
        }
        Ok(ValidityTime::At(time.to_rfc5280()))
    }
}

impl ValidityTime {
    /// The time, `now` being the time the certificate is made.
    fn at(&self, now: u64) -> Time {
        match self {
            ValidityTime::Today => Time::from_unix_seconds(now),
            ValidityTime::At(t) => t.clone(),
        }
    }
}

/// The value of `-<option>`, a [`ValidityTime`].
///
/// # Errors
///
/// A usage error on what is not one.
pub(crate) fn validity_time(
    option: &str,
    value: &OsStr,
) -> Result<ValidityTime> {
    let prefix = format!("-{option}");
    value
        .to_str()
        .ok_or_else(|| {
            Error::Usage(format!("{prefix}: invalid time {}", value.display()))
        })?
        .parse()
        .map_err(|e| prefixed(&prefix, e))
}

/// The validity options: `-days` ([`DEFAULT_DAYS`] by default, as in
/// OpenSSL), and the explicit times, which win over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lifetime {
    /// `-days`.
    pub(crate) days: u64,
    /// `-not_before`.
    pub(crate) not_before: Option<ValidityTime>,
    /// `-not_after`.
    pub(crate) not_after: Option<ValidityTime>,
}

impl Default for Lifetime {
    fn default() -> Self {
        Lifetime {
            days: DEFAULT_DAYS,
            not_before: None,
            not_after: None,
        }
    }
}

impl Lifetime {
    /// Reads `-days`.
    ///
    /// # Errors
    ///
    /// A usage error when the value is not a number of days.
    pub(crate) fn set_days(&mut self, value: &OsStr) -> Result<()> {
        self.days =
            value.to_str().and_then(|d| d.parse().ok()).ok_or_else(|| {
                Error::Usage(format!("invalid -days {}", value.display()))
            })?;
        Ok(())
    }

    /// The validity, starting now unless `-not_before` says otherwise.
    ///
    /// # Errors
    ///
    /// When `-days` takes the end past what a time can hold, or the clock
    /// is before 1970.
    pub(crate) fn validity(&self) -> Result<Validity> {
        let now = unix_now()?;
        let not_before = self
            .not_before
            .as_ref()
            .map_or_else(|| Time::from_unix_seconds(now), |t| t.at(now));
        let not_after = match &self.not_after {
            Some(t) => t.at(now),
            None => Time::from_unix_seconds(
                self.days
                    .checked_mul(SECONDS_PER_DAY)
                    .and_then(|d| d.checked_add(now))
                    .ok_or_else(|| {
                        Error::Usage(format!("-days {} too large", self.days))
                    })?,
            ),
        };
        Ok(Validity {
            not_before,
            not_after,
        })
    }
}

/// What a missing serial file means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum MissingSerialFile {
    /// An error.
    #[default]
    Refused,
    /// A new file, starting from a random number (`-CAcreateserial`).
    Created,
}

/// Where the serial number of a certificate comes from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum SerialSource {
    /// 159 random bits, as OpenSSL draws them.
    #[default]
    Random,
    /// `-set_serial`.
    Given(SerialNumber),
    /// A serial file (`-CAserial`, or the CA's file name with `.srl`), as
    /// OpenSSL's `x509` keeps it: the number read is incremented, used, and
    /// written back.
    File {
        /// The file.
        path: PathBuf,
        /// When it does not exist.
        missing: MissingSerialFile,
    },
}

/// The default serial file of a CA certificate, as OpenSSL names it: the
/// file name with its extension, if any, replaced by `.srl`.
#[must_use]
pub(crate) fn default_serial_file(ca: &OsStr) -> PathBuf {
    Path::new(ca).with_extension("srl")
}

impl SerialSource {
    /// The serial number to use; a serial file's new contents go to
    /// `out`, written before the certificate is signed, as OpenSSL's
    /// `x509_load_serial` saves it.
    ///
    /// # Errors
    ///
    /// A missing file that is not to be created, an unreadable one, or one
    /// that holds no number.
    pub(crate) fn next(&self, out: &mut Outputs) -> Result<SerialNumber> {
        match self {
            SerialSource::Random => SerialNumber::random(),
            SerialSource::Given(s) => Ok(s.clone()),
            SerialSource::File { path, missing } => {
                let shown = path.display().to_string();
                let serial = match (read_if_present(path)?, missing) {
                    (Some(bytes), _) => {
                        let text =
                            std::str::from_utf8(&bytes).map_err(|_| {
                                Error::Usage(format!(
                                    "{shown}: unable to load number"
                                ))
                            })?;
                        SerialNumber::following_file(text)
                            .map_err(|e| prefixed(&shown, e))?
                    }
                    (None, MissingSerialFile::Created) => {
                        SerialNumber::random()?
                    }
                    (None, MissingSerialFile::Refused) => {
                        return Err(Error::Io {
                            context: shown,
                            message: "No such file or directory".into(),
                        });
                    }
                };
                out.file(path, Access::Default, serial.to_serial_file());
                Ok(serial)
            }
        }
    }
}

/// The digest a certificate can be signed with: every digest baldssl has
/// but SHA-1, which baldssl does not sign with. `None` for SHA-1.
#[must_use]
pub(crate) fn signing_digest_opt(digest: Digest) -> Option<Digest> {
    match digest {
        Digest::Sha1 => None,
        d @ (Digest::Sha224
        | Digest::Sha256
        | Digest::Sha384
        | Digest::Sha512) => Some(d),
    }
}

/// The signature algorithm: the key's default, with the digest of a
/// `-<digest>` option as ECDSA's hash. Ed25519 fixes its hash, so a digest
/// does not change it, as in OpenSSL.
pub(crate) fn signature_algorithm(
    key: &AnyPrivateKey,
    digest: Option<Digest>,
) -> SignatureAlgorithm {
    match (key.default_signature_algorithm(), digest) {
        (SignatureAlgorithm::Ecdsa(_), Some(hash)) => {
            SignatureAlgorithm::Ecdsa(hash)
        }
        (default, _) => default,
    }
}

#[cfg(test)]
mod tests;
