//! The options that set the fields of a certificate baldssl signs, shared
//! by `req -x509` and `x509 -req`: the serial number (`-set_serial`, or a
//! serial file) and the validity (`-days`, `-not_before`, `-not_after`).

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use baldssl_core::{
    Error, Result,
    der::{Time, TimeKind},
    hex::{self, Case},
};
use baldssl_crypto::Algorithm as Digest;
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{SerialNumber, SignatureAlgorithm, Validity};

/// Big-endian bytes of the number written with `digits` in `radix` (10 or
/// 16), without leading zeros; `None` on a character that is not a digit.
fn digits_be_opt(digits: &str, radix: u16) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in digits.chars() {
        let mut carry = u16::try_from(c.to_digit(radix.into())?).ok()?;
        for byte in bytes.iter_mut().rev() {
            let v = u16::from(*byte).checked_mul(radix)?.checked_add(carry)?;
            *byte = v.to_be_bytes()[1];
            carry = v >> 8;
        }
        if carry != 0 {
            bytes.insert(0, carry.to_be_bytes()[1]);
        }
    }
    Some(bytes)
}

/// A serial number of at most 20 octets, positive, or the error saying so.
fn serial(command: &str, text: &str, bytes: &[u8]) -> Result<SerialNumber> {
    SerialNumber::new_opt(bytes).ok_or_else(|| {
        Error::unsupported(format!(
            "{command}: serial {text}: a serial must be positive and at most \
             20 octets"
        ))
    })
}

/// The serial number of `-set_serial`: decimal digits, or hexadecimal ones
/// after `0x`, as OpenSSL's `s2i_ASN1_INTEGER` reads them.
///
/// # Errors
///
/// A usage error on anything else; unsupported for zero, negative numbers
/// and serials longer than 20 octets.
pub(crate) fn parse_serial(
    command: &str,
    value: &OsStr,
) -> Result<SerialNumber> {
    let invalid = || {
        Error::Usage(format!(
            "{command}: invalid serial number {}",
            value.display()
        ))
    };
    let text = value.to_str().ok_or_else(invalid)?;
    let (digits, radix) =
        match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            Some(hex) => (hex, 16),
            None => (text, 10),
        };
    if digits.is_empty() {
        return Err(invalid());
    }
    let bytes = digits_be_opt(digits, radix).ok_or_else(invalid)?;
    serial(command, text, &bytes)
}

/// Seconds since the Unix epoch, now.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A `-not_before` or `-not_after` time: `today`, or a UTCTime or
/// GeneralizedTime, written as RFC 5280 requires (UTCTime through 2049),
/// as OpenSSL's `ASN1_TIME_set_string_X509` does.
///
/// # Errors
///
/// A usage error on any other text.
pub(crate) fn parse_time(
    command: &str,
    option: &str,
    value: &OsStr,
) -> Result<Time> {
    let invalid = || {
        Error::Usage(format!(
            "{command}: -{option}: invalid time {}",
            value.display()
        ))
    };
    let bytes = value.as_encoded_bytes();
    if bytes == b"today" {
        return Ok(Time::from_unix_seconds(now()));
    }
    let kind = match bytes.len() {
        13 => TimeKind::Utc,
        15 => TimeKind::Generalized,
        _ => return Err(invalid()),
    };
    let time = Time::parse(kind, bytes).map_err(|_| invalid())?;
    if !time.fraction().is_empty() {
        return Err(invalid());
    }
    Ok(time.to_rfc5280())
}

/// The validity options: `-days` (30 by default, as in OpenSSL), and the
/// explicit times, which win over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lifetime {
    /// `-days`.
    pub(crate) days: u64,
    /// `-not_before`.
    pub(crate) not_before: Option<Time>,
    /// `-not_after`.
    pub(crate) not_after: Option<Time>,
}

impl Default for Lifetime {
    fn default() -> Self {
        Lifetime {
            days: 30,
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
    pub(crate) fn set_days(
        &mut self,
        command: &str,
        value: &OsStr,
    ) -> Result<()> {
        self.days =
            value.to_str().and_then(|d| d.parse().ok()).ok_or_else(|| {
                Error::Usage(format!(
                    "{command}: invalid -days {}",
                    value.display()
                ))
            })?;
        Ok(())
    }

    /// The validity, starting now unless `-not_before` says otherwise.
    ///
    /// # Errors
    ///
    /// When `-days` takes the end past what a time can hold.
    pub(crate) fn validity(&self, command: &str) -> Result<Validity> {
        let start = now();
        let not_before = self
            .not_before
            .clone()
            .unwrap_or_else(|| Time::from_unix_seconds(start));
        let not_after = match &self.not_after {
            Some(t) => t.clone(),
            None => Time::from_unix_seconds(
                self.days
                    .checked_mul(86_400)
                    .and_then(|d| d.checked_add(start))
                    .ok_or_else(|| {
                        Error::Usage(format!(
                            "{command}: -days {} too large",
                            self.days
                        ))
                    })?,
            ),
        };
        Ok(Validity {
            not_before,
            not_after,
        })
    }
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
    /// written back. A missing file is an error unless `create`
    /// (`-CAcreateserial`), which starts from a random number.
    File {
        /// The file.
        path: PathBuf,
        /// `-CAcreateserial`.
        create: bool,
    },
}

/// The default serial file of a CA certificate, as OpenSSL names it: the
/// file name with its extension, if any, replaced by `.srl`.
#[must_use]
pub(crate) fn default_serial_file(ca: &OsStr) -> PathBuf {
    Path::new(ca).with_extension("srl")
}

/// The serial file's number, as `a2i_ASN1_INTEGER` reads it: hexadecimal
/// digits, upper or lower case.
fn read_serial_file(command: &str, path: &Path, text: &str) -> Result<Vec<u8>> {
    digits_be_opt(text.trim(), 16)
        .filter(|b| !b.is_empty() || !text.trim().is_empty())
        .ok_or_else(|| {
            Error::Usage(format!(
                "{command}: {}: unable to load number",
                path.display()
            ))
        })
}

/// One more than the big-endian `bytes`.
fn increment(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for byte in out.iter_mut().rev() {
        let (v, overflow) = byte.overflowing_add(1);
        *byte = v;
        if !overflow {
            return out;
        }
    }
    out.insert(0, 1);
    out
}

impl SerialSource {
    /// The serial number to use, after updating the serial file.
    ///
    /// # Errors
    ///
    /// A missing file without `create`, an unreadable one, or one that
    /// cannot be written.
    pub(crate) fn next(&self, command: &str) -> Result<SerialNumber> {
        match self {
            SerialSource::Random => SerialNumber::random(),
            SerialSource::Given(s) => Ok(s.clone()),
            SerialSource::File { path, create } => {
                let used = match fs::read_to_string(path) {
                    Ok(text) => {
                        increment(&read_serial_file(command, path, &text)?)
                    }
                    Err(e)
                        if *create
                            && e.kind() == std::io::ErrorKind::NotFound =>
                    {
                        SerialNumber::random()?.as_be_bytes().to_vec()
                    }
                    Err(e) => {
                        return Err(Error::Io {
                            context: path.display().to_string(),
                            message: e.to_string(),
                        });
                    }
                };
                let serial =
                    serial(command, &path.display().to_string(), &used)?;
                let mut text = hex::plain(serial.as_be_bytes(), Case::Upper);
                text.push('\n');
                fs::write(path, text).map_err(|e| Error::Io {
                    context: path.display().to_string(),
                    message: e.to_string(),
                })?;
                Ok(serial)
            }
        }
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
