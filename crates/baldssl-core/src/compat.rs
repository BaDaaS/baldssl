//! The OpenSSL release line whose output baldssl reproduces.
//!
//! The text forms of certificates, requests and keys differ between
//! OpenSSL's release lines only in a few places: the geometry of the hex
//! dumps, the EC key header, the sign byte of a bignum, and the style of
//! names. Every crate that prints takes the line as a [`Compat`].
//! `scripts/interop.sh` checks each line against real binaries of it.

use core::str::FromStr;

use crate::{Error, Result};

/// Which OpenSSL release line's layout to reproduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compat {
    /// OpenSSL 3.0, whose names use the older escaped style.
    V30,
    /// OpenSSL 3.2 to 3.6.
    #[default]
    V3,
    /// OpenSSL 4.0 and later.
    V4,
}

impl Compat {
    /// Bytes per line in `ASN1_buf_print` (keys, modulus).
    #[must_use]
    pub fn key_bytes_per_line(self) -> usize {
        match self {
            Compat::V30 | Compat::V3 => 15,
            Compat::V4 => 16,
        }
    }

    /// Bytes per line in `X509_signature_dump`.
    #[must_use]
    pub fn signature_bytes_per_line(self) -> usize {
        match self {
            Compat::V30 | Compat::V3 => 18,
            Compat::V4 => 24,
        }
    }

    /// Whether a bignum with its top bit set is printed with a leading
    /// `00:` (the two's-complement sign byte).
    #[must_use]
    pub fn bn_sign_byte(self) -> bool {
        self != Compat::V4
    }
}

/// The line of a profile (`3.0`, `3` or `4`) or of an OpenSSL version
/// (`3.0.22`, `3.5.9`, `4.1.0`).
///
/// # Errors
///
/// [`Error::Usage`] for any other text.
impl FromStr for Compat {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let s = text.trim();
        if s == "3.0" || s.starts_with("3.0.") {
            return Ok(Compat::V30);
        }
        match s.split('.').next() {
            Some("3") => Ok(Compat::V3),
            Some("4") => Ok(Compat::V4),
            _ => Err(Error::Usage(format!(
                "not an OpenSSL release line: {text:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Compat;

    /// Profiles and versions name their line; other text does not.
    #[test]
    fn versions() {
        for (text, line) in [
            ("4.1.0", Compat::V4),
            ("3", Compat::V3),
            ("3.0", Compat::V30),
            ("3.0.22", Compat::V30),
            ("3.5.9", Compat::V3),
            (" 4 ", Compat::V4),
        ] {
            assert_eq!(text.parse::<Compat>(), Ok(line), "{text}");
        }
        for text in ["1.1.1", "", "x"] {
            assert!(text.parse::<Compat>().is_err(), "{text}");
        }
    }
}
