//! Generating a key from the options OpenSSL takes for it, shared by
//! `genpkey` (`-algorithm`, `-pkeyopt`) and `req` (`-newkey`, `-pkeyopt`),
//! and writing a private key to a file only its owner can read.

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{ffi::OsStr, fs::OpenOptions, io::Write as _, path::Path};

use baldssl_core::{Error, Result, pem};
use baldssl_pkey::Algorithm;

use crate::input::read_input;

/// The curve for an `ec_paramgen_curve` value, by its NIST or OpenSSL name.
/// OpenSSL does not accept `secp256r1`, so neither does this.
pub(crate) fn curve_opt(name: &str) -> Option<Algorithm> {
    match name.to_ascii_lowercase().as_str() {
        "p-256" | "prime256v1" => Some(Algorithm::P256),
        "p-384" | "secp384r1" => Some(Algorithm::P384),
        "p-521" | "secp521r1" => Some(Algorithm::P521),
        _ => None,
    }
}

/// An option value as UTF-8.
///
/// # Errors
///
/// A usage error when it is not.
pub(crate) fn utf8<'a>(
    command: &str,
    option: &str,
    value: &'a OsStr,
) -> Result<&'a str> {
    value
        .to_str()
        .ok_or_else(|| Error::Usage(format!("{command}: -{option}: not UTF-8")))
}

/// What the options say about the key to generate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeyParameters {
    /// The algorithm name, upper case.
    algorithm: Option<String>,
    /// `-pkeyopt ec_paramgen_curve:<name>` (or `group:<name>`).
    curve: Option<String>,
    /// The parameters file of `-newkey ec:<file>`.
    parameters: Option<std::ffi::OsString>,
}

impl KeyParameters {
    /// `genpkey -algorithm <name>`.
    ///
    /// # Errors
    ///
    /// A name that is not UTF-8.
    pub(crate) fn set_algorithm(
        &mut self,
        command: &str,
        value: &OsStr,
    ) -> Result<()> {
        self.algorithm =
            Some(utf8(command, "algorithm", value)?.to_ascii_uppercase());
        Ok(())
    }

    /// `req -newkey <name>` or `-newkey <name>:<parameters file>`.
    ///
    /// # Errors
    ///
    /// A value that is not UTF-8.
    pub(crate) fn set_newkey(
        &mut self,
        command: &str,
        value: &OsStr,
    ) -> Result<()> {
        let text = utf8(command, "newkey", value)?;
        let (name, file) = match text.split_once(':') {
            Some((name, file)) => (name, Some(file)),
            None => (text, None),
        };
        self.algorithm = Some(name.to_ascii_uppercase());
        self.parameters = file.map(Into::into);
        Ok(())
    }

    /// `-pkeyopt <option>:<value>`.
    ///
    /// # Errors
    ///
    /// Unsupported for any option but the curve and `ec_param_enc`.
    pub(crate) fn pkeyopt(
        &mut self,
        command: &str,
        value: &OsStr,
    ) -> Result<()> {
        let v = utf8(command, "pkeyopt", value)?;
        match v.split_once(':') {
            Some(("ec_paramgen_curve" | "group", name)) => {
                self.curve = Some(name.to_string());
                Ok(())
            }
            Some(("ec_param_enc", "named_curve")) => Ok(()),
            _ => Err(Error::unsupported(format!("{command} -pkeyopt {v}"))),
        }
    }

    /// The algorithm the options name.
    ///
    /// # Errors
    ///
    /// No algorithm, an EC key without a curve, an unreadable parameters
    /// file, or an algorithm or curve baldssl does not implement.
    pub(crate) fn algorithm(&self, command: &str) -> Result<Algorithm> {
        match self.algorithm.as_deref() {
            Some("EC") => {
                if let Some(file) = &self.parameters {
                    let bytes = read_input(Some(file))?;
                    let block = pem::decode_first(&bytes, &["EC PARAMETERS"])?;
                    return Algorithm::from_ec_parameters(&block.contents);
                }
                let name = self.curve.as_deref().ok_or_else(|| {
                    Error::Usage(format!(
                        "{command}: EC needs -pkeyopt ec_paramgen_curve:<curve>"
                    ))
                })?;
                curve_opt(name).ok_or_else(|| {
                    Error::unsupported(format!("{command}: EC curve {name}"))
                })
            }
            Some("ED25519") if self.parameters.is_none() => {
                Ok(Algorithm::Ed25519)
            }
            Some(other) => Err(Error::unsupported(format!(
                "{command}: key algorithm {}",
                other.to_ascii_lowercase()
            ))),
            None => Err(Error::Usage(format!(
                "{command}: no algorithm given (EC or ED25519)"
            ))),
        }
    }
}

/// Writes a private key to `path`, creating the file readable and writable
/// by its owner only (mode 0600 where files have modes), as OpenSSL opens
/// key outputs (`bio_open_owner`). An existing file keeps its mode, as
/// with OpenSSL.
///
/// # Errors
///
/// When the file cannot be created or written.
pub(crate) fn write_private_key(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| Error::Io {
            context: format!("writing {}", path.display()),
            message: e.to_string(),
        })
}

#[cfg(test)]
mod tests;
