//! Generating a key from the options OpenSSL takes for it, shared by
//! `genpkey` (`-algorithm`, `-pkeyopt`) and `req` (`-newkey`, `-pkeyopt`).

use std::ffi::OsStr;

use baldssl_core::{Error, Result, der::syntax::RawTlv, pem};
use baldssl_pkey::Algorithm;

use crate::input::read_input;

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
                    return Algorithm::try_from(&RawTlv::parse(
                        &block.contents,
                    )?);
                }
                let name = self.curve.as_deref().ok_or_else(|| {
                    Error::Usage(format!(
                        "{command}: EC needs -pkeyopt ec_paramgen_curve:<curve>"
                    ))
                })?;
                // Ed25519 is not a curve EC parameters can name.
                match name.parse() {
                    Ok(Algorithm::Ed25519) | Err(_) => Err(Error::unsupported(
                        format!("{command}: EC curve {name}"),
                    )),
                    Ok(curve) => Ok(curve),
                }
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

#[cfg(test)]
mod tests;
