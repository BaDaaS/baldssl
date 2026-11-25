//! Generating a key from the options OpenSSL takes for it, shared by
//! `genpkey` (`-algorithm`, `-pkeyopt`) and `req` (`-newkey`, `-pkeyopt`).

use std::{
    ffi::{OsStr, OsString},
    str::FromStr,
};

use baldssl_core::{Error, Result, der::syntax::RawTlv, pem};
use baldssl_pkey::Algorithm;

use crate::input::read_input;

/// The PEM label of EC parameters, as `openssl ecparam` writes them
/// (`PEM_STRING_ECPARAMETERS` in `include/openssl/pem.h`).
const EC_PARAMETERS_LABEL: &str = "EC PARAMETERS";

/// The key algorithms OpenSSL names that baldssl generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyAlgorithm {
    /// `EC`: an elliptic-curve key, on the curve the options name.
    Ec,
    /// `ED25519`.
    Ed25519,
}

impl KeyAlgorithm {
    /// Every algorithm, with the name OpenSSL gives it.
    const ALL: [(&'static str, KeyAlgorithm); 2] =
        [("EC", KeyAlgorithm::Ec), ("ED25519", KeyAlgorithm::Ed25519)];
}

/// An algorithm name baldssl does not generate, lower case, as the error
/// names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnknownAlgorithm(String);

/// An algorithm name, in any case, as OpenSSL reads `-algorithm` and
/// `-newkey`.
///
/// # Errors
///
/// [`UnknownAlgorithm`] for a name baldssl does not generate.
impl FromStr for KeyAlgorithm {
    type Err = UnknownAlgorithm;

    fn from_str(name: &str) -> std::result::Result<Self, UnknownAlgorithm> {
        KeyAlgorithm::ALL
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, a)| a)
            .ok_or_else(|| UnknownAlgorithm(name.to_ascii_lowercase()))
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
    /// The algorithm named; an unknown name is kept so that it is refused
    /// after the other options, where OpenSSL refuses it.
    algorithm: Option<std::result::Result<KeyAlgorithm, UnknownAlgorithm>>,
    /// `-pkeyopt ec_paramgen_curve:<name>` (or `group:<name>`).
    curve: Option<String>,
    /// The parameters file of `-newkey ec:<file>`.
    parameters: Option<OsString>,
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
        self.algorithm = Some(utf8(command, "algorithm", value)?.parse());
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
        self.algorithm = Some(name.parse());
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

    /// Whether an algorithm was named (`-newkey` was given).
    pub(crate) fn is_named(&self) -> bool {
        self.algorithm.is_some()
    }

    /// The algorithm the options name.
    ///
    /// # Errors
    ///
    /// No algorithm, an EC key without a curve, an unreadable parameters
    /// file, or an algorithm or curve baldssl does not implement.
    pub(crate) fn algorithm(&self, command: &str) -> Result<Algorithm> {
        match &self.algorithm {
            Some(Ok(KeyAlgorithm::Ec)) => {
                if let Some(file) = &self.parameters {
                    let bytes = read_input(Some(file))?;
                    let block =
                        pem::decode_first(&bytes, &[EC_PARAMETERS_LABEL])?;
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
            Some(Ok(KeyAlgorithm::Ed25519)) => match self.parameters {
                None => Ok(Algorithm::Ed25519),
                Some(_) => Err(Error::unsupported(format!(
                    "{command}: key algorithm ed25519 with parameters"
                ))),
            },
            Some(Err(UnknownAlgorithm(name))) => Err(Error::unsupported(
                format!("{command}: key algorithm {name}"),
            )),
            None => Err(Error::Usage(format!(
                "{command}: no algorithm given (EC or ED25519)"
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
