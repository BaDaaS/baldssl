//! `baldssl genpkey`: generate a private key, written as PKCS#8 like
//! `openssl genpkey`.
//!
//! Supported: `-algorithm EC` with `-pkeyopt ec_paramgen_curve:<curve>` for
//! P-256 (`prime256v1`), P-384 (`secp384r1`) and P-521 (`secp521r1`), and
//! `-algorithm ED25519`; `-out`, `-outform PEM|DER`. Algorithm names are
//! case-insensitive, as in OpenSSL. Anything else (RSA, X25519, encryption
//! with a cipher, `-text`, parameter files) is reported as unsupported.

use std::ffi::OsString;

use baldssl_core::{Error, Result, encoding::Encodable, pem::Pem};
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::Format;

use crate::{
    args::{self, Kind, Spec},
    input::parse_format,
    keygen::KeyParameters,
};

/// Every option `baldssl genpkey` accepts.
pub(crate) const SPECS: &[Spec] = &[
    Spec {
        name: "help",
        kind: Kind::Flag,
        help: "Display this summary",
    },
    Spec {
        name: "algorithm",
        kind: Kind::Value,
        help: "The key algorithm: EC or ED25519",
    },
    Spec {
        name: "pkeyopt",
        kind: Kind::Value,
        help: "Algorithm option, e.g. ec_paramgen_curve:P-256",
    },
    Spec {
        name: "out",
        kind: Kind::Value,
        help: "Output file (default stdout)",
    },
    Spec {
        name: "outform",
        kind: Kind::Value,
        help: "Output format: PEM or DER (default PEM)",
    },
    Spec {
        name: "text",
        kind: Kind::Flag,
        help: "Print the key in text form (not supported yet)",
    },
];

/// Renders the generated key, and where to write it.
///
/// # Errors
///
/// Usage errors, unsupported algorithms or options, and randomness errors.
pub(crate) fn render(raw: &[OsString]) -> Result<(Vec<u8>, Option<OsString>)> {
    let opts = args::parse("genpkey", raw, SPECS, |_| false)?;
    let mut parameters = KeyParameters::default();
    let mut output = None;
    let mut der = false;
    for opt in opts {
        let value = opt.value.clone().unwrap_or_default();
        match opt.name.as_str() {
            "help" => {
                return Ok((args::usage("genpkey", SPECS).into_bytes(), None));
            }
            "algorithm" => parameters.set_algorithm("genpkey", &value)?,
            "pkeyopt" => parameters.pkeyopt("genpkey", &value)?,
            "out" => output = Some(value),
            "outform" => {
                der =
                    parse_format(&value, "genpkey", "outform")? == Format::Der;
            }
            "text" => return Err(Error::unsupported("genpkey -text")),
            _ => {}
        }
    }
    let algorithm = parameters.algorithm("genpkey")?;
    let key = AnyPrivateKey::generate(algorithm)?;
    let bytes = if der {
        key.encode()
    } else {
        key.to_pem().into_bytes()
    };
    Ok((bytes, output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn outputs() {
        let (pem, out) = render(&os(&["-algorithm", "ed25519"])).unwrap();
        assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
        assert!(out.is_none());
        let (der, _) = render(&os(&[
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-384",
            "-outform",
            "DER",
        ]))
        .unwrap();
        assert_eq!(der.first(), Some(&0x30));
    }

    #[test]
    fn errors() {
        for (args, usage) in [
            (&["-algorithm", "EC"][..], true),
            (&[][..], true),
            (&["-algorithm", "RSA"][..], false),
            (
                &[
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:secp256r1",
                ][..],
                false,
            ),
            (&["-algorithm", "ED25519", "-text"][..], false),
            (&["-algorithm", "ED25519", "-pkeyopt", "x:y"][..], false),
        ] {
            let err = render(&os(args)).unwrap_err();
            assert_eq!(
                matches!(err, Error::Usage(_)),
                usage,
                "{args:?}: {err:?}"
            );
        }
    }
}
