//! `baldssl genpkey`: generate a private key, written as PKCS#8 like
//! `openssl genpkey`.
//!
//! Supported: `-algorithm EC` with `-pkeyopt ec_paramgen_curve:<curve>` for
//! P-256 (`prime256v1`), P-384 (`secp384r1`) and P-521 (`secp521r1`), and
//! `-algorithm ED25519`; `-out`, `-outform PEM|DER`. Algorithm names are
//! case-insensitive, as in OpenSSL. Anything else (RSA, X25519, encryption
//! with a cipher, `-text`, parameter files) is reported as unsupported.

use std::ffi::{OsStr, OsString};

use baldssl_core::{Error, Result, encoding::Encodable, pem::Pem};
use baldssl_pkey::{Algorithm, AnyPrivateKey};

use crate::args::{self, Kind, Spec};

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

/// The curve for an `ec_paramgen_curve` value, by its NIST or OpenSSL name.
/// OpenSSL does not accept `secp256r1`, so neither does this.
fn curve_opt(name: &str) -> Option<Algorithm> {
    match name.to_ascii_lowercase().as_str() {
        "p-256" | "prime256v1" => Some(Algorithm::P256),
        "p-384" | "secp384r1" => Some(Algorithm::P384),
        "p-521" | "secp521r1" => Some(Algorithm::P521),
        _ => None,
    }
}

fn utf8<'a>(value: &'a OsStr, option: &str) -> Result<&'a str> {
    value
        .to_str()
        .ok_or_else(|| Error::Usage(format!("genpkey: -{option}: not UTF-8")))
}

/// Renders the generated key, and where to write it.
///
/// # Errors
///
/// Usage errors, unsupported algorithms or options, and randomness errors.
pub(crate) fn render(raw: &[OsString]) -> Result<(Vec<u8>, Option<OsString>)> {
    let opts = args::parse("genpkey", raw, SPECS, |_| false)?;
    let mut algorithm: Option<String> = None;
    let mut curve_name: Option<String> = None;
    let mut output = None;
    let mut der = false;
    for opt in opts {
        let value = opt.value.clone().unwrap_or_default();
        match opt.name.as_str() {
            "help" => {
                return Ok((args::usage("genpkey", SPECS).into_bytes(), None));
            }
            "algorithm" => {
                algorithm =
                    Some(utf8(&value, "algorithm")?.to_ascii_uppercase());
            }
            "pkeyopt" => {
                let v = utf8(&value, "pkeyopt")?;
                match v.split_once(':') {
                    Some(("ec_paramgen_curve" | "group", name)) => {
                        curve_name = Some(name.to_string());
                    }
                    Some(("ec_param_enc", "named_curve")) => {}
                    _ => {
                        return Err(Error::unsupported(format!(
                            "genpkey -pkeyopt {v}"
                        )));
                    }
                }
            }
            "out" => output = Some(value),
            "outform" => {
                match utf8(&value, "outform")?.to_ascii_uppercase().as_str() {
                    "PEM" => der = false,
                    "DER" => der = true,
                    other => {
                        return Err(Error::Usage(format!(
                            "genpkey: Invalid format \"{other}\" for option -outform"
                        )));
                    }
                }
            }
            "text" => return Err(Error::unsupported("genpkey -text")),
            _ => {}
        }
    }
    let algorithm = match algorithm.as_deref() {
        Some("EC") => {
            let name = curve_name.ok_or_else(|| {
                Error::Usage(
                    "genpkey: EC needs -pkeyopt ec_paramgen_curve:<curve>"
                        .into(),
                )
            })?;
            curve_opt(&name).ok_or_else(|| {
                Error::unsupported(format!("genpkey: EC curve {name}"))
            })?
        }
        Some("ED25519") => Algorithm::Ed25519,
        Some(other) => {
            return Err(Error::unsupported(format!(
                "genpkey -algorithm {other}"
            )));
        }
        None => {
            return Err(Error::Usage(
                "genpkey: no algorithm given (-algorithm EC or ED25519)".into(),
            ));
        }
    };
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
    fn curve_names() {
        assert_eq!(curve_opt("P-256"), Some(Algorithm::P256));
        assert_eq!(curve_opt("prime256v1"), Some(Algorithm::P256));
        assert_eq!(curve_opt("secp384r1"), Some(Algorithm::P384));
        assert_eq!(curve_opt("p-521"), Some(Algorithm::P521));
        assert_eq!(curve_opt("secp256r1"), None);
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
