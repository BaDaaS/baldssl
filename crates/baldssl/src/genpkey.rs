//! `baldssl genpkey`: generate a private key, written as PKCS#8 like
//! `openssl genpkey`.
//!
//! Supported: `-algorithm EC` with `-pkeyopt ec_paramgen_curve:<curve>` for
//! P-256 (`prime256v1`), P-384 (`secp384r1`) and P-521 (`secp521r1`), and
//! `-algorithm ED25519`; `-out`, `-outform PEM|DER`. Algorithm names are
//! case-insensitive, as in OpenSSL. The key file is created readable by its
//! owner only, as `apps/genpkey.c` opens it with `bio_open_owner`. Anything
//! else (RSA, X25519, encryption with a cipher, `-text`, parameter files)
//! is reported as unsupported.

use std::ffi::OsString;

use baldssl_core::{Result, pem::Pem};
use baldssl_fs::Access;
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::Format;

use crate::{
    args::{self, Kind, Spec, Unknown},
    input::format_value,
    keygen::KeyParameters,
    outputs::Outputs,
};

/// The name of the command.
const COMMAND: &str = "genpkey";

/// An option of `baldssl genpkey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Opt {
    /// `-help`.
    Help,
    /// `-algorithm`.
    Algorithm(OsString),
    /// `-pkeyopt`.
    Pkeyopt(OsString),
    /// `-out`.
    Out(OsString),
    /// `-outform`.
    Outform(OsString),
    /// `-text`.
    Text,
}

/// Every option `baldssl genpkey` accepts.
pub(crate) const SPECS: &[Spec<Opt>] = &[
    Spec {
        name: "help",
        kind: Kind::Flag(Opt::Help),
        help: "Display this summary",
    },
    Spec {
        name: "algorithm",
        kind: Kind::Value(Opt::Algorithm),
        help: "The key algorithm: EC or ED25519",
    },
    Spec {
        name: "pkeyopt",
        kind: Kind::Value(Opt::Pkeyopt),
        help: "Algorithm option, e.g. ec_paramgen_curve:P-256",
    },
    Spec {
        name: "out",
        kind: Kind::Value(Opt::Out),
        help: "Output file (default stdout)",
    },
    Spec {
        name: "outform",
        kind: Kind::Value(Opt::Outform),
        help: "Output format: PEM or DER (default PEM)",
    },
    Spec {
        name: "text",
        kind: Kind::Flag(Opt::Text),
        help: "Print the key in text form (not supported)",
    },
];

/// Generates the key, and records where it is written.
///
/// # Errors
///
/// Usage errors, unsupported algorithms or options, and randomness errors.
pub(crate) fn run(raw: &[OsString], out: &mut Outputs) -> Result<()> {
    let opts = args::parse(COMMAND, raw, SPECS, Unknown::Refused)?;
    let mut parameters = KeyParameters::default();
    let mut output = None;
    let mut format = Format::Pem;
    for given in opts {
        match given.option {
            Opt::Help => {
                out.stdout(args::usage(COMMAND, SPECS));
                return Ok(());
            }
            Opt::Algorithm(v) => parameters.set_algorithm(COMMAND, &v)?,
            Opt::Pkeyopt(v) => parameters.pkeyopt(COMMAND, &v)?,
            Opt::Out(v) => output = Some(v),
            Opt::Outform(v) => format = format_value(&v, COMMAND, "outform")?,
            Opt::Text => {
                return Err(baldssl_core::Error::unsupported("genpkey -text"));
            }
        }
    }
    let key = AnyPrivateKey::generate(parameters.algorithm(COMMAND)?)?;
    let bytes = match format {
        Format::Der => key.pkcs8().expose().to_vec(),
        Format::Pem => key.to_pem().into_bytes(),
    };
    out.output(output.as_deref(), Access::OwnerOnly, bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use baldssl_core::Error;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn run_to_outputs(v: &[&str]) -> Result<Outputs> {
        let mut out = Outputs::default();
        run(&os(v), &mut out).map(|()| out)
    }

    #[test]
    fn outputs() {
        let pem = run_to_outputs(&["-algorithm", "ed25519"]).unwrap();
        assert!(
            pem.stdout_bytes()
                .starts_with(b"-----BEGIN PRIVATE KEY-----\n")
        );
        let der = run_to_outputs(&[
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-384",
            "-outform",
            "der",
        ])
        .unwrap();
        assert_eq!(der.stdout_bytes().first(), Some(&0x30));
        let file = run_to_outputs(&["-algorithm", "ED25519", "-out", "k.pem"])
            .unwrap();
        assert!(matches!(
            file.effects(),
            [crate::outputs::Effect::File {
                access: Access::OwnerOnly,
                ..
            }]
        ));
    }

    #[test]
    fn errors() {
        for (args, usage) in [
            (&["-algorithm", "EC"][..], true),
            (&[][..], true),
            (&["-algorithm", "ED25519", "-outform", "XML"][..], true),
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
            let err = run_to_outputs(args).unwrap_err();
            assert_eq!(
                matches!(err, Error::Usage(_)),
                usage,
                "{args:?}: {err:?}"
            );
        }
    }
}
