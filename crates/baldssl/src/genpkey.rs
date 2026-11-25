//! `baldssl genpkey`: generate a private key, written as PKCS#8 like
//! `openssl genpkey`.
//!
//! Supported: `-algorithm EC` with `-pkeyopt ec_paramgen_curve:<curve>` for
//! P-256 (`prime256v1`), P-384 (`secp384r1`) and P-521 (`secp521r1`), and
//! `-algorithm ED25519`; `-out`, `-outform PEM|DER` (in DER, the form
//! [`Compat::generated_key_der`](baldssl_x509::Compat::generated_key_der)
//! names for the release line), and `-text`, which follows the key with its
//! text as `pkey -text` prints it, to the same output, as `apps/genpkey.c`
//! does with `EVP_PKEY_print_private`.
//! Algorithm names are case-insensitive, as in OpenSSL. The key file is
//! created readable by its owner only, as `apps/genpkey.c` opens it with
//! `bio_open_owner`. Anything else (RSA, X25519, encryption with a cipher,
//! parameter files) is reported as unsupported.

use std::ffi::OsString;

use baldssl_core::{Result, pem::Pem};
use baldssl_fs::Access;
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{Format, print_private_key_text};

use crate::{
    args::{self, Kind, Spec, Unknown},
    input::{compat, format_value},
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
        help: "Print the key in text form after it",
    },
];

/// Whether the key is followed by its text. `-text` only moves it up: no
/// option clears it, as in `apps/genpkey.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Text {
    /// The key alone.
    Nothing,
    /// The key, then its text (`-text`).
    Printed,
}

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
    let mut text = Text::Nothing;
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
            Opt::Text => text = text.max(Text::Printed),
        }
    }
    let compat = compat()?;
    let key = AnyPrivateKey::generate(parameters.algorithm(COMMAND)?)?;
    let mut bytes = match format {
        Format::Der => key.der(compat.generated_key_der()).expose().to_vec(),
        Format::Pem => key.to_pem().into_bytes(),
    };
    match text {
        Text::Nothing => {}
        Text::Printed => {
            bytes.extend(print_private_key_text(&key, compat)?);
        }
    }
    out.output(output.as_deref(), Access::OwnerOnly, bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use baldssl_core::{Error, der::parse_tlv, encoding::Decodable as _};

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

    /// `-text` follows the key with the text of the key written, in PEM and
    /// in DER, and giving it twice changes nothing.
    #[test]
    fn text() {
        let compat = compat().unwrap();
        for alg in [
            &["-algorithm", "ED25519"][..],
            &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"],
        ] {
            for text in [&["-text"][..], &["-text", "-text"]] {
                let pem = run_to_outputs(&[alg, text].concat()).unwrap();
                let pem = pem.stdout_bytes();
                let key = AnyPrivateKey::from_pem(&pem).unwrap();
                let expected = [
                    key.to_pem().into_bytes(),
                    print_private_key_text(&key, compat).unwrap(),
                ]
                .concat();
                assert_eq!(pem, expected);

                let der =
                    run_to_outputs(&[alg, text, &["-outform", "DER"]].concat())
                        .unwrap();
                let der = der.stdout_bytes();
                let (_, len) = parse_tlv(&der).unwrap();
                let key = AnyPrivateKey::decode(&der[..len]).unwrap();
                let expected = [
                    key.der(compat.generated_key_der()).expose().to_vec(),
                    print_private_key_text(&key, compat).unwrap(),
                ]
                .concat();
                assert_eq!(der, expected);
            }
        }
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
