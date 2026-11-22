//! `baldssl x509`: the OpenSSL-compatible certificate display command.
//!
//! # Output order
//!
//! As in OpenSSL's `apps/x509.c`, each printing option is numbered when it is
//! seen (`text = ++num`) and the outputs are printed in increasing number. A
//! repeated option therefore prints once, at its last position, and `-dates`
//! counts as `-startdate -enddate`. The certificate itself (PEM, or DER with
//! `-outform DER`) is written last unless `-noout` is given.
//!
//! # Deviations from OpenSSL (intentional, documented in the README)
//!
//! * `-fingerprint` defaults to SHA-256 (OpenSSL: SHA-1). Pass `-sha1` for
//!   the OpenSSL behaviour.
//! * `-fingerprint <digest>` is accepted as well as OpenSSL's
//!   `-fingerprint -<digest>`.
//! * A missing input file exits with 2 (OpenSSL: 1).

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read},
};

use baldssl_core::{Error, Result, pem};
use baldssl_crypto::Algorithm;
use baldssl_x509::{
    Certificate, Format, certificate_der, fingerprint_line,
    text::{self, Compat},
};

use crate::args::{self, Kind, Spec};

/// Every option `baldssl x509` accepts, besides `-<digest>`.
pub const SPECS: &[Spec] = &[
    Spec {
        name: "help",
        kind: Kind::Flag,
        help: "Display this summary",
    },
    Spec {
        name: "in",
        kind: Kind::Value,
        help: "Certificate input file (default stdin)",
    },
    Spec {
        name: "inform",
        kind: Kind::Value,
        help: "Input format: PEM or DER (default: detect)",
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
        name: "noout",
        kind: Kind::Flag,
        help: "Do not output the certificate",
    },
    Spec {
        name: "text",
        kind: Kind::Flag,
        help: "Print the certificate in text form",
    },
    Spec {
        name: "subject",
        kind: Kind::Flag,
        help: "Print the subject",
    },
    Spec {
        name: "issuer",
        kind: Kind::Flag,
        help: "Print the issuer",
    },
    Spec {
        name: "serial",
        kind: Kind::Flag,
        help: "Print the serial number",
    },
    Spec {
        name: "startdate",
        kind: Kind::Flag,
        help: "Print the notBefore date",
    },
    Spec {
        name: "enddate",
        kind: Kind::Flag,
        help: "Print the notAfter date",
    },
    Spec {
        name: "dates",
        kind: Kind::Flag,
        help: "Print both dates",
    },
    Spec {
        name: "fingerprint",
        kind: Kind::Flag,
        help: "Print the fingerprint (default SHA-256; -sha1 for OpenSSL's)",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Print {
    Issuer,
    Subject,
    Serial,
    StartDate,
    EndDate,
    Fingerprint,
    Text,
}

/// Parsed `x509` invocation.
#[derive(Debug)]
struct Options {
    input: Option<OsString>,
    output: Option<OsString>,
    inform: Option<Format>,
    outform: Format,
    noout: bool,
    help: bool,
    /// `(sequence number, what)`, sorted before printing.
    prints: Vec<(usize, Print)>,
    digest: (Algorithm, String),
}

fn parse_format(value: &OsStr, option: &str) -> Result<Format> {
    match value.to_str().map(str::to_ascii_uppercase).as_deref() {
        Some("PEM") => Ok(Format::Pem),
        Some("DER") => Ok(Format::Der),
        _ => Err(Error::Usage(format!(
            "x509: Invalid format \"{}\" for option -{option}",
            value.to_string_lossy()
        ))),
    }
}

/// Digest names OpenSSL accepts that baldssl does not implement.
fn is_unimplemented_digest(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "md5"
            | "md4"
            | "sha512-224"
            | "sha512-256"
            | "sha3-224"
            | "sha3-256"
            | "sha3-384"
            | "sha3-512"
            | "shake128"
            | "shake256"
            | "sm3"
            | "ripemd160"
            | "blake2b512"
            | "blake2s256"
    )
}

/// The `-fingerprint <digest>` extension: rewrites it to OpenSSL's
/// `-fingerprint -<digest>`.
fn expand_fingerprint_value(args: &[OsString]) -> Vec<OsString> {
    let mut out = Vec::with_capacity(args.len());
    let mut it = args.iter().peekable();
    while let Some(arg) = it.next() {
        out.push(arg.clone());
        let is_fp =
            matches!(arg.to_str(), Some("-fingerprint" | "--fingerprint"));
        if is_fp
            && let Some(next) = it.peek().and_then(|n| n.to_str())
            && !next.starts_with('-')
            && Algorithm::from_name_opt(next).is_some()
        {
            out.push(OsString::from(format!("-{next}")));
            it.next();
        }
    }
    out
}

fn parse_options(raw: &[OsString]) -> Result<Options> {
    let raw = expand_fingerprint_value(raw);
    let opts = args::parse("x509", &raw, SPECS, |n| {
        Algorithm::from_name_opt(n).is_some() || is_unimplemented_digest(n)
    })?;
    let mut o = Options {
        input: None,
        output: None,
        inform: None,
        outform: Format::Pem,
        noout: false,
        help: false,
        prints: Vec::new(),
        digest: (Algorithm::Sha256, "sha256".to_string()),
    };
    let mut seq = 0usize;
    let mut mark = |o: &mut Options, p: Print| {
        seq = seq.saturating_add(1);
        o.prints.retain(|(_, q)| *q != p);
        o.prints.push((seq, p));
    };
    for opt in opts {
        let value = opt.value.clone().unwrap_or_default();
        match opt.name.as_str() {
            "help" => o.help = true,
            "in" => o.input = Some(value),
            "out" => o.output = Some(value),
            "inform" => o.inform = Some(parse_format(&value, "inform")?),
            "outform" => o.outform = parse_format(&value, "outform")?,
            "noout" => o.noout = true,
            "text" => mark(&mut o, Print::Text),
            "subject" => mark(&mut o, Print::Subject),
            "issuer" => mark(&mut o, Print::Issuer),
            "serial" => mark(&mut o, Print::Serial),
            "startdate" => mark(&mut o, Print::StartDate),
            "enddate" => mark(&mut o, Print::EndDate),
            "dates" => {
                mark(&mut o, Print::StartDate);
                mark(&mut o, Print::EndDate);
            }
            "fingerprint" => mark(&mut o, Print::Fingerprint),
            name => match Algorithm::from_name_opt(name) {
                Some(alg) => o.digest = (alg, name.to_string()),
                None => {
                    return Err(Error::unsupported(format!("digest {name}")));
                }
            },
        }
    }
    o.prints.sort_unstable();
    Ok(o)
}

fn read_input(path: Option<&OsStr>) -> Result<Vec<u8>> {
    match path {
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).map_err(|e| Error::Io {
                context: "reading stdin".into(),
                message: e.to_string(),
            })?;
            Ok(buf)
        }
        Some(p) => fs::read(p).map_err(|e| {
            let shown = p.to_string_lossy().into_owned();
            if e.kind() == io::ErrorKind::NotFound {
                Error::NotFound { path: shown }
            } else {
                Error::Io {
                    context: format!("reading {shown}"),
                    message: e.to_string(),
                }
            }
        }),
    }
}

/// The environment variable selecting the OpenSSL release line to imitate.
pub const COMPAT_ENV: &str = "BALDSSL_OPENSSL_COMPAT";

/// Reads [`COMPAT_ENV`]: `3` (default), `3.0` or `4`.
fn compat() -> Result<Compat> {
    match std::env::var(COMPAT_ENV) {
        Err(_) => Ok(Compat::default()),
        Ok(v) => Compat::from_version_opt(&v).ok_or_else(|| {
            Error::Usage(format!(
                "{COMPAT_ENV}: expected 3.0, 3 or 4, got {v:?}"
            ))
        }),
    }
}

/// Renders everything `x509` writes to its output.
///
/// # Errors
///
/// Usage, decoding, or unsupported-feature errors.
pub fn render(raw: &[OsString]) -> Result<(Vec<u8>, Option<OsString>)> {
    let o = parse_options(raw)?;
    let compat = compat()?;
    if o.help {
        return Ok((args::usage("x509", SPECS).into_bytes(), None));
    }
    let input = read_input(o.input.as_deref())?;
    let der = certificate_der(&input, o.inform)?;
    let cert = Certificate::from_der(&der)?;

    let mut out = Vec::new();
    for (_, p) in &o.prints {
        match p {
            Print::Issuer => {
                out.extend_from_slice(b"issuer=");
                out.extend_from_slice(
                    &cert.issuer.to_openssl(compat.name_style())?,
                );
                out.push(b'\n');
            }
            Print::Subject => {
                out.extend_from_slice(b"subject=");
                out.extend_from_slice(
                    &cert.subject.to_openssl(compat.name_style())?,
                );
                out.push(b'\n');
            }
            Print::Serial => {
                out.extend_from_slice(
                    text::serial_line(&cert.serial).as_bytes(),
                );
            }
            Print::StartDate => {
                let t = text::time_rfc822(&cert.validity.not_before);
                out.extend_from_slice(format!("notBefore={t}\n").as_bytes());
            }
            Print::EndDate => {
                let t = text::time_rfc822(&cert.validity.not_after);
                out.extend_from_slice(format!("notAfter={t}\n").as_bytes());
            }
            Print::Fingerprint => {
                let (alg, label) = &o.digest;
                out.extend_from_slice(
                    fingerprint_line(cert.der, *alg, label).as_bytes(),
                );
            }
            Print::Text => {
                out.extend_from_slice(&text::print_text(&cert, compat)?);
            }
        }
    }
    if !o.noout {
        match o.outform {
            Format::Pem => {
                out.extend_from_slice(
                    pem::encode("CERTIFICATE", cert.der).as_bytes(),
                );
            }
            Format::Der => out.extend_from_slice(cert.der),
        }
    }
    Ok((out, o.output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn prints(v: &[&str]) -> Vec<Print> {
        parse_options(&os(v))
            .unwrap()
            .prints
            .into_iter()
            .map(|(_, p)| p)
            .collect()
    }

    #[test]
    fn order_follows_last_occurrence() {
        assert_eq!(
            prints(&["-enddate", "-subject"]),
            [Print::EndDate, Print::Subject]
        );
        assert_eq!(
            prints(&["-subject", "-enddate", "-subject"]),
            [Print::EndDate, Print::Subject]
        );
        assert_eq!(
            prints(&["-dates", "-serial"]),
            [Print::StartDate, Print::EndDate, Print::Serial]
        );
    }

    #[test]
    fn unimplemented_digests_are_named() {
        assert!(is_unimplemented_digest("MD5"));
        assert!(is_unimplemented_digest("sha3-256"));
        assert!(!is_unimplemented_digest("sha256"));
        assert!(!is_unimplemented_digest("text"));
    }

    #[test]
    fn help_lists_every_option() {
        let (out, path) = render(&os(&["-help"])).unwrap();
        assert!(path.is_none());
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("Usage: baldssl x509 [options]\n"));
        for spec in SPECS {
            assert!(
                text.contains(&format!(" -{}", spec.name)),
                "{}",
                spec.name
            );
        }
        assert!(text.contains(" -in val"));
    }

    #[test]
    fn digests() {
        let o = parse_options(&os(&["-fingerprint"])).unwrap();
        assert_eq!(o.digest, (Algorithm::Sha256, "sha256".into()));
        let o = parse_options(&os(&["-SHA384", "-fingerprint"])).unwrap();
        assert_eq!(o.digest, (Algorithm::Sha384, "SHA384".into()));
        let o = parse_options(&os(&["-fingerprint", "sha1"])).unwrap();
        assert_eq!(o.digest, (Algorithm::Sha1, "sha1".into()));
        assert!(matches!(
            parse_options(&os(&["-md5"])),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            parse_options(&os(&["-inform", "XML"])),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            parse_options(&os(&["-fingerprint", "x"])),
            Err(Error::Usage(_))
        ));
    }
}
