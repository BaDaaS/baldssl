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
//!
//! # Signing requests
//!
//! `-req` reads a certificate request instead of a certificate, checks its
//! signature (printing "Certificate request self-signature ok" and its
//! subject on standard error, as OpenSSL does) and signs a certificate for
//! it with `-CA` and `-CAkey` (the key defaults to the `-CA` file, as in
//! OpenSSL), with the extensions of the release line
//! `BALDSSL_OPENSSL_COMPAT` names (see
//! [`baldssl_x509::CertificateTemplate::issued`]). The serial number is
//! `-set_serial`, or the next one of the serial file (`-CAserial`, or with
//! `-CAcreateserial` the `-CA` file name with `.srl`), or 159 random bits;
//! the validity is `-days` (30 by default), `-not_before` and `-not_after`.
//! The printing options then apply to the new certificate. Not supported:
//! `-req` without `-CA` (`-key`, self-signing), `-CA` without `-req`,
//! `-extfile`, `-extensions` and `-copy_extensions`.

use std::{ffi::OsString, io::Write as _};

use baldssl_core::{Error, Result, pem};
use baldssl_crypto::Algorithm;
use baldssl_x509::{
    Certificate, CertificateTemplate, Compat, Format, certificate_der,
    fingerprint_line, print_text, serial_line, time_rfc822,
};

use crate::{
    args::{self, Kind, Spec},
    input::{parse_format, read_input, read_key, read_request},
    issuing::{
        Lifetime, SerialSource, default_serial_file, parse_serial, parse_time,
        signature_algorithm,
    },
};

/// Every option `baldssl x509` accepts, besides `-<digest>`.
pub(crate) const SPECS: &[Spec] = &[
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
    Spec {
        name: "req",
        kind: Kind::Flag,
        help: "Input is a certificate request, to sign with -CA",
    },
    Spec {
        name: "CA",
        kind: Kind::Value,
        help: "CA certificate that signs the request",
    },
    Spec {
        name: "CAform",
        kind: Kind::Value,
        help: "CA certificate format: PEM or DER (default: detect)",
    },
    Spec {
        name: "CAkey",
        kind: Kind::Value,
        help: "CA private key (default: the -CA file)",
    },
    Spec {
        name: "CAkeyform",
        kind: Kind::Value,
        help: "CA private key format: PEM or DER (default: detect)",
    },
    Spec {
        name: "CAserial",
        kind: Kind::Value,
        help: "Serial file, read, incremented and written back",
    },
    Spec {
        name: "CAcreateserial",
        kind: Kind::Flag,
        help: "Create the serial file if it does not exist",
    },
    Spec {
        name: "set_serial",
        kind: Kind::Value,
        help: "Serial number of the certificate",
    },
    Spec {
        name: "days",
        kind: Kind::Value,
        help: "Days the certificate is valid for (default 30)",
    },
    Spec {
        name: "not_before",
        kind: Kind::Value,
        help: "Start of validity: YYMMDDHHMMSSZ, YYYYMMDDHHMMSSZ or today",
    },
    Spec {
        name: "not_after",
        kind: Kind::Value,
        help: "End of validity, overriding -days: as -not_before",
    },
    Spec {
        name: "key",
        kind: Kind::Value,
        help: "Self-sign with this key (not supported yet)",
    },
];

/// What the input is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Source {
    /// A certificate, to print.
    #[default]
    Certificate,
    /// A request, to sign with a CA (`-req`).
    Request,
}

/// The options of `-req`.
#[derive(Debug, Default)]
struct Signing {
    /// `-CA`.
    ca: Option<OsString>,
    /// `-CAform`.
    ca_form: Option<Format>,
    /// `-CAkey`.
    ca_key: Option<OsString>,
    /// `-CAkeyform`.
    ca_key_form: Option<Format>,
    /// `-CAserial`.
    ca_serial: Option<OsString>,
    /// `-CAcreateserial`.
    create_serial: bool,
    /// `-set_serial`.
    serial: Option<baldssl_x509::SerialNumber>,
    /// `-days`, `-not_before`, `-not_after`.
    lifetime: Lifetime,
    /// The `-<digest>` option, when one is given.
    digest: Option<Algorithm>,
}

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
    source: Source,
    signing: Signing,
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
        source: Source::default(),
        signing: Signing::default(),
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
            "inform" => {
                o.inform = Some(parse_format(&value, "x509", "inform")?);
            }
            "outform" => o.outform = parse_format(&value, "x509", "outform")?,
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
            "req" => o.source = Source::Request,
            "CA" => o.signing.ca = Some(value),
            "CAform" => {
                o.signing.ca_form =
                    Some(parse_format(&value, "x509", "CAform")?);
            }
            "CAkey" => o.signing.ca_key = Some(value),
            "CAkeyform" => {
                o.signing.ca_key_form =
                    Some(parse_format(&value, "x509", "CAkeyform")?);
            }
            "CAserial" => o.signing.ca_serial = Some(value),
            "CAcreateserial" => o.signing.create_serial = true,
            "set_serial" => {
                o.signing.serial = Some(parse_serial("x509", &value)?);
            }
            "days" => o.signing.lifetime.set_days("x509", &value)?,
            "not_before" => {
                o.signing.lifetime.not_before =
                    Some(parse_time("x509", "not_before", &value)?);
            }
            "not_after" => {
                o.signing.lifetime.not_after =
                    Some(parse_time("x509", "not_after", &value)?);
            }
            "key" => return Err(Error::unsupported("x509 -key")),
            name => match Algorithm::from_name_opt(name) {
                Some(alg) => {
                    o.digest = (alg, name.to_string());
                    o.signing.digest = Some(alg);
                }
                None => {
                    return Err(Error::unsupported(format!("digest {name}")));
                }
            },
        }
    }
    o.prints.sort_unstable();
    match (o.source, o.signing.ca.is_some()) {
        (Source::Request, false) => {
            return Err(Error::unsupported("x509 -req without -CA (-key)"));
        }
        (Source::Certificate, true) => {
            return Err(Error::unsupported("x509 -CA without -req"));
        }
        _ => {}
    }
    Ok(o)
}

/// Where the serial number comes from: `-set_serial`, the serial file, or
/// random bits.
fn serial_source(s: &Signing) -> SerialSource {
    match (&s.serial, &s.ca_serial, &s.ca) {
        (Some(serial), _, _) => SerialSource::Given(serial.clone()),
        (None, Some(path), _) => SerialSource::File {
            path: path.into(),
            create: s.create_serial,
        },
        (None, None, Some(ca)) if s.create_serial => SerialSource::File {
            path: default_serial_file(ca),
            create: true,
        },
        _ => SerialSource::Random,
    }
}

/// Writes `line` and a newline on standard error.
fn note(line: &[u8]) {
    let mut err = std::io::stderr();
    // Nothing to do if standard error is gone.
    let _ = err.write_all(line).and_then(|()| err.write_all(b"\n"));
}

/// The certificate `-req` signs: the request of the input, checked, then
/// signed by the CA. Prints what OpenSSL prints on standard error.
fn issue(o: &Options, compat: Compat) -> Result<Vec<u8>> {
    let s = &o.signing;
    let request = read_request(o.input.as_deref(), o.inform)?;
    if !request.verify() {
        if compat != Compat::V30 {
            note(b"Warning: CSR self-signature does not match the contents");
        }
        note(b"Certificate request self-signature did not match the contents");
        return Err(Error::invalid(
            "certificate request self-signature did not match the contents",
        ));
    }
    note(b"Certificate request self-signature ok");
    let mut subject = b"subject=".to_vec();
    subject.extend_from_slice(
        &request.subject_name()?.to_openssl(compat.name_style())?,
    );
    note(&subject);
    let ca_path = s
        .ca
        .as_deref()
        .ok_or_else(|| Error::unsupported("x509 -req without -CA (-key)"))?;
    let ca_der = certificate_der(&read_input(Some(ca_path))?, s.ca_form)?;
    let ca = Certificate::from_der(&ca_der)?;
    let ca_key =
        read_key(s.ca_key.as_deref().unwrap_or(ca_path), s.ca_key_form)?;
    if !ca.matches_private_key(&ca_key) {
        note(b"CA certificate and CA private key do not match");
        return Err(Error::invalid(
            "CA certificate and CA private key do not match",
        ));
    }
    if s.digest == Some(Algorithm::Sha1) {
        return Err(Error::unsupported("x509 -req: digest sha1"));
    }
    CertificateTemplate::issued(
        &request,
        &ca,
        &ca_key,
        serial_source(s).next("x509")?,
        s.lifetime.validity("x509")?,
        compat,
    )?
    .sign(&ca_key, signature_algorithm(&ca_key, s.digest))
}

/// The environment variable selecting the OpenSSL release line to imitate.
pub(crate) const COMPAT_ENV: &str = "BALDSSL_OPENSSL_COMPAT";

/// Reads [`COMPAT_ENV`]: `3` (default), `3.0` or `4`.
pub(crate) fn compat() -> Result<Compat> {
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
pub(crate) fn render(raw: &[OsString]) -> Result<(Vec<u8>, Option<OsString>)> {
    let o = parse_options(raw)?;
    let compat = compat()?;
    if o.help {
        return Ok((args::usage("x509", SPECS).into_bytes(), None));
    }
    let der = match o.source {
        Source::Request => issue(&o, compat)?,
        Source::Certificate => {
            certificate_der(&read_input(o.input.as_deref())?, o.inform)?
        }
    };
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
                out.extend_from_slice(serial_line(&cert.serial).as_bytes());
            }
            Print::StartDate => {
                let t = time_rfc822(&cert.validity.not_before);
                out.extend_from_slice(format!("notBefore={t}\n").as_bytes());
            }
            Print::EndDate => {
                let t = time_rfc822(&cert.validity.not_after);
                out.extend_from_slice(format!("notAfter={t}\n").as_bytes());
            }
            Print::Fingerprint => {
                let (alg, label) = &o.digest;
                out.extend_from_slice(
                    fingerprint_line(cert.der, *alg, label).as_bytes(),
                );
            }
            Print::Text => {
                out.extend_from_slice(&print_text(&cert, compat)?);
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

    /// `-req` takes `-CA`, `-CA` takes `-req`, and the serial comes from
    /// `-set_serial`, the serial file, or random bits, in that order.
    #[test]
    fn signing_options() {
        let o = parse_options(&os(&[
            "-req", "-CA", "ca.crt", "-days", "90", "-sha384",
        ]))
        .unwrap();
        assert_eq!(o.source, Source::Request);
        assert_eq!(o.signing.lifetime.days, 90);
        assert_eq!(o.signing.digest, Some(Algorithm::Sha384));
        assert_eq!(serial_source(&o.signing), SerialSource::Random);
        let o =
            parse_options(&os(&["-req", "-CA", "ca.crt", "-CAcreateserial"]))
                .unwrap();
        assert_eq!(
            serial_source(&o.signing),
            SerialSource::File {
                path: "ca.srl".into(),
                create: true
            }
        );
        let o = parse_options(&os(&[
            "-req",
            "-CA",
            "ca.crt",
            "-CAserial",
            "s.srl",
            "-set_serial",
            "5",
        ]))
        .unwrap();
        assert!(matches!(
            serial_source(&o.signing),
            SerialSource::Given(s) if s.as_be_bytes() == [5]
        ));
        for refused in [&["-req"][..], &["-CA", "ca.crt"], &["-key", "k.pem"]] {
            assert!(
                matches!(
                    parse_options(&os(refused)),
                    Err(Error::Unsupported(_))
                ),
                "{refused:?}"
            );
        }
    }
}
