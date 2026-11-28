//! `baldssl x509`: the OpenSSL-compatible certificate display command.
//!
//! # Output order
//!
//! As in OpenSSL's `apps/x509.c`, each printing option is numbered when it is
//! seen (`text = ++num`) and the outputs are printed in increasing number. A
//! repeated option therefore prints once, at its last position, and `-dates`
//! counts as `-startdate -enddate`. baldssl keeps the printing options in a
//! list, moving one seen again to the end, which is that order. The certificate itself (PEM, or DER with
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
//! OpenSSL). Its extensions are, in order: the request's that
//! `-copy_extensions` copies (`none` by default, `copy`, `copyall`), then
//! those of a section of `-extfile` (`-extensions`, or the `extensions`
//! value of the default section, or the default section; each replacing
//! one of its kind, which then comes after the others), then the key
//! identifiers OpenSSL adds, by the release line baldssl is built for
//! (see [`baldssl_x509::CertificateTemplate::issued`]). The serial
//! number is
//! `-set_serial`, or the next one of the serial file (`-CAserial`, or with
//! `-CAcreateserial` the `-CA` file name with `.srl`), or 159 random bits;
//! the validity is `-days` (30 by default, `DEFAULT_DAYS` in `apps/x509.c`),
//! `-not_before` and `-not_after`.
//! The printing options then apply to the new certificate. Not supported:
//! `-key` (self-signing), `-CA` without `-req`, and the configuration file
//! syntax [`baldssl_x509::Config`] does not read.

use std::ffi::{OsStr, OsString};

use baldssl_core::{Error, Result, pem, text::Text as _};
use baldssl_crypto::Algorithm;
use baldssl_fs::Access;
use baldssl_x509::{
    Certificate, CertificateTemplate, Compat, Config, CopyExtensions,
    CsrSignatureWarning, ExtensionFile, Extensions, ExtensionsWithoutFile,
    Format, IssuedExtensions, SerialNumber, certificate_der, fingerprint_line,
    serial_line, time_rfc822,
};

use crate::{
    args::{self, Kind, Spec, Unknown},
    digest::DigestName,
    input::{OutputForm, format_value, read_input, read_key, read_request},
    issuing::{
        Lifetime, MissingSerialFile, SerialSource, default_serial_file,
        set_serial, signature_algorithm, signing_digest_opt, validity_time,
    },
    keygen::utf8,
    line::compat,
    outputs::Outputs,
};

/// The name of the command.
const COMMAND: &str = "x509";

/// What OpenSSL's `apps/x509.c` (and, for one, `apps/lib/apps.c`) prints on
/// standard error, and the prefixes of the printing options' lines.
mod message {
    /// `-extensions` without `-extfile`, in 3.x.
    pub(super) const EXTENSIONS_IGNORED: &str =
        "Warning: ignoring -extensions option without -extfile";
    /// A section of the extension file that does not hold extensions,
    /// before its name.
    pub(super) const EXTENSION_SECTION: &str =
        "Error checking extension section";
    /// `load_csr` in `apps/lib/apps.c`, from 3.2, for a request whose
    /// signature does not match.
    pub(super) const CSR_SIGNATURE_WARNING: &str =
        "Warning: CSR self-signature does not match the contents";
    /// A request whose signature does not match.
    pub(super) const REQUEST_MISMATCH: &str =
        "Certificate request self-signature did not match the contents";
    /// A request whose signature matches.
    pub(super) const REQUEST_OK: &str = "Certificate request self-signature ok";
    /// A CA certificate whose key is not `-CAkey`.
    pub(super) const CA_KEY_MISMATCH: &str =
        "CA certificate and CA private key do not match";
    /// Before the subject (`-subject`, and after a request is checked).
    pub(super) const SUBJECT: &str = "subject=";
    /// Before the issuer (`-issuer`).
    pub(super) const ISSUER: &str = "issuer=";
    /// Before the start of validity (`-startdate`).
    pub(super) const NOT_BEFORE: &str = "notBefore=";
    /// Before the end of validity (`-enddate`).
    pub(super) const NOT_AFTER: &str = "notAfter=";
}

/// An option of `baldssl x509`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Opt {
    /// `-help`.
    Help,
    /// `-in`.
    In(OsString),
    /// `-inform`.
    Inform(OsString),
    /// `-out`.
    Out(OsString),
    /// `-outform`.
    Outform(OsString),
    /// `-noout`.
    Noout,
    /// `-text`, `-subject` and the other printing options.
    Print(Print),
    /// `-dates`: `-startdate -enddate`.
    Dates,
    /// `-req`.
    Req,
    /// `-CA`.
    Ca(OsString),
    /// `-CAform`.
    CaForm(OsString),
    /// `-CAkey`.
    CaKey(OsString),
    /// `-CAkeyform`.
    CaKeyForm(OsString),
    /// `-CAserial`.
    CaSerial(OsString),
    /// `-CAcreateserial`.
    CaCreateSerial,
    /// `-set_serial`.
    SetSerial(OsString),
    /// `-days`.
    Days(OsString),
    /// `-not_before`.
    NotBefore(OsString),
    /// `-not_after`.
    NotAfter(OsString),
    /// `-extfile`.
    Extfile(OsString),
    /// `-extensions`.
    Extensions(OsString),
    /// `-copy_extensions`.
    CopyExtensions(OsString),
    /// `-key`.
    Key(OsString),
    /// `-<digest>`, a digest baldssl has.
    Digest(Algorithm),
    /// `-<digest>`, a digest OpenSSL has and baldssl does not.
    UnimplementedDigest,
}

/// Every option `baldssl x509` accepts, besides `-<digest>`.
pub(crate) const SPECS: &[Spec<Opt>] = &[
    Spec {
        name: "help",
        kind: Kind::Flag(Opt::Help),
        help: "Display this summary",
    },
    Spec {
        name: "in",
        kind: Kind::Value(Opt::In),
        help: "Certificate input file (default stdin)",
    },
    Spec {
        name: "inform",
        kind: Kind::Value(Opt::Inform),
        help: "Input format: PEM or DER (default: detect)",
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
        name: "noout",
        kind: Kind::Flag(Opt::Noout),
        help: "Do not output the certificate",
    },
    Spec {
        name: "text",
        kind: Kind::Flag(Opt::Print(Print::Text)),
        help: "Print the certificate in text form",
    },
    Spec {
        name: "subject",
        kind: Kind::Flag(Opt::Print(Print::Subject)),
        help: "Print the subject",
    },
    Spec {
        name: "issuer",
        kind: Kind::Flag(Opt::Print(Print::Issuer)),
        help: "Print the issuer",
    },
    Spec {
        name: "serial",
        kind: Kind::Flag(Opt::Print(Print::Serial)),
        help: "Print the serial number",
    },
    Spec {
        name: "startdate",
        kind: Kind::Flag(Opt::Print(Print::StartDate)),
        help: "Print the notBefore date",
    },
    Spec {
        name: "enddate",
        kind: Kind::Flag(Opt::Print(Print::EndDate)),
        help: "Print the notAfter date",
    },
    Spec {
        name: "dates",
        kind: Kind::Flag(Opt::Dates),
        help: "Print both dates",
    },
    Spec {
        name: "fingerprint",
        kind: Kind::Flag(Opt::Print(Print::Fingerprint)),
        help: "Print the fingerprint (default SHA-256; -sha1 for OpenSSL's)",
    },
    Spec {
        name: "req",
        kind: Kind::Flag(Opt::Req),
        help: "Input is a certificate request, to sign with -CA",
    },
    Spec {
        name: "CA",
        kind: Kind::Value(Opt::Ca),
        help: "CA certificate that signs the request",
    },
    Spec {
        name: "CAform",
        kind: Kind::Value(Opt::CaForm),
        help: "CA certificate format: PEM or DER (default: detect)",
    },
    Spec {
        name: "CAkey",
        kind: Kind::Value(Opt::CaKey),
        help: "CA private key (default: the -CA file)",
    },
    Spec {
        name: "CAkeyform",
        kind: Kind::Value(Opt::CaKeyForm),
        help: "CA private key format: PEM or DER (default: detect)",
    },
    Spec {
        name: "CAserial",
        kind: Kind::Value(Opt::CaSerial),
        help: "Serial file, read, incremented and written back",
    },
    Spec {
        name: "CAcreateserial",
        kind: Kind::Flag(Opt::CaCreateSerial),
        help: "Create the serial file if it does not exist",
    },
    Spec {
        name: "set_serial",
        kind: Kind::Value(Opt::SetSerial),
        help: "Serial number of the certificate",
    },
    Spec {
        name: "days",
        kind: Kind::Value(Opt::Days),
        help: "Days the certificate is valid for (default 30)",
    },
    Spec {
        name: "not_before",
        kind: Kind::Value(Opt::NotBefore),
        help: "Start of validity: YYMMDDHHMMSSZ, YYYYMMDDHHMMSSZ or today",
    },
    Spec {
        name: "not_after",
        kind: Kind::Value(Opt::NotAfter),
        help: "End of validity, overriding -days: as -not_before",
    },
    Spec {
        name: "extfile",
        kind: Kind::Value(Opt::Extfile),
        help: "Configuration file with the extensions to add",
    },
    Spec {
        name: "extensions",
        kind: Kind::Value(Opt::Extensions),
        help: "Section of -extfile with the extensions (default: default)",
    },
    Spec {
        name: "copy_extensions",
        kind: Kind::Value(Opt::CopyExtensions),
        help: "Request extensions to copy: none (default), copy or copyall",
    },
    Spec {
        name: "key",
        kind: Kind::Value(Opt::Key),
        help: "Self-sign with this key (not supported)",
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
    missing_serial: MissingSerialFile,
    /// `-set_serial`.
    serial: Option<SerialNumber>,
    /// `-days`, `-not_before`, `-not_after`.
    lifetime: Lifetime,
    /// The `-<digest>` option, when one is given.
    digest: Option<Algorithm>,
    /// `-extfile`.
    extfile: Option<OsString>,
    /// `-extensions`.
    section: Option<String>,
    /// `-copy_extensions`.
    copy: CopyExtensions,
}

/// What a printing option prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Print {
    /// `-issuer`.
    Issuer,
    /// `-subject`.
    Subject,
    /// `-serial`.
    Serial,
    /// `-startdate`.
    StartDate,
    /// `-enddate`.
    EndDate,
    /// `-fingerprint`.
    Fingerprint,
    /// `-text`.
    Text,
}

/// The digest of `-fingerprint`, and its name as typed, which OpenSSL
/// echoes (`-SHA256` prints `SHA256`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    /// The digest.
    algorithm: Algorithm,
    /// Its name as typed.
    label: String,
}

impl Default for Fingerprint {
    /// SHA-256, a deviation from OpenSSL's SHA-1 (see the module
    /// documentation).
    fn default() -> Self {
        Fingerprint {
            algorithm: Algorithm::Sha256,
            label: "sha256".into(),
        }
    }
}

/// Parsed `x509` invocation.
#[derive(Debug, Default)]
struct Options {
    input: Option<OsString>,
    output_path: Option<OsString>,
    inform: Option<Format>,
    output: OutputForm,
    /// The printing options, in the order they print.
    prints: Vec<Print>,
    fingerprint: Fingerprint,
    source: Source,
    signing: Signing,
}

impl Options {
    /// A printing option seen: it prints after every other one seen so far.
    fn mark(&mut self, print: Print) {
        self.prints.retain(|p| *p != print);
        self.prints.push(print);
    }
}

/// The option a `-<digest>` names, if any.
fn digest_option_opt(name: &str) -> Option<Opt> {
    DigestName::from_option_opt(name).map(|digest| match digest {
        DigestName::Implemented(algorithm) => Opt::Digest(algorithm),
        DigestName::Unimplemented => Opt::UnimplementedDigest,
    })
}

/// The spellings of `-fingerprint`.
const FINGERPRINT_OPTIONS: [&str; 2] = ["-fingerprint", "--fingerprint"];

/// The `-fingerprint <digest>` extension: rewrites it to OpenSSL's
/// `-fingerprint -<digest>`.
fn expand_fingerprint_value(args: &[OsString]) -> Vec<OsString> {
    let mut out = Vec::with_capacity(args.len());
    let mut it = args.iter().peekable();
    while let Some(arg) = it.next() {
        out.push(arg.clone());
        let is_fp = arg
            .to_str()
            .is_some_and(|a| FINGERPRINT_OPTIONS.contains(&a));
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

/// The options; `None` for `-help`.
fn parse_options(raw: &[OsString]) -> Result<Option<Options>> {
    let raw = expand_fingerprint_value(raw);
    let opts =
        args::parse(COMMAND, &raw, SPECS, Unknown::Digests(digest_option_opt))?;
    let mut o = Options::default();
    let mut help = false;
    for given in opts {
        match given.option {
            Opt::Help => help = true,
            Opt::In(v) => o.input = Some(v),
            Opt::Out(v) => o.output_path = Some(v),
            Opt::Inform(v) => {
                o.inform = Some(format_value(&v, COMMAND, "inform")?);
            }
            Opt::Outform(v) => {
                o.output =
                    o.output.with_format(format_value(&v, COMMAND, "outform")?);
            }
            Opt::Noout => o.output = OutputForm::Nothing,
            Opt::Print(p) => o.mark(p),
            Opt::Dates => {
                o.mark(Print::StartDate);
                o.mark(Print::EndDate);
            }
            Opt::Req => o.source = Source::Request,
            Opt::Ca(v) => o.signing.ca = Some(v),
            Opt::CaForm(v) => {
                o.signing.ca_form = Some(format_value(&v, COMMAND, "CAform")?);
            }
            Opt::CaKey(v) => o.signing.ca_key = Some(v),
            Opt::CaKeyForm(v) => {
                o.signing.ca_key_form =
                    Some(format_value(&v, COMMAND, "CAkeyform")?);
            }
            Opt::CaSerial(v) => o.signing.ca_serial = Some(v),
            Opt::CaCreateSerial => {
                o.signing.missing_serial = MissingSerialFile::Created;
            }
            Opt::SetSerial(v) => {
                o.signing.serial = Some(set_serial(&v)?);
            }
            Opt::Days(v) => o.signing.lifetime.set_days(&v)?,
            Opt::NotBefore(v) => {
                o.signing.lifetime.not_before =
                    Some(validity_time("not_before", &v)?);
            }
            Opt::NotAfter(v) => {
                o.signing.lifetime.not_after =
                    Some(validity_time("not_after", &v)?);
            }
            Opt::Extfile(v) => o.signing.extfile = Some(v),
            Opt::Extensions(v) => {
                o.signing.section = Some(utf8("extensions", &v)?.to_string());
            }
            Opt::CopyExtensions(v) => o.signing.copy = copy_extensions(&v)?,
            Opt::Key(_) => return Err(Error::unsupported("x509 -key")),
            Opt::Digest(algorithm) => {
                o.fingerprint = Fingerprint {
                    algorithm,
                    label: given.name,
                };
                o.signing.digest = Some(algorithm);
            }
            Opt::UnimplementedDigest => {
                return Err(Error::unsupported(format!(
                    "digest {}",
                    given.name
                )));
            }
        }
    }
    match (o.source, o.signing.ca.is_some()) {
        (Source::Request, false) => {
            return Err(Error::unsupported("x509 -req without -CA (-key)"));
        }
        (Source::Certificate, true) => {
            return Err(Error::unsupported("x509 -CA without -req"));
        }
        (Source::Request, true) | (Source::Certificate, false) => {}
    }
    Ok((!help).then_some(o))
}

/// Where the serial number comes from: `-set_serial`, the serial file, or
/// random bits.
fn serial_source(s: &Signing) -> SerialSource {
    match (&s.serial, &s.ca_serial, &s.ca, s.missing_serial) {
        (Some(serial), _, _, _) => SerialSource::Given(serial.clone()),
        (None, Some(path), _, missing) => SerialSource::File {
            path: path.into(),
            missing,
        },
        (None, None, Some(ca), MissingSerialFile::Created) => {
            SerialSource::File {
                path: default_serial_file(ca),
                missing: MissingSerialFile::Created,
            }
        }
        (None, None, Some(_), MissingSerialFile::Refused)
        | (None, None, None, _) => SerialSource::Random,
    }
}

/// `-copy_extensions` (see the `FromStr` of [`CopyExtensions`]).
fn copy_extensions(value: &OsStr) -> Result<CopyExtensions> {
    let text = utf8("copy_extensions", value)?;
    text.parse()
        .map_err(|_| Error::Usage(format!("invalid -copy_extensions {text:?}")))
}

/// The extensions of `-extfile`'s section: `-extensions`, or the
/// `extensions` value of the default section, or the default section, as
/// OpenSSL finds it. Nothing without `-extfile`, where `-extensions` is
/// ignored or looked up in the default configuration file by the release
/// line ([`Compat::extensions_without_file`]); baldssl does not read that
/// file, so it fails there as OpenSSL does for a missing section.
fn extension_file(
    s: &Signing,
    compat: Compat,
    out: &mut Outputs,
) -> Result<Extensions> {
    let Some(path) = &s.extfile else {
        match (&s.section, compat.extensions_without_file()) {
            (Some(section), ExtensionsWithoutFile::DefaultConfiguration) => {
                out.diagnostic(format!(
                    "{} {section}",
                    message::EXTENSION_SECTION
                ));
                return Err(Error::unsupported(
                    "x509 -extensions without -extfile (the default configuration file)",
                ));
            }
            (Some(_), ExtensionsWithoutFile::Ignored) => {
                out.diagnostic(message::EXTENSIONS_IGNORED);
            }
            (None, _) => {}
        }
        return Ok(Extensions::new());
    };
    let bytes = read_input(Some(path))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Usage("x509 -extfile: not UTF-8".into()))?;
    let config: Config = text.parse()?;
    // OpenSSL's order: -extensions, then the default section's
    // `extensions`, then the default section itself.
    let section = s
        .section
        .as_deref()
        .or_else(|| config.value_opt("default", "extensions"))
        .unwrap_or("default");
    config.extensions(section).inspect_err(|_| {
        out.diagnostic(format!("{} {section}", message::EXTENSION_SECTION));
    })
}

/// The certificate `-req` signs: the request of the input, checked, then
/// signed by the CA. Records what OpenSSL prints on standard error.
fn issue(o: &Options, compat: Compat, out: &mut Outputs) -> Result<Vec<u8>> {
    let s = &o.signing;
    // OpenSSL checks the extension file before it reads the request.
    let section = extension_file(s, compat, out)?;
    let request = read_request(o.input.as_deref(), o.inform)?;
    if !request.verify() {
        match compat.csr_signature_warning() {
            CsrSignatureWarning::Silent => {}
            CsrSignatureWarning::Printed => {
                out.diagnostic(message::CSR_SIGNATURE_WARNING);
            }
        }
        out.diagnostic(message::REQUEST_MISMATCH);
        return Err(Error::invalid(
            "certificate request self-signature did not match the contents",
        ));
    }
    out.diagnostic(message::REQUEST_OK);
    let mut subject = message::SUBJECT.as_bytes().to_vec();
    subject.extend_from_slice(
        &request.subject_name()?.to_openssl(compat.name_style())?,
    );
    out.diagnostic(subject);
    let ca_path = s
        .ca
        .as_deref()
        .ok_or_else(|| Error::unsupported("x509 -req without -CA (-key)"))?;
    let ca_der = certificate_der(&read_input(Some(ca_path))?, s.ca_form)?;
    let ca = Certificate::from_der(&ca_der)?;
    // Without -CAkey the key is read from the -CA file, as OpenSSL's x509
    // reads it (`CAkeyfile = CAfile`).
    let ca_key =
        read_key(s.ca_key.as_deref().unwrap_or(ca_path), s.ca_key_form)?;
    if !ca.matches_private_key(&ca_key) {
        out.diagnostic(message::CA_KEY_MISMATCH);
        return Err(Error::invalid(
            "CA certificate and CA private key do not match",
        ));
    }
    let digest = match s.digest {
        None => None,
        Some(d) => Some(
            signing_digest_opt(d)
                .ok_or_else(|| Error::unsupported("x509 -req: digest sha1"))?,
        ),
    };
    CertificateTemplate::issued(
        &request,
        &ca,
        &ca_key,
        serial_source(s).next(out)?,
        s.lifetime.validity()?,
        &IssuedExtensions {
            extensions: s
                .copy
                .apply(&Extensions::new(), &request)?
                .override_with(&section),
            extension_file: match s.extfile {
                Some(_) => ExtensionFile::Given,
                None => ExtensionFile::Absent,
            },
        },
        compat,
    )?
    .sign(&ca_key, signature_algorithm(&ca_key, digest))
}

/// Reads (or issues) the certificate, and records everything `x509`
/// writes.
///
/// # Errors
///
/// Usage, decoding, or unsupported-feature errors.
pub(crate) fn run(raw: &[OsString], outputs: &mut Outputs) -> Result<()> {
    let Some(o) = parse_options(raw)? else {
        outputs.stdout(args::usage(COMMAND, SPECS));
        return Ok(());
    };
    let compat = compat();
    let der = match o.source {
        Source::Request => issue(&o, compat, outputs)?,
        Source::Certificate => {
            certificate_der(&read_input(o.input.as_deref())?, o.inform)?
        }
    };
    let cert = Certificate::from_der(&der)?;

    let mut out = Vec::new();
    for p in &o.prints {
        match p {
            Print::Issuer => {
                out.extend_from_slice(message::ISSUER.as_bytes());
                out.extend_from_slice(
                    &cert.issuer.to_openssl(compat.name_style())?,
                );
                out.push(b'\n');
            }
            Print::Subject => {
                out.extend_from_slice(message::SUBJECT.as_bytes());
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
                out.extend_from_slice(
                    format!("{}{t}\n", message::NOT_BEFORE).as_bytes(),
                );
            }
            Print::EndDate => {
                let t = time_rfc822(&cert.validity.not_after);
                out.extend_from_slice(
                    format!("{}{t}\n", message::NOT_AFTER).as_bytes(),
                );
            }
            Print::Fingerprint => {
                let Fingerprint { algorithm, label } = &o.fingerprint;
                out.extend_from_slice(
                    fingerprint_line(cert.der, *algorithm, label).as_bytes(),
                );
            }
            Print::Text => out.extend(cert.to_text(compat)?),
        }
    }
    match o.output {
        OutputForm::Nothing => {}
        OutputForm::Pem => out.extend_from_slice(
            pem::encode(Certificate::LABEL, cert.der).as_bytes(),
        ),
        OutputForm::Der => out.extend_from_slice(cert.der),
    }
    outputs.output(o.output_path.as_deref(), Access::Default, out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn options(v: &[&str]) -> Options {
        parse_options(&os(v)).unwrap().unwrap()
    }

    #[test]
    fn order_follows_last_occurrence() {
        assert_eq!(
            options(&["-enddate", "-subject"]).prints,
            [Print::EndDate, Print::Subject]
        );
        assert_eq!(
            options(&["-subject", "-enddate", "-subject"]).prints,
            [Print::EndDate, Print::Subject]
        );
        assert_eq!(
            options(&["-dates", "-serial"]).prints,
            [Print::StartDate, Print::EndDate, Print::Serial]
        );
    }

    #[test]
    fn help_lists_every_option() {
        let mut out = Outputs::default();
        run(&os(&["-help"]), &mut out).unwrap();
        let text = String::from_utf8(out.stdout_bytes()).unwrap();
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
        let fp = |v: &[&str]| {
            let Fingerprint { algorithm, label } = options(v).fingerprint;
            (algorithm, label)
        };
        assert_eq!(fp(&["-fingerprint"]), (Algorithm::Sha256, "sha256".into()));
        assert_eq!(
            fp(&["-SHA384", "-fingerprint"]),
            (Algorithm::Sha384, "SHA384".into())
        );
        assert_eq!(
            fp(&["-fingerprint", "sha1"]),
            (Algorithm::Sha1, "sha1".into())
        );
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

    /// `-noout` wins over `-outform`, in either order.
    #[test]
    fn noout_wins() {
        for order in [["-noout", "-outform"], ["-outform", "-noout"]] {
            let mut args = order.to_vec();
            args.insert(
                args.iter().position(|a| *a == "-outform").unwrap() + 1,
                "DER",
            );
            assert_eq!(options(&args).output, OutputForm::Nothing, "{args:?}");
        }
        assert_eq!(options(&["-outform", "DER"]).output, OutputForm::Der);
    }

    /// `-req` takes `-CA`, `-CA` takes `-req`, and the serial comes from
    /// `-set_serial`, the serial file, or random bits, in that order.
    #[test]
    fn signing_options() {
        let o = options(&["-req", "-CA", "ca.crt", "-days", "90", "-sha384"]);
        assert_eq!(o.source, Source::Request);
        assert_eq!(o.signing.lifetime.days, 90);
        assert_eq!(o.signing.digest, Some(Algorithm::Sha384));
        assert_eq!(serial_source(&o.signing), SerialSource::Random);
        let o = options(&["-req", "-CA", "ca.crt", "-CAcreateserial"]);
        assert_eq!(
            serial_source(&o.signing),
            SerialSource::File {
                path: "ca.srl".into(),
                missing: MissingSerialFile::Created,
            }
        );
        let o = options(&["-req", "-CA", "ca.crt", "-CAserial", "s.srl"]);
        assert_eq!(
            serial_source(&o.signing),
            SerialSource::File {
                path: "s.srl".into(),
                missing: MissingSerialFile::Refused,
            }
        );
        let o = options(&[
            "-req",
            "-CA",
            "ca.crt",
            "-CAserial",
            "s.srl",
            "-set_serial",
            "5",
        ]);
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

    /// `-extensions` without `-extfile`: a warning in 3.x, an error naming
    /// the section in 4.
    #[test]
    fn extensions_without_a_file() {
        let o = options(&["-req", "-CA", "ca.crt", "-extensions", "v3"]);
        for (compat, stderr, fails) in [
            (
                Compat::V3,
                format!("{}\n", message::EXTENSIONS_IGNORED),
                false,
            ),
            (
                Compat::V4,
                format!("{} v3\n", message::EXTENSION_SECTION),
                true,
            ),
        ] {
            let mut out = Outputs::default();
            let result = extension_file(&o.signing, compat, &mut out);
            assert_eq!(result.is_err(), fails, "{compat:?}");
            assert_eq!(out.stderr_bytes(), stderr.as_bytes(), "{compat:?}");
        }
    }
}
