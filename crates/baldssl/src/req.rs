//! `baldssl req`: create, read and verify certificate signing requests
//! (PKCS#10), like `openssl req`.
//!
//! Supported:
//!
//! - creating a request: `-new -key <file> -subj <name>`, with `-keyform`,
//!   `-utf8` (`-subj` is otherwise read as Latin-1, as in OpenSSL),
//!   `-multivalue-rdn` (accepted; multi-valued RDNs are always on, as in
//!   OpenSSL 3), and a digest (`-sha224`, `-sha256`, `-sha384`, `-sha512`;
//!   SHA-256 by default, and none for Ed25519);
//! - generating the key as well: `-newkey ec` with `-pkeyopt
//!   ec_paramgen_curve:<curve>`, `-newkey ec:<parameters file>` (as
//!   `openssl ecparam` writes it) or `-newkey ed25519`, which implies
//!   `-new`; the key is written unencrypted (`-noenc` or `-nodes`, which
//!   are required) as PKCS#8 PEM to `-keyout`, or to `privkey.pem` as
//!   OpenSSL's default configuration says, readable by its owner only;
//! - extensions: `-addext name=value`, as a configuration file writes them
//!   (`subjectAltName`, `keyUsage`, `extendedKeyUsage`, `basicConstraints`;
//!   see the `FromStr` of [`baldssl_x509::Extension`]), each name once, as in
//!   OpenSSL; with `-x509`, an `-addext` replaces the default extension of
//!   its kind, which then comes after the others, as in OpenSSL;
//! - reading one: `-in <file>` (standard input without it), `-inform`;
//! - `-verify` (a failure on standard error, exit 1; success on standard
//!   error with OpenSSL 3.0 and on standard output from 3.2, see
//!   [`baldssl_x509::Compat::request_verified_stream`]), `-text` (the request, or the `-x509` certificate, as OpenSSL
//!   prints it, before the PEM or DER), `-out`, `-outform PEM|DER`,
//!   `-noout`;
//! - a self-signed certificate instead of a request: `-x509`, which
//!   implies `-new` as in OpenSSL 3, with `-days` (30 by default,
//!   `DEFAULT_DAYS` in `apps/req.c`),
//!   `-set_serial` (decimal, or hexadecimal after `0x`; 159 random bits by
//!   default, as OpenSSL draws them), `-not_before` and `-not_after`
//!   (`YYMMDDHHMMSSZ`, `YYYYMMDDHHMMSSZ` or `today`; `-not_after` wins over
//!   `-days`). The certificate carries the extensions of the `v3_ca`
//!   section of OpenSSL's default configuration file, which differs
//!   between OpenSSL 3 and 4 in the authority key identifier; the release
//!   line is the one baldssl is built for, as for `x509` (see
//!   [`baldssl_x509::CertificateTemplate::self_signed`]).
//!
//! As in OpenSSL, `-key` does not imply `-new`: without `-new`, `-newkey`
//! or `-x509`, a request is read. Not supported, and reported as such:
//! `-config`, RSA and other key algorithms, encrypting
//! the generated key (`-newkey` without `-noenc`), `-x509` with `-in`
//! (signing an existing request), `-x509` with `-verify`, negative or zero
//! serials, the interactive prompts (a request is created only with
//! `-subj`), and encrypted keys.

use std::ffi::{OsStr, OsString};

use baldssl_core::{
    Error, Result,
    encoding::Encodable,
    pem::{self, Pem},
    text::Text as _,
};
use baldssl_crypto::Algorithm as Digest;
use baldssl_fs::Access;
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{
    Certificate, CertificateTemplate, CertificationRequest, Compat,
    DistinguishedName, Extension, Extensions, Format, InputEncoding,
    ParsedSubject, RdnMode, RdnPosition, Stream, SubjWarning, UTF8_ONLY,
};

use crate::{
    args::{self, Kind, Spec, Unknown},
    input::{OutputForm, format_value, read_key, read_request},
    issuing::{
        Lifetime, SerialSource, set_serial, signature_algorithm,
        signing_digest_opt, validity_time,
    },
    keygen::{KeyParameters, utf8},
    line::{Line, compat},
    outputs::Outputs,
};

/// The name of the command.
const COMMAND: &str = "req";

/// The file a generated key is written to without `-keyout`:
/// `default_keyfile` in the `req` section of OpenSSL's default
/// configuration file, `apps/openssl.cnf`.
const DEFAULT_KEYFILE: &str = "privkey.pem";

/// What OpenSSL's `apps/req.c` prints on standard error once it has
/// generated a key.
const KEY_GENERATED: &str = "-----";

/// `-verify`'s message when the signature verifies (`apps/req.c`).
const VERIFY_OK: &str = "Certificate request self-signature verify OK";

/// `-verify`'s message when it does not (`apps/req.c`).
const VERIFY_FAILURE: &str =
    "Certificate request self-signature verify failure";

/// `-addext`'s message for a name given twice (`apps/req.c`).
const DUPLICATE_EXTENSION: &str = "Duplicate extension name";

/// The warnings of `parse_name` in OpenSSL's `apps/lib/apps.c`, after
/// `req `, for an attribute `-subj` skips.
mod subj {
    /// An attribute name OpenSSL does not know.
    pub(super) const UNKNOWN_ATTRIBUTE: &str =
        "warning: Skipping unknown subject name attribute";
    /// After an unknown attribute that follows a `+`.
    pub(super) const PLUS_HINT: &str = "hint: a '+' in a value string needs \
        be escaped using '\\' else a new member of a multi-valued RDN is \
        expected";
    /// An attribute without a value: before and after its name.
    pub(super) const EMPTY_VALUE: (&str, &str) = (
        "warning: No value provided for subject name attribute",
        "skipped",
    );
}

/// An option of `baldssl req`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Opt {
    /// `-help`.
    Help,
    /// `-new`.
    New,
    /// `-key`.
    Key(OsString),
    /// `-keyform`.
    Keyform(OsString),
    /// `-subj`.
    Subj(OsString),
    /// `-utf8`.
    Utf8,
    /// `-multivalue-rdn`.
    MultivalueRdn,
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
    /// `-verify`.
    Verify,
    /// `-text`.
    Text,
    /// `-newkey`.
    Newkey(OsString),
    /// `-pkeyopt`.
    Pkeyopt(OsString),
    /// `-keyout`.
    Keyout(OsString),
    /// `-noenc`.
    Noenc,
    /// `-nodes`.
    Nodes,
    /// `-x509`.
    X509,
    /// `-days`.
    Days(OsString),
    /// `-set_serial`.
    SetSerial(OsString),
    /// `-not_before`.
    NotBefore(OsString),
    /// `-not_after`.
    NotAfter(OsString),
    /// `-config`.
    Config(OsString),
    /// `-addext`.
    Addext(OsString),
    /// `-<digest>`.
    Digest(Digest),
}

/// Every option `baldssl req` accepts, besides the digests.
pub(crate) const SPECS: &[Spec<Opt>] = &[
    Spec {
        name: "help",
        kind: Kind::Flag(Opt::Help),
        help: "Display this summary",
    },
    Spec {
        name: "new",
        kind: Kind::Flag(Opt::New),
        help: "Create a new request",
    },
    Spec {
        name: "key",
        kind: Kind::Value(Opt::Key),
        help: "Key to sign the new request with",
    },
    Spec {
        name: "keyform",
        kind: Kind::Value(Opt::Keyform),
        help: "Key file format: PEM or DER (detected by default)",
    },
    Spec {
        name: "subj",
        kind: Kind::Value(Opt::Subj),
        help: "Subject of the new request, /type0=value0/type1=value1...",
    },
    Spec {
        name: "utf8",
        kind: Kind::Flag(Opt::Utf8),
        help: "Read -subj as UTF-8 (Latin-1 by default)",
    },
    Spec {
        name: "multivalue-rdn",
        kind: Kind::Flag(Opt::MultivalueRdn),
        help: "Accepted; multi-valued RDNs are always on",
    },
    Spec {
        name: "in",
        kind: Kind::Value(Opt::In),
        help: "Request to read (default stdin)",
    },
    Spec {
        name: "inform",
        kind: Kind::Value(Opt::Inform),
        help: "Input format: PEM or DER (detected by default)",
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
        help: "Do not output the request",
    },
    Spec {
        name: "verify",
        kind: Kind::Flag(Opt::Verify),
        help: "Verify the request's self-signature",
    },
    Spec {
        name: "text",
        kind: Kind::Flag(Opt::Text),
        help: "Print the request (or the -x509 certificate) in text form",
    },
    Spec {
        name: "newkey",
        kind: Kind::Value(Opt::Newkey),
        help: "Generate a key: ec (with -pkeyopt), ec:<paramfile> or ed25519",
    },
    Spec {
        name: "pkeyopt",
        kind: Kind::Value(Opt::Pkeyopt),
        help: "Key generation option: ec_paramgen_curve:<curve>",
    },
    Spec {
        name: "keyout",
        kind: Kind::Value(Opt::Keyout),
        help: "File the generated key is written to (default privkey.pem)",
    },
    Spec {
        name: "noenc",
        kind: Kind::Flag(Opt::Noenc),
        help: "Do not encrypt the generated key",
    },
    Spec {
        name: "nodes",
        kind: Kind::Flag(Opt::Nodes),
        help: "Same as -noenc",
    },
    Spec {
        name: "x509",
        kind: Kind::Flag(Opt::X509),
        help: "Write a self-signed certificate instead of a request",
    },
    Spec {
        name: "days",
        kind: Kind::Value(Opt::Days),
        help: "Days the certificate is valid for (default 30)",
    },
    Spec {
        name: "set_serial",
        kind: Kind::Value(Opt::SetSerial),
        help: "Serial number of the certificate (default random)",
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
        name: "config",
        kind: Kind::Value(Opt::Config),
        help: "Configuration file (not supported)",
    },
    Spec {
        name: "addext",
        kind: Kind::Value(Opt::Addext),
        help: "Extension to add: name=value, as in a configuration file",
    },
];

/// Whether `req` creates a request or reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Mode {
    /// Read a request (`-in`, or standard input).
    #[default]
    Read,
    /// Create one (`-new`).
    Create,
}

/// What `req` produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Product {
    /// A certificate signing request.
    #[default]
    Request,
    /// A self-signed certificate (`-x509`).
    Certificate,
}

/// Whether the request's signature is checked (`-verify`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Verify {
    /// It is not.
    #[default]
    Skipped,
    /// It is, and the outcome printed.
    SelfSignature,
}

/// Whether the text form is printed (`-text`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Text {
    /// It is not.
    #[default]
    Omitted,
    /// It is, before the PEM or DER.
    Printed,
}

/// Whether a generated key is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum KeyEncryption {
    /// It is, OpenSSL's default, which baldssl does not do.
    #[default]
    Encrypted,
    /// It is not (`-noenc`, `-nodes`).
    Plain,
}

/// A key `-newkey` generates, and where it is written.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NewKey {
    /// `-newkey` and `-pkeyopt`.
    parameters: KeyParameters,
    /// `-keyout`, or [`DEFAULT_KEYFILE`].
    keyout: OsString,
}

/// Where the key of a new request or certificate comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeySource {
    /// `-key`.
    File(OsString),
    /// `-newkey`.
    New(NewKey),
}

/// The options, once read.
struct Options {
    mode: Mode,
    product: Product,
    lifetime: Lifetime,
    serial: SerialSource,
    key: Option<KeySource>,
    keyform: Option<Format>,
    subj: Option<OsString>,
    encoding: InputEncoding,
    input: Option<OsString>,
    inform: Option<Format>,
    output_path: Option<OsString>,
    output: OutputForm,
    verify: Verify,
    text: Text,
    extensions: Extensions,
    digest: Option<Digest>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            mode: Mode::default(),
            product: Product::default(),
            lifetime: Lifetime::default(),
            serial: SerialSource::default(),
            key: None,
            keyform: None,
            subj: None,
            encoding: InputEncoding::Latin1,
            input: None,
            inform: None,
            output_path: None,
            output: OutputForm::default(),
            verify: Verify::default(),
            text: Text::default(),
            extensions: Extensions::new(),
            digest: None,
        }
    }
}

/// Records OpenSSL's warning for an attribute `-subj` skipped.
fn warn(warning: &SubjWarning, out: &mut Outputs) {
    match warning {
        SubjWarning::UnknownAttribute { name, position } => {
            out.diagnostic(format!(
                "{COMMAND} {} \"{name}\"",
                subj::UNKNOWN_ATTRIBUTE
            ));
            match position {
                RdnPosition::Further => {
                    out.diagnostic(format!("{COMMAND} {}", subj::PLUS_HINT));
                }
                RdnPosition::First => {}
            }
        }
        SubjWarning::EmptyValue { name } => {
            let (before, after) = subj::EMPTY_VALUE;
            out.diagnostic(format!("{COMMAND} {before} \"{name}\", {after}"));
        }
    }
}

/// The subject of `-subj`, its warnings recorded.
fn subject(o: &Options, out: &mut Outputs) -> Result<DistinguishedName> {
    let subj = o.subj.as_deref().ok_or_else(|| {
        Error::unsupported("req -new without -subj (interactive prompts)")
    })?;
    let ParsedSubject {
        name: subject,
        warnings,
    } = DistinguishedName::from_subj(
        subj.as_encoded_bytes(),
        o.encoding,
        RdnMode::MultiValued,
        UTF8_ONLY,
    )
    .map_err(|e| Error::Usage(e.to_string()))?;
    for w in &warnings {
        warn(w, out);
    }
    Ok(subject)
}

/// The key of `-key`, or the one `-newkey` generates, written to its file.
fn key(o: &Options, out: &mut Outputs) -> Result<AnyPrivateKey> {
    match &o.key {
        None => Err(Error::unsupported(
            "req -new without -key or -newkey (a key from the configuration)",
        )),
        Some(KeySource::File(path)) => read_key(path, o.keyform),
        Some(KeySource::New(new)) => {
            let key = AnyPrivateKey::generate(new.parameters.algorithm()?)?;
            // OpenSSL's line for a generated key, the same for every
            // algorithm baldssl generates.
            out.diagnostic(KEY_GENERATED);
            out.file(&new.keyout, Access::OwnerOnly, key.to_pem());
            Ok(key)
        }
    }
}

/// A new request, from `-key` and `-subj`.
fn create(o: &Options, out: &mut Outputs) -> Result<CertificationRequest> {
    let key = key(o, out)?;
    CertificationRequest::sign(
        &subject(o, out)?,
        &key,
        signature_algorithm(&key, o.digest),
        &o.extensions,
    )
}

/// A new self-signed certificate, DER, from `-key`, `-subj` and the
/// validity and serial options.
fn self_sign(o: &Options, out: &mut Outputs) -> Result<Vec<u8>> {
    let key = key(o, out)?;
    let subject = subject(o, out)?;
    let mut template = CertificateTemplate::self_signed::<Line>(
        &subject,
        &(&key).into(),
        o.serial.next(out)?,
        o.lifetime.validity()?,
    );
    // -addext replaces v3_ca's extension of the same kind (which moves to
    // the end) and adds the others, as OpenSSL's replace mode does.
    template.extensions = template.extensions.override_with(&o.extensions);
    template.sign(&key, signature_algorithm(&key, o.digest))
}

/// One `-addext`: the extension, refused when its name was given before
/// (OpenSSL's "Duplicate extension name"). Extensions go by short name
/// only, one per kind, so a name given once is a kind given once.
fn add_extension(
    extensions: &mut Extensions,
    names: &mut Vec<String>,
    value: &OsStr,
) -> Result<()> {
    let line = utf8("addext", value)?;
    // A line without `=` is all name; parsing it as an extension then
    // fails, as OpenSSL refuses it.
    let name = line.split_once('=').map_or(line, |(n, _)| n).trim();
    if names.iter().any(|n| n == name) {
        return Err(Error::Usage(format!("{DUPLICATE_EXTENSION}: {name}")));
    }
    names.push(name.to_string());
    extensions.push_new(line.parse::<Extension>()?)
}

/// The digest of a `-<digest>` option: one OpenSSL's `opt_md` knows, to
/// be refused later if baldssl does not sign with it.
fn digest_option_opt(name: &str) -> Option<Opt> {
    Digest::from_name_opt(name).map(Opt::Digest)
}

/// Where the key comes from: `-key`, or `-newkey` (with `-pkeyopt`,
/// `-keyout`, and `-noenc`, which baldssl requires), or neither.
fn key_source(
    key_file: Option<OsString>,
    parameters: KeyParameters,
    keyout: Option<OsString>,
    encryption: KeyEncryption,
) -> Result<Option<KeySource>> {
    match (key_file, parameters.is_named(), encryption) {
        (Some(_), true, _) => {
            Err(Error::Usage("-key and -newkey exclude each other".into()))
        }
        (Some(path), false, _) => Ok(Some(KeySource::File(path))),
        (None, true, KeyEncryption::Encrypted) => Err(Error::unsupported(
            "req -newkey without -noenc (encrypting the key)",
        )),
        (None, true, KeyEncryption::Plain) => {
            Ok(Some(KeySource::New(NewKey {
                parameters,
                keyout: keyout.unwrap_or_else(|| DEFAULT_KEYFILE.into()),
            })))
        }
        (None, false, _) => Ok(None),
    }
}

/// Reads the options; `None` for `-help`.
fn parse_options(raw: &[OsString]) -> Result<Option<Options>> {
    let opts =
        args::parse(COMMAND, raw, SPECS, Unknown::Digests(digest_option_opt))?;
    let mut o = Options::default();
    let mut key_file: Option<OsString> = None;
    let mut parameters = KeyParameters::default();
    let mut keyout: Option<OsString> = None;
    let mut encryption = KeyEncryption::default();
    let mut addext_names: Vec<String> = Vec::new();
    for given in opts {
        match given.option {
            Opt::Help => return Ok(None),
            Opt::New => o.mode = Mode::Create,
            Opt::Key(v) => key_file = Some(v),
            Opt::Newkey(v) => parameters.set_newkey(&v)?,
            Opt::Pkeyopt(v) => parameters.pkeyopt(COMMAND, &v)?,
            Opt::Keyout(v) => keyout = Some(v),
            Opt::Noenc | Opt::Nodes => encryption = KeyEncryption::Plain,
            Opt::Keyform(v) => {
                o.keyform = Some(format_value(&v, COMMAND, "keyform")?);
            }
            Opt::Subj(v) => o.subj = Some(v),
            Opt::Utf8 => o.encoding = InputEncoding::Utf8,
            Opt::MultivalueRdn => {}
            Opt::In(v) => o.input = Some(v),
            Opt::Inform(v) => {
                o.inform = Some(format_value(&v, COMMAND, "inform")?);
            }
            Opt::Out(v) => o.output_path = Some(v),
            Opt::Outform(v) => {
                o.output =
                    o.output.with_format(format_value(&v, COMMAND, "outform")?);
            }
            Opt::Noout => o.output = OutputForm::Nothing,
            Opt::Verify => o.verify = Verify::SelfSignature,
            Opt::X509 => o.product = Product::Certificate,
            Opt::Days(v) => o.lifetime.set_days(&v)?,
            Opt::SetSerial(v) => {
                o.serial = SerialSource::Given(set_serial(&v)?);
            }
            Opt::NotBefore(v) => {
                o.lifetime.not_before = Some(validity_time("not_before", &v)?);
            }
            Opt::NotAfter(v) => {
                o.lifetime.not_after = Some(validity_time("not_after", &v)?);
            }
            Opt::Text => o.text = Text::Printed,
            Opt::Addext(v) => {
                add_extension(&mut o.extensions, &mut addext_names, &v)?;
            }
            Opt::Config(_) => {
                return Err(Error::unsupported(format!(
                    "{COMMAND} -{}",
                    given.name
                )));
            }
            Opt::Digest(d) => {
                o.digest = Some(signing_digest_opt(d).ok_or_else(|| {
                    Error::unsupported(format!("digest {}", given.name))
                })?);
            }
        }
    }
    o.key = key_source(key_file, parameters, keyout, encryption)?;
    // As in OpenSSL, -newkey and -x509 create a request.
    if let Some(KeySource::New(_)) = o.key {
        o.mode = Mode::Create;
    }
    match o.product {
        Product::Request => {}
        Product::Certificate => {
            if o.input.is_some() {
                return Err(Error::unsupported("req -x509 -in"));
            }
            match o.verify {
                Verify::Skipped => {}
                Verify::SelfSignature => {
                    return Err(Error::unsupported("req -x509 -verify"));
                }
            }
            o.mode = Mode::Create;
        }
    }
    Ok(Some(o))
}

/// `-verify`: the outcome, on the stream the release line prints it on.
fn verify(
    request: &CertificationRequest,
    compat: Compat,
    out: &mut Outputs,
) -> Result<()> {
    if !request.verify() {
        out.diagnostic(VERIFY_FAILURE);
        return Err(Error::invalid(
            "certificate request self-signature verify failure",
        ));
    }
    match compat.request_verified_stream() {
        Stream::Stderr => out.diagnostic(VERIFY_OK),
        Stream::Stdout => out.stdout(format!("{VERIFY_OK}\n")),
    }
    Ok(())
}

/// Creates or reads the request (or creates the certificate), and records
/// what `req` writes.
///
/// # Errors
///
/// Usage errors, unreadable keys or requests, unsupported options, and a
/// failed `-verify`.
pub(crate) fn run(raw: &[OsString], out: &mut Outputs) -> Result<()> {
    let Some(o) = parse_options(raw)? else {
        out.stdout(args::usage(COMMAND, SPECS));
        return Ok(());
    };
    let compat = compat();
    let mut bytes = Vec::new();
    match o.product {
        Product::Certificate => {
            let der = self_sign(&o, out)?;
            match o.text {
                Text::Omitted => {}
                Text::Printed => {
                    bytes.extend(Certificate::from_der(&der)?.to_text(compat)?);
                }
            }
            match o.output {
                OutputForm::Nothing => {}
                OutputForm::Der => bytes.extend_from_slice(&der),
                OutputForm::Pem => bytes.extend_from_slice(
                    pem::encode(Certificate::LABEL, &der).as_bytes(),
                ),
            }
        }
        Product::Request => {
            let request = match o.mode {
                Mode::Create => create(&o, out)?,
                Mode::Read => read_request(o.input.as_deref(), o.inform)?,
            };
            match o.verify {
                Verify::Skipped => {}
                Verify::SelfSignature => verify(&request, compat, out)?,
            }
            match o.text {
                Text::Omitted => {}
                Text::Printed => bytes.extend(request.to_text(compat)?),
            }
            match o.output {
                OutputForm::Nothing => {}
                OutputForm::Der => bytes.extend_from_slice(&request.encode()),
                OutputForm::Pem => {
                    bytes.extend_from_slice(request.to_pem().as_bytes());
                }
            }
        }
    }
    out.output(o.output_path.as_deref(), Access::Default, bytes);
    Ok(())
}

#[cfg(test)]
mod tests;
