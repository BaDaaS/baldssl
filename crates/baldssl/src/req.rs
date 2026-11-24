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
//! - `-verify` (the message on standard error, exit 1 on failure, as
//!   OpenSSL), `-text` (the request, or the `-x509` certificate, as OpenSSL
//!   prints it, before the PEM or DER), `-out`, `-outform PEM|DER`,
//!   `-noout`;
//! - a self-signed certificate instead of a request: `-x509`, which
//!   implies `-new` as in OpenSSL 3, with `-days` (30 by default),
//!   `-set_serial` (decimal, or hexadecimal after `0x`; 159 random bits by
//!   default, as OpenSSL draws them), `-not_before` and `-not_after`
//!   (`YYMMDDHHMMSSZ`, `YYYYMMDDHHMMSSZ` or `today`; `-not_after` wins over
//!   `-days`). The certificate carries the extensions of the `v3_ca`
//!   section of OpenSSL's default configuration file, which differs
//!   between OpenSSL 3 and 4 in the authority key identifier; the release
//!   line is the one `BALDSSL_OPENSSL_COMPAT` names, as for `x509` (see
//!   [`baldssl_x509::CertificateTemplate::self_signed`]).
//!
//! As in OpenSSL, `-key` does not imply `-new`: without `-new`, `-newkey`
//! or `-x509`, a request is read. Not supported, and reported as such:
//! `-config`, RSA and other key algorithms, encrypting
//! the generated key (`-newkey` without `-noenc`), `-x509` with `-in`
//! (signing an existing request), `-x509` with `-verify`, negative or zero
//! serials, the interactive prompts (a request is created only with
//! `-subj`), and encrypted keys.

use std::{
    ffi::{OsStr, OsString},
    path::Path,
};

use baldssl_core::{
    Error, Result,
    encoding::Encodable,
    pem::{self, Pem},
};
use baldssl_crypto::Algorithm as Digest;
use baldssl_fs::{
    WritePem as _, WriteText as _, create_owner_only, write_error,
};
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{
    Certificate, CertificateTemplate, CertificationRequest, DistinguishedName,
    Extension, Extensions, Format, InputEncoding, SubjWarning, UTF8_ONLY,
};

use crate::{
    args::{self, Kind, Spec},
    input::{parse_format, read_key, read_request},
    issuing::{
        Lifetime, SerialSource, parse_serial, parse_time, signature_algorithm,
    },
    keygen::{KeyParameters, utf8},
};

/// Every option `baldssl req` accepts, besides the digests.
pub(crate) const SPECS: &[Spec] = &[
    Spec {
        name: "help",
        kind: Kind::Flag,
        help: "Display this summary",
    },
    Spec {
        name: "new",
        kind: Kind::Flag,
        help: "Create a new request",
    },
    Spec {
        name: "key",
        kind: Kind::Value,
        help: "Key to sign the new request with",
    },
    Spec {
        name: "keyform",
        kind: Kind::Value,
        help: "Key file format: PEM or DER (detected by default)",
    },
    Spec {
        name: "subj",
        kind: Kind::Value,
        help: "Subject of the new request, /type0=value0/type1=value1...",
    },
    Spec {
        name: "utf8",
        kind: Kind::Flag,
        help: "Read -subj as UTF-8 (Latin-1 by default)",
    },
    Spec {
        name: "multivalue-rdn",
        kind: Kind::Flag,
        help: "Accepted; multi-valued RDNs are always on",
    },
    Spec {
        name: "in",
        kind: Kind::Value,
        help: "Request to read (default stdin)",
    },
    Spec {
        name: "inform",
        kind: Kind::Value,
        help: "Input format: PEM or DER (detected by default)",
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
        help: "Do not output the request",
    },
    Spec {
        name: "verify",
        kind: Kind::Flag,
        help: "Verify the request's self-signature",
    },
    Spec {
        name: "text",
        kind: Kind::Flag,
        help: "Print the request (or the -x509 certificate) in text form",
    },
    Spec {
        name: "newkey",
        kind: Kind::Value,
        help: "Generate a key: ec (with -pkeyopt), ec:<paramfile> or ed25519",
    },
    Spec {
        name: "pkeyopt",
        kind: Kind::Value,
        help: "Key generation option: ec_paramgen_curve:<curve>",
    },
    Spec {
        name: "keyout",
        kind: Kind::Value,
        help: "File the generated key is written to (default privkey.pem)",
    },
    Spec {
        name: "noenc",
        kind: Kind::Flag,
        help: "Do not encrypt the generated key",
    },
    Spec {
        name: "nodes",
        kind: Kind::Flag,
        help: "Same as -noenc",
    },
    Spec {
        name: "x509",
        kind: Kind::Flag,
        help: "Write a self-signed certificate instead of a request",
    },
    Spec {
        name: "days",
        kind: Kind::Value,
        help: "Days the certificate is valid for (default 30)",
    },
    Spec {
        name: "set_serial",
        kind: Kind::Value,
        help: "Serial number of the certificate (default random)",
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
        name: "config",
        kind: Kind::Value,
        help: "Configuration file (not supported)",
    },
    Spec {
        name: "addext",
        kind: Kind::Value,
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

/// How `req` writes what it produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Output {
    /// PEM.
    #[default]
    Pem,
    /// DER.
    Der,
    /// Nothing (`-noout`).
    Nothing,
}

/// The options, once read.
/// A key `-newkey` generates, and where it is written.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NewKey {
    /// `-newkey` and `-pkeyopt`.
    parameters: KeyParameters,
    /// `-keyout`; OpenSSL's default `privkey.pem` without it.
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
    output: Output,
    verify: bool,
    text: bool,
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
            output: Output::default(),
            verify: false,
            text: false,
            extensions: Extensions::new(),
            digest: None,
        }
    }
}

/// The digests a request can be signed with.
fn digest_opt(name: &str) -> Option<Digest> {
    match Digest::from_name_opt(name)? {
        Digest::Sha1 => None,
        d => Some(d),
    }
}

/// Prints OpenSSL's warning for an attribute `-subj` skipped.
fn warn(warning: &SubjWarning) {
    match warning {
        SubjWarning::UnknownAttribute { name, multi } => {
            eprintln!(
                "req warning: Skipping unknown subject name attribute \"{name}\""
            );
            if *multi {
                eprintln!(
                    "req hint: a '+' in a value string needs be escaped using \
                     '\\' else a new member of a multi-valued RDN is expected"
                );
            }
        }
        SubjWarning::EmptyValue { name } => eprintln!(
            "req warning: No value provided for subject name attribute \
             \"{name}\", skipped"
        ),
    }
}

/// The subject of `-subj`, its warnings printed.
fn subject(o: &Options) -> Result<DistinguishedName> {
    let subj = o.subj.as_deref().ok_or_else(|| {
        Error::unsupported("req -new without -subj (interactive prompts)")
    })?;
    let (subject, warnings) = DistinguishedName::from_subj(
        subj.as_encoded_bytes(),
        o.encoding,
        true,
        UTF8_ONLY,
    )
    .map_err(|e| Error::Usage(format!("req: {e}")))?;
    for w in &warnings {
        warn(w);
    }
    Ok(subject)
}

/// The key of `-key`.
fn key(o: &Options) -> Result<AnyPrivateKey> {
    match &o.key {
        None => Err(Error::unsupported(
            "req -new without -key or -newkey (a key from the configuration)",
        )),
        Some(KeySource::File(path)) => read_key(path, o.keyform),
        Some(KeySource::New(new)) => {
            let key =
                AnyPrivateKey::generate(new.parameters.algorithm("req")?)?;
            // OpenSSL's progress line for a generated key, the same for
            // every algorithm baldssl generates.
            eprintln!("-----");
            let path = Path::new(&new.keyout);
            key.write_pem(create_owner_only(path)?)
                .map_err(|e| write_error(path, &e))?;
            Ok(key)
        }
    }
}

/// A new request, from `-key` and `-subj`.
fn create(o: &Options) -> Result<CertificationRequest> {
    let key = key(o)?;
    CertificationRequest::sign(
        &subject(o)?,
        &key,
        signature_algorithm(&key, o.digest),
        &o.extensions,
    )
}

/// A new self-signed certificate, DER, from `-key`, `-subj` and the
/// validity and serial options.
fn self_sign(o: &Options) -> Result<Vec<u8>> {
    let key = key(o)?;
    let subject = subject(o)?;
    let mut template = CertificateTemplate::self_signed(
        &subject,
        &(&key).into(),
        o.serial.next("req")?,
        o.lifetime.validity("req")?,
        crate::x509::compat()?,
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
    let line = utf8("req", "addext", value)?;
    let name = line.split_once('=').map_or(line, |(n, _)| n).trim();
    if names.iter().any(|n| n == name) {
        return Err(Error::Usage(format!("Duplicate extension name: {name}")));
    }
    names.push(name.to_string());
    extensions.push_new(line.parse::<Extension>()?)
}

/// Reads the options.
fn parse_options(raw: &[OsString]) -> Result<Option<Options>> {
    let opts =
        args::parse("req", raw, SPECS, |n| Digest::from_name_opt(n).is_some())?;
    let mut o = Options::default();
    let mut key_file: Option<OsString> = None;
    let mut parameters = KeyParameters::default();
    let mut newkey = false;
    let mut keyout: Option<OsString> = None;
    let mut noenc = false;
    let mut addext_names: Vec<String> = Vec::new();
    for opt in opts {
        let value = opt.value.clone().unwrap_or_default();
        match opt.name.as_str() {
            "help" => return Ok(None),
            "new" => o.mode = Mode::Create,
            "key" => key_file = Some(value),
            "newkey" => {
                parameters.set_newkey("req", &value)?;
                newkey = true;
            }
            "pkeyopt" => parameters.pkeyopt("req", &value)?,
            "keyout" => keyout = Some(value),
            "noenc" | "nodes" => noenc = true,
            "keyform" => {
                o.keyform = Some(parse_format(&value, "req", "keyform")?);
            }
            "subj" => o.subj = Some(value),
            "utf8" => o.encoding = InputEncoding::Utf8,
            "in" => o.input = Some(value),
            "inform" => o.inform = Some(parse_format(&value, "req", "inform")?),
            "out" => o.output_path = Some(value),
            // -noout wins over -outform, wherever it comes.
            "outform" if o.output != Output::Nothing => {
                o.output = match parse_format(&value, "req", "outform")? {
                    Format::Pem => Output::Pem,
                    Format::Der => Output::Der,
                };
            }
            "outform" => {
                parse_format(&value, "req", "outform")?;
            }
            "noout" => o.output = Output::Nothing,
            "verify" => o.verify = true,
            "x509" => o.product = Product::Certificate,
            "days" => o.lifetime.set_days("req", &value)?,
            "set_serial" => {
                o.serial = SerialSource::Given(parse_serial("req", &value)?);
            }
            "not_before" => {
                o.lifetime.not_before =
                    Some(parse_time("req", "not_before", &value)?);
            }
            "not_after" => {
                o.lifetime.not_after =
                    Some(parse_time("req", "not_after", &value)?);
            }
            "text" => o.text = true,
            "addext" => {
                add_extension(&mut o.extensions, &mut addext_names, &value)?;
            }
            "config" => {
                return Err(Error::unsupported(format!("req -{}", opt.name)));
            }
            name => {
                o.digest = Some(digest_opt(name).ok_or_else(|| {
                    Error::unsupported(format!("req: digest {name}"))
                })?);
            }
        }
    }
    o.key = match (key_file, newkey) {
        (Some(_), true) => {
            return Err(Error::Usage(
                "req: -key and -newkey exclude each other".into(),
            ));
        }
        (Some(path), false) => Some(KeySource::File(path)),
        (None, true) => {
            if !noenc {
                return Err(Error::unsupported(
                    "req -newkey without -noenc (encrypting the key)",
                ));
            }
            // As in OpenSSL, -newkey creates a request.
            o.mode = Mode::Create;
            Some(KeySource::New(NewKey {
                parameters,
                keyout: keyout.unwrap_or_else(|| "privkey.pem".into()),
            }))
        }
        (None, false) => None,
    };
    if o.product == Product::Certificate {
        if o.input.is_some() {
            return Err(Error::unsupported("req -x509 -in"));
        }
        if o.verify {
            return Err(Error::unsupported("req -x509 -verify"));
        }
        o.mode = Mode::Create;
    }
    Ok(Some(o))
}

/// Renders the request, and where to write it.
///
/// # Errors
///
/// Usage errors, unreadable keys or requests, unsupported options, and a
/// failed `-verify`.
pub(crate) fn render(raw: &[OsString]) -> Result<(Vec<u8>, Option<OsString>)> {
    let Some(o) = parse_options(raw)? else {
        return Ok((args::usage("req", SPECS).into_bytes(), None));
    };
    let compat = crate::x509::compat()?;
    let mut bytes = Vec::new();
    if o.product == Product::Certificate {
        let der = self_sign(&o)?;
        if o.text {
            Certificate::from_der(&der)?.write_text(compat, &mut bytes)?;
        }
        match o.output {
            Output::Nothing => {}
            Output::Der => bytes.extend_from_slice(&der),
            Output::Pem => bytes
                .extend_from_slice(pem::encode("CERTIFICATE", &der).as_bytes()),
        }
        return Ok((bytes, o.output_path));
    }
    let request = match o.mode {
        Mode::Create => create(&o)?,
        Mode::Read => read_request(o.input.as_deref(), o.inform)?,
    };
    if o.verify {
        if request.verify() {
            eprintln!("Certificate request self-signature verify OK");
        } else {
            eprintln!("Certificate request self-signature verify failure");
            return Err(Error::invalid(
                "certificate request self-signature verify failure",
            ));
        }
    }
    if o.text {
        request.write_text(compat, &mut bytes)?;
    }
    match o.output {
        Output::Nothing => {}
        Output::Der => bytes.extend_from_slice(&request.encode()),
        Output::Pem => bytes.extend_from_slice(request.to_pem().as_bytes()),
    }
    Ok((bytes, o.output_path))
}

#[cfg(test)]
mod tests;
