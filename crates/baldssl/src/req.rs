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
//! - reading one: `-in <file>` (standard input without it), `-inform`;
//! - `-verify` (the message on standard error, exit 1 on failure, as
//!   OpenSSL), `-out`, `-outform PEM|DER`, `-noout`.
//!
//! As in OpenSSL, `-key` does not imply `-new`: without `-new`, a request
//! is read. Not supported, and reported as such: `-text`, `-newkey`,
//! `-x509`, `-config`, `-addext`, the interactive prompts (a request is
//! created only with `-subj`), and encrypted keys.

use std::ffi::{OsStr, OsString};

use baldssl_core::{
    Error, Result,
    encoding::{Decodable, Encodable},
    pem::{self, Pem},
};
use baldssl_crypto::Algorithm as Digest;
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{
    CertificationRequest, DistinguishedName, Format, InputEncoding,
    SignatureAlgorithm, SubjWarning, UTF8_ONLY,
};

use crate::{
    args::{self, Kind, Spec},
    input::{parse_format, read_input},
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
        help: "Print the request in text form (not supported yet)",
    },
    Spec {
        name: "newkey",
        kind: Kind::Value,
        help: "Generate a key with the request (not supported yet)",
    },
    Spec {
        name: "x509",
        kind: Kind::Flag,
        help: "Write a self-signed certificate (not supported yet)",
    },
    Spec {
        name: "config",
        kind: Kind::Value,
        help: "Configuration file (not supported)",
    },
    Spec {
        name: "addext",
        kind: Kind::Value,
        help: "Extension to add (not supported yet)",
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

/// What `req` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Output {
    /// The request, PEM.
    #[default]
    Pem,
    /// The request, DER.
    Der,
    /// Nothing (`-noout`).
    Nothing,
}

/// The options, once read.
struct Options {
    mode: Mode,
    key: Option<OsString>,
    keyform: Option<Format>,
    subj: Option<OsString>,
    encoding: InputEncoding,
    input: Option<OsString>,
    inform: Option<Format>,
    output_path: Option<OsString>,
    output: Output,
    verify: bool,
    digest: Option<Digest>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            mode: Mode::default(),
            key: None,
            keyform: None,
            subj: None,
            encoding: InputEncoding::Latin1,
            input: None,
            inform: None,
            output_path: None,
            output: Output::default(),
            verify: false,
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

/// Whether the bytes are PEM: a `-----BEGIN` boundary, as OpenSSL 3 detects
/// it when no format is given.
fn is_pem(bytes: &[u8]) -> bool {
    bytes.windows(10).any(|w| w == b"-----BEGIN")
}

/// The private key of `-key`.
fn read_key(path: &OsStr, form: Option<Format>) -> Result<AnyPrivateKey> {
    let bytes = read_input(Some(path))?;
    let pem = form.map_or_else(|| is_pem(&bytes), |f| f == Format::Pem);
    if pem {
        AnyPrivateKey::from_pem(&bytes)
    } else {
        AnyPrivateKey::decode(&bytes)
    }
}

/// The request of `-in`, or of standard input.
fn read_request(
    path: Option<&OsStr>,
    form: Option<Format>,
) -> Result<CertificationRequest> {
    let bytes = read_input(path)?;
    let pem = form.map_or_else(|| is_pem(&bytes), |f| f == Format::Pem);
    if pem {
        let block = pem::decode_first(&bytes, &[CertificationRequest::LABEL])?;
        CertificationRequest::decode(&block.contents)
    } else {
        CertificationRequest::decode(&bytes)
    }
}

/// The signature algorithm: the key's default, with the digest of a
/// `-<digest>` option as ECDSA's hash. Ed25519 fixes its hash, so a digest
/// does not change it, as in OpenSSL.
fn signature_algorithm(
    key: &AnyPrivateKey,
    digest: Option<Digest>,
) -> SignatureAlgorithm {
    match (key.default_signature_algorithm(), digest) {
        (SignatureAlgorithm::Ecdsa(_), Some(hash)) => {
            SignatureAlgorithm::Ecdsa(hash)
        }
        (default, _) => default,
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

/// The request `-new` creates.
fn create(o: &Options) -> Result<CertificationRequest> {
    let key_path = o
        .key
        .as_deref()
        .ok_or_else(|| Error::unsupported("req -new without -key (-newkey)"))?;
    let key = read_key(key_path, o.keyform)?;
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
    CertificationRequest::sign(
        &subject,
        &key,
        signature_algorithm(&key, o.digest),
    )
}

/// Reads the options.
fn parse_options(raw: &[OsString]) -> Result<Option<Options>> {
    let opts =
        args::parse("req", raw, SPECS, |n| Digest::from_name_opt(n).is_some())?;
    let mut o = Options::default();
    for opt in opts {
        let value = opt.value.clone().unwrap_or_default();
        match opt.name.as_str() {
            "help" => return Ok(None),
            "new" => o.mode = Mode::Create,
            "key" => o.key = Some(value),
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
            "text" | "newkey" | "x509" | "config" | "addext" => {
                return Err(Error::unsupported(format!("req -{}", opt.name)));
            }
            name => {
                o.digest = Some(digest_opt(name).ok_or_else(|| {
                    Error::unsupported(format!("req: digest {name}"))
                })?);
            }
        }
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
    let bytes = match o.output {
        Output::Nothing => Vec::new(),
        Output::Der => request.encode(),
        Output::Pem => request.to_pem().into_bytes(),
    };
    Ok((bytes, o.output_path))
}

#[cfg(test)]
mod tests;
