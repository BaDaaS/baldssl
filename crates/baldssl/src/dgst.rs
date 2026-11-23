//! `baldssl dgst`: hash, MAC, sign and verify files, like `openssl dgst`
//! (`apps/dgst.c`); and its shortcuts `sha1`, `sha224`, `sha256`, `sha384`
//! and `sha512`, which are `dgst -<digest>`.
//!
//! Supported: the files to read as arguments (standard input without
//! one), the digests SHA-1 and SHA-2 (`-sha256` and the others; SHA-256 by
//! default), `-hmac <key>`, `-sign <key>`, `-verify <public key>`,
//! `-prverify <private key>` with `-signature <file>`, `-keyform PEM|DER`,
//! `-out`, `-hex`, `-binary`, `-c` (colons) and `-r` (the coreutils
//! format). Signatures are ECDSA on the key's curve with the digest, and
//! Ed25519, which takes no digest (OpenSSL 3.5 and later; 3.0 cannot sign
//! with it in `dgst`).
//!
//! The output is OpenSSL's, byte for byte: `SHA2-256(file)= <hex>` (but
//! `SHA256` when no digest is named, as OpenSSL's default `EVP_sha256`
//! names itself), the key type in front for a signature or a MAC
//! (`EC-SHA2-256(file)=`, `ED25519(file)=`, `HMAC-SHA256(file)=`) except on
//! standard input, signatures in binary unless `-hex`, and "Verified OK" or
//! "Verification failure". As in OpenSSL, the options end at the first file
//! name, a missing file is reported and the others still processed, a
//! signature file is read up to the longest signature of the key, and a
//! signature that does not verify is told apart from bytes that are not a
//! signature ("Error verifying data").
//!
//! Not supported, and reported as such: other digests (MD5, SHA-3, ...),
//! `-mac`, `-macopt`, `-sigopt`, `-passin`, `-list`, `-xoflen` beyond its
//! error, and RSA keys.

use std::{ffi::OsString, fmt::Write as _, io::Write as _};

use baldssl_core::{Error, Result, encoding::Decodable as _};
use baldssl_crypto::{hash::Algorithm, signature::SignatureAlgorithm};
use baldssl_pkey::{AnyPrivateKey, PublicKey};
use baldssl_x509::{Compat, Format};

use crate::{
    args::{self, Kind, Spec},
    digest::{fetched_name, is_digest_option},
    input::{is_pem, parse_format, read_input},
    output::write_output,
};

/// Every option `baldssl dgst` accepts, besides `-<digest>`.
pub(crate) const SPECS: &[Spec] = &[
    Spec {
        name: "help",
        kind: Kind::Flag,
        help: "Display this summary",
    },
    Spec {
        name: "out",
        kind: Kind::Value,
        help: "Output to filename rather than stdout",
    },
    Spec {
        name: "c",
        kind: Kind::Flag,
        help: "Print the digest with separating colons",
    },
    Spec {
        name: "r",
        kind: Kind::Flag,
        help: "Print the digest in coreutils format",
    },
    Spec {
        name: "hex",
        kind: Kind::Flag,
        help: "Print as hex dump",
    },
    Spec {
        name: "binary",
        kind: Kind::Flag,
        help: "Print in binary form",
    },
    Spec {
        name: "sign",
        kind: Kind::Value,
        help: "Sign digest using private key",
    },
    Spec {
        name: "verify",
        kind: Kind::Value,
        help: "Verify a signature using public key",
    },
    Spec {
        name: "prverify",
        kind: Kind::Value,
        help: "Verify a signature using private key",
    },
    Spec {
        name: "signature",
        kind: Kind::Value,
        help: "File with signature to verify",
    },
    Spec {
        name: "keyform",
        kind: Kind::Value,
        help: "Key file format (DER/PEM)",
    },
    Spec {
        name: "hmac",
        kind: Kind::Value,
        help: "Create hashed MAC with key",
    },
    Spec {
        name: "xoflen",
        kind: Kind::Value,
        help: "Output length for XOF algorithms",
    },
    Spec {
        name: "passin",
        kind: Kind::Value,
        help: "Input file pass phrase source (not supported)",
    },
    Spec {
        name: "sigopt",
        kind: Kind::Value,
        help: "Signature parameter in n:v form (not supported)",
    },
    Spec {
        name: "mac",
        kind: Kind::Value,
        help: "Create MAC (not necessarily HMAC) (not supported)",
    },
    Spec {
        name: "macopt",
        kind: Kind::Value,
        help: "MAC algorithm parameters in n:v form (not supported)",
    },
    Spec {
        name: "list",
        kind: Kind::Flag,
        help: "List digests (not supported)",
    },
];

/// The largest input OpenSSL reads for a one-shot signature (Ed25519),
/// 16 MiB (`do_fp_oneshot_sign`).
const ONESHOT_MAX: usize = 16 * 1024 * 1024;

/// How a digest, MAC or signature is printed in hexadecimal (`-c`, `-r`;
/// the last given wins, as in OpenSSL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Separator {
    /// `NAME(file)= 0a1b...`.
    #[default]
    Plain,
    /// `NAME(file)= 0a:1b:...` (`-c`).
    Colons,
    /// `0a1b... *file` (`-r`), as `sha256sum` prints.
    Coreutils,
}

/// The options, as OpenSSL's `dgst_main` holds them.
#[derive(Debug, Default)]
struct Options {
    /// The digest named, if any.
    digest: Option<Algorithm>,
    /// `-binary` (`Some(true)`) or `-hex` (`Some(false)`), the last given.
    binary: Option<bool>,
    separator: Separator,
    output: Option<OsString>,
    /// `-sign`, `-verify` or `-prverify`: the last key named.
    key_file: Option<OsString>,
    /// `-verify` or `-prverify` was given.
    verify: bool,
    /// `-verify` was given: the key is public.
    public_key: bool,
    signature: Option<OsString>,
    keyform: Option<Format>,
    hmac: Option<OsString>,
    xoflen: bool,
    files: Vec<OsString>,
}

fn parse_options(
    command: &str,
    preset: Option<Algorithm>,
    raw: &[OsString],
) -> Result<Option<Options>> {
    let (opts, files) =
        args::parse_with_operands(command, raw, SPECS, is_digest_option)?;
    let mut o = Options {
        digest: preset,
        files,
        ..Options::default()
    };
    for opt in opts {
        let value = opt.value.clone().unwrap_or_default();
        match opt.name.as_str() {
            "help" => return Ok(None),
            "out" => o.output = Some(value),
            "c" => o.separator = Separator::Colons,
            "r" => o.separator = Separator::Coreutils,
            "hex" => o.binary = Some(false),
            "binary" => o.binary = Some(true),
            "sign" => o.key_file = Some(value),
            "verify" => {
                o.key_file = Some(value);
                o.verify = true;
                o.public_key = true;
            }
            "prverify" => {
                o.key_file = Some(value);
                o.verify = true;
            }
            "signature" => o.signature = Some(value),
            "keyform" => {
                o.keyform = Some(parse_format(&value, command, "keyform")?);
            }
            "hmac" => o.hmac = Some(value),
            "xoflen" => o.xoflen = true,
            name => match Algorithm::from_name_opt(name) {
                Some(algorithm) => o.digest = Some(algorithm),
                None if is_digest_option(name) => {
                    return Err(Error::unsupported(format!("digest {name}")));
                }
                None => {
                    return Err(Error::unsupported(format!(
                        "{command} -{name}"
                    )));
                }
            },
        }
    }
    Ok(Some(o))
}

/// What is done to each input, with the key it needs.
enum Operation {
    /// Hash it.
    Digest,
    /// Its HMAC under this key.
    Hmac(Vec<u8>),
    /// Sign it.
    Sign(AnyPrivateKey),
    /// Verify this signature of it under this key.
    Verify(PublicKey, Vec<u8>),
    /// What OpenSSL does with `-sign` and `-signature` together: it sets
    /// the key up to sign, then asks it to verify the signature read,
    /// which never succeeds.
    VerifyWhileSigning(AnyPrivateKey),
}

impl Operation {
    /// The key type OpenSSL prints in front of a result
    /// (`EVP_PKEY_get0_type_name`).
    fn key_type_opt(&self) -> Option<&'static str> {
        match self {
            Operation::Digest => None,
            Operation::Hmac(_) => Some("HMAC"),
            Operation::Sign(AnyPrivateKey::Ed25519(_))
            | Operation::VerifyWhileSigning(AnyPrivateKey::Ed25519(_))
            | Operation::Verify(PublicKey::Ed25519(_), _) => Some("ED25519"),
            Operation::Sign(_)
            | Operation::VerifyWhileSigning(_)
            | Operation::Verify(..) => Some("EC"),
        }
    }

    /// Whether the key is Ed25519, which signs the message itself: one
    /// shot, no digest.
    fn is_oneshot(&self) -> bool {
        matches!(
            self,
            Operation::Sign(AnyPrivateKey::Ed25519(_))
                | Operation::VerifyWhileSigning(AnyPrivateKey::Ed25519(_))
                | Operation::Verify(PublicKey::Ed25519(_), _)
        )
    }
}

/// A failure OpenSSL reports with this line on standard error, exiting 1.
fn report(line: &str) -> Error {
    note(format!("{line}\n").as_bytes());
    Error::Reported(1)
}

/// Writes `bytes` on standard error.
fn note(bytes: &[u8]) {
    // Nothing to do if standard error is gone.
    let _ = std::io::stderr().write_all(bytes);
}

/// The line OpenSSL prints when it cannot load the key of `-sign` or
/// `-prverify` (private) or `-verify` (public) from `path`
/// (`load_key_certs_crls` in `apps/lib/apps.c`): the file is missing, or
/// holds no such key. From OpenSSL 3.2, a public key that fails to load
/// is described as a private key "of public key", because `load_pubkey`
/// reports the failure of its fallback, reading a private key.
fn key_load_error(
    path: &str,
    public: bool,
    missing: bool,
    compat: Compat,
) -> Error {
    let what = match (public, compat) {
        (false, _) => "private key",
        (true, Compat::V30) => "public key",
        (true, _) => "private key of public key",
    };
    let line = match (missing, compat) {
        (true, Compat::V30) => {
            format!("Could not open file or uri for loading {what} from {path}")
        }
        (true, _) => format!(
            "Could not open file or uri for loading {what} from {path}: No \
             such file or directory"
        ),
        (false, Compat::V30) => format!("Could not read {what} from {path}"),
        (false, Compat::V3) => format!("Could not find {what} from {path}"),
        (false, Compat::V4) => {
            format!("Could not find or decode {what} from {path}")
        }
    };
    report(&line)
}

/// The key of `-sign`, `-verify` or `-prverify`.
fn load_key(o: &Options, path: &OsString, compat: Compat) -> Result<Operation> {
    let label = path.to_string_lossy();
    let fail = |missing| key_load_error(&label, o.public_key, missing, compat);
    let bytes = match read_input(Some(path)) {
        Ok(bytes) => bytes,
        Err(Error::NotFound { .. }) => return Err(fail(true)),
        Err(e) => return Err(e),
    };
    let pem = o
        .keyform
        .map_or_else(|| is_pem(&bytes), |f| f == Format::Pem);
    let private = || {
        if pem {
            AnyPrivateKey::from_pem(&bytes)
        } else {
            AnyPrivateKey::decode(&bytes)
        }
    };
    if !o.public_key {
        return private().map(Operation::Sign).map_err(|_| fail(false));
    }
    let public = if pem {
        PublicKey::from_pem(&bytes)
    } else {
        PublicKey::decode(&bytes)
    };
    // OpenSSL 3.2 and later also take the public key of a private key.
    match (public, compat) {
        (Ok(public), _) => Ok(Operation::Verify(public, Vec::new())),
        (Err(_), Compat::V30) => Err(fail(false)),
        (Err(_), _) => private()
            .map(|k| Operation::Verify(PublicKey::from(&k), Vec::new()))
            .map_err(|_| fail(false)),
    }
}

/// The signature to verify: the first bytes of the file, up to the longest
/// signature of the key, as OpenSSL reads it.
fn read_signature(path: &OsString, public: &PublicKey) -> Result<Vec<u8>> {
    let label = path.to_string_lossy();
    let Ok(mut bytes) = read_input(Some(path)) else {
        return Err(report(&format!("Error opening signature file {label}")));
    };
    bytes.truncate(public.max_signature_len());
    if bytes.is_empty() {
        return Err(report(&format!("Error reading signature file {label}")));
    }
    Ok(bytes)
}

/// Everything to know before reading the inputs, checked in OpenSSL's
/// order.
fn prepare(command: &str, o: &Options, compat: Compat) -> Result<Operation> {
    if o.key_file.is_some() && o.files.len() > 1 {
        return Err(report(&format!(
            "{command}: Can only sign or verify one file."
        )));
    }
    if o.verify && o.signature.is_none() {
        return Err(report(
            "No signature to verify: use the -signature option",
        ));
    }
    if o.hmac.is_some() && o.key_file.is_some() {
        return Err(report("MAC and signing key cannot both be specified"));
    }
    let mut operation = match (&o.key_file, &o.hmac) {
        (Some(path), _) => {
            let mut key = load_key(o, path, compat)?;
            if o.verify
                && let Operation::Sign(private) = &key
            {
                key = Operation::Verify(PublicKey::from(private), Vec::new());
            }
            key
        }
        (None, Some(hmac)) => {
            Operation::Hmac(hmac.to_string_lossy().into_owned().into_bytes())
        }
        (None, None) => Operation::Digest,
    };
    if operation.is_oneshot() {
        if compat == Compat::V30 {
            return Err(report("Key type not supported for this operation"));
        }
        if o.digest.is_some() {
            return Err(report("Error setting context"));
        }
    }
    // OpenSSL reads `-signature` whenever there is a key, MAC keys too.
    if let Some(path) = &o.signature {
        operation = match operation {
            Operation::Verify(public, _) => {
                let signature = read_signature(path, &public)?;
                Operation::Verify(public, signature)
            }
            Operation::Sign(key) => {
                read_signature(path, &PublicKey::from(&key))?;
                Operation::VerifyWhileSigning(key)
            }
            Operation::Hmac(_) => {
                if read_input(Some(path)).is_err() {
                    return Err(report(&format!(
                        "Error opening signature file {}",
                        path.to_string_lossy()
                    )));
                }
                // A MAC key has no signature size, and OpenSSL fails to
                // allocate a buffer of none.
                return Err(report(&format!(
                    "{command}: Could not allocate 0 bytes for signature buffer"
                )));
            }
            other => other,
        };
    }
    if o.xoflen {
        return Err(report("Length can only be specified for XOF"));
    }
    Ok(operation)
}

/// The digest name printed: as fetched when named or chosen for a key,
/// `SHA256` for OpenSSL's built-in default otherwise; none for Ed25519.
fn digest_label_opt(
    o: &Options,
    operation: &Operation,
) -> Option<&'static str> {
    match (o.digest, operation) {
        _ if operation.is_oneshot() => None,
        (Some(a), _) => Some(fetched_name(a)),
        (
            None,
            Operation::Sign(_)
            | Operation::Verify(..)
            | Operation::VerifyWhileSigning(_),
        ) => Some(fetched_name(Algorithm::Sha256)),
        (None, _) => Some("SHA256"),
    }
}

/// `file` with each newline written `\n`, and whether there was one
/// (`newline_escape_filename`).
fn escape_newlines(file: &str) -> (String, bool) {
    (file.replace('\n', "\\n"), file.contains('\n'))
}

/// One result as OpenSSL prints it (`print_out`).
fn print(
    out: &mut Vec<u8>,
    result: &[u8],
    o: &Options,
    binary: bool,
    labels: (Option<&str>, Option<&str>),
    file: &str,
) {
    if binary {
        out.extend_from_slice(result);
        return;
    }
    let mut line = String::new();
    let (key_type, digest) = labels;
    if o.separator == Separator::Coreutils {
        let (name, escaped) = escape_newlines(file);
        if escaped {
            line.push('\\');
        }
        for b in result {
            let _ = write!(line, "{b:02x}");
        }
        let _ = writeln!(line, " *{name}");
    } else {
        match (key_type, digest) {
            (Some(k), Some(d)) => {
                let _ = write!(line, "{k}-{d}({file})= ");
            }
            (Some(name), None) | (None, Some(name)) => {
                let _ = write!(line, "{name}({file})= ");
            }
            (None, None) => {
                let _ = write!(line, "({file})= ");
            }
        }
        for (i, b) in result.iter().enumerate() {
            if o.separator == Separator::Colons && i != 0 {
                line.push(':');
            }
            let _ = write!(line, "{b:02x}");
        }
        line.push('\n');
    }
    out.extend_from_slice(line.as_bytes());
}

/// Processes one input; `false` when it failed (reported on standard
/// error).
fn process(
    out: &mut Vec<u8>,
    o: &Options,
    operation: &Operation,
    data: &[u8],
    file: Option<&str>,
) -> Result<bool> {
    let binary = o.binary.unwrap_or(o.key_file.is_some());
    let label = file.unwrap_or("stdin");
    if operation.is_oneshot() && data.len() > ONESHOT_MAX {
        note(format!("Read error in {label}\n").as_bytes());
        return Ok(false);
    }
    let digest = o.digest.unwrap_or(Algorithm::Sha256);
    let algorithm = if operation.is_oneshot() {
        SignatureAlgorithm::Ed25519
    } else {
        SignatureAlgorithm::Ecdsa(digest)
    };
    let result = match operation {
        Operation::Digest => digest.digest(data),
        Operation::Hmac(key) => digest.hmac(key, data).as_bytes().to_vec(),
        Operation::Sign(key) => key.sign(algorithm, data)?,
        Operation::VerifyWhileSigning(_) if operation.is_oneshot() => {
            note(b"Error verifying data\n");
            return Ok(false);
        }
        Operation::VerifyWhileSigning(_) => {
            out.extend_from_slice(b"Verification failure\n");
            return Ok(false);
        }
        Operation::Verify(public, signature) => {
            return Ok(
                match public.check_signature(algorithm, data, signature) {
                    Ok(true) => {
                        out.extend_from_slice(b"Verified OK\n");
                        true
                    }
                    Ok(false) => {
                        out.extend_from_slice(b"Verification failure\n");
                        false
                    }
                    Err(_) => {
                        note(b"Error verifying data\n");
                        false
                    }
                },
            );
        }
    };
    // The key type is printed for files only, and the digest is printed
    // for everything but Ed25519.
    let key_type = file.and(operation.key_type_opt());
    let labels = (key_type, digest_label_opt(o, operation));
    print(out, &result, o, binary, labels, label);
    Ok(true)
}

/// Renders what `dgst` (or the shortcut `command`, which presets its
/// digest) writes, and where.
///
/// # Errors
///
/// Usage errors and unsupported options; [`Error::Reported`] with exit
/// code 1 for what OpenSSL reports itself (a file that cannot be read, a
/// signature that does not verify, and the errors of its checks), after
/// writing whatever was computed.
pub(crate) fn render(
    command: &str,
    preset: Option<Algorithm>,
    raw: &[OsString],
) -> Result<(Vec<u8>, Option<OsString>)> {
    let Some(o) = parse_options(command, preset, raw)? else {
        return Ok((args::usage(command, SPECS).into_bytes(), None));
    };
    let compat = crate::x509::compat()?;
    let operation = prepare(command, &o, compat)?;
    let mut out = Vec::new();
    let mut ok = true;
    if o.files.is_empty() {
        let data = read_input(None)?;
        ok &= process(&mut out, &o, &operation, &data, None)?;
    }
    for path in &o.files {
        match read_input(Some(path)) {
            Ok(data) => {
                let file = path.to_string_lossy();
                ok &= process(&mut out, &o, &operation, &data, Some(&file))?;
            }
            Err(e) => {
                note(format!("{e}\n").as_bytes());
                ok = false;
            }
        }
    }
    if ok {
        Ok((out, o.output))
    } else {
        write_output(&out, o.output.as_ref())?;
        Err(Error::Reported(1))
    }
}

#[cfg(test)]
mod tests;
