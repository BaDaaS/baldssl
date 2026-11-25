//! `baldssl dgst`: hash, MAC (message authentication code), sign and
//! verify files, like `openssl dgst` (`apps/dgst.c`); and its shortcuts
//! `sha1`, `sha224`, `sha256`, `sha384` and `sha512`, which are
//! `dgst -<digest>`.
//!
//! Terms: SHA, the Secure Hash Algorithm family of [FIPS 180-4]; HMAC, the
//! hash-based MAC of [RFC 2104]; ECDSA, the Elliptic Curve Digital
//! Signature Algorithm of [FIPS 186-5]; XOF, an extendable-output function.
//!
//! [FIPS 180-4]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
//! [RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104
//! [FIPS 186-5]: https://csrc.nist.gov/pubs/fips/186-5/final
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

use std::{ffi::OsString, fmt::Write as _, io::Write as _, path::Path};

use baldssl_core::{Error, Result, encoding::Decodable as _};
use baldssl_crypto::{hash::Algorithm, signature::SignatureAlgorithm};
use baldssl_fs::{Access, write_file};
use baldssl_pkey::{AnyPrivateKey, PublicKey, SignatureCheck};
use baldssl_x509::{Compat, Format};

use crate::{
    args::{self, Kind, Spec},
    digest::is_digest_option,
    input::{is_pem, parse_format, read_input},
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

/// What `openssl dgst` prints for a signature that verifies (`do_fp` in
/// `apps/dgst.c`).
const VERIFIED_OK: &str = "Verified OK\n";
/// What it prints for a signature that does not verify (`do_fp`).
const VERIFICATION_FAILURE: &str = "Verification failure\n";
/// What it prints on standard error for bytes that are not a signature
/// (`do_fp`).
const ERROR_VERIFYING: &str = "Error verifying data\n";
/// Its error for an Ed25519 key in OpenSSL 3.0, which cannot sign with it
/// in `dgst`.
const KEY_TYPE_UNSUPPORTED: &str = "Key type not supported for this operation";
/// Its error for a digest named with a key that takes none (Ed25519).
const ERROR_SETTING_CONTEXT: &str = "Error setting context";
/// Its error for `-xoflen` with a digest that is not an XOF.
const XOF_ONLY: &str = "Length can only be specified for XOF";
/// Its error for `-verify` or `-prverify` without `-signature`.
const NO_SIGNATURE: &str = "No signature to verify: use the -signature option";
/// Its error for `-hmac` with a signing key.
const MAC_AND_KEY: &str = "MAC and signing key cannot both be specified";
/// Its error, after the command name, for a key with several files.
const ONE_FILE_ONLY: &str = "Can only sign or verify one file.";
/// Its error, before the path, for a signature file it cannot open.
const OPENING_SIGNATURE: &str = "Error opening signature file";
/// Its error, before the path, for an empty signature file.
const READING_SIGNATURE: &str = "Error reading signature file";
/// Its error, before the label, for an Ed25519 input over [`ONESHOT_MAX`].
const READ_ERROR_IN: &str = "Read error in";
/// Its error, after the command name, for `-signature` with an HMAC key,
/// which has no signature size (`app_malloc` of zero bytes).
const ZERO_SIGNATURE_BUFFER: &str =
    "Could not allocate 0 bytes for signature buffer";
/// The name OpenSSL's built-in default digest, `EVP_sha256`, prints when no
/// digest is named.
const DEFAULT_DIGEST_NAME: &str = "SHA256";
/// The label of standard input (`apps/dgst.c`).
const STDIN_LABEL: &str = "stdin";
/// The key types OpenSSL prints in front of a result
/// (`EVP_PKEY_get0_type_name`).
const HMAC_KEY_TYPE: &str = "HMAC";
/// See [`HMAC_KEY_TYPE`].
const EC_KEY_TYPE: &str = "EC";
/// See [`HMAC_KEY_TYPE`].
const ED25519_KEY_TYPE: &str = "ED25519";
/// The parts of the line OpenSSL prints when it cannot load a key
/// (`load_key_certs_crls` in `apps/lib/apps.c`).
const COULD_NOT_OPEN: &str = "Could not open file or uri for loading";
/// See [`COULD_NOT_OPEN`]: OpenSSL 3.0's word for a key it cannot read.
const COULD_NOT_READ: &str = "Could not read";
/// See [`COULD_NOT_OPEN`]: OpenSSL 3.2 to 3.6.
const COULD_NOT_FIND: &str = "Could not find";
/// See [`COULD_NOT_OPEN`]: OpenSSL 4.
const COULD_NOT_FIND_OR_DECODE: &str = "Could not find or decode";
/// See [`COULD_NOT_OPEN`]: what follows a missing file from OpenSSL 3.2.
const NO_SUCH_FILE: &str = "No such file or directory";
/// How OpenSSL describes the key it loads (`load_key` and `load_pubkey` in
/// `apps/lib/apps.c`): a private key.
const PRIVATE_KEY_DESC: &str = "private key";
/// See [`PRIVATE_KEY_DESC`]: a public key, in OpenSSL 3.0.
const PUBLIC_KEY_DESC: &str = "public key";
/// See [`PRIVATE_KEY_DESC`]: a public key from OpenSSL 3.2, as the
/// failure of its fallback describes it.
const PUBLIC_KEY_FALLBACK_DESC: &str = "private key of public key";

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

/// How a result is printed: `-hex` or `-binary`, the last given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// `-hex`.
    Hex,
    /// `-binary`.
    Binary,
}

/// What the key of `-sign`, `-verify` or `-prverify` is for. OpenSSL sets
/// sticky flags (`do_verify`, `want_pub`), which no later option clears:
/// the role is the greatest of those given, in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum KeyRole {
    /// `-sign`: a private key, to sign.
    Sign,
    /// `-prverify`: a private key, to verify.
    PrVerify,
    /// `-verify`: a public key, to verify.
    Verify,
}

impl KeyRole {
    /// Whether the key verifies.
    fn verifies(self) -> bool {
        self != KeyRole::Sign
    }

    /// Whether the key is public.
    fn is_public(self) -> bool {
        self == KeyRole::Verify
    }
}

/// The options, as OpenSSL's `dgst_main` holds them.
#[derive(Debug, Default)]
struct Options {
    /// The digest named, if any.
    digest: Option<Algorithm>,
    /// `-hex` or `-binary`, the last given.
    encoding: Option<Encoding>,
    separator: Separator,
    output: Option<OsString>,
    /// `-sign`, `-verify` or `-prverify`: the last key named.
    key_file: Option<OsString>,
    /// What the key is for, once one is named.
    role: Option<KeyRole>,
    signature: Option<OsString>,
    keyform: Option<Format>,
    hmac: Option<OsString>,
    xoflen: bool,
    files: Vec<OsString>,
}

impl Options {
    /// A key named for `role`: the last name wins, the role is the
    /// greatest given ([`KeyRole`]).
    fn name_key(&mut self, path: OsString, role: KeyRole) {
        self.key_file = Some(path);
        self.role = Some(self.role.map_or(role, |r| r.max(role)));
    }

    /// Whether the key, if any, verifies.
    fn verifies(&self) -> bool {
        self.role.is_some_and(KeyRole::verifies)
    }
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
            "hex" => o.encoding = Some(Encoding::Hex),
            "binary" => o.encoding = Some(Encoding::Binary),
            "sign" => o.name_key(value, KeyRole::Sign),
            "verify" => o.name_key(value, KeyRole::Verify),
            "prverify" => o.name_key(value, KeyRole::PrVerify),
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
            Operation::Hmac(_) => Some(HMAC_KEY_TYPE),
            Operation::Sign(AnyPrivateKey::Ed25519(_))
            | Operation::VerifyWhileSigning(AnyPrivateKey::Ed25519(_))
            | Operation::Verify(PublicKey::Ed25519(_), _) => {
                Some(ED25519_KEY_TYPE)
            }
            Operation::Sign(_)
            | Operation::VerifyWhileSigning(_)
            | Operation::Verify(..) => Some(EC_KEY_TYPE),
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

/// The exit code of `openssl dgst` when anything fails (`apps/dgst.c`
/// ends with `ret = 1` on every error path).
const DGST_FAILED: u8 = 1;

/// A failure OpenSSL reports with this line on standard error.
fn report(line: &str) -> Error {
    note(format!("{line}\n").as_bytes());
    Error::Reported {
        code: DGST_FAILED,
        output: Vec::new(),
    }
}

/// Writes `bytes` on standard error.
fn note(bytes: &[u8]) {
    // Nothing to do if standard error is gone.
    let _ = std::io::stderr().write_all(bytes);
}

/// Why a key did not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadFailure {
    /// The file does not exist.
    Missing,
    /// The file holds no such key.
    NoKey,
}

/// The line OpenSSL prints when it cannot load the key of `-sign` or
/// `-prverify` (private) or `-verify` (public) from `path`
/// (`load_key_certs_crls` in `apps/lib/apps.c`): the file is missing, or
/// holds no such key. From OpenSSL 3.2, a public key that fails to load
/// is described as a private key "of public key", because `load_pubkey`
/// reports the failure of its fallback, reading a private key.
fn key_load_error(
    path: &str,
    role: KeyRole,
    failure: LoadFailure,
    compat: Compat,
) -> Error {
    let what = match (role.is_public(), compat) {
        (false, _) => PRIVATE_KEY_DESC,
        (true, Compat::V30) => PUBLIC_KEY_DESC,
        (true, _) => PUBLIC_KEY_FALLBACK_DESC,
    };
    let line = match (failure, compat) {
        (LoadFailure::Missing, Compat::V30) => {
            format!("{COULD_NOT_OPEN} {what} from {path}")
        }
        (LoadFailure::Missing, _) => {
            format!("{COULD_NOT_OPEN} {what} from {path}: {NO_SUCH_FILE}")
        }
        (LoadFailure::NoKey, Compat::V30) => {
            format!("{COULD_NOT_READ} {what} from {path}")
        }
        (LoadFailure::NoKey, Compat::V3 | Compat::V36) => {
            format!("{COULD_NOT_FIND} {what} from {path}")
        }
        (LoadFailure::NoKey, Compat::V4) => {
            format!("{COULD_NOT_FIND_OR_DECODE} {what} from {path}")
        }
    };
    report(&line)
}

/// The key of `-sign`, `-verify` or `-prverify`.
fn load_key(
    o: &Options,
    path: &OsString,
    role: KeyRole,
    compat: Compat,
) -> Result<Operation> {
    let label = path.to_string_lossy();
    let fail = |failure| key_load_error(&label, role, failure, compat);
    let bytes = match read_input(Some(path)) {
        Ok(bytes) => bytes,
        Err(Error::NotFound { .. }) => return Err(fail(LoadFailure::Missing)),
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
    if !role.is_public() {
        return private()
            .map(Operation::Sign)
            .map_err(|_| fail(LoadFailure::NoKey));
    }
    let public = if pem {
        PublicKey::from_pem(&bytes)
    } else {
        PublicKey::decode(&bytes)
    };
    // OpenSSL 3.2 and later also take the public key of a private key.
    match (public, compat) {
        (Ok(public), _) => Ok(Operation::Verify(public, Vec::new())),
        (Err(_), Compat::V30) => Err(fail(LoadFailure::NoKey)),
        (Err(_), _) => private()
            .map(|k| Operation::Verify(PublicKey::from(&k), Vec::new()))
            .map_err(|_| fail(LoadFailure::NoKey)),
    }
}

/// The signature to verify: the first bytes of the file, up to the longest
/// signature of the key, as OpenSSL reads it.
fn read_signature(path: &OsString, public: &PublicKey) -> Result<Vec<u8>> {
    let label = path.to_string_lossy();
    let Ok(mut bytes) = read_input(Some(path)) else {
        return Err(report(&format!("{OPENING_SIGNATURE} {label}")));
    };
    bytes.truncate(public.max_signature_len());
    if bytes.is_empty() {
        return Err(report(&format!("{READING_SIGNATURE} {label}")));
    }
    Ok(bytes)
}

/// Everything to know before reading the inputs, checked in OpenSSL's
/// order.
fn prepare(command: &str, o: &Options, compat: Compat) -> Result<Operation> {
    if o.key_file.is_some() && o.files.len() > 1 {
        return Err(report(&format!("{command}: {ONE_FILE_ONLY}")));
    }
    if o.verifies() && o.signature.is_none() {
        return Err(report(NO_SIGNATURE));
    }
    if o.hmac.is_some() && o.key_file.is_some() {
        return Err(report(MAC_AND_KEY));
    }
    let mut operation = match (&o.key_file, o.role, &o.hmac) {
        (Some(path), Some(role), _) => {
            let mut key = load_key(o, path, role, compat)?;
            if role.verifies()
                && let Operation::Sign(private) = &key
            {
                key = Operation::Verify(PublicKey::from(private), Vec::new());
            }
            key
        }
        // The key is the argument's bytes, as OpenSSL takes them.
        (_, _, Some(hmac)) => Operation::Hmac(hmac.as_encoded_bytes().to_vec()),
        (_, _, None) => Operation::Digest,
    };
    if operation.is_oneshot() {
        if compat == Compat::V30 {
            return Err(report(KEY_TYPE_UNSUPPORTED));
        }
        if o.digest.is_some() {
            return Err(report(ERROR_SETTING_CONTEXT));
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
                        "{OPENING_SIGNATURE} {}",
                        path.to_string_lossy()
                    )));
                }
                // A MAC key has no signature size, and OpenSSL fails to
                // allocate a buffer of none.
                return Err(report(&format!(
                    "{command}: {ZERO_SIGNATURE_BUFFER}"
                )));
            }
            other @ (Operation::Digest | Operation::VerifyWhileSigning(_)) => {
                other
            }
        };
    }
    if o.xoflen {
        return Err(report(XOF_ONLY));
    }
    Ok(operation)
}

/// What is printed in front of a result: the key type and the digest name,
/// each when there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Labels<'a> {
    /// The key type ([`Operation::key_type_opt`]), for files.
    key_type: Option<&'a str>,
    /// The digest name ([`Options::digest_label_opt`]).
    digest: Option<&'a str>,
}

/// A file name with each newline written `\n` (`newline_escape_filename`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct EscapedName {
    /// The name, escaped.
    text: String,
    /// Whether it had a newline, which marks the line with a backslash.
    escaped: bool,
}

impl EscapedName {
    /// The escaped form of `file`.
    fn new(file: &str) -> Self {
        EscapedName {
            text: file.replace('\n', "\\n"),
            escaped: file.contains('\n'),
        }
    }
}

impl Options {
    /// The digest name printed: as fetched when named or chosen for a key,
    /// [`DEFAULT_DIGEST_NAME`] for OpenSSL's built-in default otherwise;
    /// none for Ed25519.
    fn digest_label_opt(&self, operation: &Operation) -> Option<&'static str> {
        match (self.digest, operation) {
            _ if operation.is_oneshot() => None,
            (Some(a), _) => Some(a.fetched_name()),
            (
                None,
                Operation::Sign(_)
                | Operation::Verify(..)
                | Operation::VerifyWhileSigning(_),
            ) => Some(Algorithm::Sha256.fetched_name()),
            (None, _) => Some(DEFAULT_DIGEST_NAME),
        }
    }

    /// One result as OpenSSL prints it (`print_out`).
    fn print(
        &self,
        out: &mut Vec<u8>,
        result: &[u8],
        encoding: Encoding,
        labels: Labels<'_>,
        file: &str,
    ) {
        if encoding == Encoding::Binary {
            out.extend_from_slice(result);
            return;
        }
        let mut line = String::new();
        if self.separator == Separator::Coreutils {
            let name = EscapedName::new(file);
            if name.escaped {
                line.push('\\');
            }
            for b in result {
                let _ = write!(line, "{b:02x}");
            }
            let _ = writeln!(line, " *{}", name.text);
        } else {
            match (labels.key_type, labels.digest) {
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
                if self.separator == Separator::Colons && i != 0 {
                    line.push(':');
                }
                let _ = write!(line, "{b:02x}");
            }
            line.push('\n');
        }
        out.extend_from_slice(line.as_bytes());
    }
}

/// How processing one input ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Its result was written.
    Done,
    /// It failed, and the failure was reported.
    Failed,
}

/// Processes one input, writing its result to `out`.
fn process(
    out: &mut Vec<u8>,
    o: &Options,
    operation: &Operation,
    data: &[u8],
    file: Option<&str>,
) -> Result<Outcome> {
    // Signatures are binary unless -hex, everything else hex.
    let encoding = o.encoding.unwrap_or(if o.key_file.is_some() {
        Encoding::Binary
    } else {
        Encoding::Hex
    });
    let label = file.unwrap_or(STDIN_LABEL);
    if operation.is_oneshot() && data.len() > ONESHOT_MAX {
        note(format!("{READ_ERROR_IN} {label}\n").as_bytes());
        return Ok(Outcome::Failed);
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
            note(ERROR_VERIFYING.as_bytes());
            return Ok(Outcome::Failed);
        }
        Operation::VerifyWhileSigning(_) => {
            out.extend_from_slice(VERIFICATION_FAILURE.as_bytes());
            return Ok(Outcome::Failed);
        }
        Operation::Verify(public, signature) => {
            return Ok(
                match public.check_signature(algorithm, data, signature)? {
                    SignatureCheck::Verified => {
                        out.extend_from_slice(VERIFIED_OK.as_bytes());
                        Outcome::Done
                    }
                    SignatureCheck::Failed => {
                        out.extend_from_slice(VERIFICATION_FAILURE.as_bytes());
                        Outcome::Failed
                    }
                    SignatureCheck::Malformed => {
                        note(ERROR_VERIFYING.as_bytes());
                        Outcome::Failed
                    }
                },
            );
        }
    };
    // The key type is printed for files only, and the digest is printed
    // for everything but Ed25519.
    let labels = Labels {
        key_type: file.and(operation.key_type_opt()),
        digest: o.digest_label_opt(operation),
    };
    o.print(out, &result, encoding, labels, label);
    Ok(Outcome::Done)
}

/// Renders what `dgst` (or the shortcut `command`, which presets its
/// digest) writes, and where.
///
/// # Errors
///
/// Usage errors and unsupported options; [`Error::Reported`] with exit
/// code [`DGST_FAILED`] for what OpenSSL reports itself (a file that cannot be read, a
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
    let mut outcomes = Vec::new();
    if o.files.is_empty() {
        let data = read_input(None)?;
        outcomes.push(process(&mut out, &o, &operation, &data, None)?);
    }
    for path in &o.files {
        match read_input(Some(path)) {
            Ok(data) => {
                let file = path.to_string_lossy();
                outcomes.push(process(
                    &mut out,
                    &o,
                    &operation,
                    &data,
                    Some(&file),
                )?);
            }
            Err(e) => {
                note(format!("{e}\n").as_bytes());
                outcomes.push(Outcome::Failed);
            }
        }
    }
    if !outcomes.contains(&Outcome::Failed) {
        return Ok((out, o.output));
    }
    // What was computed is still written: to -out, or, through the
    // failure, to standard output.
    let output = match &o.output {
        Some(path) => {
            write_file(Path::new(path), Access::Default, &out)?;
            Vec::new()
        }
        None => out,
    };
    Err(Error::Reported {
        code: DGST_FAILED,
        output,
    })
}

#[cfg(test)]
mod tests;
