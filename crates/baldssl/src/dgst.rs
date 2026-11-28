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

use std::{ffi::OsString, fmt::Write as _};

use baldssl_core::{Error, Result, encoding::Decodable as _};
use baldssl_crypto::{
    hash::Algorithm, secret::SecretBytes, signature::SignatureAlgorithm,
};
use baldssl_fs::Access;
use baldssl_pkey::{AnyPrivateKey, PublicKey, SignatureCheck};
use baldssl_x509::{Compat, Format, OneshotSigning, PublicKeyLoading};

use crate::{
    args::{self, Kind, Spec, Unknown},
    digest::DigestName,
    input::{compat, format_value, read_input},
    load::{Credential, LoadFailure, load_line},
    outputs::Outputs,
};

/// An option of `baldssl dgst` and of its shortcuts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Opt {
    /// `-help`.
    Help,
    /// `-out`.
    Out(OsString),
    /// `-c`.
    Colons,
    /// `-r`.
    Coreutils,
    /// `-hex`.
    Hex,
    /// `-binary`.
    Binary,
    /// `-sign`.
    Sign(OsString),
    /// `-verify`.
    Verify(OsString),
    /// `-prverify`.
    PrVerify(OsString),
    /// `-signature`.
    Signature(OsString),
    /// `-keyform`.
    Keyform(OsString),
    /// `-hmac`.
    Hmac(OsString),
    /// `-xoflen`.
    Xoflen(OsString),
    /// `-passin`.
    Passin(OsString),
    /// `-sigopt`.
    Sigopt(OsString),
    /// `-mac`.
    Mac(OsString),
    /// `-macopt`.
    Macopt(OsString),
    /// `-list`.
    List,
    /// `-<digest>`, a digest baldssl has.
    Digest(Algorithm),
    /// `-<digest>`, a digest OpenSSL has and baldssl does not.
    UnimplementedDigest,
}

/// Every option `baldssl dgst` accepts, besides `-<digest>`.
pub(crate) const SPECS: &[Spec<Opt>] = &[
    Spec {
        name: "help",
        kind: Kind::Flag(Opt::Help),
        help: "Display this summary",
    },
    Spec {
        name: "out",
        kind: Kind::Value(Opt::Out),
        help: "Output to filename rather than stdout",
    },
    Spec {
        name: "c",
        kind: Kind::Flag(Opt::Colons),
        help: "Print the digest with separating colons",
    },
    Spec {
        name: "r",
        kind: Kind::Flag(Opt::Coreutils),
        help: "Print the digest in coreutils format",
    },
    Spec {
        name: "hex",
        kind: Kind::Flag(Opt::Hex),
        help: "Print as hex dump",
    },
    Spec {
        name: "binary",
        kind: Kind::Flag(Opt::Binary),
        help: "Print in binary form",
    },
    Spec {
        name: "sign",
        kind: Kind::Value(Opt::Sign),
        help: "Sign digest using private key",
    },
    Spec {
        name: "verify",
        kind: Kind::Value(Opt::Verify),
        help: "Verify a signature using public key",
    },
    Spec {
        name: "prverify",
        kind: Kind::Value(Opt::PrVerify),
        help: "Verify a signature using private key",
    },
    Spec {
        name: "signature",
        kind: Kind::Value(Opt::Signature),
        help: "File with signature to verify",
    },
    Spec {
        name: "keyform",
        kind: Kind::Value(Opt::Keyform),
        help: "Key file format (DER/PEM)",
    },
    Spec {
        name: "hmac",
        kind: Kind::Value(Opt::Hmac),
        help: "Create hashed MAC with key",
    },
    Spec {
        name: "xoflen",
        kind: Kind::Value(Opt::Xoflen),
        help: "Output length for XOF algorithms",
    },
    Spec {
        name: "passin",
        kind: Kind::Value(Opt::Passin),
        help: "Input file pass phrase source (not supported)",
    },
    Spec {
        name: "sigopt",
        kind: Kind::Value(Opt::Sigopt),
        help: "Signature parameter in n:v form (not supported)",
    },
    Spec {
        name: "mac",
        kind: Kind::Value(Opt::Mac),
        help: "Create MAC (not necessarily HMAC) (not supported)",
    },
    Spec {
        name: "macopt",
        kind: Kind::Value(Opt::Macopt),
        help: "MAC algorithm parameters in n:v form (not supported)",
    },
    Spec {
        name: "list",
        kind: Kind::Flag(Opt::List),
        help: "List digests (not supported)",
    },
];

/// The option a `-<digest>` names, if any.
fn digest_option_opt(name: &str) -> Option<Opt> {
    DigestName::from_option_opt(name).map(|digest| match digest {
        DigestName::Implemented(algorithm) => Opt::Digest(algorithm),
        DigestName::Unimplemented => Opt::UnimplementedDigest,
    })
}

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
/// How OpenSSL describes the key it loads (`load_key` and `load_pubkey` in
/// `apps/lib/apps.c`): a private key.
const PRIVATE_KEY_DESC: &str = "private key";
/// See [`PRIVATE_KEY_DESC`]: a public key, also when OpenSSL 3.2 and later
/// fall back to loading a private key for it.
const PUBLIC_KEY_DESC: &str = "public key";

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

/// What a key is used for: signing or verifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// It signs.
    Signs,
    /// It verifies.
    Verifies,
}

/// The kind of key a role reads from its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    /// A private key.
    Private,
    /// A public key.
    Public,
}

impl KeyRole {
    /// What the key is for.
    fn purpose(self) -> Purpose {
        match self {
            KeyRole::Sign => Purpose::Signs,
            KeyRole::PrVerify | KeyRole::Verify => Purpose::Verifies,
        }
    }

    /// The kind of key read.
    fn key_kind(self) -> KeyKind {
        match self {
            KeyRole::Sign | KeyRole::PrVerify => KeyKind::Private,
            KeyRole::Verify => KeyKind::Public,
        }
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
    /// `-xoflen`, which no digest baldssl has accepts.
    xoflen: Option<OsString>,
    files: Vec<OsString>,
}

impl Options {
    /// A key named for `role`: the last name wins, the role is the
    /// greatest given ([`KeyRole`]).
    fn name_key(&mut self, path: OsString, role: KeyRole) {
        self.key_file = Some(path);
        self.role = Some(self.role.map_or(role, |r| r.max(role)));
    }

    /// What the key, if any, is for.
    fn purpose_opt(&self) -> Option<Purpose> {
        self.role.map(KeyRole::purpose)
    }
}

/// The options of `command`, `dgst` or a shortcut that presets its digest;
/// `None` for `-help`.
fn parse_options(
    command: &str,
    preset: Option<Algorithm>,
    raw: &[OsString],
) -> Result<Option<Options>> {
    let (opts, files) = args::parse_with_operands(
        command,
        raw,
        SPECS,
        Unknown::Digests(digest_option_opt),
    )?;
    let mut o = Options {
        digest: preset,
        files,
        ..Options::default()
    };
    for given in opts {
        match given.option {
            Opt::Help => return Ok(None),
            Opt::Out(v) => o.output = Some(v),
            Opt::Colons => o.separator = Separator::Colons,
            Opt::Coreutils => o.separator = Separator::Coreutils,
            Opt::Hex => o.encoding = Some(Encoding::Hex),
            Opt::Binary => o.encoding = Some(Encoding::Binary),
            Opt::Sign(v) => o.name_key(v, KeyRole::Sign),
            Opt::Verify(v) => o.name_key(v, KeyRole::Verify),
            Opt::PrVerify(v) => o.name_key(v, KeyRole::PrVerify),
            Opt::Signature(v) => o.signature = Some(v),
            Opt::Keyform(v) => {
                o.keyform = Some(format_value(&v, command, "keyform")?);
            }
            Opt::Hmac(v) => o.hmac = Some(v),
            Opt::Xoflen(v) => o.xoflen = Some(v),
            Opt::Digest(algorithm) => o.digest = Some(algorithm),
            Opt::UnimplementedDigest => {
                return Err(Error::unsupported(format!(
                    "digest {}",
                    given.name
                )));
            }
            Opt::Passin(_)
            | Opt::Sigopt(_)
            | Opt::Mac(_)
            | Opt::Macopt(_)
            | Opt::List => {
                return Err(Error::unsupported(format!(
                    "{command} -{}",
                    given.name
                )));
            }
        }
    }
    Ok(Some(o))
}

/// What is done to each input, with the key it needs.
enum Operation {
    /// Hash it.
    Digest,
    /// Its HMAC under this key.
    Hmac(SecretBytes),
    /// Sign it.
    Sign(AnyPrivateKey),
    /// Verify this signature of it under this key.
    Verify(PublicKey, Vec<u8>),
    /// What OpenSSL does with `-sign` and `-signature` together: it sets
    /// the key up to sign, then asks it to verify the signature read,
    /// which never succeeds.
    VerifyWhileSigning(AnyPrivateKey),
}

/// How a key signs: the message itself, in one shot (Ed25519), or its
/// digest (ECDSA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signer {
    /// No key: a digest or a MAC.
    None,
    /// ECDSA, over the digest.
    Digest,
    /// Ed25519, over the message, with no digest.
    Oneshot,
}

impl Operation {
    /// How its key signs.
    fn signer(&self) -> Signer {
        match self {
            Operation::Digest | Operation::Hmac(_) => Signer::None,
            Operation::Sign(AnyPrivateKey::Ed25519(_))
            | Operation::VerifyWhileSigning(AnyPrivateKey::Ed25519(_))
            | Operation::Verify(PublicKey::Ed25519(_), _) => Signer::Oneshot,
            Operation::Sign(
                AnyPrivateKey::P256(_)
                | AnyPrivateKey::P384(_)
                | AnyPrivateKey::P521(_),
            )
            | Operation::VerifyWhileSigning(
                AnyPrivateKey::P256(_)
                | AnyPrivateKey::P384(_)
                | AnyPrivateKey::P521(_),
            )
            | Operation::Verify(
                PublicKey::P256(_) | PublicKey::P384(_) | PublicKey::P521(_),
                _,
            ) => Signer::Digest,
        }
    }

    /// The key type OpenSSL prints in front of a result
    /// (`EVP_PKEY_get0_type_name`).
    fn key_type_opt(&self) -> Option<&'static str> {
        match (self, self.signer()) {
            (Operation::Digest, _) => None,
            (Operation::Hmac(_), _) => Some(HMAC_KEY_TYPE),
            (_, Signer::Oneshot) => Some(ED25519_KEY_TYPE),
            (_, Signer::Digest | Signer::None) => Some(EC_KEY_TYPE),
        }
    }
}

/// The exit code of `openssl dgst` when anything fails (`apps/dgst.c`
/// ends with `ret = 1` on every error path).
const DGST_FAILED: u8 = 1;

/// A failure OpenSSL reports with this line on standard error.
fn report(out: &mut Outputs, line: &str) -> Error {
    out.diagnostic(line);
    Error::Reported {
        code: DGST_FAILED,
        output: Vec::new(),
    }
}

/// The line OpenSSL prints when it cannot load the key of `-sign` or
/// `-prverify` (private) or `-verify` (public) from `path`. A public key
/// that fails to load where OpenSSL falls back to a private key
/// ([`Compat::public_key_loading`]) is reported as that fallback's failure,
/// a private key described as "public key".
fn key_load_line(
    path: &str,
    kind: KeyKind,
    failure: LoadFailure,
    compat: Compat,
) -> String {
    let (credential, desc) = match (kind, compat.public_key_loading()) {
        (KeyKind::Private, _) => (Credential::PrivateKey, PRIVATE_KEY_DESC),
        (KeyKind::Public, PublicKeyLoading::PublicOnly) => {
            (Credential::PublicKey, PUBLIC_KEY_DESC)
        }
        (KeyKind::Public, PublicKeyLoading::PrivateFallback) => {
            (Credential::PrivateKey, PUBLIC_KEY_DESC)
        }
    };
    load_line(credential, desc, path, failure, compat)
}

/// A private key, PEM or DER.
fn private_key(bytes: &[u8], format: Format) -> Result<AnyPrivateKey> {
    match format {
        Format::Pem => AnyPrivateKey::from_pem(bytes),
        Format::Der => AnyPrivateKey::decode(bytes),
    }
}

/// A public key, PEM or DER.
fn public_key(bytes: &[u8], format: Format) -> Result<PublicKey> {
    match format {
        Format::Pem => PublicKey::from_pem(bytes),
        Format::Der => PublicKey::decode(bytes),
    }
}

/// The key of `-sign`, `-verify` or `-prverify`.
fn load_key(
    out: &mut Outputs,
    o: &Options,
    path: &OsString,
    role: KeyRole,
    compat: Compat,
) -> Result<Operation> {
    let label = path.to_string_lossy();
    let kind = role.key_kind();
    let mut fail = |failure| {
        let line = key_load_line(&label, kind, failure, compat);
        report(out, &line)
    };
    let bytes = match read_input(Some(path)) {
        Ok(bytes) => bytes,
        Err(Error::NotFound { .. }) => return Err(fail(LoadFailure::Missing)),
        Err(e) => return Err(e),
    };
    let format = Format::given_or_detected(o.keyform, &bytes);
    match (kind, compat.public_key_loading()) {
        (KeyKind::Private, _) => private_key(&bytes, format)
            .map(Operation::Sign)
            .map_err(|_| fail(LoadFailure::Undecoded)),
        (KeyKind::Public, loading) => {
            match (public_key(&bytes, format), loading) {
                (Ok(public), _) => Ok(Operation::Verify(public, Vec::new())),
                (Err(_), PublicKeyLoading::PublicOnly) => {
                    Err(fail(LoadFailure::Undecoded))
                }
                (Err(_), PublicKeyLoading::PrivateFallback) => {
                    private_key(&bytes, format)
                        .map(|k| {
                            Operation::Verify(PublicKey::from(&k), Vec::new())
                        })
                        .map_err(|_| fail(LoadFailure::Undecoded))
                }
            }
        }
    }
}

/// The signature to verify: the first bytes of the file, up to the longest
/// signature of the key, as OpenSSL reads it.
fn read_signature(
    out: &mut Outputs,
    path: &OsString,
    public: &PublicKey,
) -> Result<Vec<u8>> {
    let label = path.to_string_lossy();
    let Ok(mut bytes) = read_input(Some(path)) else {
        return Err(report(out, &format!("{OPENING_SIGNATURE} {label}")));
    };
    bytes.truncate(public.max_signature_len());
    if bytes.is_empty() {
        return Err(report(out, &format!("{READING_SIGNATURE} {label}")));
    }
    Ok(bytes)
}

/// Everything to know before reading the inputs, checked in OpenSSL's
/// order.
fn prepare(
    out: &mut Outputs,
    command: &str,
    o: &Options,
    compat: Compat,
) -> Result<Operation> {
    if o.key_file.is_some() && o.files.len() > 1 {
        return Err(report(out, &format!("{command}: {ONE_FILE_ONLY}")));
    }
    match (o.purpose_opt(), &o.signature) {
        (Some(Purpose::Verifies), None) => {
            return Err(report(out, NO_SIGNATURE));
        }
        (Some(Purpose::Verifies), Some(_))
        | (Some(Purpose::Signs) | None, _) => {}
    }
    if o.hmac.is_some() && o.key_file.is_some() {
        return Err(report(out, MAC_AND_KEY));
    }
    let mut operation = match (&o.key_file, o.role, &o.hmac) {
        (Some(path), Some(role), _) => {
            match (load_key(out, o, path, role, compat)?, role.purpose()) {
                (Operation::Sign(private), Purpose::Verifies) => {
                    Operation::Verify(PublicKey::from(&private), Vec::new())
                }
                (key, Purpose::Signs | Purpose::Verifies) => key,
            }
        }
        // The key is the argument's bytes, as OpenSSL takes them.
        (_, _, Some(hmac)) => {
            Operation::Hmac(SecretBytes::new(hmac.as_encoded_bytes().to_vec()))
        }
        (_, _, None) => Operation::Digest,
    };
    match (operation.signer(), compat.dgst_oneshot(), o.digest) {
        (Signer::Oneshot, OneshotSigning::Refused, _) => {
            return Err(report(out, KEY_TYPE_UNSUPPORTED));
        }
        (Signer::Oneshot, OneshotSigning::Supported, Some(_)) => {
            return Err(report(out, ERROR_SETTING_CONTEXT));
        }
        (Signer::Oneshot, OneshotSigning::Supported, None)
        | (Signer::None | Signer::Digest, _, _) => {}
    }
    // OpenSSL reads `-signature` whenever there is a key, MAC keys too.
    if let Some(path) = &o.signature {
        operation = match operation {
            Operation::Verify(public, _) => {
                let signature = read_signature(out, path, &public)?;
                Operation::Verify(public, signature)
            }
            Operation::Sign(key) => {
                read_signature(out, path, &PublicKey::from(&key))?;
                Operation::VerifyWhileSigning(key)
            }
            Operation::Hmac(_) => {
                if read_input(Some(path)).is_err() {
                    return Err(report(
                        out,
                        &format!(
                            "{OPENING_SIGNATURE} {}",
                            path.to_string_lossy()
                        ),
                    ));
                }
                // A MAC key has no signature size, and OpenSSL fails to
                // allocate a buffer of none.
                return Err(report(
                    out,
                    &format!("{command}: {ZERO_SIGNATURE_BUFFER}"),
                ));
            }
            other @ (Operation::Digest | Operation::VerifyWhileSigning(_)) => {
                other
            }
        };
    }
    if o.xoflen.is_some() {
        return Err(report(out, XOF_ONLY));
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
    escape: Escape,
}

/// Whether a coreutils line starts with a backslash, as it does when its
/// file name had a newline to escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escape {
    /// The name is as given.
    None,
    /// A newline was escaped: the line starts with `\`.
    Marked,
}

impl EscapedName {
    /// The escaped form of `file`.
    fn new(file: &str) -> Self {
        EscapedName {
            text: file.replace('\n', "\\n"),
            escape: if file.contains('\n') {
                Escape::Marked
            } else {
                Escape::None
            },
        }
    }
}

impl Options {
    /// The digest name printed: as fetched when named or chosen for a key,
    /// [`DEFAULT_DIGEST_NAME`] for OpenSSL's built-in default otherwise;
    /// none for Ed25519.
    fn digest_label_opt(&self, operation: &Operation) -> Option<&'static str> {
        match (self.digest, operation.signer()) {
            (_, Signer::Oneshot) => None,
            (Some(a), Signer::None | Signer::Digest) => Some(a.fetched_name()),
            (None, Signer::Digest) => Some(Algorithm::Sha256.fetched_name()),
            (None, Signer::None) => Some(DEFAULT_DIGEST_NAME),
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
        match encoding {
            Encoding::Binary => {
                out.extend_from_slice(result);
                return;
            }
            Encoding::Hex => {}
        }
        // Writing to a String cannot fail.
        let mut line = String::new();
        match self.separator {
            Separator::Coreutils => {
                let name = EscapedName::new(file);
                match name.escape {
                    Escape::Marked => line.push('\\'),
                    Escape::None => {}
                }
                for b in result {
                    let _ = write!(line, "{b:02x}");
                }
                let _ = writeln!(line, " *{}", name.text);
            }
            Separator::Plain | Separator::Colons => {
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
                    match (self.separator, i) {
                        (Separator::Colons, 1..) => line.push(':'),
                        (Separator::Colons, 0)
                        | (Separator::Plain | Separator::Coreutils, _) => {}
                    }
                    let _ = write!(line, "{b:02x}");
                }
                line.push('\n');
            }
        }
        out.extend_from_slice(line.as_bytes());
    }
}

/// How processing the inputs ended: done, unless one failed, so that the
/// outcome of several is their maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
enum Outcome {
    /// Its result was written.
    #[default]
    Done,
    /// It failed, and the failure was reported.
    Failed,
}

/// Processes one input, writing its result to `results` and what OpenSSL
/// reports to `out`.
fn process(
    out: &mut Outputs,
    results: &mut Vec<u8>,
    o: &Options,
    operation: &Operation,
    data: &[u8],
    file: Option<&str>,
) -> Result<Outcome> {
    // Signatures are binary unless -hex, everything else hex.
    let encoding = o.encoding.unwrap_or(match o.key_file {
        Some(_) => Encoding::Binary,
        None => Encoding::Hex,
    });
    // No file is standard input, which OpenSSL labels so.
    let label = file.unwrap_or(STDIN_LABEL);
    let signer = operation.signer();
    match signer {
        Signer::Oneshot if data.len() > ONESHOT_MAX => {
            out.diagnostic(format!("{READ_ERROR_IN} {label}"));
            return Ok(Outcome::Failed);
        }
        Signer::Oneshot | Signer::None | Signer::Digest => {}
    }
    // No digest named is SHA-256, OpenSSL's default; Ed25519 uses none.
    let digest = o.digest.unwrap_or(Algorithm::Sha256);
    let algorithm = match signer {
        Signer::Oneshot => SignatureAlgorithm::Ed25519,
        Signer::None | Signer::Digest => SignatureAlgorithm::Ecdsa(digest),
    };
    let result = match (operation, signer) {
        (Operation::Digest, _) => digest.digest(data),
        (Operation::Hmac(key), _) => {
            digest.hmac(key.expose(), data).as_bytes().to_vec()
        }
        (Operation::Sign(key), _) => key.sign(algorithm, data)?,
        (Operation::VerifyWhileSigning(_), Signer::Oneshot) => {
            out.diagnostic(ERROR_VERIFYING);
            return Ok(Outcome::Failed);
        }
        (Operation::VerifyWhileSigning(_), Signer::None | Signer::Digest) => {
            results.extend_from_slice(VERIFICATION_FAILURE.as_bytes());
            return Ok(Outcome::Failed);
        }
        (Operation::Verify(public, signature), _) => {
            return Ok(
                match public.check_signature(algorithm, data, signature)? {
                    SignatureCheck::Verified => {
                        results.extend_from_slice(VERIFIED_OK.as_bytes());
                        Outcome::Done
                    }
                    SignatureCheck::Failed => {
                        results
                            .extend_from_slice(VERIFICATION_FAILURE.as_bytes());
                        Outcome::Failed
                    }
                    SignatureCheck::Malformed => {
                        out.diagnostic(ERROR_VERIFYING);
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
    o.print(results, &result, encoding, labels, label);
    Ok(Outcome::Done)
}

/// Runs `dgst`, or the shortcut `command`, which presets its digest, and
/// records what it writes.
///
/// # Errors
///
/// Usage errors and unsupported options; [`Error::Reported`] with exit
/// code [`DGST_FAILED`] for what OpenSSL reports itself (a file that
/// cannot be read, a signature that does not verify, and the errors of its
/// checks), after recording whatever was computed.
pub(crate) fn run(
    command: &str,
    preset: Option<Algorithm>,
    raw: &[OsString],
    out: &mut Outputs,
) -> Result<()> {
    let Some(o) = parse_options(command, preset, raw)? else {
        out.stdout(args::usage(command, SPECS));
        return Ok(());
    };
    let compat = compat()?;
    let operation = prepare(out, command, &o, compat)?;
    let mut results = Vec::new();
    let mut outcome = Outcome::Done;
    if o.files.is_empty() {
        let data = read_input(None)?;
        outcome = outcome.max(process(
            out,
            &mut results,
            &o,
            &operation,
            &data,
            None,
        )?);
    }
    for path in &o.files {
        let step = match read_input(Some(path)) {
            Ok(data) => {
                let file = path.to_string_lossy();
                process(out, &mut results, &o, &operation, &data, Some(&file))?
            }
            Err(e) => {
                out.diagnostic(e.to_string());
                Outcome::Failed
            }
        };
        outcome = outcome.max(step);
    }
    // What was computed is written even when an input failed: to -out, or
    // to standard output.
    out.output(o.output.as_deref(), Access::Default, results);
    match outcome {
        Outcome::Done => Ok(()),
        Outcome::Failed => Err(Error::Reported {
            code: DGST_FAILED,
            output: Vec::new(),
        }),
    }
}

#[cfg(test)]
mod tests;
