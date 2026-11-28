//! The OpenSSL release line this build of baldssl imitates.
//!
//! The line is chosen when baldssl is built, by exactly one of its Cargo
//! features, `openssl-3-0`, `openssl-3-5` (the default), `openssl-3-6` or
//! `openssl-4`: a binary imitates one release line, and [`Line`] is its
//! [`Profile`]. The library, `baldssl-x509`, can compile several lines at
//! once (its tests check each); the binary is a leaf, so its features are
//! not unified with any other crate's and can exclude each other.

#[cfg(not(any(
    all(
        feature = "openssl-3-0",
        not(feature = "openssl-3-5"),
        not(feature = "openssl-3-6"),
        not(feature = "openssl-4")
    ),
    all(
        feature = "openssl-3-5",
        not(feature = "openssl-3-0"),
        not(feature = "openssl-3-6"),
        not(feature = "openssl-4")
    ),
    all(
        feature = "openssl-3-6",
        not(feature = "openssl-3-0"),
        not(feature = "openssl-3-5"),
        not(feature = "openssl-4")
    ),
    all(
        feature = "openssl-4",
        not(feature = "openssl-3-0"),
        not(feature = "openssl-3-5"),
        not(feature = "openssl-3-6")
    ),
)))]
compile_error!(
    "baldssl imitates one OpenSSL release line: enable exactly one of the \
     features openssl-3-0, openssl-3-5, openssl-3-6 and openssl-4"
);

use baldssl_pkey::PrivateKeyDer;
use baldssl_x509::Profile;

/// The release line this build imitates: OpenSSL 3.0.
#[cfg(feature = "openssl-3-0")]
pub(crate) type Line = baldssl_x509::OpenSsl30;

/// The release line this build imitates: OpenSSL 3.5.
#[cfg(all(feature = "openssl-3-5", not(feature = "openssl-3-0")))]
pub(crate) type Line = baldssl_x509::OpenSsl35;

/// The release line this build imitates: OpenSSL 3.6.
#[cfg(all(
    feature = "openssl-3-6",
    not(feature = "openssl-3-0"),
    not(feature = "openssl-3-5")
))]
pub(crate) type Line = baldssl_x509::OpenSsl36;

/// The release line this build imitates: OpenSSL 4.
#[cfg(all(
    feature = "openssl-4",
    not(feature = "openssl-3-0"),
    not(feature = "openssl-3-5"),
    not(feature = "openssl-3-6")
))]
pub(crate) type Line = baldssl_x509::OpenSsl4;

/// The release line as a value, for the tests that pick their known answer
/// by line.
#[cfg(test)]
pub(crate) const fn compat() -> baldssl_x509::Compat {
    Line::COMPAT
}

/// What `opt_cipher_any` (`apps/lib/opt.c`) says of a name that is not a
/// cipher, in OpenSSL 3.0 and 3.1.
#[cfg(feature = "openssl-3-0")]
const UNKNOWN_CIPHER: &str = "Unknown cipher";

/// What `opt_cipher_any` says of a name that is not a cipher from OpenSSL
/// 3.2, where an undeclared option is read as one.
const UNKNOWN_OPTION_OR_CIPHER: &str = "Unknown option or cipher";

/// Where the release lines' applications (OpenSSL's `apps/`) differ: what
/// the commands print, accept and write, beyond the library's [`Profile`].
/// Each item's default is what the lines share; each line's type
/// overrides it where it differs.
pub(crate) trait Apps: Profile {
    /// What a second option an application does not declare does
    /// (`opt_next` in `apps/lib/opt.c`): OpenSSL 3.0 and 3.1 keep the last
    /// one, and from 3.2 the second is refused as it is read ("Multiple
    /// digest or unknown options").
    const UNDECLARED_OPTIONS: UndeclaredOptions = UndeclaredOptions::OneOnly;

    /// How an operand where an application takes none is reported. OpenSSL
    /// 3.0 and 3.1's applications go to their `opthelp` label, which prints
    /// only the hint at `-help` (`apps/pkey.c`, `apps/genpkey.c`); from 3.2,
    /// `opt_check_rest_arg` (`apps/lib/opt.c`) names the operand first.
    const EXTRA_OPERANDS: ExtraOperands = ExtraOperands::Named;

    /// What `opt_cipher_any` (`apps/lib/opt.c`) says of a name that is not
    /// a cipher: "Unknown cipher" in OpenSSL 3.0 and 3.1, "Unknown option or
    /// cipher" from 3.2, where an undeclared option is read as one.
    const UNKNOWN_CIPHER_MESSAGE: &'static str = UNKNOWN_OPTION_OR_CIPHER;

    /// The form `openssl pkey -outform DER` writes a private key in.
    /// OpenSSL 3.0 to 3.5 call `i2d_PrivateKey_bio` (`apps/pkey.c`), which
    /// writes the algorithm's traditional form (SEC 1's ECPrivateKey for
    /// EC); from 3.6, `apps/pkey.c` calls `i2d_PKCS8PrivateKey_bio` unless
    /// `-traditional` is given.
    const PRIVATE_KEY_DER: PrivateKeyDer = PrivateKeyDer::Traditional;

    /// The form `openssl genpkey -outform DER` writes the key it generates
    /// in. OpenSSL 3.0 to 3.6 call `i2d_PrivateKey_bio`
    /// (`apps/genpkey.c`), which writes the algorithm's traditional form
    /// (SEC 1's ECPrivateKey for EC); from 4.0, `apps/genpkey.c` calls
    /// `encode_private_key` (`apps/lib/apps.c`), which asks for
    /// "PrivateKeyInfo", PKCS#8. The change comes one release after
    /// [`Apps::PRIVATE_KEY_DER`]'s.
    const GENERATED_KEY_DER: PrivateKeyDer = PrivateKeyDer::Traditional;

    /// Whether `openssl x509 -req` warns, before its own message, that the
    /// request's self-signature does not match. From 3.2, `load_csr` in
    /// `apps/lib/apps.c` checks the signature as it loads the request and
    /// prints "Warning: CSR self-signature does not match the contents";
    /// 3.0's `load_csr` does not check it.
    const CSR_SIGNATURE_WARNING: CsrSignatureWarning =
        CsrSignatureWarning::Printed;

    /// What `openssl x509 -extensions` does without `-extfile`. In 3.x,
    /// `apps/x509.c` prints "Warning: ignoring -extensions option without
    /// -extfile" and goes on; in 4, it looks the section up in the default
    /// configuration file (`app_conf_try_string` on the loaded
    /// configuration), and fails with "Error checking extension section"
    /// when it is not there.
    const EXTENSIONS_WITHOUT_FILE: ExtensionsWithoutFile =
        ExtensionsWithoutFile::Ignored;

    /// The stream `openssl req -verify` prints "Certificate request
    /// self-signature verify OK" on: `bio_err` in `apps/req.c` of 3.0 and
    /// 3.1, `bio_out` (standard output, whatever `-out` says) from 3.2.
    const REQUEST_VERIFIED_STREAM: Stream = Stream::Stdout;

    /// How `openssl dgst -verify` loads its public key (`load_pubkey` in
    /// `apps/lib/apps.c`): 3.0 reads a public key only; from 3.2, it falls
    /// back to reading a private key and taking its public half, and a file
    /// that holds neither is reported as the failure of that fallback.
    const PUBLIC_KEY_LOADING: PublicKeyLoading =
        PublicKeyLoading::PrivateFallback;

    /// The form of the message `load_key_certs_crls` in `apps/lib/apps.c`
    /// prints for keys or certificates it cannot load. 3.0 says "Could not
    /// read" (with " any" for a list of certificates), names the credential
    /// as its first draft did ("key", "cert", "certs"), and gives no reason
    /// for a file that does not open. 3.2 rewrote it with `FAIL_NAME`: "Could
    /// not find", the credential named in full ("private key",
    /// "certificate", "certificates"), and the system's reason ("No such
    /// file or directory") after a file that does not open. 4 says "Could
    /// not find or decode".
    const LOAD_MESSAGE: LoadMessage = LoadMessage::Find;

    /// Whether `load_cert` in `apps/lib/apps.c` follows a certificate it
    /// could not load with `Unable to load <desc>`: 3.0 does after every
    /// failure; from 3.2 it does only for a certificate fetched over HTTP.
    const CERTIFICATE_LOAD_SUMMARY: CertificateLoadSummary =
        CertificateLoadSummary::Omitted;

    /// Whether `openssl dgst` signs and verifies with a key that signs the
    /// message itself (Ed25519). 3.0's `apps/dgst.c` feeds the input
    /// through `EVP_DigestSignUpdate`, which such a key refuses ("Key type
    /// not supported for this operation"); later lines read the input whole
    /// and sign it in one shot (`do_fp_oneshot_sign`).
    const DGST_ONESHOT: OneshotSigning = OneshotSigning::Supported;
}

#[cfg(feature = "openssl-3-0")]
impl Apps for baldssl_x509::OpenSsl30 {
    const UNDECLARED_OPTIONS: UndeclaredOptions = UndeclaredOptions::LastKept;
    const EXTRA_OPERANDS: ExtraOperands = ExtraOperands::HintOnly;
    const UNKNOWN_CIPHER_MESSAGE: &'static str = UNKNOWN_CIPHER;
    const CSR_SIGNATURE_WARNING: CsrSignatureWarning =
        CsrSignatureWarning::Silent;
    const REQUEST_VERIFIED_STREAM: Stream = Stream::Stderr;
    const PUBLIC_KEY_LOADING: PublicKeyLoading = PublicKeyLoading::PublicOnly;
    const LOAD_MESSAGE: LoadMessage = LoadMessage::Read;
    const CERTIFICATE_LOAD_SUMMARY: CertificateLoadSummary =
        CertificateLoadSummary::Printed;
    const DGST_ONESHOT: OneshotSigning = OneshotSigning::Refused;
}

#[cfg(feature = "openssl-3-5")]
impl Apps for baldssl_x509::OpenSsl35 {}

#[cfg(feature = "openssl-3-6")]
impl Apps for baldssl_x509::OpenSsl36 {
    const PRIVATE_KEY_DER: PrivateKeyDer = PrivateKeyDer::Pkcs8;
}

#[cfg(feature = "openssl-4")]
impl Apps for baldssl_x509::OpenSsl4 {
    const PRIVATE_KEY_DER: PrivateKeyDer = PrivateKeyDer::Pkcs8;
    const GENERATED_KEY_DER: PrivateKeyDer = PrivateKeyDer::Pkcs8;
    const EXTENSIONS_WITHOUT_FILE: ExtensionsWithoutFile =
        ExtensionsWithoutFile::DefaultConfiguration;
    const LOAD_MESSAGE: LoadMessage = LoadMessage::FindOrDecode;
}

/// What a second undeclared option does ([`Apps::UNDECLARED_OPTIONS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum UndeclaredOptions {
    /// Each replaces the one before it, and the last is read (OpenSSL 3.0
    /// and 3.1).
    LastKept,
    /// The second is refused (from OpenSSL 3.2).
    OneOnly,
}

/// How an operand where none is taken is reported
/// ([`Apps::EXTRA_OPERANDS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum ExtraOperands {
    /// With the hint at `-help` alone (OpenSSL 3.0 and 3.1).
    HintOnly,
    /// With a line naming it, then the hint (from OpenSSL 3.2).
    Named,
}

/// Whether a mismatched request signature gets a warning first
/// ([`Apps::CSR_SIGNATURE_WARNING`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum CsrSignatureWarning {
    /// No warning.
    Silent,
    /// "Warning: CSR self-signature does not match the contents".
    Printed,
}

/// What `-extensions` without `-extfile` does
/// ([`Apps::EXTENSIONS_WITHOUT_FILE`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum ExtensionsWithoutFile {
    /// It is ignored, with a warning.
    Ignored,
    /// The section is looked up in the default configuration file.
    DefaultConfiguration,
}

/// A standard stream of the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// How `dgst -verify` loads its public key
/// ([`Apps::PUBLIC_KEY_LOADING`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum PublicKeyLoading {
    /// A public key only.
    PublicOnly,
    /// A public key, or else the public half of a private key.
    PrivateFallback,
}

/// The form of the message for keys or certificates that do not load
/// ([`Apps::LOAD_MESSAGE`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum LoadMessage {
    /// "Could not read", the first draft's names, and no reason for a file
    /// that does not open (3.0).
    Read,
    /// "Could not find", the full names, and the reason for a file that
    /// does not open (3.2 to 3.6).
    Find,
    /// "Could not find or decode", otherwise as [`LoadMessage::Find`] (4).
    FindOrDecode,
}

/// Whether a certificate that does not load is followed by
/// `Unable to load <desc>` ([`Apps::CERTIFICATE_LOAD_SUMMARY`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum CertificateLoadSummary {
    /// It is (3.0).
    Printed,
    /// It is not.
    Omitted,
}

/// Whether `dgst` signs with a one-shot key such as Ed25519
/// ([`Apps::DGST_ONESHOT`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "a build imitates one release line, which constructs only its \
              own variant"
)]
pub(crate) enum OneshotSigning {
    /// It refuses the key.
    Refused,
    /// It signs and verifies in one shot.
    Supported,
}
