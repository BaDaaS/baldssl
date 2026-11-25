//! `openssl x509 -text`, reproduced byte for byte (`X509_print_ex` with
//! default flags, as in OpenSSL 3.x and 4.x).
//!
//! Platform note: OpenSSL decides between the one-line and the hex form of a
//! serial number by `sizeof(long)`. baldssl follows LP64 (the data model of
//! Linux and macOS, where `long` and pointers are 64 bits: 8 bytes); OpenSSL
//! on Windows (LLP64, where only `long long` and pointers are 64 bits, and
//! `long` is 4 bytes) prints serials of 5 to 8 bytes in the hex form
//! instead.

use std::str::FromStr;

use baldssl_core::{
    Error, Result,
    der::{
        BitString, Integer, Oid, Reader, Time, TimeKind, parse_tlv,
        syntax::{Null, ObjectId, RawTlv},
        tag,
    },
    encoding::Encodable,
    hex::{self, Case},
    text::Text,
};
use baldssl_crypto::models::weierstrass::{
    COMPRESSED_EVEN, COMPRESSED_ODD, UNCOMPRESSED,
};
use baldssl_pkey::{AnyPrivateKey, ED25519_KEY_LEN, PrivateKeyDer, PublicKey};

use crate::{
    CertificationRequest,
    algorithm::AlgorithmIdentifier,
    cert::{Certificate, SubjectPublicKeyInfo},
    ext::ExtensionIndent,
    name::NameStyle,
    objects,
    oid::{
        ID_EC_PUBLIC_KEY, ID_ED25519, ID_RSASSA_PSS, PRIME256V1,
        RSA_ENCRYPTION, SECP384R1, SECP521R1, SM2_WITH_SM3,
    },
    version::Version,
};

/// The indentation of the public key inside a certificate's or a
/// request's `Subject Public Key Info:` block (`X509_print_ex` calls
/// `EVP_PKEY_print_public` with 16).
const SPKI_KEY_INDENT: usize = 16;
/// The indentation of a key printed alone (`openssl pkey -text`).
const PKEY_INDENT: usize = 0;
/// How much further in than its header a key's hex dump is
/// (`ASN1_hex_dump(bp, buf, len, off + 4)` in OpenSSL's key printers).
const DUMP_STEP: usize = 4;
/// The indentation of the signature's hex dump (`X509_hex_dump(bp,
/// sig, 8)` in `X509_signature_print`).
const SIGNATURE_INDENT: usize = 8;
/// `BN_BYTES` on LP64: a bignum of at most this many bytes is printed on
/// one line, in decimal and hex (`ASN1_bn_print`, `crypto/asn1/t_pkey.c`).
const BN_BYTES: usize = 8;
/// The bytes `i2a_ASN1_INTEGER` writes before a backslash-newline
/// (`crypto/asn1/f_int.c`).
const SERIAL_BYTES_PER_LINE: usize = 35;

/// Which OpenSSL release line's output to reproduce. The lines differ in
/// the style of names (3.0), the hex-dump geometry and the EC key header
/// (4), and how `pkey` writes a private key in DER (3.6 and 4); everything
/// else is shared. `scripts/interop.sh` checks each profile against real
/// binaries of that line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compat {
    /// OpenSSL 3.0, whose names use the older escaped style
    /// ([`NameStyle::Oneline`]).
    V30,
    /// OpenSSL 3.2 to 3.5.
    #[default]
    V3,
    /// OpenSSL 3.6: as 3.5, except that `pkey` writes a private key in DER
    /// as PKCS#8 ([`Compat::private_key_der`]); `genpkey` does not
    /// ([`Compat::generated_key_der`]).
    V36,
    /// OpenSSL 4.0 and later.
    V4,
}

impl Compat {
    /// Bytes per line in `ASN1_buf_print` (keys, modulus).
    fn key_bytes_per_line(self) -> usize {
        match self {
            Compat::V30 | Compat::V3 | Compat::V36 => 15,
            Compat::V4 => 16,
        }
    }

    /// Bytes per line in `X509_signature_dump`.
    fn signature_bytes_per_line(self) -> usize {
        match self {
            Compat::V30 | Compat::V3 | Compat::V36 => 18,
            Compat::V4 => 24,
        }
    }

    /// Whether a bignum with its top bit set is printed with a leading
    /// `00:` (the two's-complement sign byte): `ASN1_bn_print` in
    /// `crypto/asn1/t_pkey.c` adds it in 3.x, and OpenSSL 4 no longer does.
    fn bn_sign_byte(self) -> bool {
        match self {
            Compat::V30 | Compat::V3 | Compat::V36 => true,
            Compat::V4 => false,
        }
    }

    /// The size an EC key's header gives (`Public-Key: (...)`), as
    /// `ec_to_text` in
    /// `providers/implementations/encode_decode/encode_key2text.c` writes
    /// it: the field size in 3.x, and the security level too in 4.
    fn ec_key_size(self) -> EcKeySize {
        match self {
            Compat::V30 | Compat::V3 | Compat::V36 => EcKeySize::Bits,
            Compat::V4 => EcKeySize::BitsAndSecurity,
        }
    }

    /// Whether `req -x509` with the default configuration writes an
    /// authority key identifier in a self-signed certificate: the `v3_ca`
    /// section of `apps/openssl.cnf` says `keyid:always,issuer` in 3.x, and
    /// `keyid:nonss,issuer:nonss` ("non-self-signed") in 4.
    pub(crate) fn self_signed_authority_key_id(
        self,
    ) -> SelfSignedAuthorityKeyId {
        match self {
            Compat::V30 | Compat::V3 | Compat::V36 => {
                SelfSignedAuthorityKeyId::Written
            }
            Compat::V4 => SelfSignedAuthorityKeyId::Omitted,
        }
    }

    /// Where `x509 -req -CA` takes the key identifiers it adds from. In 3.x,
    /// `do_X509_sign` (`apps/lib/apps.c`) adds the missing ones when it
    /// signs, which 3.0 does only for a certificate with extensions; in 4,
    /// they come from the `default_skid_akid` section of `apps/openssl.cnf`
    /// (`extensions = default_skid_akid`).
    pub(crate) fn default_key_identifiers(self) -> DefaultKeyIdentifiers {
        match self {
            Compat::V30 => DefaultKeyIdentifiers::AtSigningWithExtensions,
            Compat::V3 | Compat::V36 => DefaultKeyIdentifiers::AtSigning,
            Compat::V4 => DefaultKeyIdentifiers::FromConfiguration,
        }
    }

    /// The form `openssl pkey -outform DER` writes a private key in.
    /// OpenSSL 3.0 to 3.5 call `i2d_PrivateKey_bio` (`apps/pkey.c`), which
    /// writes the algorithm's traditional form (SEC 1's ECPrivateKey for
    /// EC); from 3.6, `apps/pkey.c` calls `i2d_PKCS8PrivateKey_bio` unless
    /// `-traditional` is given.
    #[must_use]
    pub fn private_key_der(self) -> PrivateKeyDer {
        match self {
            Compat::V30 | Compat::V3 => PrivateKeyDer::Traditional,
            Compat::V36 | Compat::V4 => PrivateKeyDer::Pkcs8,
        }
    }

    /// The form `openssl genpkey -outform DER` writes the key it generates
    /// in. OpenSSL 3.0 to 3.6 call `i2d_PrivateKey_bio`
    /// (`apps/genpkey.c`), which writes the algorithm's traditional form
    /// (SEC 1's ECPrivateKey for EC); from 4.0, `apps/genpkey.c` calls
    /// `encode_private_key` (`apps/lib/apps.c`), which asks for
    /// "PrivateKeyInfo", PKCS#8. The change comes one release after
    /// [`Compat::private_key_der`]'s.
    #[must_use]
    pub fn generated_key_der(self) -> PrivateKeyDer {
        match self {
            Compat::V30 | Compat::V3 | Compat::V36 => {
                PrivateKeyDer::Traditional
            }
            Compat::V4 => PrivateKeyDer::Pkcs8,
        }
    }

    /// Whether `openssl x509 -req` warns, before its own message, that the
    /// request's self-signature does not match. From 3.2, `load_csr` in
    /// `apps/lib/apps.c` checks the signature as it loads the request and
    /// prints "Warning: CSR self-signature does not match the contents";
    /// 3.0's `load_csr` does not check it.
    #[must_use]
    pub fn csr_signature_warning(self) -> CsrSignatureWarning {
        match self {
            Compat::V30 => CsrSignatureWarning::Silent,
            Compat::V3 | Compat::V36 | Compat::V4 => {
                CsrSignatureWarning::Printed
            }
        }
    }

    /// What `openssl x509 -extensions` does without `-extfile`. In 3.x,
    /// `apps/x509.c` prints "Warning: ignoring -extensions option without
    /// -extfile" and goes on; in 4, it looks the section up in the default
    /// configuration file (`app_conf_try_string` on the loaded
    /// configuration), and fails with "Error checking extension section"
    /// when it is not there.
    #[must_use]
    pub fn extensions_without_file(self) -> ExtensionsWithoutFile {
        match self {
            Compat::V30 | Compat::V3 | Compat::V36 => {
                ExtensionsWithoutFile::Ignored
            }
            Compat::V4 => ExtensionsWithoutFile::DefaultConfiguration,
        }
    }

    /// The stream `openssl req -verify` prints "Certificate request
    /// self-signature verify OK" on: `bio_err` in `apps/req.c` of 3.0 and
    /// 3.1, `bio_out` (standard output, whatever `-out` says) from 3.2.
    #[must_use]
    pub fn request_verified_stream(self) -> Stream {
        match self {
            Compat::V30 => Stream::Stderr,
            Compat::V3 | Compat::V36 | Compat::V4 => Stream::Stdout,
        }
    }

    /// How `openssl dgst -verify` loads its public key (`load_pubkey` in
    /// `apps/lib/apps.c`): 3.0 reads a public key only; from 3.2, it falls
    /// back to reading a private key and taking its public half, and a file
    /// that holds neither is reported as the failure of that fallback.
    #[must_use]
    pub fn public_key_loading(self) -> PublicKeyLoading {
        match self {
            Compat::V30 => PublicKeyLoading::PublicOnly,
            Compat::V3 | Compat::V36 | Compat::V4 => {
                PublicKeyLoading::PrivateFallback
            }
        }
    }

    /// The message `load_key_certs_crls` in `apps/lib/apps.c` prints for a
    /// key it cannot load: "Could not read" in 3.0, without the reason for a
    /// missing file; "Could not find" from 3.2, followed by the system's
    /// reason ("No such file or directory") for a missing file; "Could not
    /// find or decode" in 4.
    #[must_use]
    pub fn key_load_message(self) -> KeyLoadMessage {
        match self {
            Compat::V30 => KeyLoadMessage::Read,
            Compat::V3 | Compat::V36 => KeyLoadMessage::Find,
            Compat::V4 => KeyLoadMessage::FindOrDecode,
        }
    }

    /// Whether `openssl dgst` signs and verifies with a key that signs the
    /// message itself (Ed25519). 3.0's `apps/dgst.c` feeds the input
    /// through `EVP_DigestSignUpdate`, which such a key refuses ("Key type
    /// not supported for this operation"); later lines read the input whole
    /// and sign it in one shot (`do_fp_oneshot_sign`).
    #[must_use]
    pub fn dgst_oneshot(self) -> OneshotSigning {
        match self {
            Compat::V30 => OneshotSigning::Refused,
            Compat::V3 | Compat::V36 | Compat::V4 => OneshotSigning::Supported,
        }
    }

    /// How this release line prints names.
    #[must_use]
    pub fn name_style(self) -> NameStyle {
        match self {
            Compat::V30 => NameStyle::Oneline,
            Compat::V3 | Compat::V36 | Compat::V4 => NameStyle::Utf8,
        }
    }

    /// The name of the profile, as `BALDSSL_OPENSSL_COMPAT` gives it: the
    /// release line, or its major version when the line covers several
    /// minor ones.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Compat::V30 => "3.0",
            Compat::V3 => "3",
            Compat::V36 => "3.6",
            Compat::V4 => "4",
        }
    }

    /// Every profile, oldest first.
    pub const ALL: [Compat; 4] =
        [Compat::V30, Compat::V3, Compat::V36, Compat::V4];

    /// Whether `version` is this profile's name or an OpenSSL version of
    /// its line (`3.0.22` for `3.0`, `3.5.9` for `3`).
    fn covers(self, version: &str) -> bool {
        let name = self.name();
        version == name
            || version
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('.'))
    }
}

/// A profile name (`3.0`, `3`, `3.6`, `4`, [`Compat::name`]) or an OpenSSL
/// version (`3.0.22`, `3.5.9`, `4.1.0`): the profile with the longest name
/// that covers it, so that `3.6.1` is `3.6` and not `3`.
///
/// # Errors
///
/// [`Error::Usage`] naming the accepted profiles, for any other text.
impl FromStr for Compat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let version = s.trim();
        Compat::ALL
            .into_iter()
            .filter(|c| c.covers(version))
            .max_by_key(|c| c.name().len())
            .ok_or_else(|| {
                let names: Vec<&str> =
                    Compat::ALL.iter().map(|c| c.name()).collect();
                Error::Usage(format!(
                    "expected one of {}, or an OpenSSL version, got {s:?}",
                    names.join(", ")
                ))
            })
    }
}

/// Whether a mismatched request signature gets a warning first
/// ([`Compat::csr_signature_warning`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrSignatureWarning {
    /// No warning.
    Silent,
    /// "Warning: CSR self-signature does not match the contents".
    Printed,
}

/// What `-extensions` without `-extfile` does
/// ([`Compat::extensions_without_file`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionsWithoutFile {
    /// It is ignored, with a warning.
    Ignored,
    /// The section is looked up in the default configuration file.
    DefaultConfiguration,
}

/// How `dgst -verify` loads its public key
/// ([`Compat::public_key_loading`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyLoading {
    /// A public key only.
    PublicOnly,
    /// A public key, or else the public half of a private key.
    PrivateFallback,
}

/// The message for a key that does not load
/// ([`Compat::key_load_message`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLoadMessage {
    /// "Could not read", and no reason for a missing file (3.0).
    Read,
    /// "Could not find", and the reason for a missing file.
    Find,
    /// "Could not find or decode", and the reason for a missing file.
    FindOrDecode,
}

/// Whether `dgst` signs with a one-shot key such as Ed25519
/// ([`Compat::dgst_oneshot`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneshotSigning {
    /// It refuses the key.
    Refused,
    /// It signs and verifies in one shot.
    Supported,
}

/// A standard stream of the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// What an EC key's header gives as its size ([`Compat::ec_key_size`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EcKeySize {
    /// `256 bit`.
    Bits,
    /// `256 bit field, 128 bit security level`.
    BitsAndSecurity,
}

/// Whether a self-signed certificate gets an authority key identifier
/// ([`Compat::self_signed_authority_key_id`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelfSignedAuthorityKeyId {
    /// It does, its own key identifier.
    Written,
    /// It does not.
    Omitted,
}

/// When `x509 -req -CA` adds a subject and an authority key identifier
/// ([`Compat::default_key_identifiers`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefaultKeyIdentifiers {
    /// When signing, each one missing, the authority's left out when the
    /// request's key is the CA's.
    AtSigning,
    /// As [`DefaultKeyIdentifiers::AtSigning`], and only to a certificate
    /// that has extensions already.
    AtSigningWithExtensions,
    /// From the default configuration, after the copied extensions, and
    /// only without an extension file.
    FromConfiguration,
}

/// The months as `ASN1_TIME_print` names them.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
    "Nov", "Dec",
];

/// `ASN1_TIME_print` ([RFC 822 section 5] style, the default `-dateopt`).
///
/// [RFC 822 section 5]: https://www.rfc-editor.org/rfc/rfc822#section-5
#[must_use]
pub fn time_rfc822(t: &Time) -> String {
    // A `Time` holds a month from 1 to 12 (`Time::parse` refuses others),
    // so the lookup always finds one and the fallback is never printed.
    let month = MONTHS
        .get(usize::from(t.month().saturating_sub(1)))
        .copied()
        .unwrap_or("???");
    let frac = if t.kind() == TimeKind::Generalized && !t.fraction().is_empty()
    {
        format!(".{}", t.fraction())
    } else {
        String::new()
    };
    format!(
        "{month} {:2} {:02}:{:02}:{:02}{frac} {} GMT",
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.year()
    )
}

/// A hex dump as `ASN1_buf_print` (keys, moduli) and `X509_signature_dump`
/// (signatures) both write it: `per_line` bytes per line, lower-case,
/// `:`-separated, each line at `indent` spaces.
fn hex_dump(out: &mut Vec<u8>, bytes: &[u8], indent: usize, per_line: usize) {
    let pad = " ".repeat(indent);
    let per_line = per_line.max(1);
    for (i, b) in bytes.iter().enumerate() {
        if i % per_line == 0 {
            if i > 0 {
                out.push(b'\n');
            }
            out.extend_from_slice(pad.as_bytes());
        }
        out.extend_from_slice(hex::plain(&[*b], Case::Lower).as_bytes());
        if i.saturating_add(1) != bytes.len() {
            out.push(b':');
        }
    }
    out.push(b'\n');
}

/// `ASN1_bn_print`, with [`BN_BYTES`].
fn bn_print(
    out: &mut Vec<u8>,
    label: &str,
    n: &Integer,
    indent: usize,
    compat: Compat,
) {
    out.extend_from_slice(" ".repeat(indent).as_bytes());
    let neg = if n.is_negative() { "-" } else { "" };
    if n.magnitude().is_empty() {
        out.extend_from_slice(format!("{label} 0\n").as_bytes());
        return;
    }
    if let Some(v) = n
        .magnitude_u128_opt()
        .filter(|_| n.magnitude().len() <= BN_BYTES)
    {
        out.extend_from_slice(
            format!("{label} {neg}{v} ({neg}0x{v:x})\n").as_bytes(),
        );
        return;
    }
    let tail = if n.is_negative() { " (Negative)" } else { "" };
    out.extend_from_slice(format!("{label}{tail}\n").as_bytes());
    let mut buf = Vec::with_capacity(n.magnitude().len().saturating_add(1));
    if compat.bn_sign_byte()
        && n.magnitude().first().is_some_and(|b| b & 0x80 != 0)
    {
        buf.push(0);
    }
    buf.extend_from_slice(n.magnitude());
    hex_dump(
        out,
        &buf,
        indent.saturating_add(DUMP_STEP),
        compat.key_bytes_per_line(),
    );
}

/// The serial number lines of `X509_print_ex`.
fn print_serial(out: &mut Vec<u8>, serial: &Integer) {
    out.extend_from_slice(b"        Serial Number:");
    // ASN1_INTEGER_get succeeds when the value fits a 64-bit long; it
    // returns -1 on failure, so a serial of exactly -1 also takes the long
    // form.
    let fits = match serial.to_u64_opt() {
        Some(v) => i64::try_from(v).is_ok(),
        None => {
            serial.is_negative()
                && serial.magnitude().len() <= BN_BYTES
                && serial
                    .magnitude_u128_opt()
                    .is_some_and(|m| m <= 1u128 << 63)
        }
    };
    let minus_one = serial.is_negative() && serial.magnitude() == [1];
    let short = serial.magnitude_u128_opt().filter(|_| fits && !minus_one);
    if let Some(v) = short {
        let neg = if serial.is_negative() { "-" } else { "" };
        out.extend_from_slice(format!(" {neg}{v} ({neg}0x{v:x})\n").as_bytes());
    } else {
        out.extend_from_slice(b"\n            ");
        if serial.is_negative() {
            out.extend_from_slice(b" (Negative)");
        }
        out.extend_from_slice(
            hex::colon(serial.magnitude(), Case::Lower).as_bytes(),
        );
        out.push(b'\n');
    }
}

/// The name of a signature algorithm, refusing those whose OpenSSL
/// `sig_print` adds parameter lines baldssl does not print (RSASSA-PSS,
/// SM2 with SM3).
fn signature_name(alg: &AlgorithmIdentifier) -> Result<String> {
    if alg.oid == ID_RSASSA_PSS {
        return Err(Error::unsupported(
            "RSASSA-PSS parameters in -text output",
        ));
    }
    if alg.oid == SM2_WITH_SM3 {
        return Err(Error::unsupported("SM2 signatures"));
    }
    objects::long_name(&alg.oid.as_oid())
}

/// A named curve baldssl supports.
struct Curve {
    /// Its identifier.
    oid: ObjectId,
    /// OpenSSL short name (`ASN1 OID:`).
    sn: &'static str,
    /// `NIST CURVE:`, the name NIST (the National Institute of Standards
    /// and Technology) gives it.
    nist: &'static str,
    /// Order bits, the 3.x `Public-Key: (N bit)`.
    bits: usize,
    /// Security level printed by 4.x (NIST SP 800-57 strengths, capped at
    /// 256).
    security: usize,
}

static CURVES: [Curve; 3] = [
    Curve {
        oid: PRIME256V1,
        sn: "prime256v1",
        nist: "P-256",
        bits: 256,
        security: 128,
    },
    Curve {
        oid: SECP384R1,
        sn: "secp384r1",
        nist: "P-384",
        bits: 384,
        security: 192,
    },
    Curve {
        oid: SECP521R1,
        sn: "secp521r1",
        nist: "P-521",
        bits: 521,
        security: 256,
    },
];

fn field_bytes(bits: usize) -> usize {
    bits.div_ceil(8)
}

/// Whether a key block is of a private key or of a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    /// A private key, its secret printed.
    Private,
    /// A public key.
    Public,
}

impl KeyKind {
    /// The word OpenSSL's headers use (`Private-Key:`, `Public-Key:`).
    fn as_str(self) -> &'static str {
        match self {
            KeyKind::Private => "Private",
            KeyKind::Public => "Public",
        }
    }
}

/// What every key block shares: the key, the secret, the indentation, and
/// the release line.
struct KeyLayout<'a> {
    /// The public key's bytes.
    key: &'a [u8],
    /// The secret, for a private key.
    secret: Option<&'a [u8]>,
    /// The header's indentation.
    pad: String,
    /// The hex dump's indentation.
    data: usize,
    /// Bytes per hex line.
    per_line: usize,
    /// Private or public.
    kind: KeyKind,
    /// The release line.
    compat: Compat,
}

/// An EC key on a named curve.
fn print_ec_key(
    out: &mut Vec<u8>,
    spki: &SubjectPublicKeyInfo<'_>,
    layout: &KeyLayout<'_>,
) -> Result<()> {
    let KeyLayout {
        key,
        secret,
        pad: pad16,
        data,
        per_line,
        kind,
        compat,
    } = layout;
    let (key, secret, data, per_line, compat) =
        (*key, *secret, *data, *per_line, *compat);
    let kind = kind.as_str();
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| Error::invalid("EC key without parameters"))?;
    let (params, _) = parse_tlv(params.as_bytes())?;
    if params.octet_opt() != Some(tag::OID) {
        return Err(Error::unsupported(
            "explicit or implicit EC domain parameters",
        ));
    }
    let curve_oid = Oid::parse(params.value())?;
    let Some(c) = CURVES.iter().find(|c| curve_oid == c.oid) else {
        return Err(Error::unsupported(format!(
            "EC curve {} ({})",
            curve_oid.to_dotted()?,
            objects::short_name(&curve_oid)?
        )));
    };
    let len = field_bytes(c.bits);
    // SEC 1 section 2.3.3: the prefix octet, then x, then y for an
    // uncompressed point.
    let well_formed = match key.first() {
        Some(&UNCOMPRESSED) => {
            key.len() == len.saturating_mul(2).saturating_add(1)
        }
        Some(&(COMPRESSED_EVEN | COMPRESSED_ODD)) => {
            key.len() == len.saturating_add(1)
        }
        _ => false,
    };
    // The encoding is checked, not whether the point is on the curve:
    // OpenSSL refuses a point off the curve, which baldssl prints.
    if !well_formed {
        return Err(Error::invalid("EC point encoding"));
    }
    let size = match compat.ec_key_size() {
        EcKeySize::Bits => format!("{} bit", c.bits),
        EcKeySize::BitsAndSecurity => {
            format!("{} bit field, {} bit security level", c.bits, c.security)
        }
    };
    out.extend_from_slice(format!("{pad16}{kind}-Key: ({size})\n").as_bytes());
    // EC_KEY_priv2buf: the scalar at the full length of the order, leading
    // zeros kept, no sign byte, in every release line.
    if let Some(secret) = secret {
        out.extend_from_slice(format!("{pad16}priv:\n").as_bytes());
        hex_dump(out, secret, data, per_line);
    }
    out.extend_from_slice(format!("{pad16}pub:\n").as_bytes());
    hex_dump(out, key, data, per_line);
    out.extend_from_slice(
        format!("{pad16}ASN1 OID: {}\n{pad16}NIST CURVE: {}\n", c.sn, c.nist)
            .as_bytes(),
    );
    Ok(())
}

/// A key as OpenSSL's text printers write it, at `indent` spaces (16 in a
/// certificate, 0 for `pkey`): a header, the secret when there is one
/// (`priv:`, at its full length), then the public
/// key (`pub:`) and the curve.
fn print_key(
    out: &mut Vec<u8>,
    spki: &SubjectPublicKeyInfo<'_>,
    secret: Option<&[u8]>,
    indent: usize,
    compat: Compat,
) -> Result<()> {
    let per_line = compat.key_bytes_per_line();
    let kind = if secret.is_some() {
        KeyKind::Private
    } else {
        KeyKind::Public
    };
    let data = indent.saturating_add(DUMP_STEP);
    let alg = &spki.algorithm.oid;
    let key = spki.public_key.bytes();
    if spki.public_key.unused() != 0 {
        return Err(Error::invalid("public key BIT STRING with unused bits"));
    }
    let pad16 = " ".repeat(indent);
    let layout = KeyLayout {
        key,
        secret,
        pad: pad16.clone(),
        data,
        per_line,
        kind,
        compat,
    };
    if *alg == RSA_ENCRYPTION {
        // RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }, RFC 8017
        // appendix A.1.1:
        // https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1
        if secret.is_some() {
            return Err(Error::unsupported("RSA private keys"));
        }
        if let Some(p) = &spki.algorithm.parameters
            && *p != RawTlv::encode(&Null, &())
        {
            return Err(Error::invalid("rsaEncryption parameters"));
        }
        let mut outer = Reader::new(key);
        let mut seq = outer.sequence()?;
        outer.finish()?;
        let n = Integer::parse(seq.expect(tag::INTEGER)?.value())?;
        let e = Integer::parse(seq.expect(tag::INTEGER)?.value())?;
        seq.finish()?;
        out.extend_from_slice(
            format!("{pad16}Public-Key: ({} bit)\n", n.bits()).as_bytes(),
        );
        bn_print(out, "Modulus:", &n, indent, compat);
        bn_print(out, "Exponent:", &e, indent, compat);
    } else if *alg == ID_EC_PUBLIC_KEY {
        print_ec_key(out, spki, &layout)?;
    } else if *alg == ID_ED25519 {
        // No parameters, and the 32-byte key, RFC 8410 section 3:
        // https://www.rfc-editor.org/rfc/rfc8410#section-3
        if spki.algorithm.parameters.is_some() || key.len() != ED25519_KEY_LEN {
            return Err(Error::invalid("Ed25519 public key"));
        }
        let kind = kind.as_str();
        out.extend_from_slice(
            format!("{pad16}ED25519 {kind}-Key:\n").as_bytes(),
        );
        if let Some(secret) = secret {
            out.extend_from_slice(format!("{pad16}priv:\n").as_bytes());
            hex_dump(out, secret, data, per_line);
        }
        out.extend_from_slice(format!("{pad16}pub:\n").as_bytes());
        hex_dump(out, key, data, per_line);
    } else {
        return Err(Error::unsupported(format!(
            "public key algorithm {} ({})",
            alg.to_dotted()?,
            objects::long_name(&alg.as_oid())?
        )));
    }
    Ok(())
}

/// The version line, as OpenSSL prints it: `n+1 (0xn)` for v1 to v3,
/// otherwise `Unknown (n)` with `n` the value as a signed 64-bit integer,
/// or -1 when it does not fit (OpenSSL's `ASN1_INTEGER_get` result).
fn version_line(version: &Version) -> String {
    match version.known_opt() {
        Some(n) => format!(
            "        Version: {} (0x{n:x})\n",
            u16::from(n).saturating_add(1)
        ),
        None => format!(
            "        Version: Unknown ({})\n",
            version.as_integer().to_i64_opt().unwrap_or(-1)
        ),
    }
}

/// The `openssl x509 -text` block of a certificate, in the layout of the
/// release line `compat` names.
///
/// # Errors
///
/// [`Error::Unsupported`] for what baldssl does not print exactly as
/// OpenSSL does (see the module of the extensions printer, RSASSA-PSS and
/// SM2 signatures, keys other than RSA, EC on a named curve and Ed25519);
/// [`Error::Invalid`] for malformed contents.
impl Text for Certificate<'_> {
    type Layout = Compat;

    fn to_text(&self, compat: Compat) -> Result<Vec<u8>> {
        print_certificate(self, compat)
    }
}

/// The text form of a certificate, for its [`Text`] impl.
fn print_certificate(
    cert: &Certificate<'_>,
    compat: Compat,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(b"Certificate:\n    Data:\n");
    out.extend_from_slice(version_line(&cert.version).as_bytes());
    print_serial(&mut out, &cert.serial);
    out.extend_from_slice(b"        Signature Algorithm: ");
    out.extend_from_slice(signature_name(&cert.tbs_signature)?.as_bytes());
    out.extend_from_slice(b"\n        Issuer: ");
    out.extend_from_slice(&cert.issuer.to_openssl(compat.name_style())?);
    out.extend_from_slice(b"\n        Validity\n            Not Before: ");
    out.extend_from_slice(time_rfc822(&cert.validity.not_before).as_bytes());
    out.extend_from_slice(b"\n            Not After : ");
    out.extend_from_slice(time_rfc822(&cert.validity.not_after).as_bytes());
    out.extend_from_slice(b"\n        Subject: ");
    out.extend_from_slice(&cert.subject.to_openssl(compat.name_style())?);
    out.push(b'\n');
    print_subject_public_key_info(&mut out, &cert.spki, compat)?;
    cert.extensions.print_certificate_block(&mut out)?;
    print_signed(&mut out, &cert.signature_algorithm, &cert.signature, compat)?;
    Ok(out)
}

/// The `Subject Public Key Info:` block of a certificate or a request.
fn print_subject_public_key_info(
    out: &mut Vec<u8>,
    spki: &SubjectPublicKeyInfo<'_>,
    compat: Compat,
) -> Result<()> {
    out.extend_from_slice(
        b"        Subject Public Key Info:\n            Public Key Algorithm: ",
    );
    out.extend_from_slice(
        objects::long_name(&spki.algorithm.oid.as_oid())?.as_bytes(),
    );
    out.push(b'\n');
    print_key(out, spki, None, SPKI_KEY_INDENT, compat)
}

/// `openssl pkey -text`: a private key as OpenSSL prints it, by release
/// line.
///
/// # Errors
///
/// As for a certificate's key (the [`Text`] of [`Certificate`]).
pub fn print_private_key_text(
    key: &AnyPrivateKey,
    compat: Compat,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let der = PublicKey::from(key).encode();
    let spki = spki_view(&der)?;
    let secret = key.secret();
    print_key(&mut out, &spki, Some(secret.expose()), PKEY_INDENT, compat)?;
    Ok(out)
}

/// The view of a key's `SubjectPublicKeyInfo` encoding. The key printer
/// reads that view, which a certificate gives as it is (malformed and
/// unsupported keys included, which a [`PublicKey`] cannot hold); a key
/// that is already a value is printed through the view of its encoding,
/// so that one printer serves both, at the cost of this second decoding.
fn spki_view(der: &[u8]) -> Result<SubjectPublicKeyInfo<'_>> {
    let mut r = Reader::new(der);
    let spki = SubjectPublicKeyInfo::try_from(r.read()?)?;
    r.finish()?;
    Ok(spki)
}

/// `openssl pkey -text_pub` (or `-pubin -text`): a public key as OpenSSL
/// prints it, by release line.
///
/// # Errors
///
/// As for a certificate's key (the [`Text`] of [`Certificate`]).
pub fn print_public_key_text(
    key: &PublicKey,
    compat: Compat,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let der = key.encode();
    print_key(&mut out, &spki_view(&der)?, None, PKEY_INDENT, compat)?;
    Ok(out)
}

/// The outer part of X.509's `SIGNED{ToBeSigned}` ([X.509] section 6.2),
/// which certificates and requests share: the signature algorithm and the
/// signature, as `X509_signature_print` writes them.
///
/// [X.509]: https://www.itu.int/rec/T-REC-X.509
fn print_signed(
    out: &mut Vec<u8>,
    algorithm: &AlgorithmIdentifier,
    signature: &BitString<'_>,
    compat: Compat,
) -> Result<()> {
    out.extend_from_slice(b"    Signature Algorithm: ");
    out.extend_from_slice(signature_name(algorithm)?.as_bytes());
    out.extend_from_slice(b"\n    Signature Value:\n");
    if signature.unused() != 0 {
        return Err(Error::unsupported(
            "signature BIT STRING with unused bits",
        ));
    }
    hex_dump(
        out,
        signature.bytes(),
        SIGNATURE_INDENT,
        compat.signature_bytes_per_line(),
    );
    Ok(())
}

/// The `openssl req -text` block of a request, in the layout of the release
/// line `compat` names: the `CertificationRequestInfo` (version, subject,
/// key, attributes), then the signature as for a certificate. OpenSSL
/// prints `Requested Extensions:` under the attributes even when there are
/// none, so this does too.
///
/// # Errors
///
/// [`Error::Unsupported`] for attributes other than the requested
/// extensions, and as for a [`Certificate`] for the key, the extensions
/// and the signature.
impl Text for CertificationRequest {
    type Layout = Compat;

    fn to_text(&self, compat: Compat) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(
            b"Certificate Request:\n    Data:\n        Version: 1 (0x0)\n        Subject: ",
        );
        out.extend_from_slice(
            &self.subject_name()?.to_openssl(compat.name_style())?,
        );
        out.push(b'\n');
        let key = self.public_key().encode();
        print_subject_public_key_info(&mut out, &spki_view(&key)?, compat)?;
        let requested = self.requested_extensions()?;
        let extensions = requested.views()?;
        out.extend_from_slice(b"        Attributes:\n");
        if extensions.is_empty() {
            out.extend_from_slice(b"            (none)\n");
        }
        out.extend_from_slice(b"            Requested Extensions:\n");
        extensions.print_list(&mut out, ExtensionIndent::Request)?;
        print_signed(
            &mut out,
            &AlgorithmIdentifier::from(self.algorithm()),
            &BitString::from_bytes(self.signature()),
            compat,
        )?;
        Ok(out)
    }
}

/// `-serial`: `i2a_ASN1_INTEGER` (upper-case hex, `00` for zero, a
/// backslash-newline every 35 bytes).
#[must_use]
pub fn serial_line(serial: &Integer) -> String {
    let mut s = String::from("serial=");
    if serial.is_negative() {
        s.push('-');
    }
    if serial.magnitude().is_empty() {
        s.push_str("00");
    }
    for (i, b) in serial.magnitude().iter().enumerate() {
        if i > 0 && i % SERIAL_BYTES_PER_LINE == 0 {
            s.push_str("\\\n");
        }
        s.push_str(&hex::plain(&[*b], Case::Upper));
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use baldssl_core::encoding::Decodable;
    use baldssl_test_utils::{fixture, hex};

    use super::*;

    fn int(bytes: &[u8]) -> Integer {
        Integer::parse(bytes).unwrap()
    }

    fn serial(bytes: &[u8]) -> String {
        let mut out = Vec::new();
        print_serial(&mut out, &int(bytes));
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn serial_forms() {
        assert_eq!(
            serial(&[0x12, 0x34]),
            "        Serial Number: 4660 (0x1234)\n"
        );
        assert_eq!(serial(&[0x00]), "        Serial Number: 0 (0x0)\n");
        assert_eq!(serial(&[0xfe]), "        Serial Number: -2 (-0x2)\n");
        assert_eq!(
            serial(&[0xff]),
            "        Serial Number:\n             (Negative)01\n"
        );
        let max = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(
            serial(&max).contains("9223372036854775807 (0x7fffffffffffffff)")
        );
        let over = [0x00, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            serial(&over),
            "        Serial Number:\n            80:00:00:00:00:00:00:00\n"
        );
        let min = [0x80, 0, 0, 0, 0, 0, 0, 0];
        assert!(
            serial(&min)
                .contains(" -9223372036854775808 (-0x8000000000000000)")
        );
    }

    #[test]
    fn serial_lines() {
        assert_eq!(serial_line(&int(&[0x12, 0x34])), "serial=1234\n");
        assert_eq!(serial_line(&int(&[0x00])), "serial=00\n");
        assert_eq!(serial_line(&int(&[0xfe])), "serial=-02\n");
    }

    #[test]
    fn times() {
        let t = Time::parse(TimeKind::Utc, b"260301090807Z").unwrap();
        assert_eq!(time_rfc822(&t), "Mar  1 09:08:07 2026 GMT");
        let t =
            Time::parse(TimeKind::Generalized, b"20500101000000.25Z").unwrap();
        assert_eq!(time_rfc822(&t), "Jan  1 00:00:00.25 2050 GMT");
    }

    #[test]
    fn dumps() {
        let mut out = Vec::new();
        hex_dump(&mut out, &[0xab; 16], 2, 15);
        assert_eq!(
            out,
            b"  ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:\n  ab\n"
        );
        let mut out = Vec::new();
        hex_dump(&mut out, &[0x01; 19], 1, 18);
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 2);
        let mut out = Vec::new();
        bn_print(
            &mut out,
            "Exponent:",
            &int(&[0x01, 0x00, 0x01]),
            0,
            Compat::V3,
        );
        assert_eq!(out, b"Exponent: 65537 (0x10001)\n");
        let mut out = Vec::new();
        bn_print(&mut out, "Modulus:", &int(&[0x00]), 0, Compat::V3);
        assert_eq!(out, b"Modulus: 0\n");
        let mut big = vec![0x00];
        big.extend([0x80; 9]);
        let mut out = Vec::new();
        bn_print(&mut out, "Modulus:", &int(&big), 0, Compat::V3);
        assert!(out.starts_with(b"Modulus:\n    00:80:"));
        let mut out = Vec::new();
        bn_print(&mut out, "Modulus:", &int(&big), 0, Compat::V4);
        assert!(out.starts_with(b"Modulus:\n    80:80:"));
        let parse = |s: &str| s.parse::<Compat>().ok();
        assert_eq!(parse("4.1.0"), Some(Compat::V4));
        assert_eq!(parse("3"), Some(Compat::V3));
        assert_eq!(parse("1.1.1"), None);
        assert_eq!(parse("30"), None);
        assert_eq!(parse("3.0"), Some(Compat::V30));
        assert_eq!(parse("3.0.22"), Some(Compat::V30));
        assert_eq!(parse("3.5.9"), Some(Compat::V3));
        assert_eq!(parse("3.6"), Some(Compat::V36));
        assert_eq!(parse(" 3.6.5 "), Some(Compat::V36));
        // Every profile parses back from its name.
        for compat in Compat::ALL {
            assert_eq!(parse(compat.name()), Some(compat));
        }
        let Err(Error::Usage(message)) = "2".parse::<Compat>() else {
            panic!("2 is no profile")
        };
        assert!(message.contains("3.0, 3, 3.6, 4"), "{message}");
    }

    /// `req -noout -text` against what each release line of OpenSSL prints
    /// for every request of the fixtures (`req/text-<line>.txt`, recorded
    /// by `scripts/gen-request-texts.py` from OpenSSL 3.0.22, 3.5.9 and
    /// 4.1.0): ECDSA and Ed25519 keys, single and multi-valued RDNs.
    #[test]
    fn request_texts() {
        for (file, compat) in [
            ("req/text-v30.txt", Compat::V30),
            ("req/text-v3.txt", Compat::V3),
            ("req/text-v4.txt", Compat::V4),
        ] {
            let mut count = 0;
            for line in fixture(file).lines().filter(|l| !l.starts_with('#')) {
                let (request, text) = line.split_once(' ').unwrap();
                let request =
                    CertificationRequest::decode(&hex(request)).unwrap();
                assert_eq!(
                    String::from_utf8(request.to_text(compat).unwrap())
                        .unwrap(),
                    String::from_utf8(hex(text)).unwrap(),
                    "{file} {count}"
                );
                count += 1;
            }
            assert_eq!(count, 48, "{file}");
        }
    }
}
