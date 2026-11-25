//! `openssl x509 -text`, reproduced byte for byte (`X509_print_ex` with
//! default flags, as in OpenSSL 3.x and 4.x).
//!
//! Platform note: OpenSSL decides between the one-line and the hex form of a
//! serial number by `sizeof(long)`. baldssl follows LP64 (8 bytes, Linux and
//! macOS); OpenSSL on Windows (LLP64, 4-byte `long`) prints serials of 5 to
//! 8 bytes in the hex form instead.

use baldssl_core::{
    Error, Result,
    der::{Integer, Reader, Time, TimeKind, tag},
    hex::{self, Case},
    text::Text,
};

use baldssl_core::{der::BitString, encoding::Encodable};
use baldssl_pkey::{AnyPrivateKey, PublicKey};

use crate::{
    CertificationRequest, algorithm,
    cert::{AlgorithmIdentifier, Certificate, SubjectPublicKeyInfo},
    ext,
    name::NameStyle,
    objects,
    version::Version,
};

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
    /// as PKCS#8 ([`Compat::private_key_der_is_traditional`]).
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
    /// `00:` (the two's-complement sign byte).
    fn bn_sign_byte(self) -> bool {
        self != Compat::V4
    }

    /// Whether `openssl pkey -outform DER` writes a private key in its
    /// algorithm's traditional form (SEC 1's ECPrivateKey for EC) rather
    /// than PKCS#8. OpenSSL 3.0 to 3.5 call `i2d_PrivateKey_bio`, which
    /// writes the traditional form; from 3.6, `apps/pkey.c` calls
    /// `i2d_PKCS8PrivateKey_bio` unless `-traditional` is given.
    #[must_use]
    pub fn private_key_der_is_traditional(self) -> bool {
        matches!(self, Compat::V30 | Compat::V3)
    }

    /// How this release line prints names.
    #[must_use]
    pub fn name_style(self) -> NameStyle {
        match self {
            Compat::V30 => NameStyle::Oneline,
            Compat::V3 | Compat::V36 | Compat::V4 => NameStyle::Utf8,
        }
    }

    /// Parses a profile (`3.0`, `3` or `4`) or an OpenSSL version
    /// (`3.0.22`, `3.5.9`, `4.1.0`).
    #[must_use]
    pub fn from_version_opt(s: &str) -> Option<Self> {
        let s = s.trim();
        if s == "3.0" || s.starts_with("3.0.") {
            return Some(Compat::V30);
        }
        if s == "3.6" || s.starts_with("3.6.") {
            return Some(Compat::V36);
        }
        match s.split('.').next()? {
            "3" => Some(Compat::V3),
            "4" => Some(Compat::V4),
            _ => None,
        }
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
    "Nov", "Dec",
];

/// `ASN1_TIME_print` ([RFC 822][rfc822] style, the default `-dateopt`).
///
/// [rfc822]: https://www.rfc-editor.org/rfc/rfc822
#[must_use]
pub fn time_rfc822(t: &Time) -> String {
    let month = MONTHS
        .get(usize::from(t.month.saturating_sub(1)))
        .copied()
        .unwrap_or("???");
    let frac = if t.kind == TimeKind::Generalized && !t.fraction.is_empty() {
        format!(".{}", t.fraction)
    } else {
        String::new()
    };
    format!(
        "{month} {:2} {:02}:{:02}:{:02}{frac} {} GMT",
        t.day, t.hour, t.minute, t.second, t.year
    )
}

/// `ASN1_buf_print`: `per_line` bytes per line, lower-case, `:`-separated.
fn buf_print(out: &mut Vec<u8>, bytes: &[u8], indent: usize, per_line: usize) {
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

/// `ASN1_bn_print`, with `BN_BYTES = 8`.
fn bn_print(
    out: &mut Vec<u8>,
    label: &str,
    n: &Integer,
    indent: usize,
    compat: Compat,
) {
    out.extend_from_slice(" ".repeat(indent).as_bytes());
    let neg = if n.negative { "-" } else { "" };
    if n.magnitude.is_empty() {
        out.extend_from_slice(format!("{label} 0\n").as_bytes());
        return;
    }
    if n.magnitude.len() <= 8 {
        let v = n.magnitude_u128_opt().unwrap_or(0);
        out.extend_from_slice(
            format!("{label} {neg}{v} ({neg}0x{v:x})\n").as_bytes(),
        );
        return;
    }
    let tail = if n.negative { " (Negative)" } else { "" };
    out.extend_from_slice(format!("{label}{tail}\n").as_bytes());
    let mut buf = Vec::with_capacity(n.magnitude.len().saturating_add(1));
    if compat.bn_sign_byte()
        && n.magnitude.first().is_some_and(|b| b & 0x80 != 0)
    {
        buf.push(0);
    }
    buf.extend_from_slice(&n.magnitude);
    buf_print(
        out,
        &buf,
        indent.saturating_add(4),
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
            serial.negative
                && serial.magnitude.len() <= 8
                && serial
                    .magnitude_u128_opt()
                    .is_some_and(|m| m <= 1u128 << 63)
        }
    };
    let minus_one = serial.negative && serial.magnitude == [1];
    if fits && !minus_one {
        let v = serial.magnitude_u128_opt().unwrap_or(0);
        let neg = if serial.negative { "-" } else { "" };
        out.extend_from_slice(format!(" {neg}{v} ({neg}0x{v:x})\n").as_bytes());
    } else {
        out.extend_from_slice(b"\n            ");
        if serial.negative {
            out.extend_from_slice(b" (Negative)");
        }
        out.extend_from_slice(
            hex::colon(&serial.magnitude, Case::Lower).as_bytes(),
        );
        out.push(b'\n');
    }
}

/// `X509_signature_dump`: `per_line` bytes per line.
fn signature_dump(
    out: &mut Vec<u8>,
    sig: &[u8],
    indent: usize,
    per_line: usize,
) {
    let pad = " ".repeat(indent);
    let per_line = per_line.max(1);
    for (i, b) in sig.iter().enumerate() {
        if i % per_line == 0 {
            if i > 0 {
                out.push(b'\n');
            }
            out.extend_from_slice(pad.as_bytes());
        }
        out.extend_from_slice(hex::plain(&[*b], Case::Lower).as_bytes());
        if i.saturating_add(1) != sig.len() {
            out.push(b':');
        }
    }
    out.push(b'\n');
}

/// Signature algorithms whose OpenSSL `sig_print` adds parameter lines.
fn signature_name(alg: &AlgorithmIdentifier<'_>) -> Result<String> {
    match alg.oid.to_dotted()?.as_str() {
        "1.2.840.113549.1.1.10" => {
            Err(Error::unsupported("RSASSA-PSS parameters in -text output"))
        }
        "1.2.156.10197.1.501" => Err(Error::unsupported("SM2 signatures")),
        _ => objects::long_name(&alg.oid),
    }
}

/// A named curve baldssl supports.
struct Curve {
    oid: &'static str,
    /// OpenSSL short name (`ASN1 OID:`).
    sn: &'static str,
    /// `NIST CURVE:`.
    nist: &'static str,
    /// Order bits, the 3.x `Public-Key: (N bit)`.
    bits: usize,
    /// Security level printed by 4.x (NIST SP 800-57 strengths, capped at
    /// 256).
    security: usize,
}

const CURVES: [Curve; 3] = [
    Curve {
        oid: "1.2.840.10045.3.1.7",
        sn: "prime256v1",
        nist: "P-256",
        bits: 256,
        security: 128,
    },
    Curve {
        oid: "1.3.132.0.34",
        sn: "secp384r1",
        nist: "P-384",
        bits: 384,
        security: 192,
    },
    Curve {
        oid: "1.3.132.0.35",
        sn: "secp521r1",
        nist: "P-521",
        bits: 521,
        security: 256,
    },
];

fn field_bytes(bits: usize) -> usize {
    bits.div_ceil(8)
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
    /// `Private` or `Public`.
    kind: &'a str,
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
    let params = spki
        .algorithm
        .parameters
        .ok_or_else(|| Error::invalid("EC key without parameters"))?;
    if params.octet() != tag::OID {
        return Err(Error::unsupported(
            "explicit or implicit EC domain parameters",
        ));
    }
    let curve_oid = baldssl_core::der::Oid::parse(params.value)?;
    let curve = curve_oid.to_dotted()?;
    let Some(c) = CURVES.iter().find(|c| c.oid == curve) else {
        return Err(Error::unsupported(format!(
            "EC curve {curve} ({})",
            objects::short_name(&curve_oid)?
        )));
    };
    let len = field_bytes(c.bits);
    let well_formed = match key.first() {
        Some(0x04) => key.len() == 2 * len + 1,
        Some(0x02 | 0x03) => key.len() == len + 1,
        _ => false,
    };
    // TODO(ec-point-validation): OpenSSL also rejects points that
    // are not on the curve; that needs field arithmetic.
    if !well_formed {
        return Err(Error::invalid("EC point encoding"));
    }
    let size = match compat {
        Compat::V30 | Compat::V3 | Compat::V36 => format!("{} bit", c.bits),
        Compat::V4 => {
            format!("{} bit field, {} bit security level", c.bits, c.security)
        }
    };
    out.extend_from_slice(format!("{pad16}{kind}-Key: ({size})\n").as_bytes());
    // EC_KEY_priv2buf: the scalar at the full length of the order, leading
    // zeros kept, no sign byte, in every release line.
    if let Some(secret) = secret {
        out.extend_from_slice(format!("{pad16}priv:\n").as_bytes());
        buf_print(out, secret, data, per_line);
    }
    out.extend_from_slice(format!("{pad16}pub:\n").as_bytes());
    buf_print(out, key, data, per_line);
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
        "Private"
    } else {
        "Public"
    };
    let data = indent.saturating_add(4);
    let alg = spki.algorithm.oid.to_dotted()?;
    let key = spki.public_key.bytes;
    if spki.public_key.unused != 0 {
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
    match alg.as_str() {
        // rsaEncryption: RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
        "1.2.840.113549.1.1.1" => {
            if secret.is_some() {
                return Err(Error::unsupported("RSA private keys"));
            }
            if let Some(p) = &spki.algorithm.parameters
                && (p.octet() != tag::NULL || !p.value.is_empty())
            {
                return Err(Error::invalid("rsaEncryption parameters"));
            }
            let mut outer = Reader::new(key);
            let mut seq = outer.sequence()?;
            outer.finish()?;
            let n = Integer::parse(seq.expect(tag::INTEGER)?.value)?;
            let e = Integer::parse(seq.expect(tag::INTEGER)?.value)?;
            seq.finish()?;
            out.extend_from_slice(
                format!("{pad16}Public-Key: ({} bit)\n", n.bits()).as_bytes(),
            );
            bn_print(out, "Modulus:", &n, indent, compat);
            bn_print(out, "Exponent:", &e, indent, compat);
        }
        // id-ecPublicKey with a named curve.
        "1.2.840.10045.2.1" => print_ec_key(out, spki, &layout)?,
        // Ed25519 (RFC 8410): no parameters, 32-byte key.
        "1.3.101.112" => {
            if spki.algorithm.parameters.is_some() || key.len() != 32 {
                return Err(Error::invalid("Ed25519 public key"));
            }
            out.extend_from_slice(
                format!("{pad16}ED25519 {kind}-Key:\n").as_bytes(),
            );
            if let Some(secret) = secret {
                out.extend_from_slice(format!("{pad16}priv:\n").as_bytes());
                buf_print(out, secret, data, per_line);
            }
            out.extend_from_slice(format!("{pad16}pub:\n").as_bytes());
            buf_print(out, key, data, per_line);
        }
        _ => {
            return Err(Error::unsupported(format!(
                "public key algorithm {alg} ({})",
                objects::long_name(&spki.algorithm.oid)?
            )));
        }
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
/// [`Error::Unsupported`] for anything baldssl cannot yet print exactly as
/// OpenSSL does; [`Error::Invalid`] for malformed contents.
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
    ext::print_extensions(&mut out, &cert.extensions)?;
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
    out.extend_from_slice(objects::long_name(&spki.algorithm.oid)?.as_bytes());
    out.push(b'\n');
    print_key(out, spki, None, 16, compat)
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
    let mut r = Reader::new(&der);
    let spki = SubjectPublicKeyInfo::try_from(r.read()?)?;
    r.finish()?;
    let secret = key.secret();
    print_key(&mut out, &spki, Some(secret.expose()), 0, compat)?;
    Ok(out)
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
    let mut r = Reader::new(&der);
    let spki = SubjectPublicKeyInfo::try_from(r.read()?)?;
    r.finish()?;
    print_key(&mut out, &spki, None, 0, compat)?;
    Ok(out)
}

/// The outer part of X.509's `SIGNED{ToBeSigned}` ([X.509] section 6.2),
/// which certificates and requests share: the signature algorithm and the
/// signature, as `X509_signature_print` writes them.
///
/// [X.509]: https://www.itu.int/rec/T-REC-X.509
fn print_signed(
    out: &mut Vec<u8>,
    algorithm: &AlgorithmIdentifier<'_>,
    signature: &BitString<'_>,
    compat: Compat,
) -> Result<()> {
    out.extend_from_slice(b"    Signature Algorithm: ");
    out.extend_from_slice(signature_name(algorithm)?.as_bytes());
    out.extend_from_slice(b"\n    Signature Value:\n");
    if signature.unused != 0 {
        return Err(Error::unsupported(
            "signature BIT STRING with unused bits",
        ));
    }
    signature_dump(out, signature.bytes, 8, compat.signature_bytes_per_line());
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
        let mut r = Reader::new(&key);
        let spki = SubjectPublicKeyInfo::try_from(r.read()?)?;
        r.finish()?;
        print_subject_public_key_info(&mut out, &spki, compat)?;
        let extensions = self.requested_extensions()?;
        out.extend_from_slice(b"        Attributes:\n");
        if extensions.is_empty() {
            out.extend_from_slice(b"            (none)\n");
        }
        out.extend_from_slice(b"            Requested Extensions:\n");
        ext::print_extension_list(&mut out, &extensions, 16)?;
        let oid = algorithm::oid(self.algorithm());
        print_signed(
            &mut out,
            &AlgorithmIdentifier {
                oid: oid.as_oid(),
                parameters: None,
            },
            &BitString {
                unused: 0,
                bytes: self.signature(),
            },
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
    if serial.negative {
        s.push('-');
    }
    if serial.magnitude.is_empty() {
        s.push_str("00");
    }
    for (i, b) in serial.magnitude.iter().enumerate() {
        if i > 0 && i % 35 == 0 {
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
        buf_print(&mut out, &[0xab; 16], 2, 15);
        assert_eq!(
            out,
            b"  ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:\n  ab\n"
        );
        let mut out = Vec::new();
        signature_dump(&mut out, &[0x01; 19], 1, 18);
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
        assert_eq!(Compat::from_version_opt("4.1.0"), Some(Compat::V4));
        assert_eq!(Compat::from_version_opt("3"), Some(Compat::V3));
        assert_eq!(Compat::from_version_opt("1.1.1"), None);
        assert_eq!(Compat::from_version_opt("3.0"), Some(Compat::V30));
        assert_eq!(Compat::from_version_opt("3.0.22"), Some(Compat::V30));
        assert_eq!(Compat::from_version_opt("3.5.9"), Some(Compat::V3));
        assert_eq!(Compat::from_version_opt("3.6"), Some(Compat::V36));
        assert_eq!(Compat::from_version_opt("3.6.5"), Some(Compat::V36));
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
