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
};

use crate::{
    cert::Certificate, ext, name::NameStyle, objects, version::Version,
};

/// Which OpenSSL release line's `-text` layout to reproduce. The two lines
/// differ only in hex-dump geometry and the EC key header; everything else
/// is shared. `scripts/interop.sh` checks each profile against real
/// binaries of that line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compat {
    /// OpenSSL 3.0, whose names use the older escaped style
    /// ([`NameStyle::Oneline`]).
    V30,
    /// OpenSSL 3.2 to 3.6.
    #[default]
    V3,
    /// OpenSSL 4.0 and later.
    V4,
}

impl Compat {
    /// Bytes per line in `ASN1_buf_print` (keys, modulus).
    fn key_bytes_per_line(self) -> usize {
        match self {
            Compat::V30 | Compat::V3 => 15,
            Compat::V4 => 16,
        }
    }

    /// Bytes per line in `X509_signature_dump`.
    fn signature_bytes_per_line(self) -> usize {
        match self {
            Compat::V30 | Compat::V3 => 18,
            Compat::V4 => 24,
        }
    }

    /// Whether a bignum with its top bit set is printed with a leading
    /// `00:` (the two's-complement sign byte).
    fn bn_sign_byte(self) -> bool {
        self != Compat::V4
    }

    /// How this release line prints names.
    #[must_use]
    pub fn name_style(self) -> NameStyle {
        match self {
            Compat::V30 => NameStyle::Oneline,
            Compat::V3 | Compat::V4 => NameStyle::Utf8,
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
fn signature_name(
    alg: &crate::cert::AlgorithmIdentifier<'_>,
) -> Result<String> {
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

fn print_public_key(
    out: &mut Vec<u8>,
    cert: &Certificate<'_>,
    compat: Compat,
) -> Result<()> {
    let per_line = compat.key_bytes_per_line();
    let spki = &cert.spki;
    let alg = spki.algorithm.oid.to_dotted()?;
    let key = spki.public_key.bytes;
    if spki.public_key.unused != 0 {
        return Err(Error::invalid("public key BIT STRING with unused bits"));
    }
    let pad16 = " ".repeat(16);
    match alg.as_str() {
        // rsaEncryption: RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
        "1.2.840.113549.1.1.1" => {
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
            bn_print(out, "Modulus:", &n, 16, compat);
            bn_print(out, "Exponent:", &e, 16, compat);
        }
        // id-ecPublicKey with a named curve.
        "1.2.840.10045.2.1" => {
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
                Compat::V30 | Compat::V3 => format!("{} bit", c.bits),
                Compat::V4 => format!(
                    "{} bit field, {} bit security level",
                    c.bits, c.security
                ),
            };
            out.extend_from_slice(
                format!("{pad16}Public-Key: ({size})\n{pad16}pub:\n")
                    .as_bytes(),
            );
            buf_print(out, key, 20, per_line);
            out.extend_from_slice(
                format!(
                    "{pad16}ASN1 OID: {}\n{pad16}NIST CURVE: {}\n",
                    c.sn, c.nist
                )
                .as_bytes(),
            );
        }
        // Ed25519 (RFC 8410): no parameters, 32-byte key.
        "1.3.101.112" => {
            if spki.algorithm.parameters.is_some() || key.len() != 32 {
                return Err(Error::invalid("Ed25519 public key"));
            }
            out.extend_from_slice(
                format!("{pad16}ED25519 Public-Key:\n{pad16}pub:\n").as_bytes(),
            );
            buf_print(out, key, 20, per_line);
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

/// The full `-text` block.
///
/// # Errors
///
/// [`Error::Unsupported`] for anything baldssl cannot yet print exactly as
/// OpenSSL does; [`Error::Invalid`] for malformed contents.
pub fn print_text(cert: &Certificate<'_>, compat: Compat) -> Result<Vec<u8>> {
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
    out.extend_from_slice(
        b"\n        Subject Public Key Info:\n            Public Key Algorithm: ",
    );
    out.extend_from_slice(
        objects::long_name(&cert.spki.algorithm.oid)?.as_bytes(),
    );
    out.push(b'\n');
    print_public_key(&mut out, cert, compat)?;
    ext::print_extensions(&mut out, &cert.extensions)?;
    out.extend_from_slice(b"    Signature Algorithm: ");
    out.extend_from_slice(
        signature_name(&cert.signature_algorithm)?.as_bytes(),
    );
    out.extend_from_slice(b"\n    Signature Value:\n");
    if cert.signature.unused != 0 {
        return Err(Error::unsupported(
            "signature BIT STRING with unused bits",
        ));
    }
    signature_dump(
        &mut out,
        cert.signature.bytes,
        8,
        compat.signature_bytes_per_line(),
    );
    Ok(out)
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
    }
}
