//! `openssl x509 -text`, reproduced byte for byte (`X509_print_ex` with
//! default flags, as in OpenSSL 3.x and 4.x).
//!
//! Platform note: OpenSSL decides between the one-line and the hex form of a
//! serial number by `sizeof(long)`. baldssl follows LP64 (8 bytes, Linux and
//! macOS); OpenSSL on Windows (LLP64, 4-byte `long`) prints serials of 5 to
//! 8 bytes in the hex form instead.

use baldssl_core::{
    Error, Result,
    compat::Compat,
    der::{BitString, Integer, Reader, Time, TimeKind},
    encoding::Encodable,
    hex::{self, Case},
    text::Text,
};
use baldssl_pkey::{AlgorithmIdentifier, KeyLayout, SubjectPublicKeyInfo};

use crate::{
    CertificationRequest, algorithm, cert::Certificate, ext, name::NameStyle,
    objects, version::Version,
};

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
    out.extend_from_slice(&cert.issuer.to_openssl(NameStyle::from(compat))?);
    out.extend_from_slice(b"\n        Validity\n            Not Before: ");
    out.extend_from_slice(time_rfc822(&cert.validity.not_before).as_bytes());
    out.extend_from_slice(b"\n            Not After : ");
    out.extend_from_slice(time_rfc822(&cert.validity.not_after).as_bytes());
    out.extend_from_slice(b"\n        Subject: ");
    out.extend_from_slice(&cert.subject.to_openssl(NameStyle::from(compat))?);
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
    out.extend(spki.to_text(KeyLayout { compat, indent: 16 })?);
    Ok(())
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
            &self.subject_name()?.to_openssl(NameStyle::from(compat))?,
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
        signature_dump(&mut out, &[0x01; 19], 1, 18);
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 2);
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
