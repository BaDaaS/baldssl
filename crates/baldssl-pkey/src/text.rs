//! Keys as OpenSSL's text printers write them (`openssl pkey -text`, and
//! the `Subject Public Key Info:` block of `openssl x509 -text` and
//! `openssl req -text`), byte for byte, by release line ([`Compat`]).
//!
//! The printer reads a key in the structure it travels in, a
//! `SubjectPublicKeyInfo` ([RFC 5280 section 4.1]), of which this module
//! gives the borrowed view certificate and request readers share: any key
//! algorithm can be printed from it, RSA included, while [`PublicKey`] and
//! [`AnyPrivateKey`] print through it the keys baldssl implements.
//!
//! [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1

use baldssl_core::{
    Error, Result,
    compat::Compat,
    der::{BitString, DerError, Integer, Oid, Reader, Tlv, tag},
    encoding::Encodable,
    hex::{self, Case},
    text::Text,
};

use crate::{AnyPrivateKey, PublicKey};

/// The view of a DER `AlgorithmIdentifier ::= SEQUENCE { algorithm OID,
/// parameters ANY OPTIONAL }` ([RFC 5280 section 4.1.1.2]).
///
/// [RFC 5280 section 4.1.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmIdentifier<'a> {
    /// The algorithm.
    pub oid: Oid<'a>,
    /// The raw parameters, if present.
    pub parameters: Option<Tlv<'a>>,
}

impl<'a> AlgorithmIdentifier<'a> {
    /// Decodes the AlgorithmIdentifier that comes next in `r`.
    ///
    /// # Errors
    ///
    /// On malformed DER.
    pub fn read(r: &mut Reader<'a>) -> Result<Self> {
        let mut seq = r.sequence()?;
        let oid = Oid::parse(seq.expect(tag::OID)?.value)?;
        let parameters = if seq.is_empty() {
            None
        } else {
            Some(seq.read()?)
        };
        seq.finish()?;
        Ok(AlgorithmIdentifier { oid, parameters })
    }
}

/// The view of a DER `SubjectPublicKeyInfo` ([RFC 5280 section 4.1]):
/// the key's algorithm and its bits.
///
/// [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectPublicKeyInfo<'a> {
    /// The key algorithm and its parameters.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// The `subjectPublicKey` BIT STRING.
    pub public_key: BitString<'a>,
}

/// The view of one DER `SubjectPublicKeyInfo` TLV.
///
/// # Errors
///
/// A TLV that is not a SEQUENCE, or malformed contents.
impl<'a> TryFrom<Tlv<'a>> for SubjectPublicKeyInfo<'a> {
    type Error = Error;

    fn try_from(tlv: Tlv<'a>) -> Result<Self> {
        if tlv.octet() != tag::SEQUENCE {
            return Err(DerError::UnexpectedTag {
                expected: tag::SEQUENCE,
                found: tlv.octet(),
            }
            .into());
        }
        let mut r = Reader::new(tlv.value);
        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier::read(&mut r)?,
            public_key: BitString::parse(r.expect(tag::BIT_STRING)?.value)?,
        };
        r.finish()?;
        Ok(spki)
    }
}

/// Where a key block goes: the release line, and the indentation of its
/// header (16 spaces in a certificate or a request, 0 for `pkey`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLayout {
    /// The release line.
    pub compat: Compat,
    /// The header's indentation, in spaces; the hex dumps go four further.
    pub indent: usize,
}

/// The key block of a `SubjectPublicKeyInfo`: a header (`Public-Key:`,
/// `ED25519 Public-Key:`), the key, and for EC the curve.
///
/// # Errors
///
/// [`Error::Unsupported`] for a key algorithm or curve baldssl does not
/// print; [`Error::Invalid`] for a malformed key.
impl Text for SubjectPublicKeyInfo<'_> {
    type Layout = KeyLayout;

    fn to_text(&self, layout: KeyLayout) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        print_key(&mut out, self, None, layout.indent, layout.compat)?;
        Ok(out)
    }
}

/// `openssl pkey -text_pub` (or `-pubin -text`): the public key as OpenSSL
/// prints it, by release line.
///
/// # Errors
///
/// As for a [`SubjectPublicKeyInfo`].
impl Text for PublicKey {
    type Layout = Compat;

    fn to_text(&self, compat: Compat) -> Result<Vec<u8>> {
        let der = self.encode();
        let mut r = Reader::new(&der);
        let spki = SubjectPublicKeyInfo::try_from(r.read()?)?;
        r.finish()?;
        spki.to_text(KeyLayout { compat, indent: 0 })
    }
}

/// `openssl pkey -text`: the private key as OpenSSL prints it, by release
/// line: the secret (`priv:`, at its full length), then the public key.
///
/// # Errors
///
/// As for a [`SubjectPublicKeyInfo`].
impl Text for AnyPrivateKey {
    type Layout = Compat;

    fn to_text(&self, compat: Compat) -> Result<Vec<u8>> {
        let der = PublicKey::from(self).encode();
        let mut r = Reader::new(&der);
        let spki = SubjectPublicKeyInfo::try_from(r.read()?)?;
        r.finish()?;
        let secret = self.secret();
        let mut out = Vec::new();
        print_key(&mut out, &spki, Some(secret.expose()), 0, compat)?;
        Ok(out)
    }
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
struct Block<'a> {
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
    block: &Block<'_>,
) -> Result<()> {
    let Block {
        key,
        secret,
        pad: pad16,
        data,
        per_line,
        kind,
        compat,
    } = block;
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
    let curve_oid = Oid::parse(params.value)?;
    let curve = curve_oid.to_dotted()?;
    let Some(c) = CURVES.iter().find(|c| c.oid == curve) else {
        return Err(Error::unsupported(format!("EC curve {curve}")));
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
    let block = Block {
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
        "1.2.840.10045.2.1" => print_ec_key(out, spki, &block)?,
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
                "public key algorithm {alg}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use baldssl_core::{compat::Compat, der::Integer};

    use super::{bn_print, buf_print};

    fn int(bytes: &[u8]) -> Integer {
        Integer::parse(bytes).unwrap()
    }

    /// `ASN1_buf_print` and `ASN1_bn_print`, the sign byte by release line.
    #[test]
    fn dumps() {
        let mut out = Vec::new();
        buf_print(&mut out, &[0xab; 16], 2, 15);
        assert_eq!(
            out,
            b"  ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:\n  ab\n"
        );
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
    }
}
