//! Distinguished names and their OpenSSL rendering.
//!
//! Without `-nameopt`, OpenSSL's `x509` prints names in one of two styles
//! ([`NameStyle`]), both with RDNs joined by `", "`, multi-valued RDNs by
//! `" + "`, short field names, and every string type converted to UTF-8:
//!
//! * OpenSSL 3.2 and later: `XN_FLAG_SEP_CPLUS_SPC |
//!   ASN1_STRFLGS_UTF8_CONVERT`, `=` without spaces and *no escaping at
//!   all*. The output is then bytes, not necessarily valid UTF-8 (a
//!   UTF8String is copied verbatim, and BMPString surrogates are encoded one
//!   by one), so the printer returns `Vec<u8>`.
//! * OpenSSL 3.0: `XN_FLAG_ONELINE`, ` = ` with spaces, bytes above `0x7F`
//!   and control characters escaped as `\XX`, and a value containing an RFC
//!   2253 special character (`,+<>;`, or a leading `#` or space, or a
//!   trailing space) wrapped in double quotes.

use baldssl_core::{
    Error, Result,
    der::{Oid, Reader, Tlv, syntax::RawTlv, tag},
};

use crate::objects;

/// How names are printed; see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameStyle {
    /// OpenSSL 3.2 and later: `CN=x`, UTF-8, no escaping.
    Utf8,
    /// OpenSSL 3.0 (`XN_FLAG_ONELINE`): `CN = x`, escaped and quoted.
    Oneline,
}

/// `AttributeTypeAndValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attribute<'a> {
    /// The attribute type.
    pub(crate) oid: Oid<'a>,
    /// The value, any ASN.1 type.
    pub(crate) value: Tlv<'a>,
}

/// `Name ::= SEQUENCE OF RelativeDistinguishedName`, each RDN a SET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name<'a> {
    /// The RDNs in encoding order.
    pub(crate) rdns: Vec<Vec<Attribute<'a>>>,
}

impl<'a> Name<'a> {
    /// Decodes a Name from `r`.
    ///
    /// # Errors
    ///
    /// On malformed DER or an empty RDN.
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self> {
        Self::from_contents(r.expect(tag::SEQUENCE)?.value)
    }

    /// Decodes a Name from the contents of its SEQUENCE.
    ///
    /// # Errors
    ///
    /// On malformed DER or an empty RDN.
    pub(crate) fn from_contents(value: &'a [u8]) -> Result<Self> {
        let mut seq = Reader::new(value);
        let mut rdns = Vec::new();
        while !seq.is_empty() {
            let mut set = Reader::new(seq.expect(tag::SET)?.value);
            let mut rdn = Vec::new();
            while !set.is_empty() {
                let mut atv = set.sequence()?;
                let oid = Oid::parse(atv.expect(tag::OID)?.value)?;
                let value = atv.read()?;
                atv.finish()?;
                rdn.push(Attribute { oid, value });
            }
            if rdn.is_empty() {
                return Err(Error::invalid("empty RelativeDistinguishedName"));
            }
            rdns.push(rdn);
        }
        Ok(Name { rdns })
    }

    /// The name as OpenSSL compares names (`X509_NAME_cmp` over
    /// `x509_name_canon`): each RDN as the sorted DER of its attributes,
    /// where a string value (UTF8String, BMPString, UniversalString,
    /// PrintableString, T61String, IA5String, VisibleString) becomes a
    /// UTF8String with ASCII letters lowercased, leading and trailing
    /// spaces dropped and inner runs of spaces made one (`asn1_string_canon`),
    /// and any other value stays as it is. Two names are the same name for
    /// chaining exactly when their canonical forms are equal.
    ///
    /// # Errors
    ///
    /// A string that does not convert to UTF-8.
    pub(crate) fn canonical(&self) -> Result<Vec<Vec<Vec<u8>>>> {
        self.rdns
            .iter()
            .map(|rdn| {
                let mut entries = rdn
                    .iter()
                    .map(|a| {
                        let mut value = a.value.encoded.to_vec();
                        if CANONICAL_STRINGS.contains(&a.value.octet()) {
                            let mut utf8 = Vec::new();
                            string_to_utf8(&a.value, &mut utf8)?;
                            value =
                                tlv(tag::UTF8_STRING, &canonical_text(&utf8));
                        }
                        let mut entry = tlv(tag::OID, a.oid.as_bytes());
                        entry.extend(value);
                        Ok(tlv(tag::SEQUENCE, &entry))
                    })
                    .collect::<Result<Vec<Vec<u8>>>>()?;
                entries.sort();
                Ok(entries)
            })
            .collect()
    }

    /// The OpenSSL default (`-nameopt` unset) one-line rendering.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for value types OpenSSL would not print as
    /// text, and, in the [`NameStyle::Oneline`] style, for values containing
    /// `"` or `\\`, whose escaping baldssl does not reproduce yet.
    pub fn to_openssl(&self, style: NameStyle) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for (i, rdn) in self.rdns.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b", ");
            }
            for (j, atv) in rdn.iter().enumerate() {
                if j > 0 {
                    out.extend_from_slice(b" + ");
                }
                out.extend_from_slice(
                    objects::short_name(&atv.oid)?.as_bytes(),
                );
                let mut value = Vec::new();
                string_to_utf8(&atv.value, &mut value)?;
                match style {
                    NameStyle::Utf8 => {
                        out.push(b'=');
                        out.extend_from_slice(&value);
                    }
                    NameStyle::Oneline => {
                        out.extend_from_slice(b" = ");
                        oneline_value(&value, &mut out)?;
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Escapes a value as `XN_FLAG_ONELINE` does (`do_buf` and `do_esc_char`
/// with `ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_ESC_QUOTE`): `\\XX` for bytes
/// above `0x7E` and control characters, and double quotes around a value
/// that contains an [RFC 2253][rfc2253] special character.
///
/// [rfc2253]: https://www.rfc-editor.org/rfc/rfc2253
fn oneline_value(value: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if value.iter().any(|&b| b == b'"' || b == b'\\') {
        return Err(Error::unsupported(
            "OpenSSL 3.0 name escaping of a value containing \" or \\",
        ));
    }
    let quote = value.iter().any(|b| b",+<>;".contains(b))
        || matches!(value.first(), Some(b'#' | b' '))
        || value.last() == Some(&b' ');
    if quote {
        out.push(b'"');
    }
    for &b in value {
        if (0x20..=0x7e).contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(format!("\\{b:02X}").as_bytes());
        }
    }
    if quote {
        out.push(b'"');
    }
    Ok(())
}

/// Appends the UTF-8 encoding of a code point the way OpenSSL's `UTF8_putc`
/// does: surrogates are encoded like any other value below `0x10000`.
fn push_utf8(c: u32, out: &mut Vec<u8>) -> Result<()> {
    // The casts below keep the low 6 bits of a shifted code point, which is
    // the definition of the UTF-8 encoding.
    #[allow(clippy::cast_possible_truncation)]
    match c {
        0..=0x7f => out.push(c as u8),
        0x80..=0x7ff => {
            out.push(0xc0 | (c >> 6) as u8);
            out.push(0x80 | (c & 0x3f) as u8);
        }
        0x800..=0xffff => {
            out.push(0xe0 | (c >> 12) as u8);
            out.push(0x80 | ((c >> 6) & 0x3f) as u8);
            out.push(0x80 | (c & 0x3f) as u8);
        }
        0x1_0000..=0x10_ffff => {
            out.push(0xf0 | (c >> 18) as u8);
            out.push(0x80 | ((c >> 12) & 0x3f) as u8);
            out.push(0x80 | ((c >> 6) & 0x3f) as u8);
            out.push(0x80 | (c & 0x3f) as u8);
        }
        _ => return Err(Error::unsupported("UniversalString above U+10FFFF")),
    }
    Ok(())
}

/// The DER TLV of a one-octet tag and contents.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    RawTlv::from_tag_and_contents(tag, contents)
        .as_bytes()
        .to_vec()
}

/// The string types OpenSSL canonicalizes in names (`ASN1_MASK_CANON`);
/// NumericString is not one of them.
const CANONICAL_STRINGS: [u8; 7] = [
    tag::UTF8_STRING,
    tag::BMP_STRING,
    tag::UNIVERSAL_STRING,
    tag::PRINTABLE_STRING,
    tag::T61_STRING,
    tag::IA5_STRING,
    tag::VISIBLE_STRING,
];

/// `asn1_string_canon` on UTF-8 text: leading and trailing spaces dropped,
/// each inner run of spaces made one, ASCII letters lowercased; bytes of
/// multi-byte characters are left alone, as OpenSSL leaves them.
fn canonical_text(text: &[u8]) -> Vec<u8> {
    let space =
        |b: &u8| b.is_ascii() && (*b == b' ' || (0x09..=0x0d).contains(b));
    let start = text.iter().position(|b| !space(b)).unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|b| !space(b))
        .map_or(start, |i| i.saturating_add(1));
    let mut out = Vec::with_capacity(end.saturating_sub(start));
    let mut in_space = false;
    for b in text.get(start..end).unwrap_or_default() {
        if space(b) {
            if !in_space {
                out.push(b' ');
            }
            in_space = true;
        } else {
            out.push(b.to_ascii_lowercase());
            in_space = false;
        }
    }
    out
}

/// Converts an ASN.1 string to the bytes OpenSSL prints with
/// `ASN1_STRFLGS_UTF8_CONVERT` and no escaping (`do_print_ex` + `do_buf`).
///
/// # Errors
///
/// [`Error::Unsupported`] for non-string types, [`Error::Invalid`] for a
/// BMPString or UniversalString of bad length.
pub(crate) fn string_to_utf8(value: &Tlv<'_>, out: &mut Vec<u8>) -> Result<()> {
    match value.octet() {
        // UTF8String is copied byte for byte, even when it is not UTF-8.
        tag::UTF8_STRING => out.extend_from_slice(value.value),
        // One byte per character, read as Latin-1, then UTF-8 encoded.
        tag::NUMERIC_STRING
        | tag::PRINTABLE_STRING
        | tag::T61_STRING
        | tag::IA5_STRING
        | tag::VISIBLE_STRING => {
            for &b in value.value {
                push_utf8(u32::from(b), out)?;
            }
        }
        tag::BMP_STRING => {
            let (units, rest) = value.value.as_chunks::<2>();
            if !rest.is_empty() {
                return Err(Error::invalid("BMPString of odd length"));
            }
            for unit in units {
                push_utf8(u32::from(u16::from_be_bytes(*unit)), out)?;
            }
        }
        tag::UNIVERSAL_STRING => {
            let (chars, rest) = value.value.as_chunks::<4>();
            if !rest.is_empty() {
                return Err(Error::invalid("UniversalString length"));
            }
            for c in chars {
                push_utf8(u32::from_be_bytes(*c), out)?;
            }
        }
        other => {
            return Err(Error::unsupported(format!(
                "name attribute value of ASN.1 type 0x{other:02x}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn tlv(octet: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![octet, u8::try_from(value.len()).unwrap()];
        v.extend_from_slice(value);
        v
    }

    fn render(octet: u8, value: &[u8]) -> Result<Vec<u8>> {
        let enc = tlv(octet, value);
        let (t, _) = baldssl_core::der::parse_tlv(&enc).unwrap();
        let mut out = Vec::new();
        string_to_utf8(&t, &mut out)?;
        Ok(out)
    }

    #[test]
    fn string_types() {
        assert_eq!(
            render(tag::UTF8_STRING, "H\u{e9}".as_bytes()).unwrap(),
            "H\u{e9}".as_bytes()
        );
        assert_eq!(render(tag::PRINTABLE_STRING, b"ab").unwrap(), b"ab");
        assert_eq!(
            render(tag::T61_STRING, &[0xe9]).unwrap(),
            "\u{e9}".as_bytes()
        );
        assert_eq!(
            render(tag::BMP_STRING, &[0x00, 0xe9, 0x20, 0xac]).unwrap(),
            "\u{e9}\u{20ac}".as_bytes()
        );
        assert_eq!(
            render(tag::UNIVERSAL_STRING, &[0, 1, 0xf6, 0x00]).unwrap(),
            "\u{1f600}".as_bytes()
        );
        assert!(render(tag::BMP_STRING, &[0x00]).is_err());
        assert!(render(tag::UNIVERSAL_STRING, &[0, 0x11, 0, 0]).is_err());
        assert!(render(tag::OCTET_STRING, b"x").is_err());
        // A lone surrogate is encoded as three bytes, as UTF8_putc does.
        assert_eq!(
            render(tag::BMP_STRING, &[0xd8, 0x00]).unwrap(),
            [0xed, 0xa0, 0x80]
        );
    }

    proptest! {
        /// On valid Rust strings, the UTF-8 encoder agrees with `char`.
        #[test]
        fn utf8_matches_std(c in any::<char>()) {
            let mut ours = Vec::new();
            push_utf8(u32::from(c), &mut ours).unwrap();
            let mut buf = [0u8; 4];
            prop_assert_eq!(ours, c.encode_utf8(&mut buf).as_bytes());
        }

        /// BMPString of any BMP text is its UTF-8.
        #[test]
        fn bmp_roundtrip(s in "[\\u{0}-\\u{d7ff}\\u{e000}-\\u{fffd}]{0,30}") {
            let units: Vec<u8> = s.encode_utf16().flat_map(u16::to_be_bytes).collect();
            prop_assume!(units.len() < 128);
            prop_assert_eq!(render(tag::BMP_STRING, &units).unwrap(), s.as_bytes());
        }
    }

    /// Names compare as OpenSSL compares them: string types, case and
    /// spaces aside, and the entries of an RDN as a set.
    #[test]
    fn canonical_names() {
        // SEQUENCE { SET { SEQUENCE { OID cn, <value> } } ... }
        let name = |rdns: &[&[(u8, &[u8])]]| -> Vec<u8> {
            let mut out = Vec::new();
            for rdn in rdns {
                let mut set = Vec::new();
                for (tag, value) in *rdn {
                    let mut atv = vec![0x06, 0x03, 0x55, 0x04, 0x03];
                    atv.push(*tag);
                    atv.push(u8::try_from(value.len()).unwrap());
                    atv.extend_from_slice(value);
                    set.push(0x30);
                    set.push(u8::try_from(atv.len()).unwrap());
                    set.extend(atv);
                }
                out.push(0x31);
                out.push(u8::try_from(set.len()).unwrap());
                out.extend(set);
            }
            let mut seq = vec![0x30, u8::try_from(out.len()).unwrap()];
            seq.extend(out);
            seq
        };
        let canonical = |der: &[u8]| {
            Name::from_contents(
                Reader::new(der).expect(tag::SEQUENCE).unwrap().value,
            )
            .unwrap()
            .canonical()
            .unwrap()
        };
        let printable = name(&[&[(tag::PRINTABLE_STRING, b"  Foo   Bar ")]]);
        let utf8 = name(&[&[(tag::UTF8_STRING, b"foo bar")]]);
        assert_eq!(canonical(&printable), canonical(&utf8));
        assert_ne!(
            canonical(&utf8),
            canonical(&name(&[&[(tag::UTF8_STRING, b"foo baz")]]))
        );
        // NumericString is not canonicalized.
        assert_ne!(
            canonical(&name(&[&[(tag::NUMERIC_STRING, b"12")]])),
            canonical(&name(&[&[(tag::UTF8_STRING, b"12")]]))
        );
        // The entries of a multi-valued RDN compare as a set.
        assert_eq!(
            canonical(&name(&[&[
                (tag::UTF8_STRING, b"a"),
                (tag::UTF8_STRING, b"b")
            ]])),
            canonical(&name(&[&[
                (tag::UTF8_STRING, b"b"),
                (tag::UTF8_STRING, b"a")
            ]]))
        );
    }
}
