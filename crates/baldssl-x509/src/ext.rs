//! X.509 v3 extensions, printed as `X509V3_EXT_print` does.
//!
//! # Policy: never print something OpenSSL would print differently
//!
//! * An extension implemented here is decoded and printed byte for byte.
//! * An extension OpenSSL does not know is printed the way OpenSSL prints
//!   unknown extensions: its dotted OID and the raw contents through
//!   `ASN1_STRING_print`.
//! * An extension OpenSSL knows and baldssl does not print returns
//!   [`Error::Unsupported`], because OpenSSL would decode it and any output
//!   of ours would differ.
//!
//! The printer reads subject key identifiers and extended key usages
//! through [`ExtensionValue`], whose decoding is the one baldssl verifies
//! with; it reads the other kinds itself, leniently, because OpenSSL
//! prints values the typed decoding refuses (an explicit `cA FALSE` or a
//! negative path length in basic constraints, a key usage with trailing
//! zero bits, the name kinds of `GeneralName` baldssl does not write, an IP
//! address of any length).

use baldssl_core::{
    Error, Result,
    der::{BitString, Integer, Oid, Reader, Tlv, parse_bool, tag},
    hex::{self, Case},
};

use crate::{
    cert::{Extension, ExtensionViews},
    extension::{
        ExtensionKind, ExtensionValue, KEY_USAGE_BITS,
        general_name_tag::{
            DIRECTORY_NAME, DNS_NAME, EDI_PARTY_NAME, IP_ADDRESS, OTHER_NAME,
            REGISTERED_ID, RFC822_NAME, URI, X400_ADDRESS,
        },
    },
    name::Name,
    objects,
};

/// Where a list of extensions is printed: `X509V3_extensions_print`
/// writes each name at this indentation and its value four further in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtensionIndent {
    /// Under a certificate's `X509v3 extensions:`, at 12 spaces.
    Certificate,
    /// Under a request's `Requested Extensions:`, at 16 spaces.
    Request,
}

impl ExtensionIndent {
    /// The spaces before each extension's name.
    fn spaces(self) -> usize {
        match self {
            ExtensionIndent::Certificate => 12,
            ExtensionIndent::Request => 16,
        }
    }
}

/// How much further in than its name an extension's value is printed.
const VALUE_STEP: usize = 4;

/// What `i2v_GENERAL_NAME` prints for the name kinds it does not decode
/// (`x400Address`, `ediPartyName`).
const UNSUPPORTED_NAME: &str = "<unsupported>";

/// The identifier octets of the alternatives of `GeneralName`, all
/// IMPLICIT: primitive for the strings, the IP address and the registered
/// ID, constructed for the others.
const GN_OTHER_NAME: u8 = tag::context_constructed(OTHER_NAME);
/// `rfc822Name`.
const GN_RFC822_NAME: u8 = tag::context(RFC822_NAME);
/// `dNSName`.
const GN_DNS_NAME: u8 = tag::context(DNS_NAME);
/// `x400Address`.
const GN_X400_ADDRESS: u8 = tag::context_constructed(X400_ADDRESS);
/// `directoryName`, EXPLICIT since `Name` is a CHOICE.
const GN_DIRECTORY_NAME: u8 = tag::context_constructed(DIRECTORY_NAME);
/// `ediPartyName`.
const GN_EDI_PARTY_NAME: u8 = tag::context_constructed(EDI_PARTY_NAME);
/// `uniformResourceIdentifier`.
const GN_URI: u8 = tag::context(URI);
/// `iPAddress`.
const GN_IP_ADDRESS: u8 = tag::context(IP_ADDRESS);
/// `registeredID`.
const GN_REGISTERED_ID: u8 = tag::context(REGISTERED_ID);

/// The octets of an IPv6 address in `iPAddress` ([RFC 5280 section
/// 4.2.1.6]); an IPv4 address takes four.
///
/// [RFC 5280 section 4.2.1.6]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
const IPV6_OCTETS: usize = 16;

/// `authorityKeyIdentifier`'s fields ([RFC 5280 section 4.2.1.1]):
/// `keyIdentifier [0]`, `authorityCertIssuer [1]` (constructed, a
/// `GeneralNames`), `authorityCertSerialNumber [2]`.
///
/// [RFC 5280 section 4.2.1.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
const AKI_KEY_IDENTIFIER: u8 = tag::context(0);
/// `authorityCertIssuer [1]`.
const AKI_CERT_ISSUER: u8 = tag::context_constructed(1);
/// `authorityCertSerialNumber [2]`.
const AKI_CERT_SERIAL: u8 = tag::context(2);

/// How `X509V3_EXT_val_prn` lays out a value list: on one line, separated
/// by `", "`, or one value per line (`X509V3_EXT_MULTILINE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueLayout {
    /// One line.
    OneLine,
    /// One value per line.
    MultiLine,
}

/// `CONF_VALUE`: what an `i2v` method returns.
struct Value {
    name: Option<String>,
    value: Option<String>,
}

fn named(name: &str, value: String) -> Value {
    Value {
        name: Some(name.to_string()),
        value: Some(value),
    }
}

fn bare(value: String) -> Value {
    Value {
        name: None,
        value: Some(value),
    }
}

/// `X509V3_EXT_val_prn`.
fn val_prn(
    out: &mut Vec<u8>,
    values: &[Value],
    indent: usize,
    layout: ValueLayout,
) {
    let pad = " ".repeat(indent);
    let pad_first = match layout {
        ValueLayout::OneLine => true,
        ValueLayout::MultiLine => values.is_empty(),
    };
    if pad_first {
        out.extend_from_slice(pad.as_bytes());
        if values.is_empty() {
            out.extend_from_slice(b"<EMPTY>\n");
        }
    }
    for (i, v) in values.iter().enumerate() {
        match layout {
            ValueLayout::MultiLine => {
                if i > 0 {
                    out.push(b'\n');
                }
                out.extend_from_slice(pad.as_bytes());
            }
            ValueLayout::OneLine if i > 0 => out.extend_from_slice(b", "),
            ValueLayout::OneLine => {}
        }
        match (&v.name, &v.value) {
            (None, Some(val)) => out.extend_from_slice(val.as_bytes()),
            (Some(n), None) => out.extend_from_slice(n.as_bytes()),
            (Some(n), Some(val)) => {
                out.extend_from_slice(n.as_bytes());
                out.push(b':');
                out.extend_from_slice(val.as_bytes());
            }
            (None, None) => {}
        }
    }
}

/// `ASN1_STRING_print`: printable ASCII, CR and LF as is, the rest as `.`.
fn asn1_string_print(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend(bytes.iter().map(|&b| {
        if b > b'~' || (b < b' ' && b != b'\n' && b != b'\r') {
            b'.'
        } else {
            b
        }
    }));
}

/// `bignum_to_string`, as used by `i2s_ASN1_INTEGER`: decimal below 128
/// bits, `0x`-prefixed upper-case hex otherwise.
pub(crate) fn integer_to_string(int: &Integer) -> String {
    let sign = if int.is_negative() { "-" } else { "" };
    match int
        .magnitude_u128_opt()
        .filter(|_| int.bits() < DECIMAL_BITS)
    {
        Some(v) => format!("{sign}{v}"),
        None => {
            format!("{sign}0x{}", hex::plain(int.magnitude(), Case::Upper))
        }
    }
}

/// The bits below which `bignum_to_string` prints in decimal
/// (`crypto/x509/v3_utl.c`).
const DECIMAL_BITS: usize = 128;

/// Text OpenSSL accepts in a `CONF_VALUE`: no embedded NUL
/// (`x509v3_add_len_value`).
fn ia5_value(bytes: &[u8]) -> Result<String> {
    if bytes.contains(&0) {
        return Err(Error::unsupported("GeneralName containing a NUL byte"));
    }
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// `ossl_ipaddr_to_asc`.
fn ip_to_string(bytes: &[u8]) -> String {
    match bytes {
        [a, b, c, d] => format!("{a}.{b}.{c}.{d}"),
        _ if bytes.len() == IPV6_OCTETS => bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| format!("{:X}", u16::from_be_bytes(*p)))
            .collect::<Vec<_>>()
            .join(":"),
        _ => format!("<invalid length={}>", bytes.len()),
    }
}

/// `X509_NAME_oneline` for the plain-ASCII names baldssl supports so far.
fn name_oneline(name: &Name<'_>) -> Result<String> {
    let mut out = String::new();
    for rdn in &name.rdns {
        for (i, atv) in rdn.iter().enumerate() {
            out.push(if i == 0 { '/' } else { '+' });
            out.push_str(&objects::short_name(&atv.oid)?);
            out.push('=');
            let printable = matches!(
                atv.value.octet_opt(),
                Some(
                    tag::PRINTABLE_STRING | tag::IA5_STRING | tag::UTF8_STRING
                )
            ) && atv
                .value
                .value()
                .iter()
                .all(|&b| (b' '..=b'~').contains(&b));
            if !printable {
                return Err(Error::unsupported(
                    "DirName with non-ASCII or non-string values",
                ));
            }
            out.push_str(&String::from_utf8_lossy(atv.value.value()));
        }
    }
    Ok(out)
}

/// `i2v_GENERAL_NAME` for one `GeneralName`.
fn general_name(gn: &Tlv<'_>, out: &mut Vec<Value>) -> Result<()> {
    match gn.octet_opt() {
        Some(GN_OTHER_NAME) => {
            return Err(Error::unsupported("GeneralName otherName"));
        }
        Some(GN_RFC822_NAME) => {
            out.push(named("email", ia5_value(gn.value())?));
        }
        Some(GN_DNS_NAME) => out.push(named("DNS", ia5_value(gn.value())?)),
        Some(GN_X400_ADDRESS) => {
            out.push(named("X400Name", UNSUPPORTED_NAME.into()));
        }
        Some(GN_DIRECTORY_NAME) => {
            let mut r = Reader::new(gn.value());
            let name = Name::read(&mut r)?;
            r.finish()?;
            out.push(named("DirName", name_oneline(&name)?));
        }
        Some(GN_EDI_PARTY_NAME) => {
            out.push(named("EdiPartyName", UNSUPPORTED_NAME.into()));
        }
        Some(GN_URI) => out.push(named("URI", ia5_value(gn.value())?)),
        Some(GN_IP_ADDRESS) => {
            out.push(named("IP Address", ip_to_string(gn.value())));
        }
        Some(GN_REGISTERED_ID) => {
            let oid = Oid::parse(gn.value())?;
            out.push(named("Registered ID", objects::long_name(&oid)?));
        }
        Some(other) => {
            return Err(Error::invalid(format!(
                "GeneralName with tag 0x{other:02x}"
            )));
        }
        None => {
            return Err(Error::invalid("GeneralName with a high tag number"));
        }
    }
    Ok(())
}

fn general_names(contents: &[u8], out: &mut Vec<Value>) -> Result<()> {
    let mut r = Reader::new(contents);
    while !r.is_empty() {
        general_name(&r.read()?, out)?;
    }
    Ok(())
}

/// Opens the single SEQUENCE an extension value consists of.
fn single_sequence(value: &[u8]) -> Result<Reader<'_>> {
    let mut r = Reader::new(value);
    let seq = r.sequence()?;
    r.finish()?;
    Ok(seq)
}

/// What to print for one extension: either an `i2s` string or an `i2v`
/// value list.
enum Printed {
    /// An `i2s` string.
    Line(String),
    /// An `i2v` value list, laid out.
    Values {
        /// The values.
        values: Vec<Value>,
        /// Their layout.
        layout: ValueLayout,
    },
    /// The contents, through `ASN1_STRING_print`: an extension OpenSSL
    /// does not know.
    Raw,
}

/// Subject Key Identifier: `i2s_ASN1_OCTET_STRING`.
fn subject_key_identifier(ext: &Extension<'_>) -> Result<Printed> {
    match ExtensionValue::try_from(ext)? {
        ExtensionValue::SubjectKeyIdentifier(id) => {
            Ok(Printed::Line(hex::colon(&id, Case::Upper)))
        }
        // The decoding of a subjectKeyIdentifier value gives no other kind.
        ExtensionValue::AuthorityKeyIdentifier(_)
        | ExtensionValue::KeyUsage(_)
        | ExtensionValue::SubjectAltName(_)
        | ExtensionValue::BasicConstraints { .. }
        | ExtensionValue::ExtendedKeyUsage(_)
        | ExtensionValue::Other { .. } => {
            Err(Error::invalid("subjectKeyIdentifier"))
        }
    }
}

/// Authority Key Identifier (multi-line).
fn authority_key_identifier(ext: &Extension<'_>) -> Result<Printed> {
    let mut seq = single_sequence(ext.value)?;
    let keyid = seq.optional(AKI_KEY_IDENTIFIER)?;
    let issuer = seq.optional(AKI_CERT_ISSUER)?;
    let serial = seq.optional(AKI_CERT_SERIAL)?;
    seq.finish()?;
    let qualified = issuer.is_some() || serial.is_some();
    let mut values = Vec::new();
    if let Some(k) = keyid {
        let h = hex::colon(k.value(), Case::Upper);
        values.push(if qualified {
            named("keyid", h)
        } else {
            bare(h)
        });
    }
    if let Some(i) = issuer {
        general_names(i.value(), &mut values)?;
    }
    if let Some(s) = serial {
        let int = Integer::parse(s.value())?;
        if int.is_negative() {
            return Err(Error::unsupported("negative AKI serial"));
        }
        values.push(named("serial", hex::colon(int.magnitude(), Case::Upper)));
    }
    Ok(Printed::Values {
        values,
        layout: ValueLayout::MultiLine,
    })
}

/// Basic Constraints.
fn basic_constraints(ext: &Extension<'_>) -> Result<Printed> {
    let mut seq = single_sequence(ext.value)?;
    let ca = match seq.optional(tag::BOOLEAN)? {
        Some(b) => parse_bool(b.value())?,
        None => false,
    };
    let pathlen = seq.optional(tag::INTEGER)?;
    seq.finish()?;
    let mut values =
        vec![named("CA", if ca { "TRUE" } else { "FALSE" }.into())];
    if let Some(p) = pathlen {
        values.push(named(
            "pathlen",
            integer_to_string(&Integer::parse(p.value())?),
        ));
    }
    Ok(Printed::Values {
        values,
        layout: ValueLayout::OneLine,
    })
}

/// Key Usage: `i2v_ASN1_BIT_STRING` over the named bits.
fn key_usage(ext: &Extension<'_>) -> Result<Printed> {
    let mut r = Reader::new(ext.value);
    let bits = BitString::parse(r.expect(tag::BIT_STRING)?.value())?;
    r.finish()?;
    let values = KEY_USAGE_BITS
        .iter()
        .enumerate()
        .filter(|(i, _)| bits.bit(*i))
        .map(|(_, (_, long))| Value {
            name: Some((*long).to_string()),
            value: None,
        })
        .collect();
    Ok(Printed::Values {
        values,
        layout: ValueLayout::OneLine,
    })
}

/// Extended Key Usage: one long name per purpose.
fn extended_key_usage(ext: &Extension<'_>) -> Result<Printed> {
    let purposes = match ExtensionValue::try_from(ext)? {
        ExtensionValue::ExtendedKeyUsage(purposes) => purposes,
        // The decoding of an extKeyUsage value gives no other kind.
        ExtensionValue::SubjectKeyIdentifier(_)
        | ExtensionValue::AuthorityKeyIdentifier(_)
        | ExtensionValue::KeyUsage(_)
        | ExtensionValue::SubjectAltName(_)
        | ExtensionValue::BasicConstraints { .. }
        | ExtensionValue::Other { .. } => {
            return Err(Error::invalid("extKeyUsage"));
        }
    };
    let values = purposes
        .iter()
        .map(|oid| Ok(bare(objects::long_name(&oid.as_oid())?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(Printed::Values {
        values,
        layout: ValueLayout::OneLine,
    })
}

/// Subject / Issuer Alternative Name.
fn alternative_name(ext: &Extension<'_>) -> Result<Printed> {
    let seq = single_sequence(ext.value)?;
    let mut r = seq;
    let mut values = Vec::new();
    while !r.is_empty() {
        general_name(&r.read()?, &mut values)?;
    }
    Ok(Printed::Values {
        values,
        layout: ValueLayout::OneLine,
    })
}

/// What to print for one extension, by its kind.
fn printed(ext: &Extension<'_>) -> Result<Printed> {
    let Some(kind) = ExtensionKind::from_oid_opt(&ext.oid) else {
        if objects::is_known(&ext.oid) {
            return Err(Error::unsupported(format!(
                "printing extension {} ({})",
                ext.oid.to_dotted()?,
                objects::long_name(&ext.oid)?
            )));
        }
        return Ok(Printed::Raw);
    };
    match kind {
        ExtensionKind::SubjectKeyIdentifier => subject_key_identifier(ext),
        ExtensionKind::AuthorityKeyIdentifier => authority_key_identifier(ext),
        ExtensionKind::BasicConstraints => basic_constraints(ext),
        ExtensionKind::KeyUsage => key_usage(ext),
        ExtensionKind::ExtendedKeyUsage => extended_key_usage(ext),
        ExtensionKind::SubjectAltName | ExtensionKind::IssuerAltName => {
            alternative_name(ext)
        }
    }
}

impl ExtensionViews<'_> {
    /// `X509V3_extensions_print(bp, "X509v3 extensions", exts, 0, 8)`: a
    /// certificate's extensions under their header, nothing without any.
    ///
    /// # Errors
    ///
    /// On a malformed extension, or [`Error::Unsupported`] (see the module
    /// documentation).
    pub(crate) fn print_certificate_block(
        &self,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        out.extend_from_slice(b"        X509v3 extensions:\n");
        self.print_list(out, ExtensionIndent::Certificate)
    }

    /// Each extension as `X509V3_extensions_print` writes it: its name at
    /// the indentation of `indent`, its value four further in.
    ///
    /// # Errors
    ///
    /// As [`ExtensionViews::print_certificate_block`].
    pub(crate) fn print_list(
        &self,
        out: &mut Vec<u8>,
        indent: ExtensionIndent,
    ) -> Result<()> {
        let name_pad = " ".repeat(indent.spaces());
        let value_indent = indent.spaces().saturating_add(VALUE_STEP);
        let value_pad = " ".repeat(value_indent);
        for ext in self {
            out.extend_from_slice(name_pad.as_bytes());
            out.extend_from_slice(objects::long_name(&ext.oid)?.as_bytes());
            out.extend_from_slice(b": ");
            if ext.critical {
                out.extend_from_slice(b"critical");
            }
            out.push(b'\n');
            match printed(ext)? {
                Printed::Line(s) => {
                    out.extend_from_slice(value_pad.as_bytes());
                    out.extend_from_slice(s.as_bytes());
                }
                Printed::Values { values, layout } => {
                    val_prn(out, &values, value_indent, layout);
                }
                Printed::Raw => {
                    out.extend_from_slice(value_pad.as_bytes());
                    asn1_string_print(out, ext.value);
                }
            }
            out.push(b'\n');
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_formats() {
        assert_eq!(ip_to_string(&[127, 0, 0, 1]), "127.0.0.1");
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[2] = 0x0d;
        v6[3] = 0xb8;
        v6[15] = 1;
        assert_eq!(ip_to_string(&v6), "2001:DB8:0:0:0:0:0:1");
        assert_eq!(ip_to_string(&[1, 2]), "<invalid length=2>");
    }

    #[test]
    fn val_prn_shapes() {
        let vals = [named("CA", "TRUE".into()), named("pathlen", "3".into())];
        let mut out = Vec::new();
        val_prn(&mut out, &vals, 4, ValueLayout::OneLine);
        assert_eq!(out, b"    CA:TRUE, pathlen:3");
        let mut out = Vec::new();
        val_prn(&mut out, &vals, 2, ValueLayout::MultiLine);
        assert_eq!(out, b"  CA:TRUE\n  pathlen:3");
        let mut out = Vec::new();
        val_prn(&mut out, &[], 2, ValueLayout::MultiLine);
        assert_eq!(out, b"  <EMPTY>\n");
    }

    #[test]
    fn integers_and_raw() {
        let small = Integer::parse(&[0x03]).unwrap();
        assert_eq!(integer_to_string(&small), "3");
        let mut big = vec![0x01];
        big.extend([0u8; 16]);
        let big = Integer::parse(&big).unwrap();
        assert_eq!(
            integer_to_string(&big),
            "0x0100000000000000000000000000000000"
        );
        let neg = Integer::parse(&[0xfd]).unwrap();
        assert_eq!(integer_to_string(&neg), "-3");
        let mut out = Vec::new();
        asn1_string_print(&mut out, &[0x0c, b'h', 0x7f, 0x80, b'\n']);
        assert_eq!(out, b".h..\n");
    }
}
