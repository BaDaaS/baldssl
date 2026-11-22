//! X.509 v3 extensions, printed as `X509V3_EXT_print` does.
//!
//! # Policy: never print something OpenSSL would print differently
//!
//! * An extension implemented here is decoded and printed byte for byte.
//! * An extension OpenSSL does not know is printed the way OpenSSL prints
//!   unknown extensions: its dotted OID and the raw contents through
//!   `ASN1_STRING_print`.
//! * An extension OpenSSL knows but baldssl does not implement yet returns
//!   [`Error::Unsupported`], because OpenSSL would decode it and any output
//!   of ours would differ.

use baldssl_core::{
    Error, Result,
    der::{BitString, Integer, Oid, Reader, Tlv, parse_bool, tag},
    hex::{self, Case},
};

use crate::{cert::Extension, name::Name, objects};

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
fn val_prn(out: &mut Vec<u8>, values: &[Value], indent: usize, ml: bool) {
    let pad = " ".repeat(indent);
    if !ml || values.is_empty() {
        out.extend_from_slice(pad.as_bytes());
        if values.is_empty() {
            out.extend_from_slice(b"<EMPTY>\n");
        }
    }
    for (i, v) in values.iter().enumerate() {
        if ml {
            if i > 0 {
                out.push(b'\n');
            }
            out.extend_from_slice(pad.as_bytes());
        } else if i > 0 {
            out.extend_from_slice(b", ");
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
    let sign = if int.negative { "-" } else { "" };
    if int.bits() < 128 {
        let v = int.magnitude_u128_opt().unwrap_or(0);
        format!("{sign}{v}")
    } else {
        format!("{sign}0x{}", hex::plain(&int.magnitude, Case::Upper))
    }
}

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
        _ if bytes.len() == 16 => bytes
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
                atv.value.octet(),
                tag::PRINTABLE_STRING | tag::IA5_STRING | tag::UTF8_STRING
            ) && atv
                .value
                .value
                .iter()
                .all(|&b| (b' '..=b'~').contains(&b));
            if !printable {
                return Err(Error::unsupported(
                    "DirName with non-ASCII or non-string values",
                ));
            }
            out.push_str(&String::from_utf8_lossy(atv.value.value));
        }
    }
    Ok(out)
}

/// `i2v_GENERAL_NAME` for one `GeneralName`.
fn general_name(gn: &Tlv<'_>, out: &mut Vec<Value>) -> Result<()> {
    match gn.octet() {
        0xa0 => return Err(Error::unsupported("GeneralName otherName")),
        0x81 => out.push(named("email", ia5_value(gn.value)?)),
        0x82 => out.push(named("DNS", ia5_value(gn.value)?)),
        0xa3 => out.push(named("X400Name", "<unsupported>".into())),
        0xa4 => {
            let mut r = Reader::new(gn.value);
            let name = Name::read(&mut r)?;
            r.finish()?;
            out.push(named("DirName", name_oneline(&name)?));
        }
        0xa5 => out.push(named("EdiPartyName", "<unsupported>".into())),
        0x86 => out.push(named("URI", ia5_value(gn.value)?)),
        0x87 => out.push(named("IP Address", ip_to_string(gn.value))),
        0x88 => {
            let oid = Oid::parse(gn.value)?;
            out.push(named("Registered ID", objects::long_name(&oid)?));
        }
        other => {
            return Err(Error::invalid(format!(
                "GeneralName with tag 0x{other:02x}"
            )));
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

const KEY_USAGE: [&str; 9] = [
    "Digital Signature",
    "Non Repudiation",
    "Key Encipherment",
    "Data Encipherment",
    "Key Agreement",
    "Certificate Sign",
    "CRL Sign",
    "Encipher Only",
    "Decipher Only",
];

/// What to print for one extension: either an `i2s` string or an `i2v`
/// value list.
enum Printed {
    Line(String),
    Values { values: Vec<Value>, multiline: bool },
    Raw,
}

/// Subject Key Identifier: `i2s_ASN1_OCTET_STRING`.
fn subject_key_identifier(ext: &Extension<'_>) -> Result<Printed> {
    let mut r = Reader::new(ext.value);
    let os = r.expect(tag::OCTET_STRING)?;
    r.finish()?;
    Ok(Printed::Line(hex::colon(os.value, Case::Upper)))
}

/// Authority Key Identifier (multi-line).
fn authority_key_identifier(ext: &Extension<'_>) -> Result<Printed> {
    let mut seq = single_sequence(ext.value)?;
    let keyid = seq.optional(tag::context(0))?;
    let issuer = seq.optional(tag::context_constructed(1))?;
    let serial = seq.optional(tag::context(2))?;
    seq.finish()?;
    let qualified = issuer.is_some() || serial.is_some();
    let mut values = Vec::new();
    if let Some(k) = keyid {
        let h = hex::colon(k.value, Case::Upper);
        values.push(if qualified {
            named("keyid", h)
        } else {
            bare(h)
        });
    }
    if let Some(i) = issuer {
        general_names(i.value, &mut values)?;
    }
    if let Some(s) = serial {
        let int = Integer::parse(s.value)?;
        if int.negative {
            return Err(Error::unsupported("negative AKI serial"));
        }
        values.push(named("serial", hex::colon(&int.magnitude, Case::Upper)));
    }
    Ok(Printed::Values {
        values,
        multiline: true,
    })
}

/// Basic Constraints.
fn basic_constraints(ext: &Extension<'_>) -> Result<Printed> {
    let mut seq = single_sequence(ext.value)?;
    let ca = match seq.optional(tag::BOOLEAN)? {
        Some(b) => parse_bool(b.value)?,
        None => false,
    };
    let pathlen = seq.optional(tag::INTEGER)?;
    seq.finish()?;
    let mut values =
        vec![named("CA", if ca { "TRUE" } else { "FALSE" }.into())];
    if let Some(p) = pathlen {
        values.push(named(
            "pathlen",
            integer_to_string(&Integer::parse(p.value)?),
        ));
    }
    Ok(Printed::Values {
        values,
        multiline: false,
    })
}

/// Key Usage: `i2v_ASN1_BIT_STRING` over the named bits.
fn key_usage(ext: &Extension<'_>) -> Result<Printed> {
    let mut r = Reader::new(ext.value);
    let bits = BitString::parse(r.expect(tag::BIT_STRING)?.value)?;
    r.finish()?;
    let values = KEY_USAGE
        .iter()
        .enumerate()
        .filter(|(i, _)| bits.bit(*i))
        .map(|(_, n)| Value {
            name: Some((*n).to_string()),
            value: None,
        })
        .collect();
    Ok(Printed::Values {
        values,
        multiline: false,
    })
}

/// Extended Key Usage: one long name per purpose.
fn extended_key_usage(ext: &Extension<'_>) -> Result<Printed> {
    let mut seq = single_sequence(ext.value)?;
    let mut values = Vec::new();
    while !seq.is_empty() {
        let oid = Oid::parse(seq.expect(tag::OID)?.value)?;
        values.push(bare(objects::long_name(&oid)?));
    }
    Ok(Printed::Values {
        values,
        multiline: false,
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
        multiline: false,
    })
}

fn decode(ext: &Extension<'_>, dotted: &str) -> Result<Printed> {
    let printed = match dotted {
        "2.5.29.14" => subject_key_identifier(ext)?,
        "2.5.29.35" => authority_key_identifier(ext)?,
        "2.5.29.19" => basic_constraints(ext)?,
        "2.5.29.15" => key_usage(ext)?,
        "2.5.29.37" => extended_key_usage(ext)?,
        "2.5.29.17" | "2.5.29.18" => alternative_name(ext)?,
        _ if objects::is_known(dotted) => {
            return Err(Error::unsupported(format!(
                "printing extension {dotted} ({})",
                objects::long_name(&ext.oid)?
            )));
        }
        _ => Printed::Raw,
    };
    Ok(printed)
}

/// `X509V3_extensions_print(bp, "X509v3 extensions", exts, 0, 8)`.
///
/// # Errors
///
/// On a malformed extension, or [`Error::Unsupported`] (see the module
/// documentation).
pub fn print_extensions(
    out: &mut Vec<u8>,
    exts: &[Extension<'_>],
) -> Result<()> {
    if exts.is_empty() {
        return Ok(());
    }
    out.extend_from_slice(b"        X509v3 extensions:\n");
    for ext in exts {
        let dotted = ext.oid.to_dotted()?;
        out.extend_from_slice(b"            ");
        out.extend_from_slice(objects::long_name(&ext.oid)?.as_bytes());
        out.extend_from_slice(b": ");
        if ext.critical {
            out.extend_from_slice(b"critical");
        }
        out.push(b'\n');
        match decode(ext, &dotted)? {
            Printed::Line(s) => {
                out.extend_from_slice(b"                ");
                out.extend_from_slice(s.as_bytes());
            }
            Printed::Values { values, multiline } => {
                val_prn(out, &values, 16, multiline);
            }
            Printed::Raw => {
                out.extend_from_slice(b"                ");
                asn1_string_print(out, ext.value);
            }
        }
        out.push(b'\n');
    }
    Ok(())
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
        val_prn(&mut out, &vals, 4, false);
        assert_eq!(out, b"    CA:TRUE, pathlen:3");
        let mut out = Vec::new();
        val_prn(&mut out, &vals, 2, true);
        assert_eq!(out, b"  CA:TRUE\n  pathlen:3");
        let mut out = Vec::new();
        val_prn(&mut out, &[], 2, true);
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
