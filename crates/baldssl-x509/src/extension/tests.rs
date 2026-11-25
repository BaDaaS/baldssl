//! The configuration parser, OpenSSL's spacing rules included, and the
//! encodings.

use std::net::IpAddr;

use baldssl_core::Error;

use proptest::prelude::*;

use baldssl_core::der::{DerError, parse_tlv, syntax::decode};

use super::{
    ConfItem, ConfList, Extension, ExtensionKind, ExtensionValue, Extensions,
    GeneralName, Ia5String, KeyUsage, extension_syntax, strip_spaces_opt,
};
use crate::cert::ExtensionViews;

fn dns(name: &str) -> GeneralName {
    GeneralName::Dns(name.parse::<Ia5String>().unwrap())
}

/// OpenSSL's `strip_spaces`, quirk included: a one-character item keeps
/// its trailing spaces.
#[test]
fn stripping() {
    assert_eq!(strip_spaces_opt("  ab  "), Some("ab"));
    assert_eq!(strip_spaces_opt("  a  "), Some("a  "));
    assert_eq!(strip_spaces_opt("a"), Some("a"));
    assert_eq!(strip_spaces_opt("   "), None);
    assert_eq!(strip_spaces_opt(""), None);
}

#[test]
fn lists() {
    let pairs = |v: &str| v.parse::<ConfList>().unwrap().0;
    let pair = |n: &str, v: Option<&str>| ConfItem {
        name: n.to_string(),
        value: v.map(str::to_string),
    };
    assert_eq!(
        pairs("DNS:a , DNS:bc"),
        [pair("DNS", Some("a ")), pair("DNS", Some("bc"))]
    );
    assert_eq!(pairs(" xy , zw "), [pair("xy", None), pair("zw", None)]);
    // The quirk holds for names too: one character keeps its spaces.
    assert_eq!(pairs(" x , y "), [pair("x ", None), pair("y ", None)]);
    // A value runs to the next comma, colons included.
    assert_eq!(
        pairs("URI:http://h.example.com:1/"),
        [pair("URI", Some("http://h.example.com:1/"))]
    );
    for empty in ["DNS:a,,DNS:b", "DNS:", ",", " "] {
        assert!(
            matches!(empty.parse::<ConfList>(), Err(Error::Usage(_))),
            "{empty:?}"
        );
    }
}

#[test]
fn lines() {
    let ext = |l: &str| l.parse::<Extension>().unwrap();
    assert_eq!(
        ext("subjectAltName = DNS:a.example, IP:10.0.0.1, IP:::1"),
        Extension::new(ExtensionValue::SubjectAltName(vec![
            dns("a.example"),
            GeneralName::Ip("10.0.0.1".parse::<IpAddr>().unwrap()),
            GeneralName::Ip("::1".parse::<IpAddr>().unwrap()),
        ]))
    );
    assert_eq!(
        ext("keyUsage=critical,  digitalSignature, Certificate Sign"),
        Extension::critical(ExtensionValue::KeyUsage(
            KeyUsage::DIGITAL_SIGNATURE.union(KeyUsage::KEY_CERT_SIGN)
        ))
    );
    assert_eq!(
        ext("basicConstraints=CA:yes,pathlen:0"),
        Extension::new(ExtensionValue::BasicConstraints {
            ca: true,
            path_length: Some(0),
        })
    );
    // "critical" with a space before its comma is not the prefix.
    for (line, usage) in [
        ("keyUsage=critical ,digitalSignature", true),
        ("keyUsage=badName", true),
        ("fooBar=x", true),
        // Extensions go by short name only, as OBJ_sn2nid finds them.
        ("X509v3 Basic Constraints=CA:TRUE", true),
        ("2.5.29.19=CA:TRUE", true),
        ("subjectAltName=email:copy", false),
        ("subjectAltName=dirName:x", false),
        ("nameConstraints=permitted;DNS:x", false),
        ("basicConstraints=CA:maybe", true),
        ("no equals sign", true),
    ] {
        let err = line.parse::<Extension>().unwrap_err();
        assert_eq!(matches!(err, Error::Usage(_)), usage, "{line}: {err:?}");
    }
}

/// An extension from a small pool: three kinds, three values each, so that
/// random sets overlap.
fn pooled(kind: u8, variant: u8) -> Extension {
    let value = match kind % 3 {
        0 => ExtensionValue::KeyUsage(KeyUsage(1 << (variant % 3))),
        1 => ExtensionValue::BasicConstraints {
            ca: variant.is_multiple_of(2),
            path_length: Some(u64::from(variant)),
        },
        _ => ExtensionValue::SubjectAltName(vec![dns(&format!("h{variant}"))]),
    };
    Extension {
        critical: variant == 0,
        value,
    }
}

fn arb_extensions() -> impl Strategy<Value = Extensions> {
    prop::collection::vec((0u8..3, 0u8..3), 0..5)
        .prop_map(|v| v.into_iter().map(|(k, n)| pooled(k, n)).collect())
}

/// The kinds of a set, in order, as their object identifiers.
fn kinds(set: &Extensions) -> Vec<String> {
    set.as_slice()
        .iter()
        .map(|e| e.value.oid().to_dotted().unwrap())
        .collect()
}

proptest! {
    /// `override_with` is a band with the empty set as identity: the
    /// right side wins values and places (it is a suffix), and the left
    /// keeps the order of what the right does not replace.
    #[test]
    fn override_is_a_band(
        a in arb_extensions(),
        b in arb_extensions(),
        c in arb_extensions(),
    ) {
        prop_assert_eq!(
            a.override_with(&b).override_with(&c),
            a.override_with(&b.override_with(&c))
        );
        prop_assert_eq!(a.override_with(&a), a.clone());
        prop_assert_eq!(a.override_with(&Extensions::new()), a.clone());
        prop_assert_eq!(Extensions::new().override_with(&a), a.clone());
        let ab = a.override_with(&b);
        for e in b.as_slice() {
            prop_assert!(ab.as_slice().contains(e));
        }
        let (kb, kab) = (kinds(&b), kinds(&ab));
        prop_assert_eq!(&kab[kab.len() - kb.len()..], &kb[..]);
        let kept: Vec<String> =
            kinds(&a).into_iter().filter(|k| !kb.contains(k)).collect();
        prop_assert_eq!(&kab[..kab.len() - kb.len()], &kept[..]);
    }
}

/// Replacing moves the extension to the end, as OpenSSL's replace mode
/// does: overriding the first of three puts it last.
#[test]
fn replacing_moves_to_the_end() {
    let a: Extensions = [pooled(0, 0), pooled(1, 0), pooled(2, 0)]
        .into_iter()
        .collect();
    let b: Extensions = [pooled(0, 1)].into_iter().collect();
    assert_eq!(
        a.override_with(&b).as_slice(),
        [pooled(1, 0), pooled(2, 0), pooled(0, 1)]
    );
}

#[test]
fn duplicates() {
    let mut set = Extensions::new();
    set.push_new(pooled(0, 0)).unwrap();
    set.push_new(pooled(1, 0)).unwrap();
    assert!(matches!(set.push_new(pooled(0, 1)), Err(Error::Usage(_))));
    assert_eq!(set.as_slice().len(), 2);
}

/// Any set of the nine named key usages.
fn arb_key_usage() -> impl Strategy<Value = KeyUsage> {
    (0u16..0x200).prop_map(KeyUsage)
}

proptest! {
    /// Union makes key usages a join-semilattice with the empty set as
    /// identity, and `contains` is its order.
    #[test]
    fn key_usage_semilattice(
        a in arb_key_usage(),
        b in arb_key_usage(),
        c in arb_key_usage(),
    ) {
        prop_assert_eq!(a.union(b).union(c), a.union(b.union(c)));
        prop_assert_eq!(a.union(b), b.union(a));
        prop_assert_eq!(a.union(a), a);
        prop_assert_eq!(a.union(KeyUsage::default()), a);
        prop_assert_eq!(a.contains(b), a.union(b) == a);
        prop_assert!(a.union(b).contains(a));
    }
}

/// Every kind is found again from its identifier, so the identifiers are
/// distinct.
#[test]
fn kinds_round_trip() {
    for kind in ExtensionKind::ALL {
        assert_eq!(
            ExtensionKind::from_oid_opt(&kind.oid().as_oid()),
            Some(kind)
        );
    }
}

/// DER forbids an explicit `critical FALSE` ([X.690] 11.5), and the
/// description the writer uses refuses it; OpenSSL 3.5 and 4.1 read it as
/// not critical, and so does the lenient reader of certificates' and
/// requests' extensions.
///
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
#[test]
fn extension_views_accept_explicit_false() {
    // SEQUENCE { OID keyUsage, BOOLEAN FALSE, OCTET STRING { 03 02 07 80 } }
    let extension = [
        0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0x00, 0x04, 0x04,
        0x03, 0x02, 0x07, 0x80,
    ];
    assert_eq!(
        decode(&extension_syntax(), &extension),
        Err(DerError::ExplicitDefault)
    );
    let mut list = vec![0x30, 0x10];
    list.extend(extension);
    let (tlv, _) = parse_tlv(&list).unwrap();
    let views = ExtensionViews::try_from(tlv).unwrap();
    assert_eq!(views.0.len(), 1);
    assert!(!views.0[0].critical);
    // What the writer writes, the lenient reader reads back.
    let written = Extension::critical(ExtensionValue::KeyUsage(
        KeyUsage::DIGITAL_SIGNATURE,
    ))
    .to_raw();
    let mut list = vec![0x30, u8::try_from(written.as_bytes().len()).unwrap()];
    list.extend(written.as_bytes());
    let (tlv, _) = parse_tlv(&list).unwrap();
    let views = ExtensionViews::try_from(tlv).unwrap();
    assert!(views.0[0].critical);
    assert_eq!(
        ExtensionValue::try_from(&views.0[0]).unwrap(),
        ExtensionValue::KeyUsage(KeyUsage::DIGITAL_SIGNATURE)
    );
}
