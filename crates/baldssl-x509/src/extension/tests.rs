//! The configuration parser, OpenSSL's spacing rules included, and the
//! encodings.

use std::net::IpAddr;

use baldssl_core::Error;

use proptest::prelude::*;

use super::{
    ConfItem, ConfList, Extension, ExtensionValue, Extensions, GeneralName,
    Ia5String, KeyUsage, strip_spaces_opt,
};

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
