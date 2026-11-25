//! Reading configuration files as OpenSSL's NCONF does, as far as
//! extension files go.

use std::str::FromStr as _;

use baldssl_core::Error;

use proptest::prelude::*;

use super::{ConfValue, Config, replace_push};
use crate::extension::{Extension, ExtensionValue, GeneralName, Ia5String};

#[test]
fn sections_and_values() {
    let config = Config::from_str(
        "extensions = server\n\
         keyUsage = digitalSignature # a comment\n\
         \n\
         [ server ]\n\
         subjectAltName=@alt\n\
         basicConstraints = CA:FALSE\n\
         [alt]\n\
         DNS.1 = a.example\n\
         DNS.2 = b.example\n\
         # a whole-line comment\n\
         [ server ]\n\
         extendedKeyUsage = serverAuth\n",
    )
    .unwrap();
    assert_eq!(config.value_opt("default", "extensions"), Some("server"));
    assert_eq!(
        config.value_opt("default", "keyUsage"),
        Some("digitalSignature")
    );
    // A section opened twice gathers both parts.
    let names: Vec<&str> = config
        .section_opt("server")
        .unwrap()
        .iter()
        .map(|v| v.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["subjectAltName", "basicConstraints", "extendedKeyUsage"]
    );
    assert_eq!(config.section_opt("none"), None);

    // @alt lists the section's values, DNS.1 and DNS.2 both naming DNS.
    let server = config.extensions("server").unwrap();
    let dns = |n: &str| GeneralName::Dns(Ia5String::from_str(n).unwrap());
    assert_eq!(
        server.as_slice()[0],
        Extension::new(ExtensionValue::SubjectAltName(vec![
            dns("a.example"),
            dns("b.example")
        ]))
    );
    assert!(matches!(config.extensions("missing"), Err(Error::Usage(_))));
}

/// A name given twice keeps the later value, which moves to the end, as
/// OpenSSL's `_CONF_add_string` does.
#[test]
fn repeated_names() {
    let config = Config::from_str("a = 1\nb = 2\na = 3\n").unwrap();
    assert_eq!(
        config.section_opt("default").unwrap(),
        [
            ConfValue {
                name: "b".to_string(),
                value: "2".to_string()
            },
            ConfValue {
                name: "a".to_string(),
                value: "3".to_string()
            }
        ]
    );
    let mut v = vec![1, 2, 3];
    replace_push(&mut v, 4, |a, b| a % 2 == b % 2);
    assert_eq!(v, [1, 3, 4]);
}

#[test]
fn refusals() {
    assert!(matches!(
        Config::from_str("no equal sign\n"),
        Err(Error::Usage(_))
    ));
    assert!(matches!(Config::from_str("[ open\n"), Err(Error::Usage(_))));
    assert!(matches!(Config::from_str("[ ]\n"), Err(Error::Usage(_))));
    for unsupported in
        ["a = \"quoted\"\n", "a = $b\n", "a = x\\\n", ".include x\n"]
    {
        assert!(
            matches!(Config::from_str(unsupported), Err(Error::Unsupported(_))),
            "{unsupported:?}"
        );
    }
    let config = Config::from_str("subjectAltName = @none\n").unwrap();
    assert!(config.extensions("default").is_err());
}

/// The fold law of `replace_push`, stated directly: folding a list keeps,
/// of each class, its last item, in the order of those last items.
fn fold_spec(items: &[(u8, u8)]) -> Vec<(u8, u8)> {
    items
        .iter()
        .enumerate()
        .filter(|(i, (class, _))| {
            !items
                .get(i.saturating_add(1)..)
                .unwrap_or_default()
                .iter()
                .any(|(later, _)| later == class)
        })
        .map(|(_, item)| *item)
        .collect()
}

proptest! {
    /// Items are `(class, payload)`; two items are the same when their
    /// classes are.
    #[test]
    fn replace_push_fold(items in prop::collection::vec((0u8..4, any::<u8>()), 0..24)) {
        let mut folded = Vec::new();
        for item in &items {
            replace_push(&mut folded, *item, |a: &(u8, u8), b| a.0 == b.0);
        }
        prop_assert_eq!(folded, fold_spec(&items));
    }

    /// Folding is idempotent: folding the result again changes nothing.
    #[test]
    fn replace_push_idempotent(items in prop::collection::vec((0u8..4, any::<u8>()), 0..24)) {
        let fold = |list: &[(u8, u8)]| {
            let mut out = Vec::new();
            for item in list {
                replace_push(&mut out, *item, |a: &(u8, u8), b| a.0 == b.0);
            }
            out
        };
        let once = fold(&items);
        prop_assert_eq!(fold(&once), once);
    }
}
