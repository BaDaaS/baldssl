//! Names from `-subj`, against what OpenSSL makes of the same arguments.
//!
//! Known answers: `req/subj-names.txt` of the fixtures
//! (`scripts/gen-subj-names.py`): for a corpus of `-subj` arguments, with
//! and without `-utf8`, the subject Name OpenSSL wrote, or that it failed,
//! and how many attributes it skipped with a warning. OpenSSL 3.5 and 4.1
//! give the same answers.

use baldssl_core::encoding::Encodable;
use baldssl_test_utils::{fixture, hex};

use super::{
    DistinguishedName, InputEncoding, ParsedSubject, RdnMode, StringType,
    StringTypes, SubjError, UTF8_ONLY,
};
use crate::objects::find_by_name_opt;

/// Every line of the fixture: same name, same failure, same warnings.
#[test]
fn matches_openssl() {
    let text = fixture("req/subj-names.txt");
    let mut seen = 0;
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split(' ').collect();
        let encoding = if f[0] == "1" {
            InputEncoding::Utf8
        } else {
            InputEncoding::Latin1
        };
        let arg = hex(f[1]);
        let shown = String::from_utf8_lossy(&arg).into_owned();
        let result = DistinguishedName::from_subj(
            &arg,
            encoding,
            RdnMode::MultiValued,
            UTF8_ONLY,
        );
        match (f[2], result) {
            ("ok", Ok(ParsedSubject { name, warnings })) => {
                assert_eq!(name.encode(), hex(f[3]), "{shown} ({encoding:?})");
                assert_eq!(
                    warnings.len().to_string(),
                    f[4],
                    "{shown}: warnings"
                );
            }
            ("error", Err(_)) => {}
            (expected, got) => {
                panic!(
                    "{shown} ({encoding:?}): OpenSSL {expected}, baldssl {got:?}"
                )
            }
        }
        seen += 1;
    }
    assert_eq!(seen, 80);
}

/// Every attribute of the string-type table is an object OpenSSL knows.
#[test]
fn rules_name_known_attributes() {
    for rule in super::RULES {
        assert!(
            find_by_name_opt(rule.short_name).is_some(),
            "{}",
            rule.short_name
        );
    }
}

/// The errors, each for its own reason.
#[test]
fn errors() {
    let parse = |s: &[u8]| {
        DistinguishedName::from_subj(
            s,
            InputEncoding::Latin1,
            RdnMode::MultiValued,
            UTF8_ONLY,
        )
        .err()
    };
    assert!(matches!(parse(b"CN=x"), Some(SubjError::NotAName(_))));
    assert_eq!(parse(b"/CN"), Some(SubjError::MissingEquals("CN".into())));
    assert_eq!(parse(b"/CN=a\\"), Some(SubjError::TrailingEscape));
    assert_eq!(
        parse(b"/C=BEL"),
        Some(SubjError::TooLong {
            name: "C".into(),
            max: 2
        })
    );
    assert_eq!(
        parse(b"/C=B"),
        Some(SubjError::TooShort {
            name: "C".into(),
            min: 2
        })
    );
    assert_eq!(
        parse(b"/C=B@"),
        Some(SubjError::IllegalCharacters { name: "C".into() })
    );
    // OpenSSL: req: Error adding subject name attribute "/ISO=x".
    assert_eq!(
        parse(b"/ISO=x"),
        Some(SubjError::NotEncodable {
            name: "ISO".into(),
            value: "x".into()
        })
    );
    assert_eq!(
        DistinguishedName::from_subj(
            b"/CN=\xff",
            InputEncoding::Utf8,
            RdnMode::MultiValued,
            UTF8_ONLY
        )
        .err(),
        Some(SubjError::InvalidUtf8)
    );
}

/// Without multi-valued RDNs, `+` is part of the value.
#[test]
fn plus_without_multi() {
    let name = DistinguishedName::from_subj(
        b"/CN=a+b",
        InputEncoding::Latin1,
        RdnMode::SingleValued,
        UTF8_ONLY,
    )
    .unwrap()
    .name;
    assert_eq!(name.0.len(), 1);
    assert_eq!(name.0[0].0[0].contents, b"a+b");
}

/// The minimal type: digits are a NumericString where allowed, Latin-1 a
/// T61String, and the global mask narrows the attributes that are not
/// fixed.
#[test]
fn string_types() {
    let all = StringTypes::DIRECTORY;
    let name = DistinguishedName::from_subj(
        b"/CN=abc/O=caf\xe9/INN=123",
        InputEncoding::Latin1,
        RdnMode::MultiValued,
        all,
    )
    .unwrap()
    .name;
    let types: Vec<StringType> =
        name.0.iter().map(|rdn| rdn.0[0].string_type).collect();
    assert_eq!(
        types,
        [StringType::Printable, StringType::T61, StringType::Numeric]
    );
}
