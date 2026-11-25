//! The version field's description against the laws of `der::syntax`, and
//! the version line of certificates with every kind of version field, with
//! the lines OpenSSL 3.5.9 and 4.1.0 print for them.

use baldssl_core::{
    compat::Compat,
    der::{
        Integer,
        syntax::laws::{laws, round_trip},
    },
    pem,
    text::Text as _,
};
use baldssl_test_utils::{
    fixture,
    strategies::{bytes_not_starting_with, sign_magnitude},
};
use proptest::prelude::*;

use super::{Version, version_field};
use crate::cert::Certificate;

fn version() -> impl Strategy<Value = Version> {
    sign_magnitude(12).prop_map(|(negative, magnitude)| {
        Version(Integer {
            negative,
            magnitude,
        })
    })
}

proptest! {
    /// Absent and present versions round-trip, whatever follows that does
    /// not start with `[0]`, and the present field obeys every law.
    #[test]
    fn field_laws(
        v in prop::option::of(version()),
        at in any::<usize>(),
        xor in 1u8..,
        suffix in bytes_not_starting_with(0xa0, 8),
    ) {
        let field = version_field();
        round_trip(&field, &v, &suffix);
        if let Some(v) = v {
            laws(&field.0, &v, at, xor, &suffix);
        }
    }
}

#[test]
fn known_versions() {
    assert_eq!(Version::v1().known_opt(), Some(0));
    let n = |m: &[u8], negative| {
        Version(Integer {
            negative,
            magnitude: m.to_vec(),
        })
        .known_opt()
    };
    assert_eq!(n(&[2], false), Some(2));
    assert_eq!(n(&[3], false), None);
    assert_eq!(n(&[1], true), None);
    assert_eq!(n(&[1, 0], false), None);
}

/// The version line of each `tests/fixtures/certs/p256-version-*.crt`
/// (`scripts/gen-version-certs.py`), as OpenSSL 3.5.9 and 4.1.0 print it.
#[test]
fn version_lines_match_openssl() {
    let cases = [
        ("absent", "Version: 1 (0x0)"),
        ("explicit-v1", "Version: 1 (0x0)"),
        ("3", "Version: Unknown (3)"),
        ("minus1", "Version: Unknown (-1)"),
        ("i64max", "Version: Unknown (9223372036854775807)"),
        ("toolarge", "Version: Unknown (-1)"),
    ];
    for (name, line) in cases {
        let text = fixture(&format!("certs/p256-version-{name}.crt"));
        let block = pem::decode_first(text.as_bytes(), &["CERTIFICATE"])
            .expect("a PEM certificate");
        let cert = Certificate::from_der(&block.contents).expect(name);
        let printed = cert.to_text(Compat::V4).expect(name);
        let printed = String::from_utf8(printed).expect("UTF-8");
        let got = printed
            .lines()
            .find(|l| l.trim_start().starts_with("Version:"))
            .map(str::trim_start);
        assert_eq!(got, Some(line), "{name}");
    }
}
