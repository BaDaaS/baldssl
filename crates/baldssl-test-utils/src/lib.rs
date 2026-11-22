//! Helpers shared by the baldssl test suites: decoding the hexadecimal of
//! test vectors, and reading the fixtures under `tests/fixtures`.
//!
//! Used only as a dev-dependency and never published. Without dependencies
//! of its own, except proptest for the generators of `strategies`, behind
//! the `proptest` feature. A malformed vector or a missing fixture is a bug in the test,
//! so the helpers panic rather than return errors.

#![allow(
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "test-only helpers: a malformed vector is a failing test"
)]

use std::path::PathBuf;

#[cfg(feature = "proptest")]
pub mod strategies;

/// The bytes of a hexadecimal string, two digits per byte, either case.
///
/// # Panics
///
/// On an odd length or a character that is not a hexadecimal digit.
#[must_use]
pub fn hex(s: &str) -> Vec<u8> {
    let digits = s.as_bytes();
    assert!(
        digits.len().is_multiple_of(2),
        "odd-length hexadecimal: {s:?}"
    );
    digits
        .chunks(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).unwrap_or_default();
            u8::from_str_radix(pair, 16)
                .unwrap_or_else(|_| panic!("not hexadecimal: {s:?}"))
        })
        .collect()
}

/// [`hex`] into an array of exactly `N` bytes (a seed, a key, a digest).
///
/// # Panics
///
/// As [`hex`], or if the string does not encode exactly `N` bytes.
#[must_use]
pub fn array<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!("expected {N} bytes, got {}: {s:?}", v.len())
    })
}

/// The path of a fixture, relative to `tests/fixtures` at the repository
/// root, which `make fixtures` fills from the pinned release of
/// [baldssl-fixtures](https://github.com/BaDaaS/baldssl-fixtures).
#[must_use]
pub fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(relative)
}

/// The contents of a text fixture.
///
/// # Panics
///
/// If the fixture cannot be read.
#[must_use]
pub fn fixture(relative: &str) -> String {
    let path = fixture_path(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("reading {}: {e} (run `make fixtures`)", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::{array, fixture_path, hex};

    #[test]
    fn decodes() {
        assert_eq!(hex(""), Vec::<u8>::new());
        assert_eq!(hex("00ffA5"), vec![0x00, 0xff, 0xa5]);
        assert_eq!(array::<2>("beef"), [0xbe, 0xef]);
        assert!(fixture_path("keys").is_dir());
    }

    #[test]
    #[should_panic(expected = "odd-length")]
    fn rejects_odd_length() {
        let _ = hex("abc");
    }

    #[test]
    #[should_panic(expected = "not hexadecimal")]
    fn rejects_non_hex() {
        let _ = hex("zz");
    }

    #[test]
    #[should_panic(expected = "expected 3 bytes")]
    fn rejects_wrong_length() {
        let _ = array::<3>("beef");
    }
}
