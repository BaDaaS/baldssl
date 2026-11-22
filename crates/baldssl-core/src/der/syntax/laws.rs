//! The laws every syntax description satisfies, as checks any test suite
//! can run on its own descriptions: the partial isomorphism between values
//! and encodings ([`round_trip`] from `write`'s side, [`canonical`] from
//! `read`'s), and [`prefix_free`] for tagged descriptions. [`laws`] runs them
//! all on one value.
//!
//! Compiled for this crate's tests, and for other crates with the `laws`
//! feature. Each check panics on a violation: a failing law is a failing
//! test.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test checks: a violated law is a failing test"
)]

use core::fmt::Debug;

use super::{Syntax, Tagged, encode};

/// The partial-isomorphism law from `write`'s side: reading
/// `write(v) ++ suffix` gives back `v` and `suffix`. For a tagged
/// description any suffix will do (its encodings are a prefix code); for an
/// optional field, the suffix must not start with the field's tag, the rule
/// ASN.1 sets on whatever follows an OPTIONAL or DEFAULT field.
pub fn round_trip<S>(syntax: &S, value: &S::Value, suffix: &[u8])
where
    S: Syntax,
    S::Value: PartialEq + Debug,
{
    let mut bytes = encode(syntax, value);
    bytes.extend_from_slice(suffix);
    let (back, rest) = syntax.read(&bytes).expect("reads its own encoding");
    assert_eq!(&back, value, "round trip");
    assert_eq!(rest, suffix, "consumes exactly the encoding");
}

/// The law from `read`'s side, canonicity: whatever `read` accepts is
/// `write(v) ++ rest`, byte for byte.
pub fn canonical<S>(syntax: &S, bytes: &[u8])
where
    S: Syntax,
{
    if let Ok((value, rest)) = syntax.read(bytes) {
        let mut again = encode(syntax, &value);
        again.extend_from_slice(rest);
        assert_eq!(again, bytes, "a non-canonical encoding was accepted");
    }
}

/// Prefix-freeness: no proper prefix of an encoding is accepted, so
/// encodings factor uniquely. Only for tagged descriptions: an absent
/// OPTIONAL encodes to nothing, a prefix of everything.
pub fn prefix_free<S>(syntax: &S, value: &S::Value)
where
    S: Tagged,
{
    let bytes = encode(syntax, value);
    assert_eq!(bytes.first(), Some(&syntax.tag()), "starts with its tag");
    for k in 0..bytes.len() {
        let prefix = bytes.get(..k).unwrap_or_default();
        assert!(syntax.read(prefix).is_err(), "prefix of length {k}");
    }
}

/// Every law of a tagged description, plus canonicity on mutations of the encoding (one byte
/// changed, one byte dropped), which reach accepted inputs far more often
/// than random strings.
pub fn laws<S>(syntax: &S, value: &S::Value, at: usize, xor: u8, suffix: &[u8])
where
    S: Tagged,
    S::Value: PartialEq + Debug,
{
    round_trip(syntax, value, suffix);
    prefix_free(syntax, value);
    let bytes = encode(syntax, value);
    canonical(syntax, &bytes);
    let i = at
        .checked_rem(bytes.len())
        .expect("a tagged encoding is never empty");
    let mut changed = bytes.clone();
    if let Some(octet) = changed.get_mut(i) {
        *octet ^= xor;
    }
    canonical(syntax, &changed);
    let mut dropped = bytes.clone();
    dropped.remove(i);
    canonical(syntax, &dropped);
}
