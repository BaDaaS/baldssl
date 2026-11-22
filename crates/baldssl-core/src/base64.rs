//! Base64, [RFC 4648 section 4][rfc4648-4] (standard alphabet, `=` padding).
//!
//! # Canonicity
//!
//! [`decode`] accepts exactly the image of [`encode`]: it rejects missing
//! padding, misplaced padding and non-zero pad bits ([RFC 4648 section 3.5][rfc4648-3.5]).
//! So `decode` is injective on the strings it accepts and
//! `encode(decode(s)?) == s` holds, the same "one value, one encoding"
//! discipline that DER imposes on ASN.1.
//!
//! # Lean 4 / Aeneas
//!
//! [`decode`] is the first extraction target (see `proofs/README.md`). It is
//! written in the subset Aeneas translates: `while` loops over an index, no
//! closures, no iterator adaptors, no trait-generic helpers. The slice
//! indexing and the `u8` arithmetic below are exactly the obligations the
//! totality theorem discharges: every index is in bounds because
//! `i + 3 < input.len()` follows from `i < n` and `n % 4 == 0`, and every
//! subtraction is guarded by the comparison right before it. That is why
//! `indexing_slicing` and `arithmetic_side_effects` are allowed in this module
//! only.
//! The explicit `c >= x && c <= y` comparisons (instead of
//! `RangeInclusive::contains`) are deliberate too: they translate to plain
//! Lean conditionals, where `contains` would pull in a trait method.
//!
//! [rfc4648-4]: https://www.rfc-editor.org/rfc/rfc4648#section-4
//! [rfc4648-3.5]: https://www.rfc-editor.org/rfc/rfc4648#section-3.5
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::manual_range_contains,
    clippy::many_single_char_names,
    clippy::manual_is_multiple_of
)]

/// Why a base64 string was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// The length is not a multiple of 4.
    InvalidLength,
    /// A byte outside the alphabet, at this offset.
    InvalidCharacter(usize),
    /// `=` somewhere other than the last one or two positions.
    InvalidPadding,
    /// The pad bits of the final quantum are not zero.
    NonCanonical,
}

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Maps one alphabet byte to its 6-bit value.
fn sextet_opt(c: u8) -> Option<u8> {
    if c >= b'A' && c <= b'Z' {
        Some(c - b'A')
    } else if c >= b'a' && c <= b'z' {
        Some(c - b'a' + 26)
    } else if c >= b'0' && c <= b'9' {
        Some(c - b'0' + 52)
    } else if c == b'+' {
        Some(62)
    } else if c == b'/' {
        Some(63)
    } else {
        None
    }
}

fn sextet_at(input: &[u8], i: usize) -> Result<u8, Base64Error> {
    match sextet_opt(input[i]) {
        Some(v) => Ok(v),
        None if input[i] == b'=' => Err(Base64Error::InvalidPadding),
        None => Err(Base64Error::InvalidCharacter(i)),
    }
}

/// Decodes canonical, padded base64. The input must contain no whitespace;
/// strip line breaks first (see [`crate::pem`]).
///
/// # Errors
///
/// Returns a [`Base64Error`] when the input is not the [`encode`] image of
/// any byte string.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let n = input.len();
    if n % 4 != 0 {
        return Err(Base64Error::InvalidLength);
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let last = i + 4 == n;
        let a = sextet_at(input, i)?;
        let b = sextet_at(input, i + 1)?;
        let c2 = input[i + 2];
        let c3 = input[i + 3];
        if c2 == b'=' {
            if !last || c3 != b'=' {
                return Err(Base64Error::InvalidPadding);
            }
            if b & 0x0f != 0 {
                return Err(Base64Error::NonCanonical);
            }
            out.push((a << 2) | (b >> 4));
        } else {
            let c = sextet_at(input, i + 2)?;
            if c3 == b'=' {
                if !last {
                    return Err(Base64Error::InvalidPadding);
                }
                if c & 0x03 != 0 {
                    return Err(Base64Error::NonCanonical);
                }
                out.push((a << 2) | (b >> 4));
                out.push(((b & 0x0f) << 4) | (c >> 2));
            } else {
                let d = sextet_at(input, i + 3)?;
                out.push((a << 2) | (b >> 4));
                out.push(((b & 0x0f) << 4) | (c >> 2));
                out.push(((c & 0x03) << 6) | d);
            }
        }
        i += 4;
    }
    Ok(out)
}

/// Encodes bytes as padded base64 without line breaks.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let push = |out: &mut String, v: u8| {
            out.push(char::from(ALPHABET[usize::from(v & 0x3f)]));
        };
        push(&mut out, b0 >> 2);
        push(&mut out, (b0 << 4) | (b1 >> 4));
        if chunk.len() > 1 {
            push(&mut out, (b1 << 2) | (b2 >> 6));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            push(&mut out, b2);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// [RFC 4648 section 10][rfc4648-10] test vectors.
    ///
    /// [rfc4648-10]: https://www.rfc-editor.org/rfc/rfc4648#section-10
    #[test]
    fn rfc4648_vectors() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, enc) in cases {
            assert_eq!(encode(raw), enc);
            assert_eq!(decode(enc.as_bytes()).unwrap(), raw);
        }
    }

    #[test]
    fn rejects_bad_inputs() {
        assert_eq!(decode(b"Zg="), Err(Base64Error::InvalidLength));
        assert_eq!(decode(b"Z==="), Err(Base64Error::InvalidPadding));
        assert_eq!(decode(b"Zg==Zg=="), Err(Base64Error::InvalidPadding));
        assert_eq!(decode(b"Zm=v"), Err(Base64Error::InvalidPadding));
        assert_eq!(decode(b"Zh=="), Err(Base64Error::NonCanonical));
        assert_eq!(decode(b"Zm9="), Err(Base64Error::NonCanonical));
        assert_eq!(decode(b"Zm9v\n"), Err(Base64Error::InvalidLength));
        assert_eq!(decode(b"Zm*v"), Err(Base64Error::InvalidCharacter(2)));
    }

    #[test]
    fn alphabet_is_inverse_of_sextet() {
        for (v, &c) in ALPHABET.iter().enumerate() {
            assert_eq!(sextet_opt(c), Some(u8::try_from(v).unwrap()));
        }
        let valid = (0..=255u8).filter(|&c| sextet_opt(c).is_some()).count();
        assert_eq!(valid, 64);
    }

    proptest! {
        /// `decode` is a left inverse of `encode`.
        #[test]
        fn decode_encode(data in prop::collection::vec(any::<u8>(), 0..300)) {
            prop_assert_eq!(decode(encode(&data).as_bytes()).unwrap(), data);
        }

        /// Canonicity: `encode` is a left inverse of `decode` on the accepted
        /// set, so no two accepted strings decode to the same bytes. A decoder
        /// that ignored pad bits would fail this.
        #[test]
        fn encode_decode(s in "[A-Za-z0-9+/=]{0,64}") {
            if let Ok(bytes) = decode(s.as_bytes()) {
                prop_assert_eq!(encode(&bytes), s);
            }
        }

        /// Totality on arbitrary bytes (what the Lean theorem states).
        #[test]
        fn never_panics(data in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = decode(&data);
        }

        /// Exactly 3 bytes per 4 characters, minus padding.
        #[test]
        fn length_law(data in prop::collection::vec(any::<u8>(), 0..300)) {
            prop_assert_eq!(encode(&data).len(), data.len().div_ceil(3) * 4);
        }
    }
}
