//! Hexadecimal formatting in the shapes OpenSSL prints.

const LOWER: &[u8; 16] = b"0123456789abcdef";
const UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Letter case of the hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case {
    /// `ab`
    Lower,
    /// `AB`
    Upper,
}

fn push_byte(out: &mut String, b: u8, case: Case) {
    let table = match case {
        Case::Lower => LOWER,
        Case::Upper => UPPER,
    };
    for nibble in [b >> 4, b & 0x0f] {
        if let Some(&c) = table.get(usize::from(nibble)) {
            out.push(char::from(c));
        }
    }
}

/// `de:ad:be:ef`, the separator-joined form of `OPENSSL_buf2hexstr`.
#[must_use]
pub fn colon(bytes: &[u8], case: Case) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3));
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        push_byte(&mut out, b, case);
    }
    out
}

/// `deadbeef`.
#[must_use]
pub fn plain(bytes: &[u8], case: Case) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        push_byte(&mut out, b, case);
    }
    out
}

/// Parses a hex string with no separators: the inverse of [`plain`], for the
/// round-trip property test.
///
/// # Errors
///
/// Returns `None` on odd length or a non-hex digit.
#[cfg(test)]
#[must_use]
pub(crate) fn parse_opt(s: &str) -> Option<Vec<u8>> {
    fn val_opt(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a' - 10),
            b'A'..=b'F' => c.checked_sub(b'A' - 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks(2)
        .map(|p| match p {
            [h, l] => Some((val_opt(*h)? << 4) | val_opt(*l)?),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn shapes() {
        assert_eq!(colon(&[0xde, 0xad, 0x01], Case::Lower), "de:ad:01");
        assert_eq!(colon(&[0xde, 0xad, 0x01], Case::Upper), "DE:AD:01");
        assert_eq!(colon(&[], Case::Upper), "");
        assert_eq!(plain(&[0x0f, 0xa0], Case::Upper), "0FA0");
        assert_eq!(parse_opt("0fA0"), Some(vec![0x0f, 0xa0]));
        assert_eq!(parse_opt("0"), None);
        assert_eq!(parse_opt("zz"), None);
    }

    proptest! {
        #[test]
        fn roundtrip(data in prop::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(parse_opt(&plain(&data, Case::Lower)).unwrap(), data.clone());
            prop_assert_eq!(parse_opt(&plain(&data, Case::Upper)).unwrap(), data.clone());
            let c = colon(&data, Case::Lower);
            prop_assert_eq!(c.len(), (data.len() * 3).saturating_sub(1));
        }
    }
}
