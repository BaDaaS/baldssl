//! A DER writer, the inverse of [`super::Reader`] on the values baldssl
//! writes. The module documentation of [`super`] explains DER and TLVs.
//!
//! Every function returns one complete TLV with the minimal length encoding
//! (lengths big-endian, as X.690 requires),
//! and minimal contents where DER requires it (INTEGER, OID), so the output
//! is the unique DER encoding of the value. The tests check each function
//! against the strict reader, which rejects any other encoding.

use super::{Integer, tag};

/// One TLV with identifier octet `tag` and the given contents.
#[must_use]
pub(crate) fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = Vec::with_capacity(contents.len().saturating_add(10));
    out.push(tag);
    if let Ok(short) = u8::try_from(len)
        && short < 0x80
    {
        out.push(short);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let significant = bytes.get(first..).unwrap_or(&[]);
        // At most 8 length bytes on a 64-bit target, so the count fits.
        let count = u8::try_from(significant.len()).unwrap_or(0);
        out.push(0x80 | count);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(contents);
    out
}

/// A SEQUENCE of already-encoded elements.
#[must_use]
pub fn sequence(elements: &[&[u8]]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &elements.concat())
}

/// `[n]` context-specific constructed, around already-encoded elements.
#[must_use]
pub fn context_constructed(n: u8, elements: &[&[u8]]) -> Vec<u8> {
    tlv(tag::context_constructed(n), &elements.concat())
}

/// A non-negative INTEGER from its big-endian magnitude: leading zero bytes
/// removed, and one `00` added when the top bit is set, so the two's
/// complement encoding is minimal and positive.
#[must_use]
pub(crate) fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let first = magnitude.iter().position(|&b| b != 0);
    let digits = first.and_then(|i| magnitude.get(i..)).unwrap_or(&[]);
    let mut contents = Vec::with_capacity(digits.len().saturating_add(1));
    if digits.first().is_none_or(|&b| b & 0x80 != 0) {
        contents.push(0);
    }
    contents.extend_from_slice(digits);
    tlv(tag::INTEGER, &contents)
}

/// An INTEGER of either sign: the minimal two's complement encoding
/// ([X.690] 8.3.2), big-endian. The value is one [`Integer::parse`]
/// returns: a negative one has a nonzero magnitude.
///
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
#[must_use]
pub fn integer(value: &Integer) -> Vec<u8> {
    if !value.negative {
        return unsigned_integer(&value.magnitude);
    }
    // -m in two's complement over the magnitude's width: !m + 1.
    let mut contents = value.magnitude.clone();
    let mut carry = true;
    for b in contents.iter_mut().rev() {
        let (v, c) = (!*b).overflowing_add(u8::from(carry));
        *b = v;
        carry = c;
    }
    // A clear top bit would read as positive: sign-extend with ff.
    if contents.first().is_none_or(|&b| b & 0x80 == 0) {
        contents.insert(0, 0xff);
    }
    // Drop redundant ff octets, keeping the encoding minimal.
    while let [0xff, next, ..] = contents.as_slice()
        && next & 0x80 != 0
    {
        contents.remove(0);
    }
    tlv(tag::INTEGER, &contents)
}

/// A non-negative INTEGER.
#[must_use]
pub fn small_integer(v: u64) -> Vec<u8> {
    unsigned_integer(&v.to_be_bytes())
}

/// An OCTET STRING.
#[must_use]
pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, bytes)
}

/// A BIT STRING of whole bytes (no unused bits).
#[must_use]
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut contents = Vec::with_capacity(bytes.len().saturating_add(1));
    contents.push(0);
    contents.extend_from_slice(bytes);
    tlv(tag::BIT_STRING, &contents)
}

/// An OBJECT IDENTIFIER from its dotted form, `None` if it is not one: at
/// least two arcs, the first 0, 1 or 2, the second below 40 unless the first
/// is 2, every arc below $2^{128}$. The first two arcs are combined as
/// $40 a_1 + a_2$, and each sub-identifier is base 128, most significant
/// group first, with the high bit on every byte but the last.
#[must_use]
pub fn oid_opt(dotted: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u128> = dotted
        .split('.')
        .map(|a| {
            // No leading zeros or signs, as in the canonical dotted form.
            let canonical = !a.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && (a == "0" || !a.starts_with('0'));
            canonical.then(|| a.parse::<u128>().ok()).flatten()
        })
        .collect::<Option<_>>()?;
    let (&first, rest) = arcs.split_first()?;
    let (&second, rest) = rest.split_first()?;
    if first > 2 || (first < 2 && second >= 40) {
        return None;
    }
    let mut contents = Vec::new();
    let combined = first.checked_mul(40)?.checked_add(second)?;
    for arc in core::iter::once(combined).chain(rest.iter().copied()) {
        let mut groups = Vec::new();
        let mut value = arc;
        loop {
            groups.push(u8::try_from(value & 0x7f).ok()?);
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        for (i, group) in groups.iter().rev().enumerate() {
            let more = i.checked_add(1)? < groups.len();
            contents.push(if more { group | 0x80 } else { *group });
        }
    }
    Some(tlv(tag::OID, &contents))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{DerError, Integer, Oid, Reader, parse_tlv, tag};
    use core::fmt::Write as _;
    use proptest::prelude::*;

    /// The example of the module documentation: the SEQUENCE of INTEGER 5
    /// and OCTET STRING "hi", and its BER-only spelling with a long-form
    /// length, which DER rejects.
    #[test]
    fn documented_example() {
        let v = sequence(&[&small_integer(5), &octet_string(b"hi")]);
        assert_eq!(v, [0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, 0x68, 0x69]);
        let ber = [0x30, 0x81, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, 0x68, 0x69];
        assert_eq!(
            Reader::new(&ber).read().map(|_| ()),
            Err(DerError::NonMinimalLength)
        );
    }

    #[test]
    fn lengths() {
        for len in [0usize, 1, 127, 128, 255, 256, 65_535, 65_536] {
            let contents = vec![0xab; len];
            let enc = tlv(tag::OCTET_STRING, &contents);
            let (t, used) = parse_tlv(&enc).unwrap();
            assert_eq!((t.value, used), (&contents[..], enc.len()), "{len}");
        }
        assert_eq!(tlv(0x04, &[1, 2]), [0x04, 0x02, 1, 2]);
        assert_eq!(&tlv(0x04, &[0; 128])[..3], &[0x04, 0x81, 0x80]);
        assert_eq!(&tlv(0x04, &[0; 256])[..4], &[0x04, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn integers() {
        assert_eq!(small_integer(0), [0x02, 0x01, 0x00]);
        assert_eq!(small_integer(1), [0x02, 0x01, 0x01]);
        assert_eq!(small_integer(0x80), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(unsigned_integer(&[0, 0, 0x7f]), [0x02, 0x01, 0x7f]);
        assert_eq!(unsigned_integer(&[]), [0x02, 0x01, 0x00]);
    }

    #[test]
    fn known_oids() {
        // id-ecPublicKey, prime256v1, Ed25519.
        assert_eq!(
            oid_opt("1.2.840.10045.2.1").unwrap(),
            [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
        );
        assert_eq!(
            oid_opt("1.2.840.10045.3.1.7").unwrap(),
            [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        );
        assert_eq!(
            oid_opt("1.3.101.112").unwrap(),
            [0x06, 0x03, 0x2b, 0x65, 0x70]
        );
        assert_eq!(oid_opt("2.999").unwrap(), [0x06, 0x02, 0x88, 0x37]);
        for bad in ["", "1", "3.1", "1.40", "1.2.x", "1..2", "1.02", "-1.2"] {
            assert_eq!(oid_opt(bad), None, "{bad}");
        }
    }

    #[test]
    fn structures() {
        let seq = sequence(&[&small_integer(1), &octet_string(&[])]);
        let mut r = Reader::new(&seq);
        let mut inner = r.sequence().unwrap();
        inner.expect(tag::INTEGER).unwrap();
        inner.expect(tag::OCTET_STRING).unwrap();
        inner.finish().unwrap();
        let ctx = context_constructed(1, &[&bit_string(&[4, 5])]);
        assert_eq!(ctx, [0xa1, 0x05, 0x03, 0x03, 0x00, 0x04, 0x05]);
    }

    proptest! {
        /// The writer's integers are the reader's canonical integers.
        #[test]
        fn integer_round_trip(magnitude in prop::collection::vec(any::<u8>(), 0..40)) {
            let enc = unsigned_integer(&magnitude);
            let (t, _) = parse_tlv(&enc).unwrap();
            let int = Integer::parse(t.value).unwrap();
            let first = magnitude.iter().position(|&b| b != 0).unwrap_or(magnitude.len());
            prop_assert!(!int.negative);
            prop_assert_eq!(&int.magnitude[..], &magnitude[first..]);
        }

        /// Dotted to DER to dotted is the identity.
        #[test]
        fn oid_round_trip(
            first in 0u128..3,
            second in 0u128..40,
            rest in prop::collection::vec(any::<u64>(), 0..6),
        ) {
            let mut dotted = format!("{first}.{second}");
            for arc in &rest {
                write!(dotted, ".{arc}").unwrap();
            }
            let enc = oid_opt(&dotted).unwrap();
            let (t, _) = parse_tlv(&enc).unwrap();
            prop_assert_eq!(Oid::parse(t.value).unwrap().to_dotted().unwrap(), dotted);
        }

        /// Any contents survive a TLV round trip through the strict reader.
        #[test]
        fn tlv_round_trip(contents in prop::collection::vec(any::<u8>(), 0..300)) {
            let enc = octet_string(&contents);
            let (t, used) = parse_tlv(&enc).unwrap();
            prop_assert_eq!(used, enc.len());
            prop_assert_eq!(t.value, &contents[..]);
        }
    }
}
