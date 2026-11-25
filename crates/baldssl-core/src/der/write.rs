//! A DER writer, the inverse of [`super::Reader`] on the values baldssl
//! writes. The module documentation of [`super`] explains DER and TLVs.
//!
//! Every function returns one complete TLV, a [`RawTlv`], with the minimal
//! length encoding (lengths big-endian, as X.690 requires), and minimal
//! contents where DER requires it (INTEGER, OID), so the output is the
//! unique DER encoding of the value. The tests check each function against
//! the strict reader, which rejects any other encoding.

use super::{
    ARCS_PER_FIRST_ARC, BASE_128_DIGIT, FIRST_LONG_LENGTH, Integer, LONG_FORM,
    MAX_LENGTH_OCTETS, MORE_OCTETS, SIGN_BIT, strip_leading_zeros,
    syntax::RawTlv, tag,
};

/// The bits of one base-128 digit (X.690 8.19.2).
const BASE_128_DIGIT_BITS: u32 = 7;

/// The longest header [`tlv`] writes: the identifier octet, the long form's
/// first length octet, and [`MAX_LENGTH_OCTETS`] length octets.
const MAX_HEADER: usize = MAX_LENGTH_OCTETS.saturating_add(2);

/// The encoding of one TLV with identifier octet `tag` and the given
/// contents: the length in the short form below 128, else in the long form
/// with the fewest octets, at most [`MAX_LENGTH_OCTETS`] (those of a
/// `usize`), which is what the reader accepts.
#[must_use]
pub(crate) fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = Vec::with_capacity(len.saturating_add(MAX_HEADER));
    out.push(tag);
    if let Ok(short) = u8::try_from(len)
        && usize::from(short) < FIRST_LONG_LENGTH
    {
        out.push(short);
    } else {
        let bytes = len.to_be_bytes();
        let significant = strip_leading_zeros(&bytes);
        // At most MAX_LENGTH_OCTETS (8) octets, far below 128, so the
        // conversion always succeeds and the fallback is never taken.
        let count = u8::try_from(significant.len()).unwrap_or(0);
        out.push(LONG_FORM | count);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(contents);
    out
}

/// The concatenation of the encodings of `elements`.
fn concat(elements: &[RawTlv]) -> Vec<u8> {
    elements
        .iter()
        .flat_map(RawTlv::as_bytes)
        .copied()
        .collect()
}

/// A SEQUENCE of already-encoded elements.
#[must_use]
pub fn sequence(elements: &[RawTlv]) -> RawTlv {
    RawTlv::from_tag_and_contents(tag::SEQUENCE, &concat(elements))
}

/// `[n]` context-specific constructed, around already-encoded elements.
#[must_use]
pub fn context_constructed(n: u8, elements: &[RawTlv]) -> RawTlv {
    RawTlv::from_tag_and_contents(
        tag::context_constructed(n),
        &concat(elements),
    )
}

/// A non-negative INTEGER from its big-endian magnitude: leading zero bytes
/// removed, and one `00` added when the top bit is set (or for zero), so the
/// two's complement encoding is minimal and positive.
#[must_use]
pub(crate) fn unsigned_integer(magnitude: &[u8]) -> RawTlv {
    let digits = strip_leading_zeros(magnitude);
    let mut contents = Vec::with_capacity(digits.len().saturating_add(1));
    if digits.first().is_none_or(|&b| b & SIGN_BIT != 0) {
        contents.push(0);
    }
    contents.extend_from_slice(digits);
    RawTlv::from_tag_and_contents(tag::INTEGER, &contents)
}

/// An INTEGER of either sign: the minimal two's complement encoding
/// ([X.690] 8.3.2), big-endian.
///
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
#[must_use]
pub fn integer(value: &Integer) -> RawTlv {
    if !value.is_negative() {
        return unsigned_integer(value.magnitude());
    }
    // -m in two's complement over the magnitude's width: !m + 1. The
    // magnitude of a negative Integer is not empty.
    let mut contents = value.magnitude().to_vec();
    let mut carry = true;
    for b in contents.iter_mut().rev() {
        let (v, c) = (!*b).overflowing_add(u8::from(carry));
        *b = v;
        carry = c;
    }
    // A clear top bit would read as positive: sign-extend with ff.
    if contents.first().is_none_or(|&b| b & SIGN_BIT == 0) {
        contents.insert(0, 0xff);
    }
    // Drop redundant ff octets, keeping the encoding minimal.
    while let [0xff, next, ..] = contents.as_slice()
        && next & SIGN_BIT != 0
    {
        contents.remove(0);
    }
    RawTlv::from_tag_and_contents(tag::INTEGER, &contents)
}

/// A non-negative INTEGER.
#[must_use]
pub fn small_integer(v: u64) -> RawTlv {
    unsigned_integer(&v.to_be_bytes())
}

/// An OCTET STRING.
#[must_use]
pub fn octet_string(bytes: &[u8]) -> RawTlv {
    RawTlv::from_tag_and_contents(tag::OCTET_STRING, bytes)
}

/// A BIT STRING of whole bytes (no unused bits).
#[must_use]
pub fn bit_string(bytes: &[u8]) -> RawTlv {
    let mut contents = Vec::with_capacity(bytes.len().saturating_add(1));
    contents.push(0);
    contents.extend_from_slice(bytes);
    RawTlv::from_tag_and_contents(tag::BIT_STRING, &contents)
}

/// The contents octets of the OBJECT IDENTIFIER written `dotted`, `None` if
/// it is not one: see [`oid_opt`].
#[must_use]
pub(crate) fn oid_contents_opt(dotted: &str) -> Option<Vec<u8>> {
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
    if first > 2 || (first < 2 && second >= ARCS_PER_FIRST_ARC) {
        return None;
    }
    let mut contents = Vec::new();
    let combined =
        first.checked_mul(ARCS_PER_FIRST_ARC)?.checked_add(second)?;
    for arc in core::iter::once(combined).chain(rest.iter().copied()) {
        let mut groups = Vec::new();
        let mut value = arc;
        loop {
            groups.push(u8::try_from(value & u128::from(BASE_128_DIGIT)).ok()?);
            value >>= BASE_128_DIGIT_BITS;
            if value == 0 {
                break;
            }
        }
        for (i, group) in groups.iter().rev().enumerate() {
            let more = i.checked_add(1)? < groups.len();
            contents.push(if more { group | MORE_OCTETS } else { *group });
        }
    }
    Some(contents)
}

/// An OBJECT IDENTIFIER from its dotted form, `None` if it is not one: at
/// least two arcs, the first 0, 1 or 2, the second below 40 unless the
/// first is 2, every arc below $2^{128}$. The first two arcs are combined as
/// $40 a_1 + a_2$ ([X.690] 8.19.4), and each subidentifier is base 128, most
/// significant group first, with the high bit on every byte but the last
/// (8.19.2).
///
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
#[must_use]
pub fn oid_opt(dotted: &str) -> Option<RawTlv> {
    oid_contents_opt(dotted)
        .map(|contents| RawTlv::from_tag_and_contents(tag::OID, &contents))
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
        let v = sequence(&[small_integer(5), octet_string(b"hi")]);
        assert_eq!(
            v.as_bytes(),
            [0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, 0x68, 0x69]
        );
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
            assert_eq!((t.value(), used), (&contents[..], enc.len()), "{len}");
        }
        assert_eq!(tlv(0x04, &[1, 2]), [0x04, 0x02, 1, 2]);
        assert_eq!(&tlv(0x04, &[0; 128])[..3], &[0x04, 0x81, 0x80]);
        assert_eq!(&tlv(0x04, &[0; 256])[..4], &[0x04, 0x82, 0x01, 0x00]);
    }

    /// The reader takes every length the writer gives: the length octets
    /// of a `usize`, and no more.
    #[test]
    fn length_octets_agree() {
        let mut header = vec![0x04, 0x80 | 8, 0x01];
        header.extend([0u8; 7]);
        let expected = if MAX_LENGTH_OCTETS >= 8 {
            DerError::UnexpectedEnd
        } else {
            DerError::LengthTooLarge
        };
        assert_eq!(parse_tlv(&header), Err(expected));
        let mut nine = vec![0x04, 0x80 | 9, 0x01];
        nine.extend([0u8; 8]);
        assert_eq!(parse_tlv(&nine), Err(DerError::LengthTooLarge));
    }

    #[test]
    fn integers() {
        assert_eq!(small_integer(0).as_bytes(), [0x02, 0x01, 0x00]);
        assert_eq!(small_integer(1).as_bytes(), [0x02, 0x01, 0x01]);
        assert_eq!(small_integer(0x80).as_bytes(), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(
            unsigned_integer(&[0, 0, 0x7f]).as_bytes(),
            [0x02, 0x01, 0x7f]
        );
        assert_eq!(unsigned_integer(&[]).as_bytes(), [0x02, 0x01, 0x00]);
    }

    #[test]
    fn known_oids() {
        // id-ecPublicKey, prime256v1, Ed25519.
        assert_eq!(
            oid_opt("1.2.840.10045.2.1").unwrap().as_bytes(),
            [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
        );
        assert_eq!(
            oid_opt("1.2.840.10045.3.1.7").unwrap().as_bytes(),
            [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        );
        assert_eq!(
            oid_opt("1.3.101.112").unwrap().as_bytes(),
            [0x06, 0x03, 0x2b, 0x65, 0x70]
        );
        assert_eq!(
            oid_opt("2.999").unwrap().as_bytes(),
            [0x06, 0x02, 0x88, 0x37]
        );
        for bad in ["", "1", "3.1", "1.40", "1.2.x", "1..2", "1.02", "-1.2"] {
            assert_eq!(oid_opt(bad), None, "{bad}");
        }
    }

    #[test]
    fn structures() {
        let seq = sequence(&[small_integer(1), octet_string(&[])]);
        let mut r = Reader::new(seq.as_bytes());
        let mut inner = r.sequence().unwrap();
        inner.expect(tag::INTEGER).unwrap();
        inner.expect(tag::OCTET_STRING).unwrap();
        inner.finish().unwrap();
        let ctx = context_constructed(1, &[bit_string(&[4, 5])]);
        assert_eq!(ctx.as_bytes(), [0xa1, 0x05, 0x03, 0x03, 0x00, 0x04, 0x05]);
    }

    proptest! {
        /// The writer's integers are the reader's canonical integers.
        #[test]
        fn integer_round_trip(magnitude in prop::collection::vec(any::<u8>(), 0..40)) {
            let enc = unsigned_integer(&magnitude);
            let (t, _) = parse_tlv(enc.as_bytes()).unwrap();
            let int = Integer::parse(t.value()).unwrap();
            prop_assert!(!int.is_negative());
            prop_assert_eq!(int.magnitude(), strip_leading_zeros(&magnitude));
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
            let (t, _) = parse_tlv(enc.as_bytes()).unwrap();
            prop_assert_eq!(Oid::parse(t.value()).unwrap().to_dotted().unwrap(), dotted);
        }

        /// Any contents survive a TLV round trip through the strict reader.
        #[test]
        fn tlv_round_trip(contents in prop::collection::vec(any::<u8>(), 0..300)) {
            let enc = octet_string(&contents);
            let (t, used) = parse_tlv(enc.as_bytes()).unwrap();
            prop_assert_eq!(used, enc.as_bytes().len());
            prop_assert_eq!(t.value(), &contents[..]);
        }
    }
}
