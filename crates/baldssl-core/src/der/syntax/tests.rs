//! The law of every combinator (round trip and canonicity as one partial
//! isomorphism, prefix-freeness of tagged encodings), golden encodings, and
//! the rejections X.690 requires.

use core::fmt::{Debug, Write as _};

use proptest::prelude::*;

use super::{
    Any, BitString, Boolean, Choice, Constant, Either, Explicit, Implicit, Map,
    Natural, Null, ObjectId, ObjectIdentifier, OctetString, OctetStringOf,
    Optional, OptionalLast, RawTlv, Sequence, SequenceOf, SetOf, Small, Syntax,
    Tagged, Unsigned, WithDefault, decode, encode,
};
use crate::der::DerError;

/// The partial-isomorphism law from `write`'s side: reading
/// `write(v) ++ suffix` gives back `v` and `suffix`. For a tagged
/// description any suffix will do (its encodings are a prefix code); for an
/// optional field, the suffix must not start with the field's tag, the rule
/// ASN.1 sets on whatever follows an OPTIONAL or DEFAULT field.
fn round_trip<S>(syntax: &S, value: &S::Value, suffix: &[u8])
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
fn canonical<S>(syntax: &S, bytes: &[u8])
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
fn prefix_free<S>(syntax: &S, value: &S::Value)
where
    S: Tagged,
{
    let bytes = encode(syntax, value);
    assert_eq!(bytes.first(), Some(&syntax.tag()), "starts with its tag");
    for k in 0..bytes.len() {
        assert!(syntax.read(&bytes[..k]).is_err(), "prefix of length {k}");
    }
}

/// Every law, plus canonicity on mutations of the encoding (one byte
/// changed, one byte dropped), which reach accepted inputs far more often
/// than random strings.
fn laws<S>(syntax: &S, value: &S::Value, at: usize, xor: u8, suffix: &[u8])
where
    S: Tagged,
    S::Value: PartialEq + Debug,
{
    round_trip(syntax, value, suffix);
    prefix_free(syntax, value);
    let bytes = encode(syntax, value);
    canonical(syntax, &bytes);
    let i = at % bytes.len();
    let mut changed = bytes.clone();
    changed[i] ^= xor;
    canonical(syntax, &changed);
    let mut dropped = bytes.clone();
    dropped.remove(i);
    canonical(syntax, &dropped);
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

/// Object identifiers: two first arcs as X.690 8.19.4 allows, then more.
fn oid() -> impl Strategy<Value = ObjectId> {
    (
        0u64..=2,
        0u64..40,
        prop::collection::vec(any::<u32>(), 0..6),
    )
        .prop_map(|(a, b, rest)| {
            let mut dotted = format!("{a}.{b}");
            for arc in rest {
                write!(dotted, ".{arc}").unwrap();
            }
            ObjectId::from_dotted_opt(&dotted).expect("a valid identifier")
        })
}

/// `SEQUENCE { INTEGER, OCTET STRING, BOOLEAN OPTIONAL, [0] EXPLICIT
/// INTEGER DEFAULT 0 }`.
type Record = Sequence<(
    Small,
    (
        OctetString,
        (Optional<Boolean>, (WithDefault<Explicit<0, Small>>, ())),
    ),
)>;

fn record() -> Record {
    Sequence((
        Small,
        (
            OctetString,
            (
                Optional(Boolean),
                (WithDefault::new(Explicit::<0, _>(Small), 0), ()),
            ),
        ),
    ))
}

/// A refinement: version numbers 0 to 2 (as in X.509), mapped to an enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V1,
    V2,
    V3,
}

fn version() -> Map<Small, Version> {
    Map::new(
        Small,
        |v| match v {
            0 => Some(Version::V1),
            1 => Some(Version::V2),
            2 => Some(Version::V3),
            _ => None,
        },
        |v| match v {
            Version::V1 => 0,
            Version::V2 => 1,
            Version::V3 => 2,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn leaves(
        b in any::<bool>(),
        n in bytes(40),
        k in any::<u64>(),
        s in bytes(300),
        id in oid(),
        at in any::<usize>(),
        xor in 1u8..,
        suffix in bytes(8),
    ) {
        laws(&Boolean, &b, at, xor, &suffix);
        laws(&Null, &(), at, xor, &suffix);
        laws(&Unsigned, &Natural::from_be_bytes(&n), at, xor, &suffix);
        laws(&Small, &k, at, xor, &suffix);
        laws(&OctetString, &s, at, xor, &suffix);
        laws(&BitString, &s, at, xor, &suffix);
        laws(&ObjectIdentifier, &id, at, xor, &suffix);
    }

    #[test]
    fn any_tlv(s in bytes(200), tag_octet in prop::sample::select(vec![0x02u8, 0x04, 0x30, 0x31, 0x80, 0xa3]), suffix in bytes(8)) {
        let raw = RawTlv::parse(&crate::der::write::tlv(tag_octet, &s));
        // Only well-formed TLVs are values; the writer produces them.
        if let Ok(raw) = raw {
            round_trip(&Any, &raw, &suffix);
            canonical(&Any, raw.as_bytes());
        }
    }

    #[test]
    fn sequences(
        k in any::<u64>(),
        s in bytes(200),
        flag in prop::option::of(any::<bool>()),
        d in any::<u64>(),
        items in prop::collection::vec(any::<u64>(), 0..8),
        at in any::<usize>(),
        xor in 1u8..,
        suffix in bytes(8),
    ) {
        laws(&record(), &(k, (s.clone(), (flag, (d, ())))), at, xor, &suffix);
        laws(&SequenceOf(Small), &items, at, xor, &suffix);
        laws(&Sequence(()), &(), at, xor, &suffix);
        // An encoding inside an OCTET STRING, as PKCS#8's privateKey.
        laws(&OctetStringOf(Sequence((Small, ()))), &(k, ()), at, xor, &suffix);
    }

    /// SET OF writes the canonical representative of the multiset: any
    /// order of the same components gives the same bytes, read back sorted.
    /// `SEQUENCE { OBJECT IDENTIFIER, ANY OPTIONAL }`, the shape of an
    /// AlgorithmIdentifier.
    #[test]
    fn optional_last(id in oid(), param in prop::option::of(bytes(20)), at in any::<usize>(), xor in 1u8.., suffix in bytes(8)) {
        let syntax = Sequence((ObjectIdentifier, (OptionalLast(Any), ())));
        let param = param.map(|p| RawTlv::parse(&encode(&OctetString, &p)).unwrap());
        laws(&syntax, &(id, (param, ())), at, xor, &suffix);
    }

    /// Proper prefixes of any TLV are rejected: the TLVs form a prefix code.
    #[test]
    fn tlvs_are_a_prefix_code(data in bytes(64)) {
        if let Ok((raw, _)) = Any.read(&data) {
            let enc = raw.as_bytes();
            for k in 0..enc.len() {
                prop_assert!(Any.read(&enc[..k]).is_err(), "prefix {k}");
            }
        }
    }

    #[test]
    fn sets(mut items in prop::collection::vec(bytes(6), 0..8), at in any::<usize>(), xor in 1u8.., suffix in bytes(8)) {
        let syntax = SetOf(OctetString);
        let written = encode(&syntax, &items);
        let mut reversed = items.clone();
        reversed.reverse();
        prop_assert_eq!(encode(&syntax, &reversed), written.clone());
        // Sorted by encoding: for OCTET STRING, by length, then bytes.
        items.sort_by_key(|item| encode(&OctetString, item));
        prop_assert_eq!(decode(&syntax, &written).unwrap(), items.clone());
        laws(&syntax, &items, at, xor, &suffix);
    }

    #[test]
    fn tags(k in any::<u64>(), s in bytes(100), at in any::<usize>(), xor in 1u8.., suffix in bytes(8)) {
        laws(&Explicit::<3, _>(Small), &k, at, xor, &suffix);
        laws(&Implicit::<1, _>(OctetString), &s, at, xor, &suffix);
        laws(&Implicit::<2, _>(Sequence((Small, ()))), &(k, ()), at, xor, &suffix);
    }

    #[test]
    fn choices_and_refinements(k in any::<u64>(), s in bytes(50), v in 0u64..3, at in any::<usize>(), xor in 1u8.., suffix in bytes(8)) {
        let choice = Choice::new_opt(Small, OctetString).unwrap();
        round_trip(&choice, &Either::First(k), &suffix);
        round_trip(&choice, &Either::Second(s.clone()), &suffix);
        let enc = encode(&choice, &Either::First(k));
        canonical(&choice, &enc);
        let version_syntax = version();
        let value = match v { 0 => Version::V1, 1 => Version::V2, _ => Version::V3 };
        laws(&version_syntax, &value, at, xor, &suffix);
        laws(&Constant::new(Small, 7), &(), at, xor, &suffix);
    }

    /// The optional combinators, on their own: the law holds for a suffix
    /// that does not start with the field's tag (OPTIONAL, DEFAULT), or an
    /// empty one (ANY OPTIONAL in last position).
    #[test]
    fn optional_fields(
        flag in prop::option::of(any::<bool>()),
        b in any::<bool>(),
        raw in prop::option::of(bytes(20)),
        suffix in bytes(8).prop_filter("not BOOLEAN's tag", |s| s.first() != Some(&0x01)),
    ) {
        round_trip(&Optional(Boolean), &flag, &suffix);
        round_trip(&WithDefault::new(Boolean, false), &b, &suffix);
        let raw = raw.map(|p| RawTlv::parse(&encode(&OctetString, &p)).unwrap());
        round_trip(&OptionalLast(Any), &raw, &[]);
    }

    /// Canonicity and totality on arbitrary bytes, for every combinator.
    #[test]
    fn arbitrary_bytes(data in bytes(64)) {
        canonical(&Boolean, &data);
        canonical(&Null, &data);
        canonical(&Unsigned, &data);
        canonical(&Small, &data);
        canonical(&OctetString, &data);
        canonical(&BitString, &data);
        canonical(&ObjectIdentifier, &data);
        canonical(&Any, &data);
        canonical(&record(), &data);
        canonical(&SequenceOf(Small), &data);
        canonical(&SetOf(OctetString), &data);
        canonical(&Explicit::<0, _>(Small), &data);
        canonical(&Implicit::<0, _>(OctetString), &data);
        canonical(&Optional(Boolean), &data);
        canonical(&WithDefault::new(Boolean, false), &data);
        canonical(&Choice::new_opt(Small, OctetString).unwrap(), &data);
        canonical(&version(), &data);
        canonical(&OctetStringOf(Small), &data);
        canonical(&Sequence((ObjectIdentifier, (OptionalLast(Any), ()))), &data);
    }
}

/// Encodings stated in, or computed by hand from, X.690.
#[test]
fn golden() {
    assert_eq!(encode(&Boolean, &true), [0x01, 0x01, 0xff]);
    assert_eq!(encode(&Null, &()), [0x05, 0x00]);
    assert_eq!(encode(&Small, &0), [0x02, 0x01, 0x00]);
    assert_eq!(encode(&Small, &127), [0x02, 0x01, 0x7f]);
    assert_eq!(encode(&Small, &128), [0x02, 0x02, 0x00, 0x80]);
    assert_eq!(encode(&Small, &256), [0x02, 0x02, 0x01, 0x00]);
    assert_eq!(
        encode(&Unsigned, &Natural::from_be_bytes(&[0, 0, 0xff])),
        [0x02, 0x02, 0x00, 0xff]
    );
    let rsa = ObjectId::from_dotted_opt("1.2.840.113549").unwrap();
    assert_eq!(
        encode(&ObjectIdentifier, &rsa),
        [0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]
    );
    assert_eq!(rsa.to_dotted().unwrap(), "1.2.840.113549");
    // The X.509 version field, v3: [0] EXPLICIT INTEGER 2.
    assert_eq!(
        encode(&Explicit::<0, _>(Small), &2),
        [0xa0, 0x03, 0x02, 0x01, 0x02]
    );
    // [0] IMPLICIT OCTET STRING keeps the primitive form, [1] IMPLICIT
    // SEQUENCE the constructed one.
    assert_eq!(
        encode(&Implicit::<0, _>(OctetString), &b"hi".to_vec()),
        [0x80, 0x02, 0x68, 0x69]
    );
    assert_eq!(encode(&Implicit::<1, _>(Sequence(())), &()), [0xa1, 0x00]);
    // The example of the DER module documentation.
    let pair = Sequence((Small, (OctetString, ())));
    assert_eq!(
        encode(&pair, &(5, (b"hi".to_vec(), ()))),
        [0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, 0x68, 0x69]
    );
}

/// A constant identifier is the one its dotted form names.
#[test]
fn static_identifiers() {
    const EC: ObjectId =
        ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    assert_eq!(Some(EC), ObjectId::from_dotted_opt("1.2.840.10045.2.1"));
    assert_eq!(
        decode(&ObjectIdentifier, &encode(&ObjectIdentifier, &EC)),
        Ok(EC)
    );
}

/// Why the rule on what follows an optional field is needed: an absent
/// OPTIONAL BOOLEAN followed by bytes that start with a BOOLEAN reads those
/// bytes as the field. The description must not put a field with the same
/// tag right after an optional one; the reader cannot tell them apart.
#[test]
fn optional_field_followed_by_its_own_tag() {
    let field = Optional(Boolean);
    let mut bytes = encode(&field, &None);
    bytes.extend([0x01, 0x01, 0xff]);
    assert_eq!(field.read(&bytes), Ok((Some(true), &[][..])));
    // And an empty OptionalLast followed by anything reads it as the field.
    let last = OptionalLast(Any);
    assert_eq!(
        last.read(&[0x05, 0x00])
            .map(|(v, r)| (v.is_some(), r.len())),
        Ok((true, 0))
    );
}

/// What DER forbids, or what is outside the type described.
#[test]
fn rejections() {
    // X.690 11.6: SET OF in ascending order only; equal components repeat.
    let set = SetOf(OctetString);
    let a = encode(&OctetString, &b"a".to_vec());
    let b = encode(&OctetString, &b"b".to_vec());
    let wrapped =
        |parts: &[&[u8]]| crate::der::write::tlv(0x31, &parts.concat());
    assert_eq!(
        decode(&set, &wrapped(&[&b, &a])),
        Err(DerError::UnsortedSet)
    );
    assert!(decode(&set, &wrapped(&[&a, &b])).is_ok());
    assert!(decode(&set, &wrapped(&[&a, &a])).is_ok());

    // X.690 11.5: a DEFAULT value is not encoded.
    let flag = WithDefault::new(Boolean, false);
    assert_eq!(encode(&flag, &false), Vec::<u8>::new());
    assert_eq!(
        decode(&flag, &[0x01, 0x01, 0x00]),
        Err(DerError::ExplicitDefault)
    );
    assert_eq!(decode(&flag, &[0x01, 0x01, 0xff]), Ok(true));
    assert_eq!(decode(&flag, &[]), Ok(false));

    // Valid DER outside the type: a negative INTEGER, a BIT STRING with
    // unused bits, an INTEGER above 2^64, another constant.
    assert_eq!(
        decode(&Unsigned, &[0x02, 0x01, 0xff]),
        Err(DerError::UnexpectedValue)
    );
    assert_eq!(
        decode(&BitString, &[0x03, 0x02, 0x01, 0xfe]),
        Err(DerError::UnexpectedValue)
    );
    let big = [0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(decode(&Small, &big), Err(DerError::UnexpectedValue));
    assert_eq!(
        decode(&Constant::new(Small, 1), &[0x02, 0x01, 0x02]),
        Err(DerError::UnexpectedValue)
    );
    assert_eq!(
        decode(&version(), &[0x02, 0x01, 0x03]),
        Err(DerError::UnexpectedValue)
    );

    // Non-DER spellings the leaves inherit from the strict reader.
    assert_eq!(
        decode(&Boolean, &[0x01, 0x01, 0x01]),
        Err(DerError::InvalidBoolean)
    );
    assert_eq!(
        decode(&Small, &[0x02, 0x02, 0x00, 0x01]),
        Err(DerError::InvalidInteger)
    );
    assert_eq!(
        decode(&OctetString, &[0x04, 0x81, 0x01, 0x00]),
        Err(DerError::NonMinimalLength)
    );

    // A SEQUENCE must use all of its contents, and so must the top level.
    let one = Sequence((Small, ()));
    assert_eq!(
        decode(&one, &[0x30, 0x04, 0x02, 0x01, 0x05, 0x00]),
        Err(DerError::TrailingData)
    );
    assert_eq!(
        decode(&Small, &[0x02, 0x01, 0x05, 0x00]),
        Err(DerError::TrailingData)
    );

    // Constructors that would break the law.
    assert!(
        Choice::new_opt(Small, Unsigned).is_none(),
        "two INTEGER alternatives"
    );
}
