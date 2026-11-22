//! DER syntax descriptions: one description per ASN.1 type, from which both
//! the reader and the writer come.
//!
//! # The abstraction
//!
//! A [`Syntax`] is a *partial isomorphism* between a value type `V` and a set
//! of byte strings, in the sense of Rendel and Ostermann's
//! [*Invertible syntax descriptions*][iso] (Haskell Symposium 2010): a writer
//! `write : V -> bytes` and a reader `read : bytes -> V x bytes`, partial,
//! related by one law,
//!
//! ```text
//! read(b) = Ok((v, rest))   if and only if   b = write(v) ++ rest.
//! ```
//!
//! Read from left to right it is the round trip (`read` inverts `write`);
//! from right to left it is canonicity (whatever `read` accepts, `write`
//! gives back byte for byte), which is what DER adds to BER ([X.690][x690],
//! clauses 10 and 11). It also makes the set of encodings *prefix-free*: if
//! two encodings `write(v)` and `write(w)` were one a proper prefix of the
//! other, reading the longer would have two answers. A prefix code has
//! unique factorisations, so a concatenation of encodings is read in exactly
//! one way.
//!
//! Every combinator here satisfies the law when its parts do, and keeps the
//! encodings prefix-free, so a description built from them satisfies it by
//! construction. The tests check the law once per combinator, on random
//! values and on random byte strings.
//!
//! # The combinators
//!
//! | ASN.1 | Combinator | Value |
//! | --- | --- | --- |
//! | BOOLEAN | [`Boolean`] | `bool` |
//! | NULL | [`Null`] | `()` |
//! | INTEGER | [`Signed`] | [`Integer`] |
//! | INTEGER, non-negative | [`Unsigned`], [`Small`] | [`Natural`], `u64` |
//! | OCTET STRING | [`OctetString`] | `Vec<u8>` |
//! | OCTET STRING around an encoding | [`OctetStringOf`] | the inner value |
//! | BIT STRING, whole bytes | [`BitString`] | `Vec<u8>` |
//! | OBJECT IDENTIFIER | [`ObjectIdentifier`] | [`ObjectId`] |
//! | any one TLV | [`Any`] | [`RawTlv`] |
//! | SEQUENCE | [`Sequence`] over [`Fields`] | a tuple list |
//! | SEQUENCE OF, SET OF | [`SequenceOf`], [`SetOf`] | `Vec` |
//! | `[n] EXPLICIT`, `[n] IMPLICIT` | [`Explicit`], [`Implicit`] (`n` in the type) | the inner value |
//! | OPTIONAL, DEFAULT | [`Optional`], [`WithDefault`] | `Option`, the inner value |
//! | ANY OPTIONAL, last | [`OptionalLast`] | `Option` |
//! | CHOICE of two | [`Choice`] | [`Either`] |
//! | a fixed value | [`Constant`] | `()` |
//! | a refinement | [`Map`] | any type |
//!
//! The fields of a SEQUENCE are a type-level list: `()` is the empty list
//! and `(Head, Tail)` adds a field, so `Sequence((Small, (OctetString, ())))`
//! describes `SEQUENCE { INTEGER, OCTET STRING }`, with values
//! `(u64, (Vec<u8>, ()))`.
//!
//! [`Optional`], [`WithDefault`] and [`Choice`] decide by the next identifier
//! octet, so they take a [`Tagged`] description, one whose encodings always
//! start with the same octet; the types forbid an optional [`Any`]. As in
//! ASN.1, the tag of an optional or defaulted field must differ from the
//! tag of the field that follows it; that is the description's
//! responsibility.
//!
//! # Byte order
//!
//! Everything here is big-endian, as X.690 is: lengths in the long form,
//! INTEGER contents, and [`Natural`]'s bytes.
//!
//! [iso]: https://www.informatik.uni-marburg.de/~rendel/unparse
//! [x690]: https://www.itu.int/rec/T-REC-X.690

use std::borrow::Cow;

use super::{
    BitString as BitStringContents, DerError, Integer, Oid, parse_bool,
    parse_tlv, tag, write,
};

/// A description of a DER encoding: see the module documentation for the
/// law it satisfies.
pub trait Syntax {
    /// The values described.
    type Value;

    /// Appends the encoding of `value`.
    fn write(&self, value: &Self::Value, out: &mut Vec<u8>);

    /// Reads one encoding from the start of `input`, and returns the value
    /// and the bytes after it.
    ///
    /// # Errors
    ///
    /// A [`DerError`] when `input` does not start with an encoding of a
    /// value.
    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Self::Value, &'a [u8]), DerError>;
}

/// A description whose encodings all start with the same identifier octet,
/// so that [`Optional`], [`WithDefault`] and [`Choice`] can decide by it.
pub trait Tagged: Syntax {
    /// The identifier octet of every encoding.
    fn tag(&self) -> u8;
}

/// The encoding of `value`.
#[must_use]
pub fn encode<S>(syntax: &S, value: &S::Value) -> Vec<u8>
where
    S: Syntax,
{
    let mut out = Vec::new();
    syntax.write(value, &mut out);
    out
}

/// The value encoded by all of `bytes`.
///
/// # Errors
///
/// A [`DerError`] when `bytes` is not an encoding, and
/// [`DerError::TrailingData`] when bytes remain after it.
pub fn decode<S>(syntax: &S, bytes: &[u8]) -> Result<S::Value, DerError>
where
    S: Syntax,
{
    let (value, rest) = syntax.read(bytes)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(DerError::TrailingData)
    }
}

/// One TLV with identifier octet `octet` at the start of `input`: its
/// contents and the bytes after it.
fn expect(input: &[u8], octet: u8) -> Result<(&[u8], &[u8]), DerError> {
    let (tlv, used) = parse_tlv(input)?;
    if tlv.octet() != octet {
        return Err(DerError::UnexpectedTag {
            expected: octet,
            found: tlv.octet(),
        });
    }
    let rest = input.get(used..).ok_or(DerError::UnexpectedEnd)?;
    Ok((tlv.value, rest))
}

/// Appends the TLV with identifier octet `octet` and these contents.
fn put(out: &mut Vec<u8>, octet: u8, contents: &[u8]) {
    out.extend(write::tlv(octet, contents));
}

/// Reads the contents of a constructed TLV with `fields`, which must use
/// them all.
fn all<F>(fields: &F, contents: &[u8]) -> Result<F::Value, DerError>
where
    F: Fields,
{
    let (value, rest) = fields.read(contents)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(DerError::TrailingData)
    }
}

// --- Leaves ---------------------------------------------------------------

/// BOOLEAN: `01 01 FF` for true, `01 01 00` for false (X.690 11.1).
#[derive(Debug, Clone, Copy)]
pub struct Boolean;

impl Syntax for Boolean {
    type Value = bool;

    fn write(&self, value: &bool, out: &mut Vec<u8>) {
        put(out, tag::BOOLEAN, &[if *value { 0xff } else { 0x00 }]);
    }

    fn read<'a>(&self, input: &'a [u8]) -> Result<(bool, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::BOOLEAN)?;
        Ok((parse_bool(contents)?, rest))
    }
}

impl Tagged for Boolean {
    fn tag(&self) -> u8 {
        tag::BOOLEAN
    }
}

/// NULL: `05 00`.
#[derive(Debug, Clone, Copy)]
pub struct Null;

impl Syntax for Null {
    type Value = ();

    fn write(&self, (): &(), out: &mut Vec<u8>) {
        put(out, tag::NULL, &[]);
    }

    fn read<'a>(&self, input: &'a [u8]) -> Result<((), &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::NULL)?;
        if contents.is_empty() {
            Ok(((), rest))
        } else {
            Err(DerError::InvalidNull)
        }
    }
}

impl Tagged for Null {
    fn tag(&self) -> u8 {
        tag::NULL
    }
}

/// A natural number as its big-endian bytes without leading zeros (zero is
/// the empty string): the canonical form, so equal numbers are equal
/// values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Natural(Vec<u8>);

impl Natural {
    /// The number with these big-endian bytes; leading zeros are dropped.
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        Natural(bytes.get(first..).unwrap_or(&[]).to_vec())
    }

    /// The big-endian bytes, without leading zeros.
    #[must_use]
    pub fn as_be_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// INTEGER, non-negative and of any size: the minimal two's complement
/// encoding (X.690 8.3.2), with a leading `00` when the top bit is set. A
/// negative INTEGER is rejected as [`DerError::UnexpectedValue`].
#[derive(Debug, Clone, Copy)]
pub struct Unsigned;

impl Syntax for Unsigned {
    type Value = Natural;

    fn write(&self, value: &Natural, out: &mut Vec<u8>) {
        out.extend(write::unsigned_integer(value.as_be_bytes()));
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Natural, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::INTEGER)?;
        let int = Integer::parse(contents)?;
        if int.negative {
            return Err(DerError::UnexpectedValue);
        }
        Ok((Natural::from_be_bytes(&int.magnitude), rest))
    }
}

impl Tagged for Unsigned {
    fn tag(&self) -> u8 {
        tag::INTEGER
    }
}

/// INTEGER of either sign and any size, as the canonical [`Integer`] (a
/// sign and a magnitude without leading zeros), so equal numbers are equal
/// values. Its values are the ones [`Integer::parse`] returns: a negative
/// one has a nonzero magnitude.
#[derive(Debug, Clone, Copy)]
pub struct Signed;

impl Syntax for Signed {
    type Value = Integer;

    fn write(&self, value: &Integer, out: &mut Vec<u8>) {
        out.extend(write::integer(value));
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Integer, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::INTEGER)?;
        Ok((Integer::parse(contents)?, rest))
    }
}

impl Tagged for Signed {
    fn tag(&self) -> u8 {
        tag::INTEGER
    }
}

/// INTEGER, non-negative and below $2^{64}$ (versions, counts). Others are
/// rejected as [`DerError::UnexpectedValue`].
#[derive(Debug, Clone, Copy)]
pub struct Small;

impl Syntax for Small {
    type Value = u64;

    fn write(&self, value: &u64, out: &mut Vec<u8>) {
        out.extend(write::small_integer(*value));
    }

    fn read<'a>(&self, input: &'a [u8]) -> Result<(u64, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::INTEGER)?;
        let int = Integer::parse(contents)?;
        if int.negative {
            return Err(DerError::UnexpectedValue);
        }
        Ok((int.to_u64_opt().ok_or(DerError::UnexpectedValue)?, rest))
    }
}

impl Tagged for Small {
    fn tag(&self) -> u8 {
        tag::INTEGER
    }
}

/// OCTET STRING.
#[derive(Debug, Clone, Copy)]
pub struct OctetString;

impl Syntax for OctetString {
    type Value = Vec<u8>;

    fn write(&self, value: &Vec<u8>, out: &mut Vec<u8>) {
        put(out, tag::OCTET_STRING, value);
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Vec<u8>, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::OCTET_STRING)?;
        Ok((contents.to_vec(), rest))
    }
}

impl Tagged for OctetString {
    fn tag(&self) -> u8 {
        tag::OCTET_STRING
    }
}

/// OCTET STRING whose contents are exactly one encoding of `P`, as the
/// `privateKey` of PKCS#8 and the `extnValue` of an X.509 extension.
#[derive(Debug, Clone, Copy)]
pub struct OctetStringOf<P>(pub P)
where
    P: Syntax;

impl<P> Syntax for OctetStringOf<P>
where
    P: Syntax,
{
    type Value = P::Value;

    fn write(&self, value: &P::Value, out: &mut Vec<u8>) {
        put(out, tag::OCTET_STRING, &encode(&self.0, value));
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(P::Value, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::OCTET_STRING)?;
        Ok((decode(&self.0, contents)?, rest))
    }
}

impl<P> Tagged for OctetStringOf<P>
where
    P: Syntax,
{
    fn tag(&self) -> u8 {
        tag::OCTET_STRING
    }
}

/// BIT STRING of whole bytes (keys, signatures): the unused-bits octet is 0.
/// A BIT STRING with unused bits is valid DER but outside this type, and is
/// rejected as [`DerError::UnexpectedValue`].
#[derive(Debug, Clone, Copy)]
pub struct BitString;

impl Syntax for BitString {
    type Value = Vec<u8>;

    fn write(&self, value: &Vec<u8>, out: &mut Vec<u8>) {
        out.extend(write::bit_string(value));
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Vec<u8>, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::BIT_STRING)?;
        let bits = BitStringContents::parse(contents)?;
        if bits.unused != 0 {
            return Err(DerError::UnexpectedValue);
        }
        Ok((bits.bytes.to_vec(), rest))
    }
}

impl Tagged for BitString {
    fn tag(&self) -> u8 {
        tag::BIT_STRING
    }
}

/// An object identifier, as its DER contents octets (base-128 arcs, minimal,
/// X.690 8.19), checked when built.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectId(Cow<'static, [u8]>);

/// Whether `contents` are the contents of an OBJECT IDENTIFIER: not empty,
/// the last octet ends a sub-identifier, and no sub-identifier starts with
/// `0x80` (X.690 8.19.2). The same rule as [`Oid::parse`], as a `const fn`.
const fn valid_oid_contents(contents: &[u8]) -> bool {
    let Some(last) = contents.last() else {
        return false;
    };
    if *last & 0x80 != 0 {
        return false;
    }
    let mut start = true;
    let mut rest = contents;
    while let [b, tail @ ..] = rest {
        if start && *b == 0x80 {
            return false;
        }
        start = *b & 0x80 == 0;
        rest = tail;
    }
    true
}

impl ObjectId {
    /// An identifier given as its contents octets, for constants. The check
    /// runs at compile time when the result is a `const`, so an invalid
    /// constant does not compile:
    ///
    /// ```
    /// use baldssl_core::der::syntax::ObjectId;
    /// // 1.2.840.10045.2.1, id-ecPublicKey.
    /// const ID: ObjectId =
    ///     ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    /// assert_eq!(ID.to_dotted().unwrap(), "1.2.840.10045.2.1");
    /// ```
    ///
    /// # Panics
    ///
    /// On contents that are not an OBJECT IDENTIFIER's: at compile time for
    /// a constant, which is the intended use.
    #[must_use]
    pub const fn from_static(contents: &'static [u8]) -> Self {
        assert!(
            valid_oid_contents(contents),
            "not the contents of an OBJECT IDENTIFIER"
        );
        ObjectId(Cow::Borrowed(contents))
    }

    /// The identifier written in dotted form (`1.2.840.10045.2.1`), or `None`
    /// when it is not a valid object identifier.
    #[must_use]
    pub fn from_dotted_opt(dotted: &str) -> Option<Self> {
        let encoded = write::oid_opt(dotted)?;
        let (tlv, _) = parse_tlv(&encoded).ok()?;
        Some(ObjectId(Cow::Owned(tlv.value.to_vec())))
    }

    /// The dotted form.
    ///
    /// # Errors
    ///
    /// None in practice: the contents are checked when the value is built.
    pub fn to_dotted(&self) -> crate::Result<String> {
        self.as_oid().to_dotted()
    }

    /// The borrowed view of the same identifier, which decoders give: total,
    /// since the contents were checked when the value was built.
    #[must_use]
    pub fn as_oid(&self) -> Oid<'_> {
        Oid(&self.0)
    }
}

/// OBJECT IDENTIFIER.
#[derive(Debug, Clone, Copy)]
pub struct ObjectIdentifier;

impl Syntax for ObjectIdentifier {
    type Value = ObjectId;

    fn write(&self, value: &ObjectId, out: &mut Vec<u8>) {
        put(out, tag::OID, &value.0);
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(ObjectId, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::OID)?;
        Oid::parse(contents)?;
        Ok((ObjectId(Cow::Owned(contents.to_vec())), rest))
    }
}

impl Tagged for ObjectIdentifier {
    fn tag(&self) -> u8 {
        tag::OID
    }
}

/// One complete DER TLV, kept as its encoding, checked when built.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawTlv(Vec<u8>);

impl RawTlv {
    /// `bytes` when it is exactly one DER TLV.
    ///
    /// # Errors
    ///
    /// The reader's error, or [`DerError::TrailingData`].
    pub fn parse(bytes: &[u8]) -> Result<Self, DerError> {
        let (_, used) = parse_tlv(bytes)?;
        if used == bytes.len() {
            Ok(RawTlv(bytes.to_vec()))
        } else {
            Err(DerError::TrailingData)
        }
    }

    /// The encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The TLV with the one-octet identifier `tag` and these contents, the
    /// length written minimally. Total: every such pair is one TLV.
    #[must_use]
    pub fn from_tag_and_contents(tag: u8, contents: &[u8]) -> Self {
        RawTlv(write::tlv(tag, contents))
    }

    /// The encoding of `value` by a tagged description, kept raw. Total:
    /// the encodings of a tagged description are single TLVs, by its law.
    #[must_use]
    pub fn encode<S>(syntax: &S, value: &S::Value) -> Self
    where
        S: Tagged,
    {
        RawTlv(encode(syntax, value))
    }
}

/// Any one TLV, for parts the description leaves uninterpreted. Not
/// [`Tagged`]: it starts with any octet.
#[derive(Debug, Clone, Copy)]
pub struct Any;

impl Syntax for Any {
    type Value = RawTlv;

    fn write(&self, value: &RawTlv, out: &mut Vec<u8>) {
        out.extend_from_slice(&value.0);
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(RawTlv, &'a [u8]), DerError> {
        let (tlv, used) = parse_tlv(input)?;
        let rest = input.get(used..).ok_or(DerError::UnexpectedEnd)?;
        Ok((RawTlv(tlv.encoded.to_vec()), rest))
    }
}

// --- Sequences --------------------------------------------------------------

/// The fields of a SEQUENCE, as a type-level list: `()` and
/// `(Head, Tail)`. Like [`Syntax`], but read from the contents of the
/// SEQUENCE rather than from a TLV of its own.
pub trait Fields {
    /// The values of the fields, as a tuple list.
    type Value;

    /// Appends the encodings of the fields.
    fn write(&self, value: &Self::Value, out: &mut Vec<u8>);

    /// Reads the fields from the start of `input`.
    ///
    /// # Errors
    ///
    /// The first field's error.
    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Self::Value, &'a [u8]), DerError>;
}

/// No field.
impl Fields for () {
    type Value = ();

    fn write(&self, (): &(), _out: &mut Vec<u8>) {}

    fn read<'a>(&self, input: &'a [u8]) -> Result<((), &'a [u8]), DerError> {
        Ok(((), input))
    }
}

/// A field, then the others.
impl<H, T> Fields for (H, T)
where
    H: Syntax,
    T: Fields,
{
    type Value = (H::Value, T::Value);

    fn write(&self, (head, tail): &Self::Value, out: &mut Vec<u8>) {
        self.0.write(head, out);
        self.1.write(tail, out);
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Self::Value, &'a [u8]), DerError> {
        let (head, rest) = self.0.read(input)?;
        let (tail, rest) = self.1.read(rest)?;
        Ok(((head, tail), rest))
    }
}

/// SEQUENCE of the given fields, which must use all of its contents.
#[derive(Debug, Clone, Copy)]
pub struct Sequence<F>(pub F)
where
    F: Fields;

impl<F> Syntax for Sequence<F>
where
    F: Fields,
{
    type Value = F::Value;

    fn write(&self, value: &F::Value, out: &mut Vec<u8>) {
        let mut contents = Vec::new();
        self.0.write(value, &mut contents);
        put(out, tag::SEQUENCE, &contents);
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(F::Value, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::SEQUENCE)?;
        Ok((all(&self.0, contents)?, rest))
    }
}

impl<F> Tagged for Sequence<F>
where
    F: Fields,
{
    fn tag(&self) -> u8 {
        tag::SEQUENCE
    }
}

/// The components of a SEQUENCE OF or SET OF, one after the other.
fn read_components<'a, P>(
    component: &P,
    mut contents: &'a [u8],
    mut check: impl FnMut(&'a [u8]) -> Result<(), DerError>,
) -> Result<Vec<P::Value>, DerError>
where
    P: Syntax,
{
    let mut values = Vec::new();
    while !contents.is_empty() {
        let (value, rest) = component.read(contents)?;
        let used = contents
            .len()
            .checked_sub(rest.len())
            .ok_or(DerError::UnexpectedEnd)?;
        check(contents.get(..used).ok_or(DerError::UnexpectedEnd)?)?;
        values.push(value);
        contents = rest;
    }
    Ok(values)
}

/// SEQUENCE OF: the components in order.
#[derive(Debug, Clone, Copy)]
pub struct SequenceOf<P>(pub P)
where
    P: Syntax;

impl<P> Syntax for SequenceOf<P>
where
    P: Syntax,
{
    type Value = Vec<P::Value>;

    fn write(&self, value: &Vec<P::Value>, out: &mut Vec<u8>) {
        let mut contents = Vec::new();
        for v in value {
            self.0.write(v, &mut contents);
        }
        put(out, tag::SEQUENCE, &contents);
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Vec<P::Value>, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::SEQUENCE)?;
        Ok((read_components(&self.0, contents, |_| Ok(()))?, rest))
    }
}

impl<P> Tagged for SequenceOf<P>
where
    P: Syntax,
{
    fn tag(&self) -> u8 {
        tag::SEQUENCE
    }
}

/// SET OF: a multiset, written in ascending order of the components'
/// encodings, and read only in that order (X.690 11.6). X.690 compares the
/// encodings "as octet strings with the shorter components being padded at
/// their trailing end with 0-octets"; no encoding is a proper prefix of
/// another (the law makes them a prefix code), so that order is the
/// lexicographic order of byte strings. Equal components may repeat.
///
/// The value is the components in that order: reading what was written from
/// any order gives the sorted order, the canonical representative of the
/// multiset.
#[derive(Debug, Clone, Copy)]
pub struct SetOf<P>(pub P)
where
    P: Syntax;

impl<P> Syntax for SetOf<P>
where
    P: Syntax,
{
    type Value = Vec<P::Value>;

    fn write(&self, value: &Vec<P::Value>, out: &mut Vec<u8>) {
        let mut encodings: Vec<Vec<u8>> =
            value.iter().map(|v| encode(&self.0, v)).collect();
        encodings.sort();
        put(out, tag::SET, &encodings.concat());
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Vec<P::Value>, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, tag::SET)?;
        let mut previous: Option<&[u8]> = None;
        let values = read_components(&self.0, contents, |encoding| {
            if previous.is_some_and(|p| p > encoding) {
                return Err(DerError::UnsortedSet);
            }
            previous = Some(encoding);
            Ok(())
        })?;
        Ok((values, rest))
    }
}

impl<P> Tagged for SetOf<P>
where
    P: Syntax,
{
    fn tag(&self) -> u8 {
        tag::SET
    }
}

// --- Tags -------------------------------------------------------------------

/// `[N] EXPLICIT`: a context-specific constructed TLV around one encoding.
/// The tag number is part of the type, and `N` below 31 (one identifier
/// octet) is checked at compile time: `Explicit::<31, _>` does not build.
#[derive(Debug, Clone, Copy)]
pub struct Explicit<const N: u8, P>(pub P)
where
    P: Syntax;

impl<const N: u8, P> Explicit<N, P>
where
    P: Syntax,
{
    /// The identifier octet, `[N]` context-specific constructed.
    const OCTET: u8 = {
        assert!(N < 31, "a tag number below 31");
        tag::context_constructed(N)
    };
}

impl<const N: u8, P> Syntax for Explicit<N, P>
where
    P: Syntax,
{
    type Value = P::Value;

    fn write(&self, value: &P::Value, out: &mut Vec<u8>) {
        put(out, Self::OCTET, &encode(&self.0, value));
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(P::Value, &'a [u8]), DerError> {
        let (contents, rest) = expect(input, Self::OCTET)?;
        Ok((decode(&self.0, contents)?, rest))
    }
}

impl<const N: u8, P> Tagged for Explicit<N, P>
where
    P: Syntax,
{
    fn tag(&self) -> u8 {
        Self::OCTET
    }
}

/// `[N] IMPLICIT`: the inner encoding with its identifier octet replaced by
/// the context-specific one, keeping the primitive or constructed bit. `N`
/// below 31 is checked at compile time.
#[derive(Debug, Clone, Copy)]
pub struct Implicit<const N: u8, P>(pub P)
where
    P: Tagged;

impl<const N: u8, P> Implicit<N, P>
where
    P: Tagged,
{
    /// The identifier octet `[N]` context-specific, without the constructed
    /// bit.
    const NUMBER: u8 = {
        assert!(N < 31, "a tag number below 31");
        tag::context(N)
    };

    /// The identifier octet: `[N]`, constructed when the inner encoding is.
    fn octet(&self) -> u8 {
        Self::NUMBER | (self.0.tag() & 0x20)
    }
}

impl<const N: u8, P> Syntax for Implicit<N, P>
where
    P: Tagged,
{
    type Value = P::Value;

    fn write(&self, value: &P::Value, out: &mut Vec<u8>) {
        let mut encoding = encode(&self.0, value);
        if let Some(first) = encoding.first_mut() {
            *first = self.octet();
        }
        out.extend(encoding);
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(P::Value, &'a [u8]), DerError> {
        let (tlv, used) = parse_tlv(input)?;
        if tlv.octet() != self.octet() {
            return Err(DerError::UnexpectedTag {
                expected: self.octet(),
                found: tlv.octet(),
            });
        }
        let mut retagged = tlv.encoded.to_vec();
        if let Some(first) = retagged.first_mut() {
            *first = self.0.tag();
        }
        let value = decode(&self.0, &retagged)?;
        let rest = input.get(used..).ok_or(DerError::UnexpectedEnd)?;
        Ok((value, rest))
    }
}

impl<const N: u8, P> Tagged for Implicit<N, P>
where
    P: Tagged,
{
    fn tag(&self) -> u8 {
        self.octet()
    }
}

// --- Optional, default, choice ----------------------------------------------

/// OPTIONAL: present when the next identifier octet is the field's.
#[derive(Debug, Clone, Copy)]
pub struct Optional<P>(pub P)
where
    P: Tagged;

impl<P> Syntax for Optional<P>
where
    P: Tagged,
{
    type Value = Option<P::Value>;

    fn write(&self, value: &Option<P::Value>, out: &mut Vec<u8>) {
        if let Some(v) = value {
            self.0.write(v, out);
        }
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Option<P::Value>, &'a [u8]), DerError> {
        if input.first() == Some(&self.0.tag()) {
            let (v, rest) = self.0.read(input)?;
            Ok((Some(v), rest))
        } else {
            Ok((None, input))
        }
    }
}

/// OPTIONAL in last position, for a field with no fixed tag (`ANY
/// OPTIONAL`, as the parameters of an AlgorithmIdentifier): present exactly
/// when bytes remain. The law holds when nothing follows it, so it is only
/// for the last field of a [`Sequence`], which must use all its contents.
#[derive(Debug, Clone, Copy)]
pub struct OptionalLast<P>(pub P)
where
    P: Syntax;

impl<P> Syntax for OptionalLast<P>
where
    P: Syntax,
{
    type Value = Option<P::Value>;

    fn write(&self, value: &Option<P::Value>, out: &mut Vec<u8>) {
        if let Some(v) = value {
            self.0.write(v, out);
        }
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Option<P::Value>, &'a [u8]), DerError> {
        if input.is_empty() {
            return Ok((None, input));
        }
        let (v, rest) = self.0.read(input)?;
        Ok((Some(v), rest))
    }
}

/// DEFAULT: absent when the value is the default, which DER does not encode
/// (X.690 11.5); an encoded default is rejected as
/// [`DerError::ExplicitDefault`].
#[derive(Debug, Clone)]
pub struct WithDefault<P>
where
    P: Tagged,
{
    inner: P,
    default: P::Value,
}

impl<P> WithDefault<P>
where
    P: Tagged,
{
    /// `inner DEFAULT default`.
    #[must_use]
    pub fn new(inner: P, default: P::Value) -> Self {
        WithDefault { inner, default }
    }
}

impl<P> Syntax for WithDefault<P>
where
    P: Tagged,
    P::Value: PartialEq + Clone,
{
    type Value = P::Value;

    fn write(&self, value: &P::Value, out: &mut Vec<u8>) {
        if *value != self.default {
            self.inner.write(value, out);
        }
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(P::Value, &'a [u8]), DerError> {
        if input.first() != Some(&self.inner.tag()) {
            return Ok((self.default.clone(), input));
        }
        let (v, rest) = self.inner.read(input)?;
        if v == self.default {
            return Err(DerError::ExplicitDefault);
        }
        Ok((v, rest))
    }
}

/// A value of one of two types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Either<A, B> {
    /// The first alternative.
    First(A),
    /// The second alternative.
    Second(B),
}

/// CHOICE between two alternatives with different tags, decided by the next
/// identifier octet.
#[derive(Debug, Clone, Copy)]
pub struct Choice<A, B>
where
    A: Tagged,
    B: Tagged,
{
    first: A,
    second: B,
}

impl<A, B> Choice<A, B>
where
    A: Tagged,
    B: Tagged,
{
    /// The choice, or `None` when the two tags are equal (the encoding
    /// would not say which alternative it is).
    #[must_use]
    pub fn new_opt(first: A, second: B) -> Option<Self> {
        (first.tag() != second.tag()).then_some(Choice { first, second })
    }
}

impl<A, B> Syntax for Choice<A, B>
where
    A: Tagged,
    B: Tagged,
{
    type Value = Either<A::Value, B::Value>;

    fn write(&self, value: &Self::Value, out: &mut Vec<u8>) {
        match value {
            Either::First(a) => self.first.write(a, out),
            Either::Second(b) => self.second.write(b, out),
        }
    }

    fn read<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Self::Value, &'a [u8]), DerError> {
        let octet = *input.first().ok_or(DerError::UnexpectedEnd)?;
        if octet == self.first.tag() {
            let (a, rest) = self.first.read(input)?;
            Ok((Either::First(a), rest))
        } else {
            let (b, rest) = self.second.read(input)?;
            Ok((Either::Second(b), rest))
        }
    }
}

// --- Refinements ------------------------------------------------------------

/// A fixed value, such as a version number or an algorithm identifier:
/// written always, and any other value is rejected as
/// [`DerError::UnexpectedValue`].
#[derive(Debug, Clone)]
pub struct Constant<P>
where
    P: Syntax,
{
    inner: P,
    value: P::Value,
}

impl<P> Constant<P>
where
    P: Syntax,
{
    /// The constant `value` of `inner`.
    #[must_use]
    pub fn new(inner: P, value: P::Value) -> Self {
        Constant { inner, value }
    }
}

impl<P> Syntax for Constant<P>
where
    P: Syntax,
    P::Value: PartialEq,
{
    type Value = ();

    fn write(&self, (): &(), out: &mut Vec<u8>) {
        self.inner.write(&self.value, out);
    }

    fn read<'a>(&self, input: &'a [u8]) -> Result<((), &'a [u8]), DerError> {
        let (v, rest) = self.inner.read(input)?;
        if v == self.value {
            Ok(((), rest))
        } else {
            Err(DerError::UnexpectedValue)
        }
    }
}

impl<P> Tagged for Constant<P>
where
    P: Tagged,
    P::Value: PartialEq,
{
    fn tag(&self) -> u8 {
        self.inner.tag()
    }
}

/// A refinement of `inner` onto a domain type `T`, through a partial
/// isomorphism: `forward` may reject, as [`DerError::UnexpectedValue`].
/// The law holds when `forward(backward(t)) = Some(t)` for every `t`, and
/// `forward(x) = Some(t)` implies `backward(t) = x`.
pub struct Map<P, T>
where
    P: Syntax,
{
    inner: P,
    forward: fn(P::Value) -> Option<T>,
    backward: fn(&T) -> P::Value,
}

impl<P, T> Map<P, T>
where
    P: Syntax,
{
    /// `inner`, seen through `forward` and `backward`.
    #[must_use]
    pub fn new(
        inner: P,
        forward: fn(P::Value) -> Option<T>,
        backward: fn(&T) -> P::Value,
    ) -> Self {
        Map {
            inner,
            forward,
            backward,
        }
    }
}

impl<P, T> Syntax for Map<P, T>
where
    P: Syntax,
{
    type Value = T;

    fn write(&self, value: &T, out: &mut Vec<u8>) {
        self.inner.write(&(self.backward)(value), out);
    }

    fn read<'a>(&self, input: &'a [u8]) -> Result<(T, &'a [u8]), DerError> {
        let (v, rest) = self.inner.read(input)?;
        let t = (self.forward)(v).ok_or(DerError::UnexpectedValue)?;
        Ok((t, rest))
    }
}

impl<P, T> Tagged for Map<P, T>
where
    P: Tagged,
{
    fn tag(&self) -> u8 {
        self.inner.tag()
    }
}

#[cfg(any(test, feature = "laws"))]
pub mod laws;
#[cfg(test)]
mod tests;
