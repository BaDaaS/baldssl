//! A minimal, strict DER reader ([ITU-T X.690][x690], section 10).
//!
//! # ASN.1, BER and DER
//!
//! ASN.1 ([X.680][x680]) describes data abstractly: types such as INTEGER,
//! OCTET STRING, OBJECT IDENTIFIER, SEQUENCE. Certificates and keys are
//! defined in it ([RFC 5280 section 4.1][rfc5280], [RFC 5208 section
//! 5][rfc5208]). ASN.1 says nothing about bytes;
//! *encoding rules* do, and X.690 defines three of them:
//!
//! - **BER**, the Basic Encoding Rules (clause 8): the general rules. They
//!   leave the encoder choices, so one value has many encodings: a length
//!   written in the short or the long form, with leading zero octets or
//!   not; a constructed value with a definite length or an *indefinite* one
//!   ended by two zero octets; TRUE as any nonzero octet; a string split
//!   into pieces.
//! - **DER**, the Distinguished Encoding Rules (clause 10): "the basic
//!   encoding described in clause 8, together with the following
//!   restrictions and those also listed in clause 11", which remove every
//!   choice. The length is definite and "encoded in the minimum number of
//!   octets" (10.1), TRUE is `FF` (11.1), strings are primitive, the
//!   unused bits of a BIT STRING are zero, SET OF elements are sorted. So a
//!   value has exactly one DER encoding, and DER is what is signed: two
//!   parties hashing the same certificate must hash the same bytes.
//! - CER, the Canonical Encoding Rules (clause 9), another restriction of
//!   BER (indefinite lengths), not used for certificates and not
//!   implemented here.
//!
//! Every DER encoding is a valid BER encoding, not the converse.
//!
//! # TLV: tag, length, value
//!
//! Every BER value, so every DER value, is a *TLV* (X.690, 8.1): three
//! fields in order.
//!
//! - **T**, the identifier octets (8.1.2): the class (universal, application,
//!   context-specific, private, two bits), whether the value is primitive or
//!   constructed (one bit), and the tag number (five bits; 31 means the
//!   number follows in base-128 octets). INTEGER is `02`, OCTET STRING `04`,
//!   OBJECT IDENTIFIER `06`, SEQUENCE `30` (constructed tag 16).
//! - **L**, the length octets (8.1.3): the number of contents octets. Below
//!   128, one octet (the short form); otherwise `80 + n` followed by `n`
//!   octets **big-endian** (the long form). `80` alone is the indefinite
//!   form, which DER forbids.
//! - **V**, the contents octets (8.1.4): for a primitive value its bytes; for
//!   a constructed one the concatenation of the TLVs of its components.
//!
//! For example, INTEGER 5 is `02 01 05`, and the SEQUENCE holding it and
//! OCTET STRING `"hi"` is `30 07 02 01 05 04 02 68 69`. BER would also
//! accept `30 81 07 ...` (a long-form length of 7); DER does not.
//!
//! # Why strict
//!
//! DER is BER with every choice removed, so each value has exactly one
//! encoding. This reader rejects what BER allows and DER forbids:
//! indefinite lengths, non-minimal long-form lengths, non-minimal tag numbers,
//! non-minimal INTEGERs, BOOLEANs other than `00`/`FF`, non-zero BIT STRING
//! padding and non-minimal OID sub-identifiers. Accepting such encodings is
//! how signature checks get bypassed. In BERserk ([CVE-2014-1568][cve]),
//! Mozilla NSS (Network Security Services), in the words of the National
//! Vulnerability Database, "does not properly parse ASN.1 values in X.509
//! certificates, which makes it easier for remote attackers to spoof RSA
//! signatures via a crafted certificate, aka a 'signature malleability'
//! issue" (double quotes in the original).
//!
//! # Structure
//!
//! A DER stream is a word over the alphabet of TLVs. Each TLV is
//! self-delimiting (its header determines its length), so the set of encoded
//! TLVs is a prefix code and every byte string has at most one factorisation
//! into TLVs. [`Reader`] computes that factorisation one TLV at a time.
//!
//! [x690]: https://www.itu.int/rec/T-REC-X.690
//! [x680]: https://www.itu.int/rec/T-REC-X.680
//! [rfc5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
//! [rfc5208]: https://www.rfc-editor.org/rfc/rfc5208#section-5
//! [cve]: https://nvd.nist.gov/vuln/detail/CVE-2014-1568

pub mod syntax;
pub mod write;

use core::fmt::Write as _;

use self::{
    civil::{
        CENTURY, CENTURY_BUT_ONE_DAY, DAYS_PER_ERA, DAYS_PER_FIVE_MONTHS,
        DAYS_PER_YEAR, END_OF_9999, EPOCH_FROM_ERA_START, ERA_LAST_DAY,
        FIVE_MONTHS, FOUR_YEARS_BUT_ONE_DAY, LEAP_EVERY, MARCH, MONTH_OFFSET,
        MONTHS_PER_YEAR, SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE,
        YEARS_PER_ERA,
    },
    syntax::RawTlv,
};

use crate::{
    Error,
    num::{u8_to_u32, u32_to_usize},
};

/// Why a DER encoding was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    /// The input ended inside a TLV.
    UnexpectedEnd,
    /// The `0x80` indefinite length, which DER forbids.
    IndefiniteLength,
    /// A long-form length that could have been shorter.
    NonMinimalLength,
    /// A long-form length of more octets than a `usize` has (8 on 64-bit
    /// targets, 4 on 32-bit ones).
    LengthTooLarge,
    /// A high tag number that is not minimally encoded.
    NonMinimalTag,
    /// A tag other than the one the grammar requires here.
    UnexpectedTag {
        /// Expected identifier octet.
        expected: u8,
        /// The identifier octet found, `None` for a high tag number (31 and
        /// above), which takes more than one octet.
        found: Option<u8>,
    },
    /// Bytes remain after the last expected element.
    TrailingData,
    /// An INTEGER that is empty or not minimally encoded.
    InvalidInteger,
    /// A BOOLEAN that is not `00` or `FF`.
    InvalidBoolean,
    /// A NULL with contents.
    InvalidNull,
    /// A BIT STRING with bad or non-zero padding.
    InvalidBitString,
    /// A malformed OBJECT IDENTIFIER.
    InvalidOid,
    /// A malformed UTCTime or GeneralizedTime.
    InvalidTime,
    /// SET OF components not in ascending order of their encodings (X.690
    /// 11.6).
    UnsortedSet,
    /// A component encoded with its DEFAULT value, which DER omits (X.690
    /// 11.5).
    ExplicitDefault,
    /// A well-formed encoding of a value outside the type described: a
    /// negative INTEGER where a natural number is expected, another constant,
    /// a value a mapping rejects.
    UnexpectedValue,
}

/// Bits 8 and 7 of the identifier octet: the class ([X.690] 8.1.2.2,
/// Table 1).
///
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
const CLASS_BITS: u8 = 0xc0;
/// The universal class, `00` in bits 8 and 7 (X.690 Table 1).
const UNIVERSAL_CLASS: u8 = 0x00;
/// The application class, `01` in bits 8 and 7 (X.690 Table 1).
const APPLICATION_CLASS: u8 = 0x40;
/// The context-specific class, `10` in bits 8 and 7 (X.690 Table 1).
const CONTEXT_SPECIFIC_CLASS: u8 = 0x80;
/// The private class, `11` in bits 8 and 7 (X.690 Table 1).
const PRIVATE_CLASS: u8 = 0xc0;
/// Bit 6 of the identifier octet: one for a constructed encoding, zero for
/// a primitive one (X.690 8.1.2.5).
pub(crate) const CONSTRUCTED_BIT: u8 = 0x20;
/// Bits 5 to 1 of the identifier octet: the tag number when it is below 31
/// (X.690 8.1.2.2 c), all ones when it follows in subsequent octets
/// (8.1.2.4.1 c).
pub(crate) const TAG_NUMBER_BITS: u8 = 0x1f;
/// The first tag number written in the high-tag-number form, in octets
/// after the first (X.690 8.1.2.4); 0 to 30 fit in the first (8.1.2.3).
pub(crate) const FIRST_HIGH_TAG_NUMBER: u8 = 31;
/// Bit 8 of an octet of a base-128 number, one on every octet but the last:
/// a high tag number (X.690 8.1.2.4.2 a) and the subidentifiers of an
/// OBJECT IDENTIFIER (8.19.2).
pub(crate) const MORE_OCTETS: u8 = 0x80;
/// Bits 7 to 1 of an octet of a base-128 number: its digit (X.690 8.1.2.4.2
/// b, 8.19.2).
pub(crate) const BASE_128_DIGIT: u8 = 0x7f;
/// The base of high tag numbers and subidentifiers (X.690 8.1.2.4.2,
/// 8.19.2).
const BASE_128: u32 = 128;
/// Bit 8 of the first length octet: zero for the short form, a length below
/// 128 in bits 7 to 1 (X.690 8.1.3.4); one for the long form (8.1.3.5 a).
/// The octet `80` alone is the indefinite form (8.1.3.6.1), which DER
/// forbids (10.1).
pub(crate) const LONG_FORM: u8 = 0x80;
/// Bits 7 to 1 of the first length octet in the long form: how many length
/// octets follow (X.690 8.1.3.5 b).
const LENGTH_OCTETS_BITS: u8 = 0x7f;
/// The smallest length the long form writes: shorter ones take the short
/// form, as DER's minimal length requires (X.690 8.1.3.4, 10.1).
pub(crate) const FIRST_LONG_LENGTH: usize = 0x80;
/// The base of the long form's length octets, its big-endian digits (X.690
/// 8.1.3.5 c).
const OCTET_BASE: usize = 256;
/// The most length octets read or written: those of a `usize`, 8 on 64-bit
/// targets and 4 on 32-bit ones. Every length a writer gives fits, and so
/// does the length of every contents that can be in memory; X.690 allows up
/// to 126 (8.1.3.5 c).
pub(crate) const MAX_LENGTH_OCTETS: usize = core::mem::size_of::<usize>();
/// Bit 8 of the first contents octet of an INTEGER, its two's complement
/// sign (X.690 8.3.3).
pub(crate) const SIGN_BIT: u8 = 0x80;
/// The first two arcs `X.Y` of an OBJECT IDENTIFIER share one
/// subidentifier, `40 X + Y`, with `Y` below 40 when `X` is 0 or 1 (X.690
/// 8.19.4).
pub(crate) const ARCS_PER_FIRST_ARC: u128 = 40;

/// The tag class (bits 8-7 of the identifier octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// `00`
    Universal,
    /// `01`
    Application,
    /// `10`
    ContextSpecific,
    /// `11`
    Private,
}

/// Whether an encoding is primitive or constructed (bit 6 of the identifier
/// octet, X.690 8.1.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Form {
    /// The contents are the value's octets.
    Primitive,
    /// The contents are the encodings of other values.
    Constructed,
}

/// A decoded identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tag {
    /// The class.
    pub class: Class,
    /// Primitive or constructed.
    pub form: Form,
    /// The tag number.
    pub number: u32,
}

impl Tag {
    /// The single identifier octet for low tag numbers, `None` for tag
    /// numbers of 31 and above.
    #[must_use]
    pub(crate) fn octet_opt(self) -> Option<u8> {
        let class = match self.class {
            Class::Universal => UNIVERSAL_CLASS,
            Class::Application => APPLICATION_CLASS,
            Class::ContextSpecific => CONTEXT_SPECIFIC_CLASS,
            Class::Private => PRIVATE_CLASS,
        };
        let form = match self.form {
            Form::Primitive => 0,
            Form::Constructed => CONSTRUCTED_BIT,
        };
        let n = u8::try_from(self.number)
            .ok()
            .filter(|&n| n < FIRST_HIGH_TAG_NUMBER)?;
        Some(class | form | n)
    }

    /// The tag with this low-form identifier octet.
    #[must_use]
    pub(crate) const fn from_octet(b: u8) -> Self {
        let class = match b & CLASS_BITS {
            UNIVERSAL_CLASS => Class::Universal,
            APPLICATION_CLASS => Class::Application,
            CONTEXT_SPECIFIC_CLASS => Class::ContextSpecific,
            _ => Class::Private,
        };
        let form = if b & CONSTRUCTED_BIT == 0 {
            Form::Primitive
        } else {
            Form::Constructed
        };
        Tag {
            class,
            form,
            number: u8_to_u32(b & TAG_NUMBER_BITS),
        }
    }
}

/// The identifier octet `first` when it is the whole identifier, `None`
/// when a high tag number follows it (X.690 8.1.2.4).
const fn low_octet_opt(first: u8) -> Option<u8> {
    if first & TAG_NUMBER_BITS == TAG_NUMBER_BITS {
        None
    } else {
        Some(first)
    }
}

/// Universal identifier octets used by X.509.
pub mod tag {
    use super::{CONSTRUCTED_BIT, CONTEXT_SPECIFIC_CLASS, TAG_NUMBER_BITS};

    /// BOOLEAN
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER
    pub const OID: u8 = 0x06;
    /// UTF8String
    pub const UTF8_STRING: u8 = 0x0c;
    /// NumericString
    pub const NUMERIC_STRING: u8 = 0x12;
    /// PrintableString
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// T61String (TeletexString)
    pub const T61_STRING: u8 = 0x14;
    /// IA5String
    pub const IA5_STRING: u8 = 0x16;
    /// UTCTime
    pub const UTC_TIME: u8 = 0x17;
    /// GeneralizedTime
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// VisibleString
    pub const VISIBLE_STRING: u8 = 0x1a;
    /// UniversalString
    pub const UNIVERSAL_STRING: u8 = 0x1c;
    /// BMPString
    pub const BMP_STRING: u8 = 0x1e;
    /// SEQUENCE / SEQUENCE OF
    pub const SEQUENCE: u8 = 0x30;
    /// SET / SET OF
    pub const SET: u8 = 0x31;

    /// `[n]` context-specific primitive (IMPLICIT on a primitive type).
    #[must_use]
    pub const fn context(n: u8) -> u8 {
        CONTEXT_SPECIFIC_CLASS | (n & TAG_NUMBER_BITS)
    }

    /// `[n]` context-specific constructed (EXPLICIT, or IMPLICIT on a
    /// constructed type).
    #[must_use]
    pub const fn context_constructed(n: u8) -> u8 {
        context(n) | CONSTRUCTED_BIT
    }
}

/// One tag-length-value element, a view of the input it was parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The identifier.
    pub(crate) tag: Tag,
    /// The contents octets.
    value: &'a [u8],
    /// The whole element: identifier, length and contents.
    encoded: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// The one identifier octet, `None` for a high tag number (31 and
    /// above), whose identifier takes more octets.
    #[must_use]
    pub fn octet_opt(&self) -> Option<u8> {
        self.tag.octet_opt()
    }

    /// The contents octets.
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The whole element: identifier, length and contents.
    #[must_use]
    pub fn encoded(&self) -> &'a [u8] {
        self.encoded
    }
}

fn read_tag(data: &[u8]) -> Result<(Tag, usize), DerError> {
    let first = *data.first().ok_or(DerError::UnexpectedEnd)?;
    let low = Tag::from_octet(first);
    if low_octet_opt(first).is_some() {
        return Ok((low, 1));
    }
    let mut number: u32 = 0;
    let mut i = 1usize;
    loop {
        let b = *data.get(i).ok_or(DerError::UnexpectedEnd)?;
        if i == 1 && b == MORE_OCTETS {
            return Err(DerError::NonMinimalTag);
        }
        number = number
            .checked_mul(BASE_128)
            .and_then(|n| n.checked_add(u32::from(b & BASE_128_DIGIT)))
            .ok_or(DerError::NonMinimalTag)?;
        i = i.checked_add(1).ok_or(DerError::UnexpectedEnd)?;
        if b & MORE_OCTETS == 0 {
            break;
        }
    }
    if number < u32::from(FIRST_HIGH_TAG_NUMBER) {
        return Err(DerError::NonMinimalTag);
    }
    Ok((Tag { number, ..low }, i))
}

fn read_length(data: &[u8]) -> Result<(usize, usize), DerError> {
    let first = *data.first().ok_or(DerError::UnexpectedEnd)?;
    if first & LONG_FORM == 0 {
        return Ok((usize::from(first), 1));
    }
    if first == LONG_FORM {
        return Err(DerError::IndefiniteLength);
    }
    let count = usize::from(first & LENGTH_OCTETS_BITS);
    if count > MAX_LENGTH_OCTETS {
        return Err(DerError::LengthTooLarge);
    }
    let bytes = data.get(1..=count).ok_or(DerError::UnexpectedEnd)?;
    if bytes.first() == Some(&0) {
        return Err(DerError::NonMinimalLength);
    }
    let mut len: usize = 0;
    for &b in bytes {
        // At most MAX_LENGTH_OCTETS base-256 digits, which a usize holds:
        // the checks never fail, and keep the arithmetic total.
        len = len
            .checked_mul(OCTET_BASE)
            .and_then(|l| l.checked_add(usize::from(b)))
            .ok_or(DerError::LengthTooLarge)?;
    }
    if len < FIRST_LONG_LENGTH {
        return Err(DerError::NonMinimalLength);
    }
    Ok((len, count.checked_add(1).ok_or(DerError::LengthTooLarge)?))
}

/// Parses one TLV at the start of `data`; returns it and the bytes consumed.
///
/// # Errors
///
/// Any [`DerError`] of the header, or [`DerError::UnexpectedEnd`] if the
/// contents run past the input.
pub fn parse_tlv(data: &[u8]) -> Result<(Tlv<'_>, usize), DerError> {
    let (tag, tag_len) = read_tag(data)?;
    let rest = data.get(tag_len..).ok_or(DerError::UnexpectedEnd)?;
    let (len, len_len) = read_length(rest)?;
    let header = tag_len
        .checked_add(len_len)
        .ok_or(DerError::UnexpectedEnd)?;
    let total = header.checked_add(len).ok_or(DerError::UnexpectedEnd)?;
    let value = data.get(header..total).ok_or(DerError::UnexpectedEnd)?;
    let encoded = data.get(..total).ok_or(DerError::UnexpectedEnd)?;
    Ok((
        Tlv {
            tag,
            value,
            encoded,
        },
        total,
    ))
}

/// `bytes` without its leading zero octets: the big-endian digits of the
/// same natural number, the empty string for zero.
pub(crate) fn strip_leading_zeros(mut bytes: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

/// A cursor over a concatenation of TLVs.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    /// Whether every byte has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Reads the next TLV, whatever its tag.
    ///
    /// # Errors
    ///
    /// See [`parse_tlv`].
    pub fn read(&mut self) -> Result<Tlv<'a>, DerError> {
        let (tlv, used) = parse_tlv(self.data)?;
        self.data = self.data.get(used..).ok_or(DerError::UnexpectedEnd)?;
        Ok(tlv)
    }

    /// The identifier octet of the next TLV, if any.
    #[must_use]
    pub fn peek_octet_opt(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads the next TLV and checks its identifier octet, `octet`, one of
    /// a low tag number (below 31).
    ///
    /// # Errors
    ///
    /// [`DerError::UnexpectedTag`] on a mismatch.
    pub fn expect(&mut self, octet: u8) -> Result<Tlv<'a>, DerError> {
        let first = self.peek_octet_opt().ok_or(DerError::UnexpectedEnd)?;
        if first != octet {
            return Err(DerError::UnexpectedTag {
                expected: octet,
                found: low_octet_opt(first),
            });
        }
        self.read()
    }

    /// Reads the next TLV if its identifier octet is `octet`.
    ///
    /// # Errors
    ///
    /// See [`parse_tlv`].
    pub fn optional(&mut self, octet: u8) -> Result<Option<Tlv<'a>>, DerError> {
        if self.peek_octet_opt() == Some(octet) {
            self.read().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Reads a SEQUENCE and returns a reader over its contents.
    ///
    /// # Errors
    ///
    /// See [`Reader::expect`].
    pub fn sequence(&mut self) -> Result<Reader<'a>, DerError> {
        Ok(Reader::new(self.expect(tag::SEQUENCE)?.value()))
    }

    /// Checks that nothing is left.
    ///
    /// # Errors
    ///
    /// [`DerError::TrailingData`] otherwise.
    pub fn finish(&self) -> Result<(), DerError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(DerError::TrailingData)
        }
    }

    /// Reads one value of the syntax description `syntax` at the reader's
    /// position, and moves past its encoding.
    ///
    /// # Errors
    ///
    /// What `syntax` rejects.
    pub fn syntax<S>(&mut self, syntax: &S) -> Result<S::Value, DerError>
    where
        S: syntax::Syntax,
    {
        let (value, rest) = syntax.read(self.data)?;
        self.data = rest;
        Ok(value)
    }
}

/// A decoded INTEGER: a sign and the big-endian magnitude without leading
/// zero bytes (empty for zero, which is never negative). Built only by
/// [`Integer::parse`], [`Integer::from_sign_magnitude`] and `From<i64>`, so
/// equal numbers are equal values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integer {
    /// Strictly negative.
    negative: bool,
    /// `|value|`, big-endian, no leading zeros.
    magnitude: Vec<u8>,
}

impl Integer {
    /// The INTEGER with this sign and big-endian magnitude: leading zero
    /// octets are dropped, and zero is not negative. Total.
    #[must_use]
    pub fn from_sign_magnitude(negative: bool, magnitude: &[u8]) -> Self {
        let magnitude = strip_leading_zeros(magnitude).to_vec();
        Integer {
            negative: negative && !magnitude.is_empty(),
            magnitude,
        }
    }

    /// Decodes INTEGER contents (two's complement, minimal).
    ///
    /// # Errors
    ///
    /// [`DerError::InvalidInteger`] if empty or non-minimal.
    pub fn parse(value: &[u8]) -> Result<Self, DerError> {
        match value {
            [] => return Err(DerError::InvalidInteger),
            [0x00, next, ..] if next & SIGN_BIT == 0 => {
                return Err(DerError::InvalidInteger);
            }
            [0xff, next, ..] if next & SIGN_BIT != 0 => {
                return Err(DerError::InvalidInteger);
            }
            _ => {}
        }
        let negative = value.first().is_some_and(|b| b & SIGN_BIT != 0);
        let mut magnitude = value.to_vec();
        if negative {
            // |x| = !x + 1 over the two's-complement bytes.
            let mut carry = true;
            for b in magnitude.iter_mut().rev() {
                let (v, c) = (!*b).overflowing_add(u8::from(carry));
                *b = v;
                carry = c;
            }
        }
        Ok(Integer::from_sign_magnitude(negative, &magnitude))
    }

    /// Whether the value is strictly negative.
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// `|value|`, big-endian, without leading zeros: empty for zero.
    #[must_use]
    pub fn magnitude(&self) -> &[u8] {
        &self.magnitude
    }

    /// Number of significant bits of the magnitude.
    #[must_use]
    pub fn bits(&self) -> usize {
        match self.magnitude.first() {
            None => 0,
            Some(&top) => {
                let top_bits =
                    8usize.saturating_sub(u32_to_usize(top.leading_zeros()));
                self.magnitude
                    .len()
                    .saturating_sub(1)
                    .saturating_mul(8)
                    .saturating_add(top_bits)
            }
        }
    }

    /// The value as `u64` when non-negative and small enough.
    #[must_use]
    pub fn to_u64_opt(&self) -> Option<u64> {
        if self.negative || self.magnitude.len() > 8 {
            return None;
        }
        Some(
            self.magnitude
                .iter()
                .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)),
        )
    }

    /// The value as `i64` when it fits, either sign.
    #[must_use]
    pub fn to_i64_opt(&self) -> Option<i64> {
        if self.magnitude.len() > 8 {
            return None;
        }
        let m = self
            .magnitude
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        if self.negative {
            // -2^63 is the one value whose magnitude is not an i64.
            0i64.checked_sub_unsigned(m)
        } else {
            i64::try_from(m).ok()
        }
    }

    /// The magnitude as `u128` when it fits.
    #[must_use]
    pub fn magnitude_u128_opt(&self) -> Option<u128> {
        if self.magnitude.len() > 16 {
            return None;
        }
        Some(
            self.magnitude
                .iter()
                .fold(0u128, |acc, &b| (acc << 8) | u128::from(b)),
        )
    }
}

impl From<i64> for Integer {
    /// The INTEGER with value `v`: its sign, and its magnitude without
    /// leading zeros. [`Integer::to_i64_opt`] is the inverse.
    fn from(v: i64) -> Self {
        Integer::from_sign_magnitude(v < 0, &v.unsigned_abs().to_be_bytes())
    }
}

/// Decodes BOOLEAN contents.
///
/// # Errors
///
/// [`DerError::InvalidBoolean`] unless the contents are `00` or `FF`.
pub fn parse_bool(value: &[u8]) -> Result<bool, DerError> {
    match value {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(DerError::InvalidBoolean),
    }
}

/// Decodes NULL contents.
///
/// # Errors
///
/// [`DerError::InvalidNull`] if not empty.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the NULL parameters of an RSA AlgorithmIdentifier; tested"
    )
)]
pub(crate) fn parse_null(value: &[u8]) -> Result<(), DerError> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(DerError::InvalidNull)
    }
}

/// A decoded BIT STRING, built only by [`BitString::parse`] and
/// [`BitString::from_bytes`], so its padding is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitString<'a> {
    /// Number of unused bits in the last byte (0 to 7).
    unused: u8,
    /// The bytes, unused bits zero.
    bytes: &'a [u8],
}

impl<'a> BitString<'a> {
    /// Decodes BIT STRING contents.
    ///
    /// # Errors
    ///
    /// [`DerError::InvalidBitString`] on a bad unused-bit count or non-zero
    /// padding.
    pub fn parse(value: &'a [u8]) -> Result<Self, DerError> {
        let (&unused, bytes) =
            value.split_first().ok_or(DerError::InvalidBitString)?;
        if unused > 7 || (bytes.is_empty() && unused != 0) {
            return Err(DerError::InvalidBitString);
        }
        if let Some(&last) = bytes.last() {
            let mask = (1u8 << unused).wrapping_sub(1);
            if last & mask != 0 {
                return Err(DerError::InvalidBitString);
            }
        }
        Ok(BitString { unused, bytes })
    }

    /// The BIT STRING of these whole bytes, no bit unused. Total.
    #[must_use]
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        BitString { unused: 0, bytes }
    }

    /// Number of unused bits in the last byte (0 to 7, 0 when there is no
    /// byte).
    #[must_use]
    pub fn unused(&self) -> u8 {
        self.unused
    }

    /// The bytes, unused bits zero.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Bit `n` in the ASN.1 numbering (bit 0 is the MSB of the first byte).
    #[must_use]
    pub fn bit(&self, n: usize) -> bool {
        let shift = 7usize.saturating_sub(n % 8);
        self.bytes
            .get(n / 8)
            .is_some_and(|&b| (b >> shift) & 1 == 1)
    }
}

/// A validated OBJECT IDENTIFIER, kept in its DER form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oid<'a>(&'a [u8]);

impl<'a> Oid<'a> {
    /// Validates OBJECT IDENTIFIER contents.
    ///
    /// # Errors
    ///
    /// [`DerError::InvalidOid`] when empty, truncated, or a sub-identifier
    /// has a leading `0x80`.
    pub fn parse(value: &'a [u8]) -> Result<Self, DerError> {
        if value.last().is_none_or(|&b| b & MORE_OCTETS != 0) {
            return Err(DerError::InvalidOid);
        }
        let mut start = true;
        for &b in value {
            if start && b == MORE_OCTETS {
                return Err(DerError::InvalidOid);
            }
            start = b & MORE_OCTETS == 0;
        }
        Ok(Oid(value))
    }

    /// The DER contents octets.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The dotted-decimal form, e.g. `2.5.4.3`.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] if an arc is $2^{128}$ or more: parsing bounds
    /// neither the number nor the size of the arcs.
    pub fn to_dotted(&self) -> Result<String, Error> {
        let mut arcs: Vec<u128> = Vec::new();
        let mut acc: u128 = 0;
        for &b in self.0 {
            acc = acc
                .checked_mul(u128::from(BASE_128))
                .map(|a| a | u128::from(b & BASE_128_DIGIT))
                .ok_or_else(|| Error::unsupported("OID arc above 128 bits"))?;
            if b & MORE_OCTETS == 0 {
                arcs.push(acc);
                acc = 0;
            }
        }
        let mut out = String::new();
        for (i, arc) in arcs.iter().enumerate() {
            if i == 0 {
                let (first, second) = match *arc {
                    a if a < ARCS_PER_FIRST_ARC => (0, a),
                    a if a < 2 * ARCS_PER_FIRST_ARC => {
                        (1, a.saturating_sub(ARCS_PER_FIRST_ARC))
                    }
                    a => (2, a.saturating_sub(2 * ARCS_PER_FIRST_ARC)),
                };
                let _ = write!(out, "{first}.{second}");
            } else {
                let _ = write!(out, ".{arc}");
            }
        }
        Ok(out)
    }
}

/// Which ASN.1 time type a [`Time`] was encoded as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeKind {
    /// UTCTime, two-digit year.
    Utc,
    /// GeneralizedTime, four-digit year.
    Generalized,
}

/// A decoded UTCTime or GeneralizedTime (always UTC, `Z`, in DER), built
/// only by [`Time::parse`] and [`Time::from_unix_seconds`], so its fields
/// are a valid date and time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Time {
    /// Encoding used.
    kind: TimeKind,
    /// Full year.
    year: u16,
    /// 1 to 12.
    month: u8,
    /// 1 to 31, valid for the month.
    day: u8,
    /// 0 to 23.
    hour: u8,
    /// 0 to 59.
    minute: u8,
    /// 0 to 59.
    second: u8,
    /// Fraction digits after the `.`, GeneralizedTime only (no trailing
    /// zeros in DER).
    fraction: String,
}

fn digits_opt(s: &[u8]) -> Option<u16> {
    s.iter().try_fold(0u16, |acc, &c| {
        if c.is_ascii_digit() {
            acc.checked_mul(10)?
                .checked_add(u16::from(c.checked_sub(b'0')?))
        } else {
            None
        }
    })
}

fn two(s: &[u8], at: usize) -> Result<u8, DerError> {
    let end = at.checked_add(2).ok_or(DerError::InvalidTime)?;
    let v = digits_opt(s.get(at..end).ok_or(DerError::InvalidTime)?)
        .ok_or(DerError::InvalidTime)?;
    u8::try_from(v).map_err(|_| DerError::InvalidTime)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        2 => {
            let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100))
                || year.is_multiple_of(400);
            if leap { 29 } else { 28 }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The constants of Howard Hinnant's civil calendar algorithms
/// ([`civil_from_days` and `days_from_civil`][hinnant]), which count days in
/// a proleptic Gregorian calendar shifted to start each year on 1 March, so
/// that a leap day ends its year.
///
/// [hinnant]: https://howardhinnant.github.io/date_algorithms.html
mod civil {
    /// Seconds in a day, as POSIX time counts them (no leap seconds).
    pub(super) const SECONDS_PER_DAY: i64 = 86_400;
    /// Seconds in an hour.
    pub(super) const SECONDS_PER_HOUR: i64 = 3_600;
    /// Seconds in a minute.
    pub(super) const SECONDS_PER_MINUTE: i64 = 60;
    /// The last second a four-digit year can write, 9999-12-31T23:59:59Z.
    pub(super) const END_OF_9999: i64 = 253_402_300_799;
    /// Years in an era: the Gregorian calendar repeats every 400 years.
    pub(super) const YEARS_PER_ERA: i64 = 400;
    /// Days in an era: 400 years of 365 days, and 97 leap days.
    pub(super) const DAYS_PER_ERA: i64 = 146_097;
    /// Days in a common year.
    pub(super) const DAYS_PER_YEAR: i64 = 365;
    /// A leap year every four years ...
    pub(super) const LEAP_EVERY: i64 = 4;
    /// ... except at a century ...
    pub(super) const CENTURY: i64 = 100;
    /// Days in four years but the last, after which the era's day count
    /// gains a leap day.
    pub(super) const FOUR_YEARS_BUT_ONE_DAY: i64 = 1_460;
    /// Days in a century but its leap day, after which a century loses one.
    pub(super) const CENTURY_BUT_ONE_DAY: i64 = 36_524;
    /// The era's last day, where the 400-year leap day falls.
    pub(super) const ERA_LAST_DAY: i64 = 146_096;
    /// Days from 0000-03-01, where the shifted calendar starts, to the Unix
    /// epoch, 1970-01-01.
    pub(super) const EPOCH_FROM_ERA_START: i64 = 719_468;
    /// The month formula: from March, every 5 months span 153 days
    /// (31, 30, 31, 30, 31), and an offset of 2 days rounds to the month's
    /// first day.
    pub(super) const DAYS_PER_FIVE_MONTHS: i64 = 153;
    /// See [`DAYS_PER_FIVE_MONTHS`].
    pub(super) const FIVE_MONTHS: i64 = 5;
    /// See [`DAYS_PER_FIVE_MONTHS`].
    pub(super) const MONTH_OFFSET: i64 = 2;
    /// March, the first month of the shifted year.
    pub(super) const MARCH: i64 = 3;
    /// Months in a year.
    pub(super) const MONTHS_PER_YEAR: i64 = 12;
}

/// The first year RFC 5280 writes as a GeneralizedTime rather than a
/// UTCTime ([section 4.1.2.5]).
///
/// [section 4.1.2.5]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
const FIRST_GENERALIZED_YEAR: u16 = 2050;

/// The two-digit UTCTime years below which the year is in the 2000s, from
/// which it is in the 1900s: "Where YY is greater than or equal to 50, the
/// year SHALL be interpreted as 19YY; and Where YY is less than 50, the year
/// SHALL be interpreted as 20YY" ([RFC 5280 section 4.1.2.5.1]).
///
/// [RFC 5280 section 4.1.2.5.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1
const UTC_TIME_PIVOT: u16 = 50;
/// The year of UTCTime's `YY = 00` from [`UTC_TIME_PIVOT`] on.
const UTC_TIME_LATE_CENTURY: u16 = 1900;
/// The year of UTCTime's `YY = 00` below [`UTC_TIME_PIVOT`].
const UTC_TIME_EARLY_CENTURY: u16 = 2000;
/// Years in a century: UTCTime writes the year modulo it.
const YEARS_PER_CENTURY: u16 = 100;

/// The encoding RFC 5280 requires of a certificate's time in `year`
/// ([section 4.1.2.5]).
///
/// [section 4.1.2.5]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
fn rfc5280_kind(year: u16) -> TimeKind {
    if year < FIRST_GENERALIZED_YEAR {
        TimeKind::Utc
    } else {
        TimeKind::Generalized
    }
}

impl Time {
    /// The time `seconds` after the Unix epoch, in the encoding RFC 5280
    /// requires of a certificate ([section 4.1.2.5]): UTCTime through 2049,
    /// GeneralizedTime from 2050, never with a fraction. The date is
    /// Howard Hinnant's [`civil_from_days`].
    ///
    /// [section 4.1.2.5]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
    /// [`civil_from_days`]: https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    ///
    /// Times after the end of 9999 are clamped to it (253402300799 seconds),
    /// the last instant a four-digit year can write.
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "with seconds clamped to the end of 9999, every intermediate \
                  value is below 2^40, so no operation overflows, and the \
                  algorithm's invariants (doe < 146097, yoe < 400, \
                  doy < 366) keep each subtraction non-negative"
    )]
    pub fn from_unix_seconds(seconds: u64) -> Self {
        // A count above i64::MAX is past the end of 9999 too: clamped.
        let seconds =
            i64::try_from(seconds).map_or(END_OF_9999, |s| s.min(END_OF_9999));
        let days = seconds / SECONDS_PER_DAY;
        let rest = seconds % SECONDS_PER_DAY;
        let z = days + EPOCH_FROM_ERA_START;
        let era = z / DAYS_PER_ERA;
        let doe = z % DAYS_PER_ERA;
        let yoe = (doe - doe / FOUR_YEARS_BUT_ONE_DAY
            + doe / CENTURY_BUT_ONE_DAY
            - doe / ERA_LAST_DAY)
            / DAYS_PER_YEAR;
        let doy =
            doe - (DAYS_PER_YEAR * yoe + yoe / LEAP_EVERY - yoe / CENTURY);
        let mp = (FIVE_MONTHS * doy + MONTH_OFFSET) / DAYS_PER_FIVE_MONTHS;
        let day =
            doy - (DAYS_PER_FIVE_MONTHS * mp + MONTH_OFFSET) / FIVE_MONTHS + 1;
        let month = if mp + MARCH <= MONTHS_PER_YEAR {
            mp + MARCH
        } else {
            mp + MARCH - MONTHS_PER_YEAR
        };
        let year = yoe + era * YEARS_PER_ERA + i64::from(month <= 2);
        // The fallbacks are never taken: the algorithm's fields are a month,
        // a day, an hour, a minute and a second of a year from 1970 to 9999.
        let narrow = |v: i64| u8::try_from(v).unwrap_or(u8::MAX);
        let year = u16::try_from(year).unwrap_or(u16::MAX);
        Time {
            kind: rfc5280_kind(year),
            year,
            month: narrow(month),
            day: narrow(day),
            hour: narrow(rest / SECONDS_PER_HOUR),
            minute: narrow(rest % SECONDS_PER_HOUR / SECONDS_PER_MINUTE),
            second: narrow(rest % SECONDS_PER_MINUTE),
            fraction: String::new(),
        }
    }

    /// The same instant in the encoding RFC 5280 requires of a certificate
    /// ([section 4.1.2.5]): UTCTime through 2049, GeneralizedTime from 2050,
    /// without a fraction, which a certificate's time never has
    /// (sections 4.1.2.5.1 and 4.1.2.5.2), so the fraction is dropped.
    ///
    /// [section 4.1.2.5]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
    #[must_use]
    pub fn to_rfc5280(&self) -> Self {
        Time {
            kind: rfc5280_kind(self.year),
            fraction: String::new(),
            ..self.clone()
        }
    }

    /// The encoding the time was read in, or written in.
    #[must_use]
    pub fn kind(&self) -> TimeKind {
        self.kind
    }

    /// The full year, 1950 to 2049 for a UTCTime, 0 to 9999 for a
    /// GeneralizedTime.
    #[must_use]
    pub fn year(&self) -> u16 {
        self.year
    }

    /// The month, 1 to 12.
    #[must_use]
    pub fn month(&self) -> u8 {
        self.month
    }

    /// The day of the month, 1 to its last.
    #[must_use]
    pub fn day(&self) -> u8 {
        self.day
    }

    /// The hour, 0 to 23.
    #[must_use]
    pub fn hour(&self) -> u8 {
        self.hour
    }

    /// The minute, 0 to 59.
    #[must_use]
    pub fn minute(&self) -> u8 {
        self.minute
    }

    /// The second, 0 to 59.
    #[must_use]
    pub fn second(&self) -> u8 {
        self.second
    }

    /// The decimal digits of the fraction of a second, after the `.`, with
    /// no trailing zero: empty when there is none, always for a UTCTime.
    #[must_use]
    pub fn fraction(&self) -> &str {
        &self.fraction
    }

    /// Seconds after the Unix epoch, negative before it: the inverse of
    /// [`Time::from_unix_seconds`] on what it gives (a fraction is
    /// dropped). The date is Howard Hinnant's [`days_from_civil`].
    ///
    /// [`days_from_civil`]: https://howardhinnant.github.io/date_algorithms.html#days_from_civil
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the year is at most 9999 and the other fields are \
                  bounded by parsing, so every value stays far below 2^40"
    )]
    pub fn to_unix_seconds(&self) -> i64 {
        let (month, day) = (i64::from(self.month), i64::from(self.day));
        // Years start on 1 March, so a leap day ends one.
        let year = i64::from(self.year) - i64::from(month <= 2);
        let era = year.div_euclid(YEARS_PER_ERA);
        let yoe = year.rem_euclid(YEARS_PER_ERA);
        let mp = (month + MONTHS_PER_YEAR - MARCH) % MONTHS_PER_YEAR;
        let doy =
            (DAYS_PER_FIVE_MONTHS * mp + MONTH_OFFSET) / FIVE_MONTHS + day - 1;
        let doe = yoe * DAYS_PER_YEAR + yoe / LEAP_EVERY - yoe / CENTURY + doy;
        let days = era * DAYS_PER_ERA + doe - EPOCH_FROM_ERA_START;
        days * SECONDS_PER_DAY
            + i64::from(self.hour) * SECONDS_PER_HOUR
            + i64::from(self.minute) * SECONDS_PER_MINUTE
            + i64::from(self.second)
    }

    /// The DER of the time, one TLV: a UTCTime (`YYMMDDHHMMSSZ`,
    /// [`tag::UTC_TIME`]) or a GeneralizedTime (`YYYYMMDDHHMMSS[.fff]Z`,
    /// [`tag::GENERALIZED_TIME`]), the inverse of [`Time::parse`].
    #[must_use]
    pub fn to_der(&self) -> RawTlv {
        let (tag, mut text) = match self.kind {
            TimeKind::Utc => (
                tag::UTC_TIME,
                format!("{:02}", self.year % YEARS_PER_CENTURY),
            ),
            TimeKind::Generalized => {
                (tag::GENERALIZED_TIME, format!("{:04}", self.year))
            }
        };
        let _ = write!(
            text,
            "{:02}{:02}{:02}{:02}{:02}",
            self.month, self.day, self.hour, self.minute, self.second
        );
        if !self.fraction.is_empty() {
            text.push('.');
            text.push_str(&self.fraction);
        }
        text.push('Z');
        RawTlv::from_tag_and_contents(tag, text.as_bytes())
    }

    /// Decodes a UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime
    /// (`YYYYMMDDHHMMSS[.fff]Z`) in its DER form.
    ///
    /// # Errors
    ///
    /// [`DerError::InvalidTime`] on any deviation from the DER form or an
    /// out-of-range field.
    pub fn parse(kind: TimeKind, value: &[u8]) -> Result<Self, DerError> {
        let body = value.strip_suffix(b"Z").ok_or(DerError::InvalidTime)?;
        let (year, rest) = match kind {
            TimeKind::Utc => {
                let yy = u16::from(two(body, 0)?);
                let century = if yy < UTC_TIME_PIVOT {
                    UTC_TIME_EARLY_CENTURY
                } else {
                    UTC_TIME_LATE_CENTURY
                };
                let year = century.saturating_add(yy);
                (year, body.get(2..).ok_or(DerError::InvalidTime)?)
            }
            TimeKind::Generalized => {
                let year =
                    digits_opt(body.get(..4).ok_or(DerError::InvalidTime)?)
                        .ok_or(DerError::InvalidTime)?;
                (year, body.get(4..).ok_or(DerError::InvalidTime)?)
            }
        };
        let (fixed, fraction) = match kind {
            TimeKind::Utc => (rest, &[][..]),
            TimeKind::Generalized => {
                let mut parts = rest.splitn(2, |&c| c == b'.');
                let fixed = parts.next().ok_or(DerError::InvalidTime)?;
                match parts.next() {
                    None => (fixed, &[][..]),
                    Some(frac) => {
                        if frac.is_empty()
                            || frac.last() == Some(&b'0')
                            || !frac.iter().all(u8::is_ascii_digit)
                        {
                            return Err(DerError::InvalidTime);
                        }
                        (fixed, frac)
                    }
                }
            }
        };
        if fixed.len() != 10 {
            return Err(DerError::InvalidTime);
        }
        let t = Time {
            kind,
            year,
            month: two(fixed, 0)?,
            day: two(fixed, 2)?,
            hour: two(fixed, 4)?,
            minute: two(fixed, 6)?,
            second: two(fixed, 8)?,
            // ASCII digits, checked above: each octet is its character.
            fraction: fraction.iter().copied().map(char::from).collect(),
        };
        let valid = (1..=12).contains(&t.month)
            && t.day >= 1
            && t.day <= days_in_month(t.year, t.month)
            && t.hour < 24
            && t.minute < 60
            && t.second < 60;
        if valid {
            Ok(t)
        } else {
            Err(DerError::InvalidTime)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Re-encodes a header; the inverse of `parse_tlv` on its image.
    fn encode_header(octet: u8, len: usize) -> Vec<u8> {
        let mut out = vec![octet];
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap());
        } else {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect();
            out.push(0x80 | u8::try_from(bytes.len()).unwrap());
            out.extend(bytes);
        }
        out
    }

    #[test]
    fn lengths() {
        assert_eq!(parse_tlv(&[0x04, 0x00]).unwrap().1, 2);
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([0u8; 0x80]);
        assert_eq!(parse_tlv(&long).unwrap().0.value().len(), 0x80);
        assert_eq!(parse_tlv(&[0x04, 0x80]), Err(DerError::IndefiniteLength));
        assert_eq!(
            parse_tlv(&[0x04, 0x81, 0x05, 0, 0, 0, 0, 0]),
            Err(DerError::NonMinimalLength)
        );
        assert_eq!(
            parse_tlv(&[0x04, 0x82, 0x00, 0x80]),
            Err(DerError::NonMinimalLength)
        );
        assert_eq!(
            parse_tlv(&[0x04, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DerError::LengthTooLarge)
        );
        assert_eq!(parse_tlv(&[0x04, 0x02, 0]), Err(DerError::UnexpectedEnd));
        assert_eq!(parse_tlv(&[]), Err(DerError::UnexpectedEnd));
    }

    #[test]
    fn high_tags() {
        let (tlv, _) = parse_tlv(&[0x9f, 0x1f, 0x00]).unwrap();
        assert_eq!(tlv.tag.number, 31);
        assert_eq!(tlv.tag.class, Class::ContextSpecific);
        assert_eq!(
            parse_tlv(&[0x1f, 0x1e, 0x00]),
            Err(DerError::NonMinimalTag)
        );
        assert_eq!(
            parse_tlv(&[0x1f, 0x80, 0x1f, 0x00]),
            Err(DerError::NonMinimalTag)
        );
    }

    #[test]
    fn integers() {
        let i = Integer::parse(&[0x00, 0x80]).unwrap();
        assert_eq!(
            (i.is_negative(), i.magnitude().to_vec()),
            (false, vec![0x80])
        );
        let i = Integer::parse(&[0xff]).unwrap();
        assert_eq!(
            (i.is_negative(), i.magnitude().to_vec()),
            (true, vec![0x01])
        );
        let i = Integer::parse(&[0x80]).unwrap();
        assert_eq!(
            (i.is_negative(), i.magnitude().to_vec()),
            (true, vec![0x80])
        );
        let i = Integer::parse(&[0x00]).unwrap();
        assert_eq!(
            (i.is_negative(), i.magnitude().len(), i.bits()),
            (false, 0, 0)
        );
        assert_eq!(Integer::parse(&[0x01, 0x00]).unwrap().bits(), 9);
        assert!(Integer::parse(&[]).is_err());
        assert!(Integer::parse(&[0x00, 0x7f]).is_err());
        assert!(Integer::parse(&[0xff, 0x80]).is_err());
    }

    #[test]
    fn oids() {
        let cn = Oid::parse(&[0x55, 0x04, 0x03]).unwrap();
        assert_eq!(cn.to_dotted().unwrap(), "2.5.4.3");
        let rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
        assert_eq!(
            Oid::parse(&rsa).unwrap().to_dotted().unwrap(),
            "1.2.840.113549.1.1.11"
        );
        assert_eq!(
            Oid::parse(&[0x88, 0x37]).unwrap().to_dotted().unwrap(),
            "2.999"
        );
        assert!(Oid::parse(&[]).is_err());
        assert!(Oid::parse(&[0x55, 0x86]).is_err());
        assert!(Oid::parse(&[0x55, 0x80, 0x01]).is_err());
    }

    #[test]
    fn bit_strings() {
        let b = BitString::parse(&[0x05, 0xa0]).unwrap();
        assert!(b.bit(0) && !b.bit(1) && b.bit(2) && !b.bit(8));
        assert!(BitString::parse(&[0x05, 0xa1]).is_err());
        assert!(BitString::parse(&[0x08, 0x00]).is_err());
        assert!(BitString::parse(&[0x01]).is_err());
        assert!(BitString::parse(&[]).is_err());
        assert!(BitString::parse(&[0x00]).is_ok());
    }

    #[test]
    fn times() {
        let t = Time::parse(TimeKind::Utc, b"271121120424Z").unwrap();
        assert_eq!(
            (t.year(), t.month(), t.day(), t.second()),
            (2027, 11, 21, 24)
        );
        let t = Time::parse(TimeKind::Utc, b"500101000000Z").unwrap();
        assert_eq!(t.year(), 1950);
        let t = Time::parse(TimeKind::Generalized, b"20500229235959.5Z").ok();
        assert!(t.is_none(), "2050 is not a leap year");
        let t =
            Time::parse(TimeKind::Generalized, b"20480229235959.25Z").unwrap();
        assert_eq!((t.day(), t.fraction()), (29, "25"));
        for bad in [
            &b"2711211204Z"[..],
            b"271321120424Z",
            b"271121120424",
            b"271121120424+0100",
            b"271121250424Z",
        ] {
            assert!(Time::parse(TimeKind::Utc, bad).is_err());
        }
        assert!(
            Time::parse(TimeKind::Generalized, b"20271121120424.50Z").is_err()
        );
        assert!(
            Time::parse(TimeKind::Generalized, b"20271121120424.Z").is_err()
        );
    }

    #[test]
    fn reader() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x05, 0x05, 0x00];
        let mut r = Reader::new(&data);
        let mut seq = r.sequence().unwrap();
        let int = seq.expect(tag::INTEGER).unwrap();
        assert_eq!(int.value(), &[0x05]);
        seq.finish().unwrap();
        assert_eq!(r.optional(tag::BOOLEAN).unwrap(), None);
        assert!(r.expect(tag::INTEGER).is_err());
        r.expect(tag::NULL).unwrap();
        r.finish().unwrap();
    }

    /// Boundaries found by mutation testing.
    #[test]
    fn primitive_boundaries() {
        assert_eq!(parse_bool(&[0x00]), Ok(false));
        assert_eq!(parse_bool(&[0xff]), Ok(true));
        for bad in [&[][..], &[0x01], &[0x00, 0x00]] {
            assert_eq!(parse_bool(bad), Err(DerError::InvalidBoolean));
        }
        assert_eq!(parse_null(&[]), Ok(()));
        assert_eq!(parse_null(&[0]), Err(DerError::InvalidNull));

        let n = |b: &[u8]| Integer::parse(b).unwrap();
        assert_eq!(n(&[0x01, 0x02]).to_u64_opt(), Some(0x0102));
        let eight = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];
        assert_eq!(n(&eight).to_u64_opt(), Some(0x7fff_ffff_ffff_fffe));
        let mut nine = vec![0x01];
        nine.extend([0u8; 8]);
        assert_eq!(n(&nine).to_u64_opt(), None);
        assert_eq!(n(&[0xff]).to_u64_opt(), None);
        let mut sixteen = vec![0x7f];
        sixteen.extend([0xffu8; 15]);
        assert_eq!(n(&sixteen).magnitude_u128_opt(), Some(u128::MAX >> 1));
        let mut seventeen = vec![0x01];
        seventeen.extend([0u8; 16]);
        assert_eq!(n(&seventeen).magnitude_u128_opt(), None);
        // `[0xff, x]` is minimal exactly when x has its top bit clear.
        assert!(Integer::parse(&[0xff, 0x7f]).is_ok());
        assert!(Integer::parse(&[0x00, 0x80]).is_ok());

        assert!(BitString::parse(&[0x07, 0x80]).is_ok());
        assert!(BitString::parse(&[0x08, 0x00]).is_err());
    }

    #[test]
    fn tag_octets() {
        assert_eq!(tag::context(0), 0x80);
        assert_eq!(tag::context(2), 0x82);
        assert_eq!(tag::context_constructed(3), 0xa3);
        for b in [0x02u8, 0x30, 0x5e, 0x80, 0xa3, 0xde] {
            assert_eq!(Tag::from_octet(b).octet_opt(), Some(b));
        }
        let t = Tag {
            class: Class::Application,
            form: Form::Constructed,
            number: 30,
        };
        assert_eq!(t.octet_opt(), Some(0x7e));
        assert_eq!(Tag { number: 31, ..t }.octet_opt(), None);
        let (tlv, _) = parse_tlv(&[0x5f, 0x81, 0x00, 0x00]).unwrap();
        assert_eq!((tlv.tag.number, tlv.octet_opt()), (128, None));
    }

    #[test]
    fn length_bounds() {
        let mut four = vec![0x04, 0x84, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_tlv(&four), Err(DerError::NonMinimalLength));
        four[2] = 0x01;
        assert_eq!(parse_tlv(&four), Err(DerError::UnexpectedEnd));
        let mut two = vec![0x04, 0x82, 0x01, 0x00];
        two.extend([0u8; 0x100]);
        assert_eq!(parse_tlv(&two).unwrap().0.value().len(), 0x100);
    }

    #[test]
    fn reader_contract() {
        let data = [0x05, 0x00];
        let mut r = Reader::new(&data);
        assert!(!r.is_empty());
        assert_eq!(r.finish(), Err(DerError::TrailingData));
        assert!(r.optional(tag::NULL).unwrap().is_some());
        assert!(r.is_empty());
        r.finish().unwrap();
        let oid = Oid::parse(&[0x55, 0x04]).unwrap();
        assert_eq!(oid.as_bytes(), &[0x55, 0x04]);
    }

    #[test]
    fn oid_first_arc_boundaries() {
        let dotted = |b: &[u8]| Oid::parse(b).unwrap().to_dotted().unwrap();
        assert_eq!(dotted(&[39]), "0.39");
        assert_eq!(dotted(&[40]), "1.0");
        assert_eq!(dotted(&[79]), "1.39");
        assert_eq!(dotted(&[80]), "2.0");
        assert_eq!(dotted(&[0x81, 0x00]), "2.48");
        assert_eq!(dotted(&[0x2a, 0x81, 0x7f]), "1.2.255");
    }

    /// `from_unix_seconds` against dates computed independently (Python's
    /// `datetime`), and RFC 5280's switch to GeneralizedTime in 2050.
    #[test]
    fn times_from_unix_seconds() {
        for (seconds, utc_or_generalized) in [
            (0u64, &b"\x17\x0d700101000000Z"[..]),
            (951_782_400, b"\x17\x0d000229000000Z"),
            (1_795_350_000, b"\x17\x0d261122122000Z"),
            (2_524_607_999, b"\x17\x0d491231235959Z"),
            (2_524_608_000, b"\x18\x0f20500101000000Z"),
            (4_102_444_800, b"\x18\x0f21000101000000Z"),
            (253_402_300_799, b"\x18\x0f99991231235959Z"),
            (u64::MAX, b"\x18\x0f99991231235959Z"),
        ] {
            assert_eq!(
                Time::from_unix_seconds(seconds).to_der().as_bytes(),
                utc_or_generalized,
                "{seconds}"
            );
        }
    }

    proptest! {
        /// `to_unix_seconds` inverts `from_unix_seconds`.
        #[test]
        fn unix_seconds_round_trip(seconds in 0u64..=253_402_300_799) {
            let back = Time::from_unix_seconds(seconds).to_unix_seconds();
            prop_assert_eq!(u64::try_from(back).ok(), Some(seconds));
        }

        /// Every time written reads back to itself.
        #[test]
        fn times_round_trip(seconds in 0u64..=253_402_300_799) {
            let time = Time::from_unix_seconds(seconds);
            let raw = time.to_der();
            let der = raw.as_bytes();
            let kind = if der[0] == tag::UTC_TIME { TimeKind::Utc } else { TimeKind::Generalized };
            prop_assert_eq!(Time::parse(kind, &der[2..]), Ok(time));
        }
    }

    #[test]
    fn time_boundaries() {
        let utc = |s: &[u8]| Time::parse(TimeKind::Utc, s);
        assert!(utc(b"270430235959Z").is_ok());
        assert!(utc(b"270431000000Z").is_err(), "April has 30 days");
        assert!(utc(b"270631000000Z").is_err());
        assert!(utc(b"270931000000Z").is_err());
        assert!(utc(b"271131000000Z").is_err());
        assert!(utc(b"271231000000Z").is_ok());
        assert!(utc(b"280229000000Z").is_ok(), "2028 is a leap year");
        assert!(utc(b"270229000000Z").is_err());
        assert!(utc(b"271121240000Z").is_err());
        assert!(utc(b"271121236000Z").is_err());
        assert!(utc(b"271121235960Z").is_err());
        assert_eq!(utc(b"490101000000Z").unwrap().year(), 2049);
        let gt = Time::parse(TimeKind::Generalized, b"20000229000000Z");
        assert!(gt.is_ok(), "2000 is a leap year (divisible by 400)");
        let gt = Time::parse(TimeKind::Generalized, b"21000229000000Z");
        assert!(gt.is_err(), "2100 is not");
    }

    /// `from_sign_magnitude` drops leading zeros and the sign of zero, so
    /// it agrees with what `parse` gives.
    #[test]
    fn sign_magnitude_is_canonical() {
        let zero = Integer::from_sign_magnitude(true, &[0, 0]);
        assert_eq!(zero, Integer::from(0));
        assert!(!zero.is_negative());
        let minus = Integer::from_sign_magnitude(true, &[0, 0x80]);
        assert_eq!(minus, Integer::parse(&[0x80]).unwrap());
        assert_eq!(minus.magnitude(), [0x80]);
    }

    proptest! {
        /// Canonicity of `Time::parse`: whatever it accepts, `to_der` writes
        /// back as the same contents. Random digits, and digits shaped like
        /// a date, which reach the accepted set far more often.
        #[test]
        fn time_canonical(s in prop_oneof![
            "[0-9]{12,14}(\\.[0-9]{1,3})?Z",
            "(19|20)?[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])\
             ([01][0-9]|2[0-3])[0-5][0-9][0-5][0-9](\\.[0-9]{1,3})?Z",
        ]) {
            for kind in [TimeKind::Utc, TimeKind::Generalized] {
                if let Ok(time) = Time::parse(kind, s.as_bytes()) {
                    let raw = time.to_der();
                    let (tlv, _) = parse_tlv(raw.as_bytes()).unwrap();
                    prop_assert_eq!(tlv.value(), s.as_bytes());
                }
            }
        }

        /// Canonicity: an accepted TLV re-encodes to the exact bytes read,
        /// so the decoder is injective on its accepted set.
        #[test]
        fn header_canonical(
            octet in 0u8..=0xfe,
            body in prop::collection::vec(any::<u8>(), 0..400),
        ) {
            prop_assume!(octet & 0x1f != 0x1f);
            let mut enc = encode_header(octet, body.len());
            enc.extend(&body);
            let (tlv, used) = parse_tlv(&enc).unwrap();
            prop_assert_eq!(used, enc.len());
            prop_assert_eq!(tlv.value(), &body[..]);
            prop_assert_eq!(tlv.octet_opt(), Some(octet));
            let mut again = encode_header(octet, tlv.value().len());
            again.extend(tlv.value());
            prop_assert_eq!(again, enc);
        }

        /// Totality, and `encoded` is always a prefix of the input whose
        /// suffix is `value`.
        #[test]
        fn parse_is_total(data in prop::collection::vec(any::<u8>(), 0..64)) {
            if let Ok((tlv, used)) = parse_tlv(&data) {
                prop_assert_eq!(tlv.encoded(), &data[..used]);
                prop_assert!(tlv.encoded().ends_with(tlv.value()));
            }
        }

        /// The integer decoder agrees with two's complement on i64.
        #[test]
        fn integer_matches_i64(v in any::<i64>()) {
            let bytes = v.to_be_bytes();
            let mut start = 0;
            while start < 7 {
                let (a, b) = (bytes[start], bytes[start + 1]);
                if (a == 0 && b & 0x80 == 0) || (a == 0xff && b & 0x80 != 0) {
                    start += 1;
                } else {
                    break;
                }
            }
            let int = Integer::parse(&bytes[start..]).unwrap();
            prop_assert_eq!(int.is_negative(), v < 0);
            let mag = int.magnitude_u128_opt().unwrap();
            prop_assert_eq!(mag, u128::from(v.unsigned_abs()));
        }

        /// `to_dotted` gives digits and dots, and fails only on an arc too
        /// large for 128 bits, which takes 19 octets of base 128 or more.
        #[test]
        fn oid_dotted(data in prop::collection::vec(any::<u8>(), 0..48)) {
            if let Ok(oid) = Oid::parse(&data) {
                match oid.to_dotted() {
                    Ok(s) => prop_assert!(
                        s.chars().all(|c| c.is_ascii_digit() || c == '.')
                    ),
                    Err(e) => {
                        prop_assert!(matches!(e, Error::Unsupported(_)));
                        let longest = data
                            .split_inclusive(|b| b & 0x80 == 0)
                            .map(<[u8]>::len)
                            .max();
                        prop_assert!(longest >= Some(19));
                    }
                }
            }
        }

        #[test]
        fn oid_dotted_rejects_a_129_bit_arc(extra in 0u8..0x7f) {
            // 2.5, then an arc of 19 base-128 digits whose first is at
            // least 4: 4 * 128^18 = 2^128.
            let mut data = vec![0x55, 0x84 + extra % 0x7b];
            data.extend([0x80; 17]);
            data.push(0x00);
            let oid = Oid::parse(&data).unwrap();
            prop_assert!(matches!(oid.to_dotted(), Err(Error::Unsupported(_))));
        }
    }
}
