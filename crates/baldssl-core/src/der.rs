//! A minimal, strict DER reader ([ITU-T X.690][x690], section 10).
//!
//! # ASN.1, BER and DER
//!
//! ASN.1 ([X.680][x680]) describes data abstractly: types such as INTEGER,
//! OCTET STRING, OBJECT IDENTIFIER, SEQUENCE. Certificates and keys are
//! defined in it (RFC 5280, RFC 5208). ASN.1 says nothing about bytes;
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
//! how signature checks get bypassed: in BERserk (CVE-2014-1568), Mozilla
//! NSS "does not properly parse ASN.1 values", which let attackers spoof RSA
//! signatures (NVD's description; a "signature malleability" issue).
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

pub mod syntax;
pub mod write;

use core::fmt::Write as _;

use crate::Error;

/// Why a DER encoding was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    /// The input ended inside a TLV.
    UnexpectedEnd,
    /// The `0x80` indefinite length, which DER forbids.
    IndefiniteLength,
    /// A long-form length that could have been shorter.
    NonMinimalLength,
    /// A length that does not fit in 32 bits.
    LengthTooLarge,
    /// A high tag number that is not minimally encoded.
    NonMinimalTag,
    /// A tag other than the one the grammar requires here.
    UnexpectedTag {
        /// Expected identifier octet.
        expected: u8,
        /// Identifier octet found (`0` for high tag numbers).
        found: u8,
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

/// The tag class (bits 8-7 of the identifier octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `00`
    Universal,
    /// `01`
    Application,
    /// `10`
    ContextSpecific,
    /// `11`
    Private,
}

/// A decoded identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// The class.
    pub class: Class,
    /// Constructed (bit 6) or primitive.
    pub constructed: bool,
    /// The tag number.
    pub number: u32,
}

impl Tag {
    /// The single identifier octet for low tag numbers, `None` for tag
    /// numbers of 31 and above.
    #[must_use]
    pub fn octet_opt(self) -> Option<u8> {
        let class = match self.class {
            Class::Universal => 0x00,
            Class::Application => 0x40,
            Class::ContextSpecific => 0x80,
            Class::Private => 0xc0,
        };
        let pc = if self.constructed { 0x20 } else { 0x00 };
        let n = u8::try_from(self.number).ok().filter(|&n| n < 31)?;
        Some(class | pc | n)
    }

    /// The tag with this low-form identifier octet.
    #[must_use]
    pub const fn from_octet(b: u8) -> Self {
        let class = match b >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        };
        Tag {
            class,
            constructed: b & 0x20 != 0,
            number: (b & 0x1f) as u32,
        }
    }
}

/// Universal identifier octets used by X.509.
pub mod tag {
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
        0x80 | (n & 0x1f)
    }

    /// `[n]` context-specific constructed (EXPLICIT, or IMPLICIT on a
    /// constructed type).
    #[must_use]
    pub const fn context_constructed(n: u8) -> u8 {
        0xa0 | (n & 0x1f)
    }
}

/// One tag-length-value element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The identifier.
    pub tag: Tag,
    /// The contents octets.
    pub value: &'a [u8],
    /// The whole element: identifier, length and contents.
    pub encoded: &'a [u8],
}

impl Tlv<'_> {
    /// The low-form identifier octet, `0` for high tag numbers.
    #[must_use]
    pub fn octet(&self) -> u8 {
        self.tag.octet_opt().unwrap_or(0)
    }
}

fn read_tag(data: &[u8]) -> Result<(Tag, usize), DerError> {
    let first = *data.first().ok_or(DerError::UnexpectedEnd)?;
    let low = Tag::from_octet(first);
    if first & 0x1f != 0x1f {
        return Ok((low, 1));
    }
    let mut number: u32 = 0;
    let mut i = 1usize;
    loop {
        let b = *data.get(i).ok_or(DerError::UnexpectedEnd)?;
        if i == 1 && b == 0x80 {
            return Err(DerError::NonMinimalTag);
        }
        number = number
            .checked_mul(128)
            .and_then(|n| n.checked_add(u32::from(b & 0x7f)))
            .ok_or(DerError::NonMinimalTag)?;
        i = i.checked_add(1).ok_or(DerError::UnexpectedEnd)?;
        if b & 0x80 == 0 {
            break;
        }
    }
    if number < 31 {
        return Err(DerError::NonMinimalTag);
    }
    Ok((Tag { number, ..low }, i))
}

fn read_length(data: &[u8]) -> Result<(usize, usize), DerError> {
    let first = *data.first().ok_or(DerError::UnexpectedEnd)?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    if first == 0x80 {
        return Err(DerError::IndefiniteLength);
    }
    let count = usize::from(first & 0x7f);
    if count > 4 {
        return Err(DerError::LengthTooLarge);
    }
    let bytes = data.get(1..=count).ok_or(DerError::UnexpectedEnd)?;
    if bytes.first() == Some(&0) {
        return Err(DerError::NonMinimalLength);
    }
    let mut len: u32 = 0;
    for &b in bytes {
        len = (len << 8) | u32::from(b);
    }
    if len < 0x80 {
        return Err(DerError::NonMinimalLength);
    }
    let len = usize::try_from(len).map_err(|_| DerError::LengthTooLarge)?;
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

    /// Reads the next TLV and checks its identifier octet.
    ///
    /// # Errors
    ///
    /// [`DerError::UnexpectedTag`] on a mismatch.
    pub fn expect(&mut self, octet: u8) -> Result<Tlv<'a>, DerError> {
        let found = self.peek_octet_opt().ok_or(DerError::UnexpectedEnd)?;
        if found != octet {
            return Err(DerError::UnexpectedTag {
                expected: octet,
                found,
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
        Ok(Reader::new(self.expect(tag::SEQUENCE)?.value))
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
/// zero bytes (empty for zero).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integer {
    /// Strictly negative.
    pub negative: bool,
    /// `|value|`, big-endian, no leading zeros.
    pub magnitude: Vec<u8>,
}

impl Integer {
    /// Decodes INTEGER contents (two's complement, minimal).
    ///
    /// # Errors
    ///
    /// [`DerError::InvalidInteger`] if empty or non-minimal.
    pub fn parse(value: &[u8]) -> Result<Self, DerError> {
        match value {
            [] => return Err(DerError::InvalidInteger),
            [0x00, next, ..] if next & 0x80 == 0 => {
                return Err(DerError::InvalidInteger);
            }
            [0xff, next, ..] if next & 0x80 != 0 => {
                return Err(DerError::InvalidInteger);
            }
            _ => {}
        }
        let negative = value.first().is_some_and(|b| b & 0x80 != 0);
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
        let first_nonzero = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        magnitude.drain(..first_nonzero);
        Ok(Integer {
            negative,
            magnitude,
        })
    }

    /// Number of significant bits of the magnitude.
    #[must_use]
    pub fn bits(&self) -> usize {
        match self.magnitude.first() {
            None => 0,
            Some(&top) => {
                let top_bits =
                    8usize.saturating_sub(top.leading_zeros() as usize);
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
        let m = v.unsigned_abs().to_be_bytes();
        let first = m.iter().position(|&b| b != 0).unwrap_or(m.len());
        Integer {
            negative: v < 0,
            magnitude: m.get(first..).unwrap_or_default().to_vec(),
        }
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
pub fn parse_null(value: &[u8]) -> Result<(), DerError> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(DerError::InvalidNull)
    }
}

/// A decoded BIT STRING.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitString<'a> {
    /// Number of unused bits in the last byte (0 to 7).
    pub unused: u8,
    /// The bytes, unused bits zero.
    pub bytes: &'a [u8],
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

    /// Bit `n` in the ASN.1 numbering (bit 0 is the MSB of the first byte).
    #[must_use]
    pub fn bit(&self, n: usize) -> bool {
        let shift = 7u32.saturating_sub(u32::try_from(n % 8).unwrap_or(0));
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
        if value.last().is_none_or(|&b| b & 0x80 != 0) {
            return Err(DerError::InvalidOid);
        }
        let mut start = true;
        for &b in value {
            if start && b == 0x80 {
                return Err(DerError::InvalidOid);
            }
            start = b & 0x80 == 0;
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
    /// [`Error::Unsupported`] if an arc exceeds 128 bits.
    pub fn to_dotted(&self) -> Result<String, Error> {
        let mut arcs: Vec<u128> = Vec::new();
        let mut acc: u128 = 0;
        for &b in self.0 {
            acc = acc
                .checked_mul(128)
                .map(|a| a | u128::from(b & 0x7f))
                .ok_or_else(|| Error::unsupported("OID arc above 128 bits"))?;
            if b & 0x80 == 0 {
                arcs.push(acc);
                acc = 0;
            }
        }
        let mut out = String::new();
        for (i, arc) in arcs.iter().enumerate() {
            if i == 0 {
                let (first, second) = match *arc {
                    a if a < 40 => (0, a),
                    a if a < 80 => (1, a.saturating_sub(40)),
                    a => (2, a.saturating_sub(80)),
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

/// A decoded UTCTime or GeneralizedTime (always UTC, `Z`, in DER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Time {
    /// Encoding used.
    pub kind: TimeKind,
    /// Full year.
    pub year: u16,
    /// 1 to 12.
    pub month: u8,
    /// 1 to 31, valid for the month.
    pub day: u8,
    /// 0 to 23.
    pub hour: u8,
    /// 0 to 59.
    pub minute: u8,
    /// 0 to 59.
    pub second: u8,
    /// Fraction digits after the `.`, GeneralizedTime only (no trailing
    /// zeros in DER).
    pub fraction: String,
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

impl Time {
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
                let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
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
            TimeKind::Generalized => match rest.iter().position(|&c| c == b'.')
            {
                None => (rest, &[][..]),
                Some(dot) => {
                    let frac = rest.get(dot.saturating_add(1)..).unwrap_or(&[]);
                    if frac.is_empty()
                        || frac.last() == Some(&b'0')
                        || !frac.iter().all(u8::is_ascii_digit)
                    {
                        return Err(DerError::InvalidTime);
                    }
                    (rest.get(..dot).unwrap_or(&[]), frac)
                }
            },
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
            fraction: String::from_utf8_lossy(fraction).into_owned(),
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
        assert_eq!(parse_tlv(&long).unwrap().0.value.len(), 0x80);
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
            parse_tlv(&[0x04, 0x85, 1, 0, 0, 0, 0]),
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
        assert_eq!((i.negative, i.magnitude), (false, vec![0x80]));
        let i = Integer::parse(&[0xff]).unwrap();
        assert_eq!((i.negative, i.magnitude), (true, vec![0x01]));
        let i = Integer::parse(&[0x80]).unwrap();
        assert_eq!((i.negative, i.magnitude), (true, vec![0x80]));
        let i = Integer::parse(&[0x00]).unwrap();
        assert_eq!((i.negative, i.magnitude.len(), i.bits()), (false, 0, 0));
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
        assert_eq!((t.year, t.month, t.day, t.second), (2027, 11, 21, 24));
        let t = Time::parse(TimeKind::Utc, b"500101000000Z").unwrap();
        assert_eq!(t.year, 1950);
        let t = Time::parse(TimeKind::Generalized, b"20500229235959.5Z").ok();
        assert!(t.is_none(), "2050 is not a leap year");
        let t =
            Time::parse(TimeKind::Generalized, b"20480229235959.25Z").unwrap();
        assert_eq!((t.day, t.fraction.as_str()), (29, "25"));
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
        assert_eq!(int.value, &[0x05]);
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
            constructed: true,
            number: 30,
        };
        assert_eq!(t.octet_opt(), Some(0x7e));
        assert_eq!(Tag { number: 31, ..t }.octet_opt(), None);
        let (tlv, _) = parse_tlv(&[0x5f, 0x81, 0x00, 0x00]).unwrap();
        assert_eq!((tlv.tag.number, tlv.octet()), (128, 0));
    }

    #[test]
    fn length_bounds() {
        let mut four = vec![0x04, 0x84, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_tlv(&four), Err(DerError::NonMinimalLength));
        four[2] = 0x01;
        assert_eq!(parse_tlv(&four), Err(DerError::UnexpectedEnd));
        let mut two = vec![0x04, 0x82, 0x01, 0x00];
        two.extend([0u8; 0x100]);
        assert_eq!(parse_tlv(&two).unwrap().0.value.len(), 0x100);
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
        assert_eq!(utc(b"490101000000Z").unwrap().year, 2049);
        let gt = Time::parse(TimeKind::Generalized, b"20000229000000Z");
        assert!(gt.is_ok(), "2000 is a leap year (divisible by 400)");
        let gt = Time::parse(TimeKind::Generalized, b"21000229000000Z");
        assert!(gt.is_err(), "2100 is not");
    }

    proptest! {
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
            prop_assert_eq!(tlv.value, &body[..]);
            prop_assert_eq!(tlv.octet(), octet);
            let mut again = encode_header(tlv.octet(), tlv.value.len());
            again.extend(tlv.value);
            prop_assert_eq!(again, enc);
        }

        /// Totality, and `encoded` is always a prefix of the input whose
        /// suffix is `value`.
        #[test]
        fn parse_is_total(data in prop::collection::vec(any::<u8>(), 0..64)) {
            if let Ok((tlv, used)) = parse_tlv(&data) {
                prop_assert_eq!(tlv.encoded, &data[..used]);
                prop_assert!(tlv.encoded.ends_with(tlv.value));
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
            prop_assert_eq!(int.negative, v < 0);
            let mag = int.magnitude_u128_opt().unwrap();
            prop_assert_eq!(mag, u128::from(v.unsigned_abs()));
        }

        #[test]
        fn oid_dotted_total(data in prop::collection::vec(any::<u8>(), 0..32)) {
            if let Ok(oid) = Oid::parse(&data) {
                let s = oid.to_dotted().unwrap();
                prop_assert!(s.chars().all(|c| c.is_ascii_digit() || c == '.'));
            }
        }
    }
}
