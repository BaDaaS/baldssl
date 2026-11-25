//! Writing distinguished names: the `Name` of [RFC 5280 section
//! 4.1.2.4][rfc5280-4.1.2.4], built from the `-subj` argument of `openssl
//! req` and encoded as OpenSSL encodes it.
//!
//! A name is a sequence of relative distinguished names (RDNs), each a SET
//! OF attribute type and value pairs, so a multi-valued RDN (`/CN=a+O=b`)
//! is one SET with two members; DER sorts them ([X.690] 11.6), which the
//! `SetOf` description does.
//!
//! # The string type of each value
//!
//! OpenSSL picks the string type of a value from a table indexed by the
//! attribute (`tbl_standard.h`), its global `string_mask` (`utf8only` in
//! the default configuration, and when there is none), and the characters
//! (`ASN1_mbstring_ncopy`, in `crypto/asn1/a_mbstr.c`): of the types the
//! attribute allows, the first in the order NumericString, PrintableString,
//! IA5String, T61String, BMPString, UniversalString, UTF8String that can
//! hold every character. So `countryName` is a PrintableString of exactly 2
//! characters, `emailAddress` an IA5String, and `commonName` a UTF8String.
//! [`RULES`] is that table.
//!
//! # Input encodings
//!
//! `req` reads `-subj` as Latin-1 unless given `-utf8` (OpenSSL's
//! `MBSTRING_ASC` and `MBSTRING_UTF8`): each byte is then one character, and
//! UTF-8 input is encoded twice. [`InputEncoding`] says which.
//!
//! [rfc5280-4.1.2.4]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4
//! [X.690]: https://www.itu.int/rec/T-REC-X.690

use baldssl_core::{
    der::{
        syntax::{
            Any, ObjectId, ObjectIdentifier, RawTlv, Sequence, SequenceOf,
            SetOf,
        },
        tag,
    },
    encoding::Encodable,
};

use crate::objects::{self, find_by_name_opt};

use MaskRule::{Fixed, Narrowed};
use StringType::{Bmp, Ia5, Numeric, Printable, Utf8};

/// How the bytes of `-subj` are read: `req`'s default (Latin-1, one byte
/// per character) or `-utf8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEncoding {
    /// One character per byte (OpenSSL's `MBSTRING_ASC`).
    Latin1,
    /// UTF-8 (OpenSSL's `MBSTRING_UTF8`, `req -utf8`).
    Utf8,
}

/// An ASN.1 character string type, in the order OpenSSL tries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StringType {
    /// Digits and space.
    Numeric,
    /// X.680's PrintableString alphabet.
    Printable,
    /// ASCII.
    Ia5,
    /// Latin-1, as OpenSSL treats T61String.
    T61,
    /// UCS-2, big-endian.
    Bmp,
    /// UCS-4, big-endian.
    Universal,
    /// UTF-8.
    Utf8,
}

impl StringType {
    /// Every type, in OpenSSL's order.
    const ALL: [StringType; 7] = [
        StringType::Numeric,
        StringType::Printable,
        StringType::Ia5,
        StringType::T61,
        StringType::Bmp,
        StringType::Universal,
        StringType::Utf8,
    ];

    /// The universal tag ([X.680] clause 8.4, table 1).
    ///
    /// [X.680]: https://www.itu.int/rec/T-REC-X.680
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            StringType::Numeric => tag::NUMERIC_STRING,
            StringType::Printable => tag::PRINTABLE_STRING,
            StringType::Ia5 => tag::IA5_STRING,
            StringType::T61 => tag::T61_STRING,
            StringType::Bmp => tag::BMP_STRING,
            StringType::Universal => tag::UNIVERSAL_STRING,
            StringType::Utf8 => tag::UTF8_STRING,
        }
    }

    /// Whether the type can hold the character `c` (OpenSSL's `type_str`).
    fn holds(self, c: char) -> bool {
        match self {
            StringType::Numeric => c == ' ' || c.is_ascii_digit(),
            StringType::Printable => {
                c.is_ascii_alphanumeric() || PRINTABLE_PUNCTUATION.contains(c)
            }
            StringType::Ia5 => c.is_ascii(),
            StringType::T61 => u32::from(c) <= LATIN1_MAX,
            StringType::Bmp => u32::from(c) <= BMP_MAX,
            StringType::Universal | StringType::Utf8 => true,
        }
    }

    /// The contents of a string of this type holding `chars`, each of which
    /// the type holds: one octet per character for the 8-bit types, UCS-2
    /// or UCS-4 big-endian, or UTF-8.
    fn encode(self, chars: &[char]) -> Vec<u8> {
        let mut out = Vec::new();
        for &c in chars {
            let [_, _, high, low] = u32::from(c).to_be_bytes();
            match self {
                StringType::Numeric
                | StringType::Printable
                | StringType::Ia5
                | StringType::T61 => out.push(low),
                StringType::Bmp => out.extend_from_slice(&[high, low]),
                StringType::Universal => {
                    out.extend_from_slice(&u32::from(c).to_be_bytes());
                }
                StringType::Utf8 => {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
        out
    }
}

/// The punctuation of X.680's PrintableString alphabet, besides letters and
/// digits ([X.680] clause 41.4, table 10), which is OpenSSL's
/// `ossl_isasn1print`.
///
/// [X.680]: https://www.itu.int/rec/T-REC-X.680
const PRINTABLE_PUNCTUATION: &str = " '()+,-./:=?";
/// The largest code point of Latin-1, which OpenSSL takes T61String to be.
const LATIN1_MAX: u32 = 0xff;
/// The largest code point of the Basic Multilingual Plane, which UCS-2
/// (BMPString) holds.
const BMP_MAX: u32 = 0xffff;

/// A set of string types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringTypes(u8);

impl StringTypes {
    /// The bit of one type: the type's place in [`StringType`].
    #[allow(
        clippy::as_conversions,
        reason = "an enum's discriminant is read only with `as`; it is the \
                  bit index, below 8"
    )]
    const fn of(t: StringType) -> u8 {
        1 << t as u8
    }

    /// One type.
    #[must_use]
    pub const fn only(t: StringType) -> Self {
        StringTypes(Self::of(t))
    }

    /// OpenSSL's `DIRSTRING_TYPE`: Printable, T61, BMP and UTF8.
    pub const DIRECTORY: Self = StringTypes(
        Self::of(StringType::Printable)
            | Self::of(StringType::T61)
            | Self::of(StringType::Bmp)
            | Self::of(StringType::Utf8),
    );

    /// OpenSSL's `PKCS9STRING_TYPE`: `DIRSTRING_TYPE` and IA5.
    pub const PKCS9: Self =
        StringTypes(Self::DIRECTORY.0 | Self::of(StringType::Ia5));

    /// Whether `t` is in the set.
    #[must_use]
    pub fn contains(self, t: StringType) -> bool {
        self.0 & Self::of(t) != 0
    }

    /// The types in both sets.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        StringTypes(self.0 & other.0)
    }
}

/// The global `string_mask` of the default configuration, `utf8only`
/// (also OpenSSL's value without a configuration).
pub const UTF8_ONLY: StringTypes = StringTypes::only(StringType::Utf8);

/// Whether an attribute's string types are narrowed by the global mask: the
/// `STABLE_NO_MASK` flag of `tbl_standard.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaskRule {
    /// The types are narrowed by the global mask.
    Narrowed,
    /// The types are used as they are (`STABLE_NO_MASK`).
    Fixed,
}

/// What OpenSSL allows for one attribute: an entry of `tbl_standard.h`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AttributeRule {
    /// OpenSSL's short name of the attribute.
    pub(crate) short_name: &'static str,
    /// The fewest characters, when bounded.
    pub(crate) min: Option<usize>,
    /// The most characters, when bounded.
    pub(crate) max: Option<usize>,
    /// The string types the attribute allows.
    pub(crate) types: StringTypes,
    /// Whether the global mask narrows the types.
    pub(crate) mask: MaskRule,
}

/// The rule of a `tbl_standard.h` entry.
const fn rule(
    short_name: &'static str,
    min: Option<usize>,
    max: Option<usize>,
    types: StringTypes,
    mask: MaskRule,
) -> AttributeRule {
    AttributeRule {
        short_name,
        min,
        max,
        types,
        mask,
    }
}

/// OpenSSL 3.5's `tbl_standard.h`, with the bounds of its `ub_*` constants
/// (`ub_name` 32768, `ub_common_name` 64, `ub_locality_name` 128,
/// `ub_state_name` 128, `ub_organization_name` 64,
/// `ub_organization_unit_name` 64, `ub_email_address` 128,
/// `ub_serial_number` 64, `ub_rfc822_mailbox` 256). A negative bound there
/// is no bound here. Attributes without an entry allow `DIRSTRING_TYPE`
/// narrowed by the global mask, without bounds.
pub(crate) const RULES: &[AttributeRule] = &[
    rule("CN", Some(1), Some(64), StringTypes::DIRECTORY, Narrowed),
    rule("C", Some(2), Some(2), StringTypes::only(Printable), Fixed),
    rule("L", Some(1), Some(128), StringTypes::DIRECTORY, Narrowed),
    rule("ST", Some(1), Some(128), StringTypes::DIRECTORY, Narrowed),
    rule("O", Some(1), Some(64), StringTypes::DIRECTORY, Narrowed),
    rule("OU", Some(1), Some(64), StringTypes::DIRECTORY, Narrowed),
    rule(
        "emailAddress",
        Some(1),
        Some(128),
        StringTypes::only(Ia5),
        Fixed,
    ),
    rule(
        "unstructuredName",
        Some(1),
        None,
        StringTypes::PKCS9,
        Narrowed,
    ),
    rule(
        "challengePassword",
        Some(1),
        None,
        StringTypes::PKCS9,
        Narrowed,
    ),
    rule(
        "unstructuredAddress",
        Some(1),
        None,
        StringTypes::DIRECTORY,
        Narrowed,
    ),
    rule("GN", Some(1), Some(32768), StringTypes::DIRECTORY, Narrowed),
    rule("SN", Some(1), Some(32768), StringTypes::DIRECTORY, Narrowed),
    rule(
        "initials",
        Some(1),
        Some(32768),
        StringTypes::DIRECTORY,
        Narrowed,
    ),
    rule(
        "serialNumber",
        Some(1),
        Some(64),
        StringTypes::only(Printable),
        Fixed,
    ),
    rule("friendlyName", None, None, StringTypes::only(Bmp), Fixed),
    rule(
        "name",
        Some(1),
        Some(32768),
        StringTypes::DIRECTORY,
        Narrowed,
    ),
    rule(
        "dnQualifier",
        None,
        None,
        StringTypes::only(Printable),
        Fixed,
    ),
    rule("DC", Some(1), None, StringTypes::only(Ia5), Fixed),
    rule("CSPName", None, None, StringTypes::only(Bmp), Fixed),
    rule("mail", Some(1), Some(256), StringTypes::only(Ia5), Fixed),
    rule(
        "jurisdictionC",
        Some(2),
        Some(2),
        StringTypes::only(Printable),
        Fixed,
    ),
    rule("INN", Some(1), Some(12), StringTypes::only(Numeric), Fixed),
    rule("OGRN", Some(1), Some(13), StringTypes::only(Numeric), Fixed),
    rule(
        "SNILS",
        Some(1),
        Some(11),
        StringTypes::only(Numeric),
        Fixed,
    ),
    rule("c3", Some(3), Some(3), StringTypes::only(Printable), Fixed),
    rule("n3", Some(3), Some(3), StringTypes::only(Numeric), Fixed),
    rule("dnsName", None, None, StringTypes::only(Utf8), Fixed),
    rule(
        "id-on-SmtpUTF8Mailbox",
        Some(1),
        Some(128),
        StringTypes::only(Utf8),
        Fixed,
    ),
];

/// One attribute of a name and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeTypeAndValue {
    /// The attribute.
    pub attribute: ObjectId,
    /// The value's string type.
    pub string_type: StringType,
    /// The value's contents in that type's encoding.
    pub contents: Vec<u8>,
}

/// A relative distinguished name: one or more attributes, a SET OF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativeDistinguishedName(pub Vec<AttributeTypeAndValue>);

/// A distinguished name: a sequence of RDNs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DistinguishedName(pub Vec<RelativeDistinguishedName>);

/// Whether an unescaped `+` in `-subj` starts a further member of the same
/// RDN (`req -multivalue-rdn`, which OpenSSL 3 always applies) or is part
/// of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdnMode {
    /// A `+` is part of the value: every RDN has one member.
    SingleValued,
    /// A `+` starts a further member of the RDN.
    MultiValued,
}

impl RdnMode {
    /// Whether an unescaped `+` starts a further member of the RDN.
    fn plus_starts_member(self) -> bool {
        match self {
            RdnMode::SingleValued => false,
            RdnMode::MultiValued => true,
        }
    }
}

/// Where an attribute of `-subj` stands in its RDN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdnPosition {
    /// The first member, after a `/`.
    First,
    /// A further member of a multi-valued RDN, after a `+`.
    Further,
}

/// What `-subj` parsing skips, as OpenSSL warns about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjWarning {
    /// An attribute OpenSSL does not know; OpenSSL adds a hint about `+`
    /// when it was a further member of an RDN.
    UnknownAttribute {
        /// The attribute as written.
        name: String,
        /// Where it stood in its RDN.
        position: RdnPosition,
    },
    /// An attribute with an empty value.
    EmptyValue {
        /// The attribute as written.
        name: String,
    },
}

/// Why `-subj` could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjError {
    /// Not starting with `/`.
    NotAName(String),
    /// An attribute type with no `=` after it.
    MissingEquals(String),
    /// A `\` at the end.
    TrailingEscape,
    /// Input that is not UTF-8 under [`InputEncoding::Utf8`].
    InvalidUtf8,
    /// A value with fewer characters than its attribute allows.
    TooShort {
        /// The attribute as written.
        name: String,
        /// The fewest characters allowed.
        min: usize,
    },
    /// A value with more characters than its attribute allows.
    TooLong {
        /// The attribute as written.
        name: String,
        /// The most characters allowed.
        max: usize,
    },
    /// A value with a character no allowed string type can hold.
    IllegalCharacters {
        /// The attribute as written.
        name: String,
    },
    /// An attribute OpenSSL knows but cannot encode: the roots of the
    /// object identifier tree (`ISO`), which have one arc.
    NotEncodable {
        /// The attribute as written.
        name: String,
        /// Its value, as written.
        value: String,
    },
}

impl core::fmt::Display for SubjError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SubjError::NotAName(text) => write!(
                f,
                "subject name is expected to be in the format \
                 /type0=value0/type1=value1/type2=... where characters may \
                 be escaped by \\. This name is not in that format: '{text}'"
            ),
            SubjError::MissingEquals(t) => write!(
                f,
                "Missing '=' after RDN type string '{t}' in subject name \
                 string"
            ),
            SubjError::TrailingEscape => {
                write!(f, "Escape character at end of subject name string")
            }
            SubjError::InvalidUtf8 => write!(f, "invalid UTF8 string"),
            SubjError::TooShort { name, min } => {
                write!(f, "string too short (minsize={min}) for {name}")
            }
            SubjError::TooLong { name, max } => {
                write!(f, "string too long (maxsize={max}) for {name}")
            }
            SubjError::IllegalCharacters { name } => {
                write!(f, "illegal characters in {name}")
            }
            SubjError::NotEncodable { name, value } => write!(
                f,
                "Error adding subject name attribute \"/{name}={value}\""
            ),
        }
    }
}

/// The name `-subj` gives, and the attributes it skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSubject {
    /// The name.
    pub name: DistinguishedName,
    /// What was skipped, in order, as OpenSSL warns about it.
    pub warnings: Vec<SubjWarning>,
}

/// The characters of `bytes` under `encoding`: under Latin-1 each byte is
/// the code point of its value.
fn characters(
    bytes: &[u8],
    encoding: InputEncoding,
) -> Result<Vec<char>, SubjError> {
    match encoding {
        InputEncoding::Latin1 => {
            Ok(bytes.iter().map(|&b| char::from(b)).collect())
        }
        InputEncoding::Utf8 => core::str::from_utf8(bytes)
            .map(|s| s.chars().collect())
            .map_err(|_| SubjError::InvalidUtf8),
    }
}

/// The value of attribute `name` (as written) with the bytes `value`, as
/// OpenSSL's `ASN1_STRING_set_by_NID` makes it under the global mask
/// `mask`.
fn attribute_value(
    name: &str,
    attribute: ObjectId,
    value: &[u8],
    encoding: InputEncoding,
    mask: StringTypes,
) -> Result<AttributeTypeAndValue, SubjError> {
    let rule = RULES.iter().find(|r| {
        find_by_name_opt(r.short_name).is_some_and(|id| id == attribute)
    });
    let (types, min, max) = match rule {
        Some(r) => match r.mask {
            MaskRule::Fixed => (r.types, r.min, r.max),
            MaskRule::Narrowed => (r.types.and(mask), r.min, r.max),
        },
        None => (StringTypes::DIRECTORY.and(mask), None, None),
    };
    let chars = characters(value, encoding)?;
    if let Some(min) = min.filter(|&m| chars.len() < m) {
        return Err(SubjError::TooShort {
            name: name.to_owned(),
            min,
        });
    }
    if let Some(max) = max.filter(|&m| chars.len() > m) {
        return Err(SubjError::TooLong {
            name: name.to_owned(),
            max,
        });
    }
    let string_type = StringType::ALL
        .into_iter()
        .filter(|&t| types.contains(t))
        .find(|t| chars.iter().all(|&c| t.holds(c)))
        .ok_or_else(|| SubjError::IllegalCharacters {
            name: name.to_owned(),
        })?;
    Ok(AttributeTypeAndValue {
        attribute,
        string_type,
        contents: string_type.encode(&chars),
    })
}

impl DistinguishedName {
    /// The name `-subj` gives, as OpenSSL's `parse_name` reads it
    /// (`apps/lib/apps.c`): `/type=value` pairs, `\` escaping the next
    /// character, an unescaped `+` starting a further member of the same
    /// RDN under [`RdnMode::MultiValued`]. Unknown attributes and empty values are
    /// skipped with a warning, as OpenSSL does. Values are typed as in the
    /// module documentation, under the global mask `mask` (usually
    /// [`UTF8_ONLY`]).
    ///
    /// # Errors
    ///
    /// [`SubjError`]: a malformed argument, or a value its attribute does
    /// not allow.
    pub fn from_subj(
        text: &[u8],
        encoding: InputEncoding,
        rdn_mode: RdnMode,
        mask: StringTypes,
    ) -> Result<ParsedSubject, SubjError> {
        let Some(mut rest) = text.strip_prefix(b"/") else {
            return Err(SubjError::NotAName(
                String::from_utf8_lossy(text).into_owned(),
            ));
        };
        let mut name = DistinguishedName::default();
        let mut warnings = Vec::new();
        let mut next_position = RdnPosition::First;
        while !rest.is_empty() {
            let position = next_position;
            next_position = RdnPosition::First;
            let mut parts = rest.splitn(2, |&b| b == b'=');
            let (Some(type_bytes), Some(after)) = (parts.next(), parts.next())
            else {
                return Err(SubjError::MissingEquals(
                    String::from_utf8_lossy(rest).into_owned(),
                ));
            };
            let typestr = String::from_utf8_lossy(type_bytes).into_owned();
            rest = after;
            let mut value = Vec::new();
            while let Some((&b, after)) = rest.split_first() {
                if b == b'/' {
                    rest = after;
                    break;
                }
                if b == b'+' && rdn_mode.plus_starts_member() {
                    next_position = RdnPosition::Further;
                    rest = after;
                    break;
                }
                if b == b'\\' {
                    let Some((&escaped, after_escape)) = after.split_first()
                    else {
                        return Err(SubjError::TrailingEscape);
                    };
                    value.push(escaped);
                    rest = after_escape;
                } else {
                    value.push(b);
                    rest = after;
                }
            }
            if !objects::is_name(&typestr) {
                warnings.push(SubjWarning::UnknownAttribute {
                    name: typestr,
                    position,
                });
                continue;
            }
            if value.is_empty() {
                warnings.push(SubjWarning::EmptyValue { name: typestr });
                continue;
            }
            let Some(attribute) = find_by_name_opt(&typestr) else {
                return Err(SubjError::NotEncodable {
                    value: String::from_utf8_lossy(&value).into_owned(),
                    name: typestr,
                });
            };
            let atv =
                attribute_value(&typestr, attribute, &value, encoding, mask)?;
            match (position, name.0.last_mut()) {
                (RdnPosition::Further, Some(last)) => last.0.push(atv),
                (RdnPosition::First, _) | (RdnPosition::Further, None) => {
                    name.0.push(RelativeDistinguishedName(vec![atv]));
                }
            }
        }
        Ok(ParsedSubject { name, warnings })
    }
}

/// `Name ::= SEQUENCE OF RelativeDistinguishedName`, with
/// `RelativeDistinguishedName ::= SET OF AttributeTypeAndValue` and
/// `AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY
/// }` ([RFC 5280 section 4.1.2.4]). It writes and reads DER only, a SET OF
/// in sorted order; [`crate::Name`] is the lenient reader of names read
/// from certificates and requests.
///
/// [RFC 5280 section 4.1.2.4]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4
pub(crate) type NameSyntax =
    SequenceOf<SetOf<Sequence<(ObjectIdentifier, (Any, ()))>>>;

/// The description of [`NameSyntax`].
pub(crate) const NAME: NameSyntax =
    SequenceOf(SetOf(Sequence((ObjectIdentifier, (Any, ())))));

impl DistinguishedName {
    /// The DER `Name`, each RDN's members sorted as DER requires. Total: the
    /// description writes one TLV for every name.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let value: Vec<Vec<(ObjectId, (RawTlv, ()))>> = self
            .0
            .iter()
            .map(|rdn| {
                rdn.0
                    .iter()
                    .map(|atv| {
                        (
                            atv.attribute.clone(),
                            (
                                RawTlv::from_tag_and_contents(
                                    atv.string_type.tag(),
                                    &atv.contents,
                                ),
                                (),
                            ),
                        )
                    })
                    .collect()
            })
            .collect();
        RawTlv::encode(&NAME, &value)
    }
}

/// The DER `Name` ([`DistinguishedName::to_raw`]).
impl Encodable for DistinguishedName {
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        self.to_raw().as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests;
