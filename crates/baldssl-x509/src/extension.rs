//! Certificate extensions baldssl writes ([RFC 5280 section 4.2]), as
//! values: what an extension says, its criticality, its DER, and how
//! OpenSSL's configuration syntax names it (`-addext`, `-extfile`).
//!
//! ```text
//! Extension ::= SEQUENCE {
//!     extnID      OBJECT IDENTIFIER,
//!     critical    BOOLEAN DEFAULT FALSE,
//!     extnValue   OCTET STRING }
//! ```
//!
//! Criticality belongs to an extension, not to its kind: OpenSSL's `v3_ca`
//! marks basic constraints critical, `-addext basicConstraints=CA:FALSE`
//! does not. The configuration syntax is OpenSSL's `X509V3_EXT_nconf`: a
//! short name and a value, optionally starting with exactly
//! `critical,`, whose list is read as `X509V3_parse_list` reads it (see
//! [`ConfList`]). Each parse is the standard trait: an extension is
//! `FromStr` its line, a key usage `FromStr` its name, an [`Ia5String`]
//! `FromStr` its text.
//!
//! [RFC 5280 section 4.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2

use std::{net::IpAddr, slice, str::FromStr};

use baldssl_core::{
    Error, Result,
    der::{
        Oid,
        syntax::{
            Any, Boolean, Implicit, NamedBits, ObjectId, ObjectIdentifier,
            OctetString, Optional, RawTlv, Sequence, SequenceOf, Small,
            WithDefault, decode,
        },
    },
};

use crate::{
    cert::Extension as ExtensionView,
    conf::{Config, replace_push},
    objects,
    oid::{
        ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS,
        ID_CE_EXT_KEY_USAGE, ID_CE_ISSUER_ALT_NAME, ID_CE_KEY_USAGE,
        ID_CE_SUBJECT_ALT_NAME, ID_CE_SUBJECT_KEY_IDENTIFIER,
    },
};
use general_name_tag::{DNS_NAME, IP_ADDRESS, RFC822_NAME, URI};

/// The kinds of extension baldssl reads or writes by their meaning, each
/// named by its object identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtensionKind {
    /// `subjectKeyIdentifier`.
    SubjectKeyIdentifier,
    /// `authorityKeyIdentifier`.
    AuthorityKeyIdentifier,
    /// `keyUsage`.
    KeyUsage,
    /// `subjectAltName`.
    SubjectAltName,
    /// `issuerAltName`.
    IssuerAltName,
    /// `basicConstraints`.
    BasicConstraints,
    /// `extKeyUsage`.
    ExtendedKeyUsage,
}

impl ExtensionKind {
    /// Every kind.
    const ALL: [ExtensionKind; 7] = [
        ExtensionKind::SubjectKeyIdentifier,
        ExtensionKind::AuthorityKeyIdentifier,
        ExtensionKind::KeyUsage,
        ExtensionKind::SubjectAltName,
        ExtensionKind::IssuerAltName,
        ExtensionKind::BasicConstraints,
        ExtensionKind::ExtendedKeyUsage,
    ];

    /// The kind's object identifier.
    pub(crate) fn oid(self) -> ObjectId {
        match self {
            ExtensionKind::SubjectKeyIdentifier => ID_CE_SUBJECT_KEY_IDENTIFIER,
            ExtensionKind::AuthorityKeyIdentifier => {
                ID_CE_AUTHORITY_KEY_IDENTIFIER
            }
            ExtensionKind::KeyUsage => ID_CE_KEY_USAGE,
            ExtensionKind::SubjectAltName => ID_CE_SUBJECT_ALT_NAME,
            ExtensionKind::IssuerAltName => ID_CE_ISSUER_ALT_NAME,
            ExtensionKind::BasicConstraints => ID_CE_BASIC_CONSTRAINTS,
            ExtensionKind::ExtendedKeyUsage => ID_CE_EXT_KEY_USAGE,
        }
    }

    /// The kind an identifier names, if it is one of these: the inverse of
    /// [`ExtensionKind::oid`], by search, so the two cannot disagree.
    pub(crate) fn from_oid_opt(oid: &Oid<'_>) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| *oid == kind.oid())
    }
}

/// The context tag numbers of the alternatives of `GeneralName`
/// ([RFC 5280 section 4.2.1.6]), which the writer here and the `-text`
/// printer share.
///
/// [RFC 5280 section 4.2.1.6]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
pub(crate) mod general_name_tag {
    /// `otherName [0]`.
    pub(crate) const OTHER_NAME: u8 = 0;
    /// `rfc822Name [1]`.
    pub(crate) const RFC822_NAME: u8 = 1;
    /// `dNSName [2]`.
    pub(crate) const DNS_NAME: u8 = 2;
    /// `x400Address [3]`.
    pub(crate) const X400_ADDRESS: u8 = 3;
    /// `directoryName [4]`.
    pub(crate) const DIRECTORY_NAME: u8 = 4;
    /// `ediPartyName [5]`.
    pub(crate) const EDI_PARTY_NAME: u8 = 5;
    /// `uniformResourceIdentifier [6]`.
    pub(crate) const URI: u8 = 6;
    /// `iPAddress [7]`.
    pub(crate) const IP_ADDRESS: u8 = 7;
    /// `registeredID [8]`.
    pub(crate) const REGISTERED_ID: u8 = 8;
}

/// The named bits of key usage ([RFC 5280 section 4.2.1.3]), in bit order:
/// OpenSSL's short name, which the configuration takes, and its long name,
/// which `-text` prints and the configuration takes too.
///
/// [RFC 5280 section 4.2.1.3]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
pub(crate) const KEY_USAGE_BITS: [(&str, &str); 9] = [
    ("digitalSignature", "Digital Signature"),
    ("nonRepudiation", "Non Repudiation"),
    ("keyEncipherment", "Key Encipherment"),
    ("dataEncipherment", "Data Encipherment"),
    ("keyAgreement", "Key Agreement"),
    ("keyCertSign", "Certificate Sign"),
    ("cRLSign", "CRL Sign"),
    ("encipherOnly", "Encipher Only"),
    ("decipherOnly", "Decipher Only"),
];

/// The nine bits of key usage [RFC 5280 section 4.2.1.3] names
/// (`digitalSignature(0)` to `decipherOnly(8)`); any other bit names
/// nothing.
///
/// [RFC 5280 section 4.2.1.3]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
const NAMED_KEY_USAGE_BITS: u64 = 0x1ff;

/// A set of key usages: a subset of the nine named bits of
/// [RFC 5280 section 4.2.1.3], bit `i` for the `i`-th. Under
/// [`KeyUsage::union`] the sets form a join-semilattice with the empty set
/// (the `Default`) as identity: union is associative, commutative and
/// idempotent; [`KeyUsage::contains`] is its order (`a` contains `b`
/// exactly when `a` union `b` is `a`). DER writes each set one way (the
/// named bit list without trailing zeros).
///
/// [RFC 5280 section 4.2.1.3]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyUsage(u16);

impl KeyUsage {
    /// `digitalSignature(0)`.
    pub const DIGITAL_SIGNATURE: KeyUsage = KeyUsage(1);
    /// `keyEncipherment(2)`.
    pub const KEY_ENCIPHERMENT: KeyUsage = KeyUsage(1 << 2);
    /// `keyCertSign(5)`.
    pub const KEY_CERT_SIGN: KeyUsage = KeyUsage(1 << 5);
    /// `cRLSign(6)`.
    pub const CRL_SIGN: KeyUsage = KeyUsage(1 << 6);

    /// The union.
    #[must_use]
    pub const fn union(self, other: KeyUsage) -> KeyUsage {
        KeyUsage(self.0 | other.0)
    }

    /// Whether every usage of `other` is in this set.
    #[must_use]
    pub const fn contains(self, other: KeyUsage) -> bool {
        self.0 & other.0 == other.0
    }
}

/// The usage of one name, short (`digitalSignature`) or long (`Digital
/// Signature`), as OpenSSL reads it.
///
/// # Errors
///
/// [`Error::Usage`] for any other name.
impl FromStr for KeyUsage {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self> {
        KEY_USAGE_BITS
            .iter()
            .position(|(short, long)| *short == name || *long == name)
            .and_then(|i| u32::try_from(i).ok())
            .map(|i| KeyUsage(1 << i))
            .ok_or_else(|| {
                Error::Usage(format!("keyUsage: unknown usage {name:?}"))
            })
    }
}

/// An IA5String: ASCII, as `dNSName`, `rfc822Name` and
/// `uniformResourceIdentifier` require ([RFC 5280 section 4.2.1.6]).
///
/// [RFC 5280 section 4.2.1.6]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ia5String(String);

/// The string, when it is ASCII.
///
/// # Errors
///
/// [`Error::Usage`] for text that is not ASCII.
impl FromStr for Ia5String {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        if text.is_ascii() {
            Ok(Ia5String(text.to_string()))
        } else {
            Err(Error::Usage(format!("{text:?} is not ASCII")))
        }
    }
}

impl Ia5String {
    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A name in an alternative name extension, of the kinds OpenSSL's
/// configuration writes most ([RFC 5280 section 4.2.1.6]).
///
/// [RFC 5280 section 4.2.1.6]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralName {
    /// `rfc822Name [1]`, `email:` in the configuration.
    Email(Ia5String),
    /// `dNSName [2]`, `DNS:`.
    Dns(Ia5String),
    /// `uniformResourceIdentifier [6]`, `URI:`.
    Uri(Ia5String),
    /// `iPAddress [7]`, `IP:`: four octets for IPv4, sixteen for IPv6.
    Ip(IpAddr),
}

impl GeneralName {
    /// The DER `GeneralName`: the context tag of its kind, IMPLICIT.
    fn to_raw(&self) -> RawTlv {
        match self {
            GeneralName::Email(s) => RawTlv::encode(
                &Implicit::<RFC822_NAME, _>(OctetString),
                &s.0.as_bytes().to_vec(),
            ),
            GeneralName::Dns(s) => RawTlv::encode(
                &Implicit::<DNS_NAME, _>(OctetString),
                &s.0.as_bytes().to_vec(),
            ),
            GeneralName::Uri(s) => RawTlv::encode(
                &Implicit::<URI, _>(OctetString),
                &s.0.as_bytes().to_vec(),
            ),
            GeneralName::Ip(IpAddr::V4(a)) => RawTlv::encode(
                &Implicit::<IP_ADDRESS, _>(OctetString),
                &a.octets().to_vec(),
            ),
            GeneralName::Ip(IpAddr::V6(a)) => RawTlv::encode(
                &Implicit::<IP_ADDRESS, _>(OctetString),
                &a.octets().to_vec(),
            ),
        }
    }
}

/// One `kind:value` item of a `subjectAltName` value.
///
/// # Errors
///
/// [`Error::Usage`] for an item without a value, a value that is not
/// ASCII or a bad IP address; [`Error::Unsupported`] for another kind, and
/// for `email:copy` and `email:move`.
impl TryFrom<&ConfItem> for GeneralName {
    type Error = Error;

    fn try_from(item: &ConfItem) -> Result<Self> {
        // ossl_v3_name_cmp: "DNS" and "DNS.<anything>" both name DNS, which
        // is how a section lists several (DNS.1, DNS.2).
        let kind = item
            .name
            .split_once('.')
            .map_or(item.name.as_str(), |(k, _)| k);
        let value = item.value.as_deref().ok_or_else(|| {
            Error::Usage(format!("subjectAltName: {kind} without a value"))
        })?;
        let ia5 = || {
            value.parse::<Ia5String>().map_err(|_| {
                Error::Usage(format!("subjectAltName: {value:?} is not ASCII"))
            })
        };
        match kind {
            "DNS" => Ok(GeneralName::Dns(ia5()?)),
            "email" if value == "copy" || value == "move" => Err(
                Error::unsupported("subjectAltName email:copy and email:move"),
            ),
            "email" => Ok(GeneralName::Email(ia5()?)),
            "URI" => Ok(GeneralName::Uri(ia5()?)),
            "IP" => value.parse().map(GeneralName::Ip).map_err(|_| {
                Error::Usage(format!(
                    "subjectAltName: bad IP address {value:?}"
                ))
            }),
            other => {
                Err(Error::unsupported(format!("subjectAltName {other}:")))
            }
        }
    }
}

/// What an extension says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionValue {
    /// The subject's key identifier ([RFC 5280 section 4.2.1.2]).
    ///
    /// [RFC 5280 section 4.2.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
    SubjectKeyIdentifier(Vec<u8>),
    /// The issuer's key identifier, alone ([RFC 5280 section 4.2.1.1]).
    ///
    /// [RFC 5280 section 4.2.1.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
    AuthorityKeyIdentifier(Vec<u8>),
    /// What the key may be used for ([RFC 5280 section 4.2.1.3]).
    ///
    /// [RFC 5280 section 4.2.1.3]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
    KeyUsage(KeyUsage),
    /// The other names of the subject ([RFC 5280 section 4.2.1.6]).
    ///
    /// [RFC 5280 section 4.2.1.6]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
    SubjectAltName(Vec<GeneralName>),
    /// Whether the subject is a CA, and how many CAs may follow it
    /// ([RFC 5280 section 4.2.1.9]).
    ///
    /// [RFC 5280 section 4.2.1.9]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
    BasicConstraints {
        /// `cA`.
        ca: bool,
        /// `pathLenConstraint`.
        path_length: Option<u64>,
    },
    /// The purposes of the key, as object identifiers
    /// ([RFC 5280 section 4.2.1.12]).
    ///
    /// [RFC 5280 section 4.2.1.12]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12
    ExtendedKeyUsage(Vec<ObjectId>),
    /// Any other extension, as its identifier and the DER of its value:
    /// what copying a request's extensions carries without reading it.
    Other {
        /// `extnID`.
        oid: ObjectId,
        /// The contents of `extnValue`: the DER of the value, one TLV.
        der: RawTlv,
    },
}

impl ExtensionValue {
    /// The extension's object identifier.
    fn oid(&self) -> ObjectId {
        let kind = match self {
            ExtensionValue::SubjectKeyIdentifier(_) => {
                ExtensionKind::SubjectKeyIdentifier
            }
            ExtensionValue::AuthorityKeyIdentifier(_) => {
                ExtensionKind::AuthorityKeyIdentifier
            }
            ExtensionValue::KeyUsage(_) => ExtensionKind::KeyUsage,
            ExtensionValue::SubjectAltName(_) => ExtensionKind::SubjectAltName,
            ExtensionValue::BasicConstraints { .. } => {
                ExtensionKind::BasicConstraints
            }
            ExtensionValue::ExtendedKeyUsage(_) => {
                ExtensionKind::ExtendedKeyUsage
            }
            ExtensionValue::Other { oid, .. } => return oid.clone(),
        };
        kind.oid()
    }

    /// The DER of the value, one TLV: the contents of `extnValue`.
    fn to_raw(&self) -> RawTlv {
        match self {
            ExtensionValue::SubjectKeyIdentifier(id) => {
                RawTlv::encode(&OctetString, id)
            }
            ExtensionValue::AuthorityKeyIdentifier(id) => RawTlv::encode(
                &Sequence((Implicit::<0, _>(OctetString), ())),
                &(id.clone(), ()),
            ),
            ExtensionValue::KeyUsage(usage) => {
                RawTlv::encode(&NamedBits, &u64::from(usage.0))
            }
            ExtensionValue::SubjectAltName(names) => RawTlv::encode(
                &SequenceOf(Any),
                &names.iter().map(GeneralName::to_raw).collect(),
            ),
            ExtensionValue::BasicConstraints { ca, path_length } => {
                let ca_field = WithDefault::new(Boolean, false);
                match path_length {
                    Some(n) => RawTlv::encode(
                        &Sequence((ca_field, (Small, ()))),
                        &(*ca, (*n, ())),
                    ),
                    None => {
                        RawTlv::encode(&Sequence((ca_field, ())), &(*ca, ()))
                    }
                }
            }
            ExtensionValue::ExtendedKeyUsage(purposes) => {
                RawTlv::encode(&SequenceOf(ObjectIdentifier), purposes)
            }
            ExtensionValue::Other { der, .. } => der.clone(),
        }
    }

    /// `basicConstraints`: `CA:<bool>` and `pathlen:<n>`.
    fn basic_constraints(items: &[ConfItem]) -> Result<Self> {
        let mut ca = false;
        let mut path_length = None;
        for item in items {
            let bad = || {
                Error::Usage(format!(
                    "basicConstraints: bad item {}:{:?}",
                    item.name, item.value
                ))
            };
            match (item.name.as_str(), item.value.as_deref()) {
                ("CA", Some(v)) => ca = conf_bool_opt(v).ok_or_else(bad)?,
                ("pathlen", Some(v)) => {
                    path_length = Some(v.parse().map_err(|_| bad())?);
                }
                _ => return Err(bad()),
            }
        }
        Ok(ExtensionValue::BasicConstraints { ca, path_length })
    }
}

/// An extension: what it says, and whether it is critical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// `critical`.
    pub critical: bool,
    /// What it says.
    pub value: ExtensionValue,
}

/// `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN
/// DEFAULT FALSE, extnValue OCTET STRING }` ([RFC 5280 section 4.1]).
///
/// [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
/// It writes `critical` only when TRUE, as DER requires, and reads it the
/// same way; [`crate::cert::ExtensionViews`] is the lenient reader of
/// extensions read from certificates and requests.
type ExtensionSyntax =
    Sequence<(ObjectIdentifier, (WithDefault<Boolean>, (OctetString, ())))>;

/// The description of [`ExtensionSyntax`].
fn extension_syntax() -> ExtensionSyntax {
    Sequence((
        ObjectIdentifier,
        (WithDefault::new(Boolean, false), (OctetString, ())),
    ))
}

impl Extension {
    /// A non-critical extension.
    #[must_use]
    pub fn new(value: ExtensionValue) -> Self {
        Extension {
            critical: false,
            value,
        }
    }

    /// A critical extension.
    #[must_use]
    pub fn critical(value: ExtensionValue) -> Self {
        Extension {
            critical: true,
            value,
        }
    }

    /// The extension `name = value`, as the `FromStr` of [`Extension`]
    /// reads a line; a value `@section` lists the values of that section of
    /// `config` instead of its own items, as OpenSSL's `X509V3_EXT_nconf`
    /// reads them.
    ///
    /// # Errors
    ///
    /// As the `FromStr` of [`Extension`], and [`Error::Usage`] for an
    /// `@section` without a configuration or with no such section.
    pub(crate) fn from_name_value(
        name: &str,
        value: &str,
        config: Option<&Config>,
    ) -> Result<Self> {
        // v3_check_critical: exactly "critical,", then spaces.
        let (critical, value) = match value.strip_prefix("critical,") {
            Some(rest) => (true, rest.trim_start()),
            None => (false, value),
        };
        let items = match value.strip_prefix('@') {
            Some(section) => config
                .and_then(|c| c.section_opt(section))
                .ok_or_else(|| {
                    Error::Usage(format!("{name}: no section {section:?}"))
                })?
                .iter()
                .map(|v| ConfItem {
                    name: v.name.clone(),
                    value: Some(v.value.clone()),
                })
                .collect::<Vec<_>>(),
            None => value.parse::<ConfList>()?.0,
        };
        let names = || items.iter().map(|item| item.name.as_str());
        // OpenSSL looks the name up with OBJ_sn2nid: short names only.
        let oid = objects::find_by_short_name_opt(name).ok_or_else(|| {
            Error::Usage(format!("unknown extension name {name:?}"))
        })?;
        let unsupported = || Error::unsupported(format!("extension {name}"));
        let kind = ExtensionKind::from_oid_opt(&oid.as_oid())
            .ok_or_else(unsupported)?;
        let value = match kind {
            ExtensionKind::SubjectAltName => ExtensionValue::SubjectAltName(
                items
                    .iter()
                    .map(GeneralName::try_from)
                    .collect::<Result<_>>()?,
            ),
            ExtensionKind::KeyUsage => ExtensionValue::KeyUsage(
                names().try_fold(KeyUsage::default(), |set, name| {
                    Ok::<_, Error>(set.union(name.parse()?))
                })?,
            ),
            ExtensionKind::ExtendedKeyUsage => {
                ExtensionValue::ExtendedKeyUsage(
                    names()
                        .map(|i| {
                            objects::find_by_name_opt(i).ok_or_else(|| {
                                Error::Usage(format!(
                                    "extendedKeyUsage: unknown purpose {i:?}"
                                ))
                            })
                        })
                        .collect::<Result<_>>()?,
                )
            }
            ExtensionKind::BasicConstraints => {
                ExtensionValue::basic_constraints(&items)?
            }
            ExtensionKind::SubjectKeyIdentifier
            | ExtensionKind::AuthorityKeyIdentifier
            | ExtensionKind::IssuerAltName => return Err(unsupported()),
        };
        Ok(Extension { critical, value })
    }

    /// The DER `Extension`.
    pub(crate) fn to_raw(&self) -> RawTlv {
        RawTlv::encode(
            &extension_syntax(),
            &(
                self.value.oid(),
                (self.critical, (self.value.to_raw().as_bytes().to_vec(), ())),
            ),
        )
    }
}

/// An extension as read from a certificate or a request, kept opaque
/// ([`ExtensionValue::Other`]): what copying needs, since a typed value
/// would re-encode, and a copy must keep the original bytes even where
/// they are not the canonical encoding.
///
/// # Errors
///
/// An `extnValue` whose contents are not one DER TLV.
impl TryFrom<&ExtensionView<'_>> for Extension {
    type Error = Error;

    fn try_from(view: &ExtensionView<'_>) -> Result<Self> {
        Ok(Extension {
            critical: view.critical,
            value: ExtensionValue::Other {
                oid: view.oid.into(),
                der: RawTlv::parse(view.value)?,
            },
        })
    }
}

/// What an extension read from a certificate says, for the kinds baldssl
/// reads (subject key identifier, basic constraints, key usage and extended
/// key usage, in DER), and opaque for the others. The `-text` printer reads
/// subject key identifiers and extended key usages through it; it reads
/// basic constraints and key usage itself, as OpenSSL prints the malformed
/// values of those two that this refuses (an explicit `cA FALSE`, a
/// negative or large path length, a key usage with trailing zero bits).
///
/// # Errors
///
/// A value of one of those kinds that is not its DER, a path length beyond
/// 64 bits, and an other value that is not one DER TLV.
impl TryFrom<&ExtensionView<'_>> for ExtensionValue {
    type Error = Error;

    fn try_from(view: &ExtensionView<'_>) -> Result<Self> {
        if view.oid == ID_CE_SUBJECT_KEY_IDENTIFIER {
            return Ok(ExtensionValue::SubjectKeyIdentifier(decode(
                &OctetString,
                view.value,
            )?));
        }
        if view.oid == ID_CE_EXT_KEY_USAGE {
            return Ok(ExtensionValue::ExtendedKeyUsage(decode(
                &SequenceOf(ObjectIdentifier),
                view.value,
            )?));
        }
        if view.oid == ID_CE_BASIC_CONSTRAINTS {
            let syntax = Sequence((
                WithDefault::new(Boolean, false),
                (Optional(Small), ()),
            ));
            let (ca, (path_length, ())) = decode(&syntax, view.value)?;
            return Ok(ExtensionValue::BasicConstraints { ca, path_length });
        }
        if view.oid == ID_CE_KEY_USAGE {
            let bits = decode(&NamedBits, view.value)?;
            let named = u16::try_from(bits & NAMED_KEY_USAGE_BITS)
                .map_err(|_| Error::invalid("keyUsage"))?;
            return Ok(ExtensionValue::KeyUsage(KeyUsage(named)));
        }
        Ok(ExtensionValue::Other {
            oid: view.oid.into(),
            der: RawTlv::parse(view.value)?,
        })
    }
}

/// The extension of a `name=value` line, as `openssl req -addext` and
/// the extension sections of a configuration file write it:
/// `subjectAltName`, `keyUsage`, `extendedKeyUsage` and
/// `basicConstraints`, by short name only (`OBJ_sn2nid`); the names of
/// usages and purposes may be short or long.
///
/// # Errors
///
/// [`Error::Usage`] for a malformed line, [`Error::Unsupported`] for
/// another extension or value kind.
impl FromStr for Extension {
    type Err = Error;

    fn from_str(line: &str) -> Result<Self> {
        let (name, value) = line.split_once('=').ok_or_else(|| {
            Error::Usage(format!("extension {line:?}: expected name=value"))
        })?;
        Self::from_name_value(name.trim(), value.trim(), None)
    }
}

/// The extensions of a certificate or a request: at most one of each
/// kind, in order.
///
/// [`Extensions::override_with`] is how OpenSSL combines extension
/// sources (the configuration's section, then `-addext`, or a request's
/// extensions, then `-extfile`): it adds the right side's in "replace"
/// mode (`X509V3_CTX_REPLACE`), which deletes an extension of the same
/// kind and appends the new one, so `a` overridden with `b` is `a` without
/// `b`'s kinds, then `b`. The operation is associative and idempotent (a
/// band), with the empty set as identity, and not commutative: the right
/// side wins both the value and the place, and is always a suffix.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions(Vec<Extension>);

impl Extensions {
    /// No extension.
    #[must_use]
    pub fn new() -> Self {
        Extensions(Vec::new())
    }

    /// Adds an extension of a kind not there yet.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] when one of that kind is there already.
    pub fn push_new(&mut self, extension: Extension) -> Result<()> {
        let oid = extension.value.oid();
        if self.0.iter().any(|e| e.value.oid() == oid) {
            return Err(Error::Usage(format!(
                "duplicate extension {}",
                oid.to_dotted()?
            )));
        }
        self.0.push(extension);
        Ok(())
    }

    /// These extensions, overridden with `other` (see the type).
    #[must_use]
    pub fn override_with(&self, other: &Extensions) -> Extensions {
        let mut out = self.0.clone();
        for extension in &other.0 {
            replace_push(&mut out, extension.clone(), |a, b| {
                a.value.oid() == b.value.oid()
            });
        }
        Extensions(out)
    }

    /// Whether there is an extension of the kind of `value`.
    #[must_use]
    pub fn contains_kind(&self, value: &ExtensionValue) -> bool {
        let oid = value.oid();
        self.0.iter().any(|e| e.value.oid() == oid)
    }

    /// The extensions, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[Extension] {
        &self.0
    }

    /// The extensions, in order.
    pub fn iter(&self) -> slice::Iter<'_, Extension> {
        self.0.iter()
    }

    /// Whether there is none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a Extensions {
    type Item = &'a Extension;
    type IntoIter = slice::Iter<'a, Extension>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<Extension> for Extensions {
    /// The extensions, a later one replacing an earlier one of its kind
    /// (which leaves its place: see [`Extensions::override_with`]).
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Extension>,
    {
        iter.into_iter().fold(Extensions::new(), |set, e| {
            set.override_with(&Extensions(vec![e]))
        })
    }
}

/// A boolean as OpenSSL's `X509V3_get_value_bool` reads it.
fn conf_bool_opt(text: &str) -> Option<bool> {
    match text {
        "TRUE" | "true" | "Y" | "y" | "YES" | "yes" => Some(true),
        "FALSE" | "false" | "N" | "n" | "NO" | "no" => Some(false),
        _ => None,
    }
}

/// OpenSSL's `strip_spaces`: leading spaces go, and trailing ones too,
/// except after a single character, where OpenSSL's loop stops on that
/// character and leaves them (`"a "` stays `"a "`, `"ab "` becomes `"ab"`).
/// `None` for an item of spaces only.
fn strip_spaces_opt(item: &str) -> Option<&str> {
    let start = item.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let end = start.trim_end_matches(|c: char| c.is_ascii_whitespace());
    match end.chars().count() {
        0 => None,
        1 => Some(start),
        _ => Some(end),
    }
}

/// One item of a configuration value's list: `name`, or `name:value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfItem {
    /// The name, before the first `:`.
    pub(crate) name: String,
    /// The value, after it, if there is a `:`.
    pub(crate) value: Option<String>,
}

/// A value's list as OpenSSL's `X509V3_parse_list` reads it: items
/// separated by `,`, each `name` or `name:value` (split at the first `:`),
/// with [`strip_spaces_opt`] applied to names and values. Reading stops at
/// a line break, as OpenSSL's does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfList(pub(crate) Vec<ConfItem>);

/// # Errors
///
/// [`Error::Usage`] for an empty name or value, as OpenSSL refuses them.
impl FromStr for ConfList {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let line = value.split_once(['\r', '\n']).map_or(value, |(l, _)| l);
        let empty =
            || Error::Usage(format!("extension value {value:?}: empty item"));
        let item = |text: &str| {
            strip_spaces_opt(text).map(str::to_string).ok_or_else(empty)
        };
        let mut out = Vec::new();
        let mut rest = line;
        loop {
            // A name runs to the first ':' or ','; after a ':', the value
            // runs to the next ','.
            let Some(stop) = rest.find([':', ',']) else {
                out.push(ConfItem {
                    name: item(rest)?,
                    value: None,
                });
                return Ok(ConfList(out));
            };
            let (name, tail) = rest.split_at(stop);
            let mut chars = tail.chars();
            let separator = chars.next();
            let after = chars.as_str();
            if separator == Some(':') {
                let (value, next) = after
                    .split_once(',')
                    .map_or((after, None), |(v, n)| (v, Some(n)));
                out.push(ConfItem {
                    name: item(name)?,
                    value: Some(item(value)?),
                });
                match next {
                    Some(next) => rest = next,
                    None => return Ok(ConfList(out)),
                }
            } else {
                // The separator `find` stopped at is a ','.
                out.push(ConfItem {
                    name: item(name)?,
                    value: None,
                });
                rest = after;
            }
        }
    }
}

#[cfg(test)]
mod tests;
