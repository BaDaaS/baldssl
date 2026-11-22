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
//! [`conf_list`]).
//!
//! [RFC 5280 section 4.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2

use std::net::IpAddr;

use baldssl_core::{
    Error, Result,
    der::syntax::{
        Boolean, Implicit, NamedBits, ObjectId, ObjectIdentifier, OctetString,
        RawTlv, Sequence, SequenceOf, Small, WithDefault, encode,
    },
};

use crate::{
    cert::Extension as ExtensionView,
    conf::{Config, replace_push},
    objects,
};

/// `subjectKeyIdentifier`, 2.5.29.14.
const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x0e]);
/// `keyUsage`, 2.5.29.15.
const ID_CE_KEY_USAGE: ObjectId = ObjectId::from_static(&[0x55, 0x1d, 0x0f]);
/// `subjectAltName`, 2.5.29.17.
const ID_CE_SUBJECT_ALT_NAME: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x11]);
/// `basicConstraints`, 2.5.29.19.
const ID_CE_BASIC_CONSTRAINTS: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x13]);
/// `authorityKeyIdentifier`, 2.5.29.35.
const ID_CE_AUTHORITY_KEY_IDENTIFIER: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x23]);
/// `extKeyUsage`, 2.5.29.37.
const ID_CE_EXT_KEY_USAGE: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x25]);

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

/// A set of key usages: a subset of the nine named bits of
/// [RFC 5280 section 4.2.1.3], bit `i` for the `i`-th. Sets form a Boolean
/// algebra under union and intersection, and DER writes each set one way
/// (the named bit list without trailing zeros).
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

    /// The usage of one name, short (`digitalSignature`) or long (`Digital
    /// Signature`), as OpenSSL reads it.
    #[must_use]
    pub fn from_name_opt(name: &str) -> Option<Self> {
        KEY_USAGE_BITS
            .iter()
            .position(|(short, long)| *short == name || *long == name)
            .and_then(|i| u32::try_from(i).ok())
            .map(|i| KeyUsage(1 << i))
    }

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

/// An IA5String: ASCII, as `dNSName`, `rfc822Name` and
/// `uniformResourceIdentifier` require ([RFC 5280 section 4.2.1.6]).
///
/// [RFC 5280 section 4.2.1.6]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ia5String(String);

impl Ia5String {
    /// The string, when it is ASCII.
    #[must_use]
    pub fn new_opt(text: &str) -> Option<Self> {
        text.is_ascii().then(|| Ia5String(text.to_string()))
    }

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
    fn encode(&self) -> Vec<u8> {
        match self {
            GeneralName::Email(s) => {
                encode(&Implicit::<1, _>(OctetString), &s.0.as_bytes().to_vec())
            }
            GeneralName::Dns(s) => {
                encode(&Implicit::<2, _>(OctetString), &s.0.as_bytes().to_vec())
            }
            GeneralName::Uri(s) => {
                encode(&Implicit::<6, _>(OctetString), &s.0.as_bytes().to_vec())
            }
            GeneralName::Ip(IpAddr::V4(a)) => {
                encode(&Implicit::<7, _>(OctetString), &a.octets().to_vec())
            }
            GeneralName::Ip(IpAddr::V6(a)) => {
                encode(&Implicit::<7, _>(OctetString), &a.octets().to_vec())
            }
        }
    }

    /// One `kind:value` item of a `subjectAltName` value.
    fn from_conf(name: &str, value: Option<&str>) -> Result<Self> {
        // ossl_v3_name_cmp: "DNS" and "DNS.<anything>" both name DNS, which
        // is how a section lists several (DNS.1, DNS.2).
        let kind = name.split_once('.').map_or(name, |(k, _)| k);
        let value = value.ok_or_else(|| {
            Error::Usage(format!("subjectAltName: {kind} without a value"))
        })?;
        let ia5 = || {
            Ia5String::new_opt(value).ok_or_else(|| {
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
        /// The contents of `extnValue`.
        der: Vec<u8>,
    },
}

impl ExtensionValue {
    /// The extension's object identifier.
    fn oid(&self) -> ObjectId {
        match self {
            ExtensionValue::SubjectKeyIdentifier(_) => {
                ID_CE_SUBJECT_KEY_IDENTIFIER
            }
            ExtensionValue::AuthorityKeyIdentifier(_) => {
                ID_CE_AUTHORITY_KEY_IDENTIFIER
            }
            ExtensionValue::KeyUsage(_) => ID_CE_KEY_USAGE,
            ExtensionValue::SubjectAltName(_) => ID_CE_SUBJECT_ALT_NAME,
            ExtensionValue::BasicConstraints { .. } => ID_CE_BASIC_CONSTRAINTS,
            ExtensionValue::ExtendedKeyUsage(_) => ID_CE_EXT_KEY_USAGE,
            ExtensionValue::Other { oid, .. } => oid.clone(),
        }
    }

    /// The DER of the value, the contents of `extnValue`.
    fn encode(&self) -> Vec<u8> {
        match self {
            ExtensionValue::SubjectKeyIdentifier(id) => {
                encode(&OctetString, id)
            }
            ExtensionValue::AuthorityKeyIdentifier(id) => encode(
                &Sequence((Implicit::<0, _>(OctetString), ())),
                &(id.clone(), ()),
            ),
            ExtensionValue::KeyUsage(usage) => {
                encode(&NamedBits, &u64::from(usage.0))
            }
            ExtensionValue::SubjectAltName(names) => {
                let names: Vec<RawTlv> = names
                    .iter()
                    .filter_map(|n| RawTlv::parse(&n.encode()).ok())
                    .collect();
                encode(&SequenceOf(baldssl_core::der::syntax::Any), &names)
            }
            ExtensionValue::BasicConstraints { ca, path_length } => {
                let ca_field = WithDefault::new(Boolean, false);
                match path_length {
                    Some(n) => encode(
                        &Sequence((ca_field, (Small, ()))),
                        &(*ca, (*n, ())),
                    ),
                    None => encode(&Sequence((ca_field, ())), &(*ca, ())),
                }
            }
            ExtensionValue::ExtendedKeyUsage(purposes) => {
                encode(&SequenceOf(ObjectIdentifier), purposes)
            }
            ExtensionValue::Other { der, .. } => der.clone(),
        }
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
/// DEFAULT FALSE, extnValue OCTET STRING }` (RFC 5280 section 4.1).
type ExtensionSyntax =
    Sequence<(ObjectIdentifier, (WithDefault<Boolean>, (OctetString, ())))>;

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

    /// An extension as read from a certificate or a request, kept opaque
    /// ([`ExtensionValue::Other`]): what copying needs.
    ///
    /// # Errors
    ///
    /// None in practice: the identifier was checked when read.
    pub(crate) fn from_view(view: &ExtensionView<'_>) -> Result<Self> {
        let oid = ObjectId::from_dotted_opt(&view.oid.to_dotted()?)
            .ok_or_else(|| Error::invalid("extension identifier"))?;
        Ok(Extension {
            critical: view.critical,
            value: ExtensionValue::Other {
                oid,
                der: view.value.to_vec(),
            },
        })
    }

    /// The DER `Extension`.
    pub(crate) fn to_raw(&self) -> RawTlv {
        let syntax: ExtensionSyntax = Sequence((
            ObjectIdentifier,
            (WithDefault::new(Boolean, false), (OctetString, ())),
        ));
        RawTlv::encode(
            &syntax,
            &(self.value.oid(), (self.critical, (self.value.encode(), ()))),
        )
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
    pub fn from_conf(line: &str) -> Result<Self> {
        let (name, value) = line.split_once('=').ok_or_else(|| {
            Error::Usage(format!("extension {line:?}: expected name=value"))
        })?;
        Self::from_conf_value(name.trim(), value.trim(), None)
    }

    /// The extension `name = value` of a configuration section, as
    /// [`Extension::from_conf`] reads a line; a value `@section` lists the
    /// values of that section of `config` instead of its own items, as
    /// OpenSSL's `X509V3_EXT_nconf` reads them.
    ///
    /// # Errors
    ///
    /// As [`Extension::from_conf`], and [`Error::Usage`] for an `@section`
    /// without a configuration or with no such section.
    pub fn from_conf_value(
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
                .map(|(n, v)| (n.clone(), Some(v.clone())))
                .collect(),
            None => conf_list(value)?,
        };
        let names = || items.iter().map(|(name, _)| name.as_str());
        // OpenSSL looks the name up with OBJ_sn2nid: short names only.
        let dotted =
            objects::find_by_short_name_opt(name).ok_or_else(|| {
                Error::Usage(format!("unknown extension name {name:?}"))
            })?;
        let value = match dotted {
            "2.5.29.17" => ExtensionValue::SubjectAltName(
                items
                    .iter()
                    .map(|(kind, value)| {
                        GeneralName::from_conf(kind, value.as_deref())
                    })
                    .collect::<Result<_>>()?,
            ),
            "2.5.29.15" => ExtensionValue::KeyUsage(names().try_fold(
                KeyUsage::default(),
                |set, i| {
                    KeyUsage::from_name_opt(i).map(|u| set.union(u)).ok_or_else(
                        || {
                            Error::Usage(format!(
                                "keyUsage: unknown usage {i:?}"
                            ))
                        },
                    )
                },
            )?),
            "2.5.29.37" => ExtensionValue::ExtendedKeyUsage(
                names()
                    .map(|i| {
                        objects::find_by_name_opt(i)
                            .and_then(ObjectId::from_dotted_opt)
                            .ok_or_else(|| {
                                Error::Usage(format!(
                                    "extendedKeyUsage: unknown purpose {i:?}"
                                ))
                            })
                    })
                    .collect::<Result<_>>()?,
            ),
            "2.5.29.19" => basic_constraints(&items)?,
            _ => {
                return Err(Error::unsupported(format!("extension {name}")));
            }
        };
        Ok(Extension { critical, value })
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

    /// The extensions of a configuration section, in order, a later one
    /// replacing an earlier one of its kind, as OpenSSL adds a section.
    ///
    /// # Errors
    ///
    /// As [`Extension::from_conf_value`] for each line; [`Error::Usage`]
    /// when there is no such section.
    pub fn from_section(config: &Config, section: &str) -> Result<Extensions> {
        config
            .section_opt(section)
            .ok_or_else(|| {
                Error::Usage(format!("no extension section {section:?}"))
            })?
            .iter()
            .map(|(name, value)| {
                Extension::from_conf_value(name, value, Some(config))
            })
            .collect()
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

    /// Whether there is none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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

/// `basicConstraints`: `CA:<bool>` and `pathlen:<n>`.
fn basic_constraints(
    items: &[(String, Option<String>)],
) -> Result<ExtensionValue> {
    let mut ca = false;
    let mut path_length = None;
    for (name, value) in items {
        let bad = || {
            Error::Usage(format!("basicConstraints: bad item {name}:{value:?}"))
        };
        match (name.as_str(), value.as_deref()) {
            ("CA", Some(v)) => ca = conf_bool_opt(v).ok_or_else(bad)?,
            ("pathlen", Some(v)) => {
                path_length = Some(v.parse().map_err(|_| bad())?);
            }
            _ => return Err(bad()),
        }
    }
    Ok(ExtensionValue::BasicConstraints { ca, path_length })
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

/// A value's list as OpenSSL's `X509V3_parse_list` reads it: items
/// separated by `,`, each `name` or `name:value` (split at the first `:`),
/// with [`strip_spaces_opt`] applied to names and values. Reading stops at
/// a line break, as OpenSSL's does.
///
/// # Errors
///
/// [`Error::Usage`] for an empty name or value, as OpenSSL refuses them.
pub(crate) fn conf_list(value: &str) -> Result<Vec<(String, Option<String>)>> {
    let line = value.split(['\r', '\n']).next().unwrap_or_default();
    let empty =
        || Error::Usage(format!("extension value {value:?}: empty item"));
    let mut out = Vec::new();
    let mut rest = line;
    loop {
        // A name runs to the first ':' or ','; after a ':', the value runs
        // to the next ','.
        let stop = rest.find([':', ',']);
        match stop.map(|i| (i, rest.as_bytes().get(i).copied())) {
            Some((i, Some(b':'))) => {
                let name = strip_spaces_opt(rest.get(..i).unwrap_or_default())
                    .ok_or_else(empty)?;
                let after = rest.get(i.saturating_add(1)..).unwrap_or_default();
                let (value, next) = match after.find(',') {
                    Some(j) => (
                        after.get(..j).unwrap_or_default(),
                        Some(
                            after
                                .get(j.saturating_add(1)..)
                                .unwrap_or_default(),
                        ),
                    ),
                    None => (after, None),
                };
                let value = strip_spaces_opt(value).ok_or_else(empty)?;
                out.push((name.to_string(), Some(value.to_string())));
                match next {
                    Some(next) => rest = next,
                    None => return Ok(out),
                }
            }
            Some((i, _)) => {
                let name = strip_spaces_opt(rest.get(..i).unwrap_or_default())
                    .ok_or_else(empty)?;
                out.push((name.to_string(), None));
                rest = rest.get(i.saturating_add(1)..).unwrap_or_default();
            }
            None => {
                let name = strip_spaces_opt(rest).ok_or_else(empty)?;
                out.push((name.to_string(), None));
                return Ok(out);
            }
        }
    }
}

#[cfg(test)]
mod tests;
