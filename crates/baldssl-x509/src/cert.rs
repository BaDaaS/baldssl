//! The certificate structure ([RFC 5280 section 4.1][rfc5280-4.1]), decoded from DER.
//!
//! The decoder borrows from the input: every field is a view into the DER
//! bytes, so the original encoding is kept exactly (needed for fingerprints
//! and for `-outform DER`, which must reproduce the input byte for byte).
//!
//! [rfc5280-4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1

use std::slice;

use baldssl_core::{
    Error, Result,
    der::{
        BitString, DerError, Integer, Oid, Reader, Time, TimeKind, Tlv,
        parse_bool, tag,
    },
    encoding::Encodable,
};
use baldssl_pkey::{AnyPrivateKey, PublicKey};

use crate::{
    algorithm::{AlgorithmIdentifier, algorithm_identifier},
    extension::ExtensionValue,
    name::Name,
    oid::ID_CE_SUBJECT_KEY_IDENTIFIER,
    version::{Version, version_field},
};

/// `issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL`, the context tag
/// of the TBSCertificate field ([RFC 5280 section 4.1]).
///
/// [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
const ISSUER_UNIQUE_ID: u8 = tag::context(1);
/// `subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL`
/// ([RFC 5280 section 4.1]).
///
/// [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
const SUBJECT_UNIQUE_ID: u8 = tag::context(2);
/// `extensions [3] EXPLICIT Extensions OPTIONAL` ([RFC 5280 section 4.1]).
///
/// [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
const EXTENSIONS: u8 = tag::context_constructed(3);

/// The error of a TLV whose identifier octet is not `expected`.
fn unexpected_tag(expected: u8, found: &Tlv<'_>) -> Error {
    DerError::UnexpectedTag {
        expected,
        found: found.octet_opt(),
    }
    .into()
}

/// `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubjectPublicKeyInfo<'a> {
    /// The key algorithm and its parameters.
    pub(crate) algorithm: AlgorithmIdentifier,
    /// The `subjectPublicKey` BIT STRING.
    pub(crate) public_key: BitString<'a>,
}

/// The view of a DER `SubjectPublicKeyInfo` ([RFC 5280] section 4.1),
/// which certificates and requests share.
///
/// # Errors
///
/// A TLV that is not a SEQUENCE, or malformed contents.
///
/// [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
impl<'a> TryFrom<Tlv<'a>> for SubjectPublicKeyInfo<'a> {
    type Error = Error;

    fn try_from(tlv: Tlv<'a>) -> Result<Self> {
        if tlv.octet_opt() != Some(tag::SEQUENCE) {
            return Err(unexpected_tag(tag::SEQUENCE, &tlv));
        }
        let mut r = Reader::new(tlv.value());
        let spki = SubjectPublicKeyInfo {
            algorithm: r.syntax(&algorithm_identifier())?,
            public_key: BitString::parse(r.expect(tag::BIT_STRING)?.value())?,
        };
        r.finish()?;
        Ok(spki)
    }
}

/// One `Extension` of a certificate or a request, as a view of its DER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Extension<'a> {
    /// `extnID`.
    pub(crate) oid: Oid<'a>,
    /// `critical`, `DEFAULT FALSE`.
    pub(crate) critical: bool,
    /// The contents of `extnValue` (the DER of the extension's own type).
    pub(crate) value: &'a [u8],
}

/// The extensions of a certificate or a request, in order, as views of
/// their DER: what the `-text` printer and verification read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ExtensionViews<'a>(pub(crate) Vec<Extension<'a>>);

impl<'a> ExtensionViews<'a> {
    /// The extensions, in order.
    pub(crate) fn iter(&self) -> slice::Iter<'_, Extension<'a>> {
        self.0.iter()
    }

    /// Whether there is none.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'v, 'a> IntoIterator for &'v ExtensionViews<'a> {
    type Item = &'v Extension<'a>;
    type IntoIter = slice::Iter<'v, Extension<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The extensions of a DER `Extensions` (`SEQUENCE OF Extension`,
/// [RFC 5280 section 4.1]), in order: a certificate's, or a request's
/// `extensionRequest` attribute.
///
/// This is a second reader of `Extension`, beside the description
/// [`crate::extension::Extension`] writes with, for two reasons: it borrows
/// the input, so that the `-text` printer and copying see the bytes as they
/// are, and it is lenient where OpenSSL is. DER forbids writing `critical`
/// when it is FALSE, its default ([X.690] 11.5), and the description refuses
/// it; OpenSSL 3.5 and 4.1 read such an extension and print it as not
/// critical, so this reads it too (`extension_views_accept_explicit_false`
/// tests the difference).
///
/// # Errors
///
/// A TLV that is not a SEQUENCE, or malformed extensions.
///
/// [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
impl<'a> TryFrom<Tlv<'a>> for ExtensionViews<'a> {
    type Error = Error;

    fn try_from(list: Tlv<'a>) -> Result<Self> {
        if list.octet_opt() != Some(tag::SEQUENCE) {
            return Err(unexpected_tag(tag::SEQUENCE, &list));
        }
        let mut seq = Reader::new(list.value());
        let mut out = Vec::new();
        while !seq.is_empty() {
            let mut ext = seq.sequence()?;
            let oid = Oid::parse(ext.expect(tag::OID)?.value())?;
            let critical = match ext.optional(tag::BOOLEAN)? {
                Some(b) => parse_bool(b.value())?,
                None => false,
            };
            let value = ext.expect(tag::OCTET_STRING)?.value();
            ext.finish()?;
            out.push(Extension {
                oid,
                critical,
                value,
            });
        }
        Ok(ExtensionViews(out))
    }
}

/// `Validity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validity {
    /// `notBefore`.
    pub not_before: Time,
    /// `notAfter`.
    pub not_after: Time,
}

/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`, each `Time` a
/// UTCTime or a GeneralizedTime ([RFC 5280 section 4.1.2.5]).
///
/// # Errors
///
/// A TLV that is not a SEQUENCE of two times.
///
/// [RFC 5280 section 4.1.2.5]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
impl TryFrom<Tlv<'_>> for Validity {
    type Error = Error;

    fn try_from(tlv: Tlv<'_>) -> Result<Self> {
        if tlv.octet_opt() != Some(tag::SEQUENCE) {
            return Err(unexpected_tag(tag::SEQUENCE, &tlv));
        }
        let mut r = Reader::new(tlv.value());
        let mut time = || -> Result<Time> {
            let t = r.read()?;
            let kind = match t.octet_opt() {
                Some(tag::UTC_TIME) => TimeKind::Utc,
                Some(tag::GENERALIZED_TIME) => TimeKind::Generalized,
                _ => return Err(unexpected_tag(tag::UTC_TIME, &t)),
            };
            Ok(Time::parse(kind, t.value())?)
        };
        let validity = Validity {
            not_before: time()?,
            not_after: time()?,
        };
        r.finish()?;
        Ok(validity)
    }
}

/// A decoded X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// The complete DER encoding.
    pub der: &'a [u8],
    /// `version`, v1 when the field is absent.
    pub(crate) version: Version,
    /// `serialNumber`.
    pub serial: Integer,
    /// `signature` inside the TBSCertificate.
    pub(crate) tbs_signature: AlgorithmIdentifier,
    /// `issuer`.
    pub issuer: Name<'a>,
    /// `validity`.
    pub validity: Validity,
    /// `subject`.
    pub subject: Name<'a>,
    /// The DER of `subject`, as it is: the issuer name of what this
    /// certificate signs.
    pub(crate) subject_der: &'a [u8],
    /// `subjectPublicKeyInfo`.
    pub(crate) spki: SubjectPublicKeyInfo<'a>,
    /// The DER of `subjectPublicKeyInfo`.
    pub(crate) spki_der: &'a [u8],
    /// `extensions`, empty when absent.
    pub(crate) extensions: ExtensionViews<'a>,
    /// The DER of the `TBSCertificate`, as signed.
    pub(crate) tbs_der: &'a [u8],
    /// The outer `signatureAlgorithm`.
    pub(crate) signature_algorithm: AlgorithmIdentifier,
    /// The `signatureValue` bytes.
    pub(crate) signature: BitString<'a>,
}

impl<'a> Certificate<'a> {
    /// The PEM label of a certificate, `PEM_STRING_X509` in
    /// `include/openssl/pem.h` ([RFC 7468 section 5.1]).
    ///
    /// [RFC 7468 section 5.1]: https://www.rfc-editor.org/rfc/rfc7468#section-5.1
    pub const LABEL: &'static str = "CERTIFICATE";

    /// Whether `key` is the private key of this certificate's public key,
    /// as OpenSSL's `X509_check_private_key` asks.
    #[must_use]
    pub fn matches_private_key(&self, key: &AnyPrivateKey) -> bool {
        PublicKey::from(key).encode() == self.spki_der
    }

    /// The contents of the subject key identifier extension
    /// ([RFC 5280 section 4.2.1.2]), when it is present and well formed.
    ///
    /// [RFC 5280 section 4.2.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
    pub(crate) fn subject_key_identifier_opt(&self) -> Option<Vec<u8>> {
        let ext = self
            .extensions
            .iter()
            .find(|e| e.oid == ID_CE_SUBJECT_KEY_IDENTIFIER)?;
        match ExtensionValue::try_from(ext).ok()? {
            ExtensionValue::SubjectKeyIdentifier(id) => Some(id),
            // The decoding of a subjectKeyIdentifier value gives no other
            // kind.
            ExtensionValue::AuthorityKeyIdentifier(_)
            | ExtensionValue::KeyUsage(_)
            | ExtensionValue::SubjectAltName(_)
            | ExtensionValue::BasicConstraints { .. }
            | ExtensionValue::ExtendedKeyUsage(_)
            | ExtensionValue::Other { .. } => None,
        }
    }

    /// Decodes a DER certificate. The whole input must be one certificate.
    ///
    /// # Errors
    ///
    /// On malformed DER, and [`Error::Unsupported`] for the v2 unique
    /// identifiers.
    pub fn from_der(der: &'a [u8]) -> Result<Self> {
        let mut top = Reader::new(der);
        let mut cert = top.sequence()?;
        top.finish()?;

        let tbs_tlv = cert.expect(tag::SEQUENCE)?;
        let mut tbs = Reader::new(tbs_tlv.value());
        let version = tbs.syntax(&version_field())?.unwrap_or_else(Version::v1);
        let serial = Integer::parse(tbs.expect(tag::INTEGER)?.value())?;
        let tbs_signature = tbs.syntax(&algorithm_identifier())?;
        let issuer = Name::read(&mut tbs)?;
        let validity = Validity::try_from(tbs.read()?)?;
        let subject_tlv = tbs.expect(tag::SEQUENCE)?;
        let subject = Name::from_contents(subject_tlv.value())?;

        let spki_tlv = tbs.expect(tag::SEQUENCE)?;
        let spki = SubjectPublicKeyInfo::try_from(spki_tlv)?;

        if tbs.peek_octet_opt() == Some(ISSUER_UNIQUE_ID)
            || tbs.peek_octet_opt() == Some(SUBJECT_UNIQUE_ID)
        {
            return Err(Error::unsupported("issuerUniqueID / subjectUniqueID"));
        }
        let extensions = match tbs.optional(EXTENSIONS)? {
            Some(e) => {
                let mut inner = Reader::new(e.value());
                let list = inner.read()?;
                inner.finish()?;
                ExtensionViews::try_from(list)?
            }
            None => ExtensionViews::default(),
        };
        tbs.finish()?;

        let signature_algorithm = cert.syntax(&algorithm_identifier())?;
        let signature =
            BitString::parse(cert.expect(tag::BIT_STRING)?.value())?;
        cert.finish()?;

        Ok(Certificate {
            der,
            version,
            serial,
            tbs_signature,
            issuer,
            validity,
            subject,
            subject_der: subject_tlv.encoded(),
            spki,
            spki_der: spki_tlv.encoded(),
            extensions,
            tbs_der: tbs_tlv.encoded(),
            signature_algorithm,
            signature,
        })
    }
}
