//! The certificate structure ([RFC 5280 section 4.1][rfc5280-4.1]), decoded from DER.
//!
//! The decoder borrows from the input: every field is a view into the DER
//! bytes, so the original encoding is kept exactly (needed for fingerprints
//! and for `-outform DER`, which must reproduce the input byte for byte).
//!
//! [rfc5280-4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1

use baldssl_core::{
    Error, Result,
    der::{BitString, Integer, Oid, Reader, Time, TimeKind, Tlv, tag},
    encoding::Encodable,
};
use baldssl_pkey::{AnyPrivateKey, PublicKey};

use crate::{
    name::Name,
    version::{Version, version_field},
};

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlgorithmIdentifier<'a> {
    /// The algorithm.
    pub(crate) oid: Oid<'a>,
    /// The raw parameters, if present.
    pub(crate) parameters: Option<Tlv<'a>>,
}

impl<'a> AlgorithmIdentifier<'a> {
    /// Decodes one AlgorithmIdentifier from `r`.
    ///
    /// # Errors
    ///
    /// On malformed DER.
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self> {
        let mut seq = r.sequence()?;
        let oid = Oid::parse(seq.expect(tag::OID)?.value)?;
        let parameters = if seq.is_empty() {
            None
        } else {
            Some(seq.read()?)
        };
        seq.finish()?;
        Ok(AlgorithmIdentifier { oid, parameters })
    }
}

/// `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubjectPublicKeyInfo<'a> {
    /// The key algorithm and its parameters.
    pub(crate) algorithm: AlgorithmIdentifier<'a>,
    /// The `subjectPublicKey` BIT STRING.
    pub(crate) public_key: BitString<'a>,
}

/// One `Extension`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Extension<'a> {
    /// `extnID`.
    pub(crate) oid: Oid<'a>,
    /// `critical`, `DEFAULT FALSE`.
    pub(crate) critical: bool,
    /// The contents of `extnValue` (the DER of the extension's own type).
    pub(crate) value: &'a [u8],
}

/// `Validity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validity {
    /// `notBefore`.
    pub not_before: Time,
    /// `notAfter`.
    pub not_after: Time,
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
    pub(crate) tbs_signature: AlgorithmIdentifier<'a>,
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
    pub(crate) extensions: Vec<Extension<'a>>,
    /// The outer `signatureAlgorithm`.
    pub(crate) signature_algorithm: AlgorithmIdentifier<'a>,
    /// The `signatureValue` bytes.
    pub(crate) signature: BitString<'a>,
}

fn read_time(r: &mut Reader<'_>) -> Result<Time> {
    let tlv = r.read()?;
    let kind = match tlv.octet() {
        tag::UTC_TIME => TimeKind::Utc,
        tag::GENERALIZED_TIME => TimeKind::Generalized,
        found => {
            return Err(baldssl_core::der::DerError::UnexpectedTag {
                expected: tag::UTC_TIME,
                found,
            }
            .into());
        }
    };
    Ok(Time::parse(kind, tlv.value)?)
}

fn read_extensions(value: &[u8]) -> Result<Vec<Extension<'_>>> {
    let mut outer = Reader::new(value);
    let mut seq = outer.sequence()?;
    outer.finish()?;
    let mut out = Vec::new();
    while !seq.is_empty() {
        let mut ext = seq.sequence()?;
        let oid = Oid::parse(ext.expect(tag::OID)?.value)?;
        let critical = match ext.optional(tag::BOOLEAN)? {
            Some(b) => baldssl_core::der::parse_bool(b.value)?,
            None => false,
        };
        let value = ext.expect(tag::OCTET_STRING)?.value;
        ext.finish()?;
        out.push(Extension {
            oid,
            critical,
            value,
        });
    }
    Ok(out)
}

impl<'a> Certificate<'a> {
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
    pub(crate) fn subject_key_identifier_opt(&self) -> Option<&'a [u8]> {
        let ext = self
            .extensions
            .iter()
            .find(|e| e.oid.as_bytes() == [0x55, 0x1d, 0x0e])?;
        let mut r = Reader::new(ext.value);
        let id = r.expect(tag::OCTET_STRING).ok()?;
        r.finish().ok()?;
        Some(id.value)
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

        let mut tbs = cert.sequence()?;
        let version = tbs.syntax(&version_field())?.unwrap_or_else(Version::v1);
        let serial = Integer::parse(tbs.expect(tag::INTEGER)?.value)?;
        let tbs_signature = AlgorithmIdentifier::read(&mut tbs)?;
        let issuer = Name::read(&mut tbs)?;
        let mut validity = tbs.sequence()?;
        let validity_v = Validity {
            not_before: read_time(&mut validity)?,
            not_after: read_time(&mut validity)?,
        };
        validity.finish()?;
        let subject_tlv = tbs.expect(tag::SEQUENCE)?;
        let subject = Name::from_contents(subject_tlv.value)?;

        let spki_tlv = tbs.expect(tag::SEQUENCE)?;
        let mut spki_r = Reader::new(spki_tlv.value);
        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier::read(&mut spki_r)?,
            public_key: BitString::parse(
                spki_r.expect(tag::BIT_STRING)?.value,
            )?,
        };
        spki_r.finish()?;

        if tbs.peek_octet_opt() == Some(tag::context(1))
            || tbs.peek_octet_opt() == Some(tag::context(2))
        {
            return Err(Error::unsupported("issuerUniqueID / subjectUniqueID"));
        }
        let extensions = match tbs.optional(tag::context_constructed(3))? {
            Some(e) => read_extensions(e.value)?,
            None => Vec::new(),
        };
        tbs.finish()?;

        let signature_algorithm = AlgorithmIdentifier::read(&mut cert)?;
        let signature = BitString::parse(cert.expect(tag::BIT_STRING)?.value)?;
        cert.finish()?;

        Ok(Certificate {
            der,
            version,
            serial,
            tbs_signature,
            issuer,
            validity: validity_v,
            subject,
            subject_der: subject_tlv.encoded,
            spki,
            spki_der: spki_tlv.encoded,
            extensions,
            signature_algorithm,
            signature,
        })
    }
}
