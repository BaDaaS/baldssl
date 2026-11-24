//! Issuing certificates: the `TBSCertificate` of [RFC 5280 section 4.1],
//! signed.
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!     tbsCertificate      TBSCertificate,
//!     signatureAlgorithm  AlgorithmIdentifier,
//!     signatureValue      BIT STRING }
//!
//! TBSCertificate ::= SEQUENCE {
//!     version          [0] EXPLICIT Version DEFAULT v1,
//!     serialNumber     CertificateSerialNumber,
//!     signature        AlgorithmIdentifier,
//!     issuer           Name,
//!     validity         Validity,
//!     subject          Name,
//!     subjectPublicKeyInfo SubjectPublicKeyInfo,
//!     extensions       [3] EXPLICIT Extensions OPTIONAL }
//! ```
//!
//! The certificates written here are version 3 with extensions.
//! [`CertificateTemplate::self_signed`] gives the extensions of the
//! `v3_ca` section of OpenSSL's default configuration file, which `openssl
//! req -x509` uses: a subject key identifier (the SHA-1 of the key's bits,
//! [RFC 5280 section 4.2.1.2], method 1), an authority key identifier, and
//! basic constraints, critical, `CA:TRUE`. The authority key identifier
//! depends on the release line ([`Compat`]): OpenSSL 3's file says
//! `keyid:always,issuer`, so a self-signed certificate carries its own key
//! identifier there too; OpenSSL 4's says `keyid:nonss,issuer:nonss`
//! ("non-self-signed"), so it carries none. baldssl reads no configuration
//! file, so this is what a default installation of OpenSSL writes; one
//! without a configuration file writes only the subject key identifier.
//!
//! [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
//! [RFC 5280 section 4.2.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2

use baldssl_core::{
    Result,
    der::{
        Time,
        syntax::{
            Any, BitString, Boolean, Explicit, Implicit, Natural, ObjectId,
            ObjectIdentifier, OctetString, RawTlv, Sequence, SequenceOf, Small,
            Unsigned, WithDefault, encode,
        },
    },
    encoding::Encodable,
};
use baldssl_crypto::{
    Digest, hash::Sha1, os_rng, signature::SignatureAlgorithm,
};
use baldssl_pkey::{AnyPrivateKey, PublicKey};

use crate::{
    Compat,
    algorithm::{ALGORITHM_IDENTIFIER, identifier},
    cert::Validity,
    dn::DistinguishedName,
};

/// A certificate serial number: a positive integer of at most 20 octets
/// ([RFC 5280 section 4.1.2.2]).
///
/// [RFC 5280 section 4.1.2.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialNumber(Natural);

impl SerialNumber {
    /// The serial number with these big-endian bytes; `None` when it is
    /// zero or longer than 20 octets once encoded.
    #[must_use]
    pub fn new_opt(be: &[u8]) -> Option<Self> {
        let n = Natural::from_be_bytes(be);
        let digits = n.as_be_bytes();
        let octets = digits.len().saturating_add(usize::from(
            digits.first().is_some_and(|&b| b >= 0x80),
        ));
        (!digits.is_empty() && octets <= 20).then_some(SerialNumber(n))
    }

    /// A random serial number of 159 bits, as OpenSSL's `rand_serial`
    /// draws it (`SERIAL_RAND_BITS`): 20 octets once encoded, positive.
    ///
    /// # Errors
    ///
    /// The operating system's randomness failing.
    pub fn random() -> Result<Self> {
        loop {
            let mut bytes = [0u8; 20];
            os_rng::fill(&mut bytes).map_err(|e| baldssl_core::Error::Io {
                context: "drawing a serial number".into(),
                message: e.to_string(),
            })?;
            if let Some(first) = bytes.first_mut() {
                *first &= 0x7f;
            }
            if let Some(serial) = Self::new_opt(&bytes) {
                return Ok(serial);
            }
        }
    }

    /// The big-endian bytes, without leading zeros.
    #[must_use]
    pub fn as_be_bytes(&self) -> &[u8] {
        self.0.as_be_bytes()
    }
}

impl Validity {
    /// From `not_before` to `not_after`, seconds after the Unix epoch, each
    /// encoded as RFC 5280 requires.
    #[must_use]
    pub fn from_unix_seconds(not_before: u64, not_after: u64) -> Self {
        Validity {
            not_before: Time::from_unix_seconds(not_before),
            not_after: Time::from_unix_seconds(not_after),
        }
    }
}

/// `subjectKeyIdentifier`, 2.5.29.14.
const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x0e]);
/// `basicConstraints`, 2.5.29.19.
const ID_CE_BASIC_CONSTRAINTS: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x13]);
/// `authorityKeyIdentifier`, 2.5.29.35.
const ID_CE_AUTHORITY_KEY_IDENTIFIER: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x23]);

/// An extension a certificate written here can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// The subject's key identifier ([RFC 5280 section 4.2.1.2]).
    ///
    /// [RFC 5280 section 4.2.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
    SubjectKeyIdentifier(Vec<u8>),
    /// The issuer's key identifier, alone ([RFC 5280 section 4.2.1.1]).
    ///
    /// [RFC 5280 section 4.2.1.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
    AuthorityKeyIdentifier(Vec<u8>),
    /// Whether the subject is a CA, and how many CAs may follow it
    /// ([RFC 5280 section 4.2.1.9]); critical, as `v3_ca` writes it.
    ///
    /// [RFC 5280 section 4.2.1.9]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
    BasicConstraints {
        /// `cA`.
        ca: bool,
        /// `pathLenConstraint`.
        path_length: Option<u64>,
    },
}

/// `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN
/// DEFAULT FALSE, extnValue OCTET STRING }` (RFC 5280 section 4.1).
type ExtensionSyntax =
    Sequence<(ObjectIdentifier, (WithDefault<Boolean>, (OctetString, ())))>;

impl Extension {
    /// The extension's DER `Extension`.
    fn to_raw(&self) -> RawTlv {
        let (oid, critical, value) = match self {
            Extension::SubjectKeyIdentifier(id) => (
                ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                encode(&OctetString, id),
            ),
            Extension::AuthorityKeyIdentifier(id) => (
                ID_CE_AUTHORITY_KEY_IDENTIFIER,
                false,
                encode(
                    &Sequence((Implicit::<0, _>(OctetString), ())),
                    &(id.clone(), ()),
                ),
            ),
            Extension::BasicConstraints { ca, path_length } => {
                let ca_field = WithDefault::new(Boolean, false);
                let value = match path_length {
                    Some(n) => encode(
                        &Sequence((ca_field, (Small, ()))),
                        &(*ca, (*n, ())),
                    ),
                    None => encode(&Sequence((ca_field, ())), &(*ca, ())),
                };
                (ID_CE_BASIC_CONSTRAINTS, true, value)
            }
        };
        let syntax: ExtensionSyntax = Sequence((
            ObjectIdentifier,
            (WithDefault::new(Boolean, false), (OctetString, ())),
        ));
        RawTlv::encode(&syntax, &(oid, (critical, (value, ()))))
    }
}

/// The key identifier of a public key: the SHA-1 of the bits of its
/// `subjectPublicKey` ([RFC 5280 section 4.2.1.2], method 1), as OpenSSL's
/// `hash` computes it.
///
/// [RFC 5280 section 4.2.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
#[must_use]
pub(crate) fn key_identifier(key: &PublicKey) -> Vec<u8> {
    Sha1::digest(&key.public_key_bytes())
}

/// What a certificate says, before it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateTemplate {
    /// `serialNumber`.
    pub serial: SerialNumber,
    /// `issuer`, a DER `Name`.
    pub issuer: Vec<u8>,
    /// `validity`.
    pub validity: Validity,
    /// `subject`, a DER `Name`.
    pub subject: Vec<u8>,
    /// `subjectPublicKeyInfo`.
    pub public_key: PublicKey,
    /// `extensions`, in order.
    pub extensions: Vec<Extension>,
}

impl CertificateTemplate {
    /// The self-signed CA certificate `openssl req -x509` of the release
    /// line `compat` writes with its default configuration: issuer and
    /// subject the same name, and the extensions of `v3_ca` (see the module
    /// documentation).
    #[must_use]
    pub fn self_signed(
        subject: &DistinguishedName,
        key: &PublicKey,
        serial: SerialNumber,
        validity: Validity,
        compat: Compat,
    ) -> Self {
        let name = subject.encode();
        let id = key_identifier(key);
        let mut extensions = vec![Extension::SubjectKeyIdentifier(id.clone())];
        // OpenSSL 4's `v3_ca` asks for an authority key identifier only
        // when the certificate is not self-signed (`keyid:nonss`).
        if compat != Compat::V4 {
            extensions.push(Extension::AuthorityKeyIdentifier(id));
        }
        extensions.push(Extension::BasicConstraints {
            ca: true,
            path_length: None,
        });
        CertificateTemplate {
            serial,
            issuer: name.clone(),
            validity,
            subject: name,
            public_key: key.clone(),
            extensions,
        }
    }

    /// The DER `TBSCertificate`, signed with `algorithm`.
    fn tbs(&self, algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
        let raw = |der: &[u8]| RawTlv::parse(der);
        let extensions: Vec<RawTlv> =
            self.extensions.iter().map(Extension::to_raw).collect();
        let validity = Sequence((Any, (Any, ())));
        let tbs = Sequence((
            Explicit::<0, _>(Small),
            (
                Unsigned,
                (
                    ALGORITHM_IDENTIFIER,
                    (
                        Any,
                        (
                            validity,
                            (
                                Any,
                                (Any, (Explicit::<3, _>(SequenceOf(Any)), ())),
                            ),
                        ),
                    ),
                ),
            ),
        ));
        Ok(encode(
            &tbs,
            &(
                2,
                (
                    self.serial.0.clone(),
                    (
                        identifier(algorithm),
                        (
                            raw(&self.issuer)?,
                            (
                                (
                                    raw(&self.validity.not_before.to_der())?,
                                    (
                                        raw(&self.validity.not_after.to_der())?,
                                        (),
                                    ),
                                ),
                                (
                                    raw(&self.subject)?,
                                    (
                                        raw(&self.public_key.encode())?,
                                        (extensions, ()),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ))
    }

    /// The DER certificate, signed by `issuer_key` with `algorithm`.
    ///
    /// # Errors
    ///
    /// When `algorithm` does not match the key, or a name is not one DER
    /// TLV.
    pub fn sign(
        &self,
        issuer_key: &AnyPrivateKey,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>> {
        let tbs = self.tbs(algorithm)?;
        let signature = issuer_key.sign(algorithm, &tbs)?;
        let certificate =
            Sequence((Any, (ALGORITHM_IDENTIFIER, (BitString, ()))));
        Ok(encode(
            &certificate,
            &(
                RawTlv::parse(&tbs)?,
                (identifier(algorithm), (signature, ())),
            ),
        ))
    }
}

#[cfg(test)]
mod tests;
