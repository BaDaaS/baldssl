//! Certificate signing requests: PKCS#10 ([RFC 2986]), the request a key
//! holder sends a certificate authority.
//!
//! ```text
//! CertificationRequest ::= SEQUENCE {
//!     certificationRequestInfo  CertificationRequestInfo,
//!     signatureAlgorithm        AlgorithmIdentifier,
//!     signature                 BIT STRING }
//!
//! CertificationRequestInfo ::= SEQUENCE {
//!     version        INTEGER { v1(0) },
//!     subject        Name,
//!     subjectPKInfo  SubjectPublicKeyInfo,
//!     attributes     [0] IMPLICIT SET OF Attribute }
//! ```
//!
//! The signature covers the DER of the `CertificationRequestInfo`, which
//! [`CertificationRequest`] keeps as read, so that verification checks the
//! bytes that were signed. It is made with the key whose public key the
//! request carries: a request is a proof of possession.
//!
//! Signing and verifying are the key's ([`AnyPrivateKey::sign`],
//! [`PublicKey::verify`]); this module only says what is signed. ECDSA
//! nonces are deterministic in baldssl ([RFC 6979]) and random in OpenSSL,
//! so an ECDSA request differs from OpenSSL's in its signature only; an
//! Ed25519 request is OpenSSL's, byte for byte.
//!
//! [RFC 2986]: https://www.rfc-editor.org/rfc/rfc2986#section-4
//! [RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979

use baldssl_core::{
    Error, Result,
    der::{
        Reader,
        syntax::{
            Any, BitString, Implicit, RawTlv, Sequence, SetOf, Small, decode,
            encode,
        },
        tag,
    },
    encoding::{Decodable, Encodable},
    pem::Pem,
};
use baldssl_crypto::signature::SignatureAlgorithm;
use baldssl_pkey::{AnyPrivateKey, PublicKey};

use crate::{
    Name,
    algorithm::{
        ALGORITHM_IDENTIFIER, AlgorithmIdentifier, from_identifier, identifier,
    },
    dn::DistinguishedName,
};

/// `CertificationRequestInfo`, with the subject and the key kept as TLVs.
type InfoSyntax =
    Sequence<(Small, (Any, (Any, (Implicit<0, SetOf<Any>>, ()))))>;

/// The description of [`InfoSyntax`].
const INFO: InfoSyntax =
    Sequence((Small, (Any, (Any, (Implicit::<0, _>(SetOf(Any)), ())))));

/// `CertificationRequest`, with the info kept as a TLV (the signed bytes).
type RequestSyntax = Sequence<(Any, (AlgorithmIdentifier, (BitString, ())))>;

/// The description of [`RequestSyntax`].
const REQUEST: RequestSyntax =
    Sequence((Any, (ALGORITHM_IDENTIFIER, (BitString, ()))));

/// A certificate signing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationRequest {
    /// The DER of the `CertificationRequestInfo`, as signed.
    info: RawTlv,
    /// The subject, a DER `Name`.
    subject: RawTlv,
    /// The key the request is for.
    public_key: PublicKey,
    /// The attributes, each a DER `Attribute`.
    attributes: Vec<RawTlv>,
    /// How it is signed.
    algorithm: SignatureAlgorithm,
    /// The signature: a DER `ECDSA-Sig-Value`, or 64 Ed25519 bytes.
    signature: Vec<u8>,
}

impl CertificationRequest {
    /// The request for `subject` with the public key of `key`, signed with
    /// `key` and `algorithm`, without attributes (as `openssl req -new`
    /// writes it without a configuration that adds any).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `algorithm` does not match the key.
    pub fn sign(
        subject: &DistinguishedName,
        key: &AnyPrivateKey,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self> {
        let public_key = PublicKey::from(key);
        let subject = RawTlv::parse(&subject.encode())?;
        let spki = RawTlv::parse(&public_key.encode())?;
        let attributes: Vec<RawTlv> = Vec::new();
        let info = RawTlv::parse(&encode(
            &INFO,
            &(0, (subject.clone(), (spki, (attributes.clone(), ())))),
        ))?;
        let signature = key.sign(algorithm, info.as_bytes())?;
        Ok(CertificationRequest {
            info,
            subject,
            public_key,
            attributes,
            algorithm,
            signature,
        })
    }

    /// Whether the signature verifies under the request's own key.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.public_key.verify(
            self.algorithm,
            self.info.as_bytes(),
            &self.signature,
        )
    }

    /// The subject, decoded.
    ///
    /// # Errors
    ///
    /// When the subject is not a well-formed Name.
    pub fn subject_name(&self) -> Result<Name<'_>> {
        Name::from_contents(
            Reader::new(self.subject.as_bytes())
                .expect(tag::SEQUENCE)?
                .value,
        )
    }

    /// The subject, a DER `Name`.
    #[must_use]
    pub fn subject_der(&self) -> &[u8] {
        self.subject.as_bytes()
    }

    /// The key the request is for.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The attributes, each a DER `Attribute`.
    #[must_use]
    pub fn attributes(&self) -> &[RawTlv] {
        &self.attributes
    }

    /// How the request is signed.
    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The signature: a DER `ECDSA-Sig-Value`, or the 64 bytes of Ed25519.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// The DER `CertificationRequest`.
impl Encodable for CertificationRequest {
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        encode(
            &REQUEST,
            &(
                self.info.clone(),
                (identifier(self.algorithm), (self.signature.clone(), ())),
            ),
        )
    }
}

/// A DER `CertificationRequest`: canonical DER, version 0, a public key
/// baldssl reads, and a supported signature algorithm. The signature is not
/// checked here ([`CertificationRequest::verify`]), as OpenSSL reads a
/// request without verifying it.
impl Decodable for CertificationRequest {
    type Error = Error;

    fn decode(der: &[u8]) -> Result<Self> {
        let (info, (algorithm, (signature, ()))) = decode(&REQUEST, der)?;
        let (version, (subject, (spki, (attributes, ())))) =
            decode(&INFO, info.as_bytes())?;
        if version != 0 {
            return Err(Error::invalid(format!(
                "certificate request: version {version}"
            )));
        }
        Ok(CertificationRequest {
            info,
            subject,
            public_key: PublicKey::decode(spki.as_bytes())?,
            attributes,
            algorithm: from_identifier(&algorithm)?,
            signature,
        })
    }
}

/// `-----BEGIN CERTIFICATE REQUEST-----` ([RFC 7468 section 7]).
///
/// [RFC 7468 section 7]: https://www.rfc-editor.org/rfc/rfc7468#section-7
impl Pem for CertificationRequest {
    const LABEL: &'static str = "CERTIFICATE REQUEST";
}

#[cfg(test)]
mod tests;
