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
        Reader, parse_tlv,
        syntax::{
            Any, BitString, Implicit, ObjectIdentifier, RawTlv, Sequence,
            SequenceOf, SetOf, Small, decode, encode,
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
        AlgorithmIdentifier, AlgorithmIdentifierSyntax, algorithm_identifier,
    },
    cert::ExtensionViews,
    dn::DistinguishedName,
    extension::{Extension, Extensions},
    oid::EXTENSION_REQUEST,
};

/// `CertificationRequestInfo`'s version, `v1(0)`, its only one
/// ([RFC 2986 section 4.1]).
///
/// [RFC 2986 section 4.1]: https://www.rfc-editor.org/rfc/rfc2986#section-4
const VERSION_V1: u64 = 0;

/// `CertificationRequestInfo`, with the subject and the key kept as TLVs.
type InfoSyntax =
    Sequence<(Small, (Any, (Any, (Implicit<0, SetOf<Any>>, ()))))>;

/// The description of [`InfoSyntax`].
const INFO: InfoSyntax =
    Sequence((Small, (Any, (Any, (Implicit::<0, _>(SetOf(Any)), ())))));

/// `Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF ANY }`
/// ([RFC 2986 section 4.1]): the one description of an attribute, which
/// writes and reads the `extensionRequest` attribute.
///
/// [RFC 2986 section 4.1]: https://www.rfc-editor.org/rfc/rfc2986#section-4
type AttributeSyntax = Sequence<(ObjectIdentifier, (SetOf<Any>, ()))>;

/// The description of [`AttributeSyntax`].
const ATTRIBUTE: AttributeSyntax =
    Sequence((ObjectIdentifier, (SetOf(Any), ())));

/// `CertificationRequest`, with the info kept as a TLV (the signed bytes).
type RequestSyntax =
    Sequence<(Any, (AlgorithmIdentifierSyntax, (BitString, ())))>;

/// The description of [`RequestSyntax`].
fn request_syntax() -> RequestSyntax {
    Sequence((Any, (algorithm_identifier(), (BitString, ()))))
}

/// The `Extensions` a request asks for, each the value of an
/// `extensionRequest` attribute, as DER: what
/// [`CertificationRequest::requested_extensions`] gives, and what
/// [`RequestedExtensions::views`] reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct RequestedExtensions(Vec<RawTlv>);

impl RequestedExtensions {
    /// The extensions, in order, as views of the DER.
    ///
    /// # Errors
    ///
    /// Malformed extensions.
    pub(crate) fn views(&self) -> Result<ExtensionViews<'_>> {
        let mut out = ExtensionViews::default();
        for list in &self.0 {
            let (tlv, _) = parse_tlv(list.as_bytes())?;
            out.0.extend(ExtensionViews::try_from(tlv)?.0);
        }
        Ok(out)
    }
}

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
    /// The identifier of `algorithm`, as written.
    algorithm_id: AlgorithmIdentifier,
    /// The signature: a DER `ECDSA-Sig-Value`, or 64 Ed25519 bytes.
    signature: Vec<u8>,
}

impl CertificationRequest {
    /// The request for `subject` with the public key of `key`, signed with
    /// `key` and `algorithm`, asking for `extensions` (as `openssl req -new
    /// -addext` writes them; no attribute at all without extensions).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `algorithm` does not match the key.
    pub fn sign(
        subject: &DistinguishedName,
        key: &AnyPrivateKey,
        algorithm: SignatureAlgorithm,
        extensions: &Extensions,
    ) -> Result<Self> {
        let public_key = PublicKey::from(key);
        let subject = subject.to_raw();
        let spki = RawTlv::parse(&public_key.encode())?;
        // The extensions, when there are any, as one extensionRequest
        // attribute whose single value is their Extensions, as OpenSSL
        // writes them.
        let attributes: Vec<RawTlv> = if extensions.is_empty() {
            Vec::new()
        } else {
            let extensions: Vec<RawTlv> =
                extensions.iter().map(Extension::to_raw).collect();
            vec![RawTlv::encode(
                &ATTRIBUTE,
                &(
                    EXTENSION_REQUEST,
                    (vec![RawTlv::encode(&SequenceOf(Any), &extensions)], ()),
                ),
            )]
        };
        let info = RawTlv::parse(&encode(
            &INFO,
            &(
                VERSION_V1,
                (subject.clone(), (spki, (attributes.clone(), ()))),
            ),
        ))?;
        let algorithm_id = AlgorithmIdentifier::try_from(algorithm)?;
        let signature = key.sign(algorithm, info.as_bytes())?;
        Ok(CertificationRequest {
            info,
            subject,
            public_key,
            attributes,
            algorithm,
            algorithm_id,
            signature,
        })
    }

    /// The identifier of the signature algorithm, as written.
    pub(crate) fn algorithm_id(&self) -> &AlgorithmIdentifier {
        &self.algorithm_id
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
                .value(),
        )
    }

    /// The subject, a DER `Name`, as it is in the request.
    #[must_use]
    pub fn subject(&self) -> &RawTlv {
        &self.subject
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

    /// The extensions the request asks for: the `Extensions` of its
    /// `extensionRequest` attribute (PKCS#9, [RFC 2985 section 5.4.2]), or
    /// none without attributes. The attribute is read with the description
    /// that writes it ([`ATTRIBUTE`]), and must have exactly one value, as
    /// RFC 2985 says (`SINGLE VALUE TRUE`, [RFC 2985 section 5.4.2]).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for any other attribute; [`Error::Invalid`]
    /// for an extensionRequest without exactly one value, and on malformed
    /// DER.
    ///
    /// [RFC 2985 section 5.4.2]: https://www.rfc-editor.org/rfc/rfc2985#section-5
    pub(crate) fn requested_extensions(&self) -> Result<RequestedExtensions> {
        let mut out = Vec::new();
        for attribute in &self.attributes {
            let (oid, (values, ())) = decode(&ATTRIBUTE, attribute.as_bytes())?;
            if oid != EXTENSION_REQUEST {
                return Err(Error::unsupported(format!(
                    "request attribute {}",
                    oid.to_dotted()?
                )));
            }
            let [extensions] =
                <[RawTlv; 1]>::try_from(values).map_err(|v| {
                    Error::invalid(format!(
                        "extensionRequest with {} values",
                        v.len()
                    ))
                })?;
            out.push(extensions);
        }
        Ok(RequestedExtensions(out))
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
            &request_syntax(),
            &(
                self.info.clone(),
                (self.algorithm_id.clone(), (self.signature.clone(), ())),
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
        let (info, (algorithm, (signature, ()))) =
            decode(&request_syntax(), der)?;
        let (version, (subject, (spki, (attributes, ())))) =
            decode(&INFO, info.as_bytes())?;
        if version != VERSION_V1 {
            return Err(Error::invalid(format!(
                "certificate request: version {version}"
            )));
        }
        Ok(CertificationRequest {
            info,
            subject,
            public_key: PublicKey::decode(spki.as_bytes())?,
            attributes,
            algorithm: SignatureAlgorithm::try_from(&algorithm)?,
            algorithm_id: algorithm,
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
