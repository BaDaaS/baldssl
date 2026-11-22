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
//!
//! [`CertificateTemplate::issued`] gives what `openssl x509 -req -CA`
//! writes for a request: the request's subject and key, the CA's subject
//! as issuer, and no extension from the request. OpenSSL 3.2 and later add
//! a subject key identifier and an authority key identifier (the CA's own
//! subject key identifier, or the hash of its key when it has none);
//! OpenSSL 3.5 leaves the authority key identifier out when the request's
//! key is the CA's, OpenSSL 4 does not. OpenSSL 3.0 adds no extension, so
//! its certificates are version 1. Throughout, a certificate is version 3
//! when it has extensions and version 1 otherwise, as OpenSSL sets it.
//!
//! [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
//! [RFC 5280 section 4.2.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2

use baldssl_core::{
    Error, Result,
    der::{
        Time,
        syntax::{
            Any, BitString, Explicit, Natural, RawTlv, Sequence, SequenceOf,
            Small, Unsigned, encode,
        },
    },
    encoding::Encodable,
};
use baldssl_crypto::{
    Digest, hash::Sha1, os_rng, signature::SignatureAlgorithm,
};
use baldssl_pkey::{AnyPrivateKey, PublicKey};

use crate::{
    Certificate, CertificationRequest, Compat,
    algorithm::{ALGORITHM_IDENTIFIER, identifier},
    cert::Validity,
    dn::DistinguishedName,
    extension::{Extension, ExtensionValue, Extensions},
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

/// The extensions a CA is asked to write, and where they come from:
/// copied from the request ([`CopyExtensions`]), then an extension file's
/// section ([`Extensions::from_section`]). Whether there was a file decides
/// whether OpenSSL 4 adds its default key identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssuedExtensions {
    /// The extensions, in order.
    pub extensions: Extensions,
    /// Whether an extension file gave some of them (`-extfile`).
    pub from_file: bool,
}

/// Which of a request's extensions a CA copies into the certificate
/// (`-copy_extensions`), as OpenSSL's `copy_extensions` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CopyExtensions {
    /// None (`none`, the default).
    #[default]
    None,
    /// Those of a kind the certificate does not have yet (`copy`).
    Copy,
    /// All of them, each replacing the certificate's of its kind
    /// (`copyall`).
    CopyAll,
}

impl CopyExtensions {
    /// `base` with the request's extensions copied in, in the request's
    /// order.
    ///
    /// # Errors
    ///
    /// A request attribute other than `extensionRequest`, or malformed
    /// extensions.
    pub fn apply(
        self,
        base: &Extensions,
        request: &CertificationRequest,
    ) -> Result<Extensions> {
        let mut out = base.clone();
        if self == CopyExtensions::None {
            return Ok(out);
        }
        for view in request.requested_extensions()? {
            let extension = Extension::from_view(&view)?;
            if self == CopyExtensions::Copy
                && out.contains_kind(&extension.value)
            {
                continue;
            }
            out = out.override_with(&[extension].into_iter().collect());
        }
        Ok(out)
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
    pub extensions: Extensions,
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
        let mut extensions = vec![Extension::new(
            ExtensionValue::SubjectKeyIdentifier(id.clone()),
        )];
        // OpenSSL 4's `v3_ca` asks for an authority key identifier only
        // when the certificate is not self-signed (`keyid:nonss`).
        if compat != Compat::V4 {
            extensions.push(Extension::new(
                ExtensionValue::AuthorityKeyIdentifier(id),
            ));
        }
        extensions.push(Extension::critical(
            ExtensionValue::BasicConstraints {
                ca: true,
                path_length: None,
            },
        ));
        CertificateTemplate {
            serial,
            issuer: name.clone(),
            validity,
            subject: name,
            public_key: key.clone(),
            extensions: extensions.into_iter().collect(),
        }
    }

    /// The certificate a CA issues for `request`, as `openssl x509 -req -CA`
    /// of the release line `compat` writes it: the request's subject and
    /// key, the CA's subject as issuer, and `extensions` (see
    /// [`IssuedExtensions`]) with the key identifiers OpenSSL adds. The
    /// request's signature is not checked here.
    ///
    /// The key identifiers are a subject key identifier (the hash of the
    /// request's key) and an authority key identifier (the CA's own key
    /// identifier). OpenSSL 3 adds each one missing when it signs
    /// (`do_X509_sign`), leaving the authority key identifier out when the
    /// request's key is the CA's; OpenSSL 3.0 only to a certificate that
    /// has extensions already, so with none it writes version 1. OpenSSL 4
    /// takes them from its default configuration file instead
    /// (`extensions = default_skid_akid`), applied after the copied
    /// extensions, and only without an extension file.
    ///
    /// # Errors
    ///
    /// When `ca_key` is not the key of `ca`, which OpenSSL reports as "CA
    /// certificate and CA private key do not match"; unsupported when the
    /// CA certificate has no subject key identifier, where OpenSSL names
    /// the issuer and serial instead.
    pub fn issued(
        request: &CertificationRequest,
        ca: &Certificate<'_>,
        ca_key: &AnyPrivateKey,
        serial: SerialNumber,
        validity: Validity,
        extensions: &IssuedExtensions,
        compat: Compat,
    ) -> Result<Self> {
        if !ca.matches_private_key(ca_key) {
            return Err(Error::invalid(
                "CA certificate and CA private key do not match",
            ));
        }
        let ca_public = PublicKey::from(ca_key);
        let subject_key = request.public_key();
        let ski = || {
            ExtensionValue::SubjectKeyIdentifier(key_identifier(subject_key))
        };
        let akid = || {
            ca.subject_key_identifier_opt()
                .map(|id| ExtensionValue::AuthorityKeyIdentifier(id.to_vec()))
                .ok_or_else(|| {
                    Error::unsupported(
                        "a CA certificate without a subject key identifier",
                    )
                })
        };
        let given = &extensions.extensions;
        let all = match compat {
            Compat::V4 if extensions.from_file => given.clone(),
            Compat::V4 => given.override_with(
                &[Extension::new(ski()), Extension::new(akid()?)]
                    .into_iter()
                    .collect(),
            ),
            Compat::V30 if given.is_empty() => Extensions::new(),
            Compat::V30 | Compat::V3 => {
                let mut defaults = Vec::new();
                if !given.contains_kind(&ski()) {
                    defaults.push(Extension::new(ski()));
                }
                if subject_key != &ca_public {
                    let akid = akid()?;
                    if !given.contains_kind(&akid) {
                        defaults.push(Extension::new(akid));
                    }
                }
                given.as_slice().iter().cloned().chain(defaults).collect()
            }
        };
        Ok(CertificateTemplate {
            serial,
            issuer: ca.subject_der.to_vec(),
            validity,
            subject: request.subject_der().to_vec(),
            public_key: subject_key.clone(),
            extensions: all,
        })
    }

    /// The DER `TBSCertificate`, signed with `algorithm`.
    fn tbs(&self, algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
        let raw = |der: &[u8]| RawTlv::parse(der);
        let extensions: Vec<RawTlv> = self
            .extensions
            .as_slice()
            .iter()
            .map(Extension::to_raw)
            .collect();
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
        if self.extensions.is_empty() {
            return self.tbs_v1(algorithm);
        }
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

    /// The DER `TBSCertificate` of a version 1 certificate (no version
    /// field, no extensions).
    fn tbs_v1(&self, algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
        let raw = |der: &[u8]| RawTlv::parse(der);
        let tbs = Sequence((
            Unsigned,
            (
                ALGORITHM_IDENTIFIER,
                (Any, (Sequence((Any, (Any, ()))), (Any, (Any, ())))),
            ),
        ));
        Ok(encode(
            &tbs,
            &(
                self.serial.0.clone(),
                (
                    identifier(algorithm),
                    (
                        raw(&self.issuer)?,
                        (
                            (
                                raw(&self.validity.not_before.to_der())?,
                                (raw(&self.validity.not_after.to_der())?, ()),
                            ),
                            (
                                raw(&self.subject)?,
                                (raw(&self.public_key.encode())?, ()),
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
