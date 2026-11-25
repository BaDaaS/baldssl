//! Certificate path validation, as `openssl verify` does it
//! (`crypto/x509/x509_vfy.c`), for the chains baldssl can check: build a
//! chain from the target to a trusted certificate, then check its
//! extensions, its signatures and its validity times, and report the
//! errors with their OpenSSL numbers and depths.
//!
//! Certificates form a directed graph, an edge from each certificate to
//! the certificates that may have issued it (the issuer's subject is the
//! certificate's issuer, as names are compared canonically, and the key
//! identifiers agree). A chain is a path in that graph from the target to
//! a trust anchor; building is a search for one, trusted certificates
//! first, as OpenSSL 3 searches. Validation is then a set of predicates on
//! the path, checked in OpenSSL's order ([RFC 5280 section 6], as OpenSSL
//! implements it):
//!
//! 1. the chain reaches a trusted certificate (errors 2, 18, 19, 20);
//! 2. every critical extension is one OpenSSL handles (34), every issuer
//!    is a CA (79), and path length constraints hold (25);
//! 3. from the top down, each issuer's key usage allows signing
//!    certificates (32), each signature verifies under its issuer's key
//!    (7), and each certificate is valid now (9, 10).
//!
//! As `openssl verify` reports them, some errors let verification go on
//! (its callback accepts them: 10, 18, 25, 34, 79), and the others end
//! it; a failure is the sequence of errors up to the first that ends it,
//! or all of them ([`VerifyError::continues`]).
//!
//! A [`TrustStore`] holds the trust anchors and the intermediates, with
//! the canonical form of every name computed once; [`TrustStore::verify`]
//! gives a [`Verification`].
//!
//! Not checked, and refused as unsupported rather than passed: name
//! constraints, revocation, policies, purposes, and signatures baldssl
//! does not verify (RSA).
//!
//! [RFC 5280 section 6]: https://www.rfc-editor.org/rfc/rfc5280#section-6

use baldssl_core::{
    Error, Result,
    der::{Reader, syntax::ObjectId, tag},
    encoding::Decodable,
};
use baldssl_crypto::signature::SignatureAlgorithm;
use baldssl_pkey::PublicKey;

use crate::{
    Certificate, Compat,
    cert::Extension as ExtensionView,
    extension::{ExtensionValue, KeyUsage},
    name::CanonicalName,
    oid::{
        ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS,
        ID_CE_CERTIFICATE_POLICIES, ID_CE_EXT_KEY_USAGE,
        ID_CE_INHIBIT_ANY_POLICY, ID_CE_KEY_USAGE, ID_CE_NAME_CONSTRAINTS,
        ID_CE_POLICY_CONSTRAINTS, ID_CE_POLICY_MAPPINGS,
        ID_CE_SUBJECT_ALT_NAME, ID_PE_AUTONOMOUS_SYS_IDS, ID_PE_IP_ADDR_BLOCKS,
        ID_PE_PROXY_CERT_INFO, NETSCAPE_CERT_TYPE,
    },
};

/// `authorityKeyIdentifier`'s `keyIdentifier [0] IMPLICIT`
/// ([RFC 5280 section 4.2.1.1]).
///
/// [RFC 5280 section 4.2.1.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
const AKI_KEY_IDENTIFIER: u8 = tag::context(0);

/// Why a chain does not verify: OpenSSL's `X509_V_ERR_*` for each check
/// baldssl makes, each with its number in `include/openssl/x509_vfy.h.in`
/// as its discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifyError {
    /// The chain reaches a trusted certificate that is not self-signed, and
    /// no issuer of it is found.
    UnableToGetIssuerCert = 2,
    /// A signature does not verify under its issuer's key.
    CertSignatureFailure = 7,
    /// `notBefore` is after now.
    CertNotYetValid = 9,
    /// `notAfter` is before now: the certificate is valid through its
    /// `notAfter` second, as OpenSSL 3.5 and 4.x have it.
    CertHasExpired = 10,
    /// The target is self-signed and not trusted.
    DepthZeroSelfSignedCert = 18,
    /// The chain ends in a self-signed certificate that is not trusted.
    SelfSignedCertInChain = 19,
    /// No issuer is found for the chain's last certificate.
    UnableToGetIssuerCertLocally = 20,
    /// An issuer's path length constraint is exceeded.
    PathLengthExceeded = 25,
    /// An issuer's key usage does not allow signing certificates.
    KeyUsageNoCertSign = 32,
    /// A critical extension OpenSSL does not handle.
    UnhandledCriticalExtension = 34,
    /// An issuer is not a CA.
    InvalidCa = 79,
}

impl VerifyError {
    /// OpenSSL's error number, the discriminant.
    #[must_use]
    #[allow(
        clippy::as_conversions,
        reason = "an enum's discriminant is read only with `as`, and the \
                  discriminants are OpenSSL's numbers"
    )]
    pub fn code(self) -> u32 {
        self as u32
    }

    /// OpenSSL's message (`X509_verify_cert_error_string` in
    /// `crypto/x509/x509_txt.c`), by release line: from 3.6, error 9 adds
    /// "or the system clock is incorrect".
    #[must_use]
    pub fn message(self, compat: Compat) -> &'static str {
        match self {
            VerifyError::UnableToGetIssuerCert => {
                "unable to get issuer certificate"
            }
            VerifyError::CertSignatureFailure => {
                "certificate signature failure"
            }
            VerifyError::CertNotYetValid
                if matches!(compat, Compat::V36 | Compat::V4) =>
            {
                "certificate is not yet valid or the system clock is incorrect"
            }
            VerifyError::CertNotYetValid => "certificate is not yet valid",
            VerifyError::CertHasExpired => "certificate has expired",
            VerifyError::DepthZeroSelfSignedCert => "self-signed certificate",
            VerifyError::SelfSignedCertInChain => {
                "self-signed certificate in certificate chain"
            }
            VerifyError::UnableToGetIssuerCertLocally => {
                "unable to get local issuer certificate"
            }
            VerifyError::PathLengthExceeded => {
                "path length constraint exceeded"
            }
            VerifyError::KeyUsageNoCertSign => {
                "key usage does not include certificate signing"
            }
            VerifyError::UnhandledCriticalExtension => {
                "unhandled critical extension"
            }
            VerifyError::InvalidCa => "invalid CA certificate",
        }
    }

    /// Whether `openssl verify` goes on after reporting this error (its
    /// callback in `apps/verify.c` accepts it), so that later errors are
    /// reported too.
    #[must_use]
    pub fn continues(self) -> bool {
        matches!(
            self,
            VerifyError::CertHasExpired
                | VerifyError::DepthZeroSelfSignedCert
                | VerifyError::InvalidCa
                | VerifyError::PathLengthExceeded
                | VerifyError::UnhandledCriticalExtension
        )
    }
}

/// One error found, and the depth of the certificate it is about (0 for
/// the target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reported {
    /// What failed.
    pub error: VerifyError,
    /// Where: the certificate's place in the chain.
    pub depth: usize,
}

/// A verification that failed: its errors in the order found, and the
/// chain built, target first.
#[derive(Debug, Clone)]
pub struct Failure<'c, 'a> {
    /// What failed, and where: every error but the last continued
    /// verification; the last ended it, or was the last found.
    pub errors: Vec<Reported>,
    /// The chain as far as it was built.
    pub chain: Vec<&'c Certificate<'a>>,
}

/// What verifying a certificate gives.
#[derive(Debug, Clone)]
pub enum Verification<'c, 'a> {
    /// It verifies: the chain, target first, ending in a trust anchor.
    Verified(Vec<&'c Certificate<'a>>),
    /// It does not.
    Failed(Failure<'c, 'a>),
}

/// Why the checks stopped before their end: an error that ends
/// verification ([`VerifyError::continues`] false), or a certificate
/// baldssl cannot check. One type for both, so that `?` stops either way.
enum Halt {
    /// Verification ends; the errors are recorded.
    Stop,
    /// What baldssl cannot check (see the module).
    Error(Error),
}

impl From<Error> for Halt {
    fn from(error: Error) -> Self {
        Halt::Error(error)
    }
}

/// The errors found so far.
struct Report(Vec<Reported>);

impl Report {
    /// Records an error, and stops when verification ends with it.
    fn record(
        &mut self,
        error: VerifyError,
        depth: usize,
    ) -> core::result::Result<(), Halt> {
        self.0.push(Reported { error, depth });
        if error.continues() {
            Ok(())
        } else {
            Err(Halt::Stop)
        }
    }
}

/// The extensions OpenSSL handles when critical (`X509_supported_extension`
/// in `crypto/x509/v3_purp.c`): Netscape certificate type, key usage,
/// subject alternative name, basic constraints, certificate policies,
/// extended key usage, policy constraints, proxy certificate information,
/// name constraints, policy mappings, inhibit any-policy, and the
/// [RFC 3779 section 2.2.1] address and [RFC 3779 section 3.2.1] AS
/// identifier blocks.
///
/// [RFC 3779 section 2.2.1]: https://www.rfc-editor.org/rfc/rfc3779#section-2.2.1
/// [RFC 3779 section 3.2.1]: https://www.rfc-editor.org/rfc/rfc3779#section-3.2.1
const HANDLED_CRITICAL: [ObjectId; 13] = [
    NETSCAPE_CERT_TYPE,
    ID_CE_KEY_USAGE,
    ID_CE_SUBJECT_ALT_NAME,
    ID_CE_BASIC_CONSTRAINTS,
    ID_CE_CERTIFICATE_POLICIES,
    ID_CE_EXT_KEY_USAGE,
    ID_CE_POLICY_CONSTRAINTS,
    ID_PE_PROXY_CERT_INFO,
    ID_CE_NAME_CONSTRAINTS,
    ID_CE_POLICY_MAPPINGS,
    ID_CE_INHIBIT_ANY_POLICY,
    ID_PE_IP_ADDR_BLOCKS,
    ID_PE_AUTONOMOUS_SYS_IDS,
];

/// What `X509_check_ca` makes of a certificate, by the value it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaKind {
    /// 0: not a CA, or a key usage that does not allow signing certificates.
    NotCa,
    /// 1: basic constraints with `cA` true.
    Ca,
    /// 3: a version 1 self-signed certificate, without basic constraints.
    V1SelfSignedRoot,
    /// 4: a key usage allowing certificate signing, without basic
    /// constraints.
    KeyUsageOnly,
}

/// `basicConstraints`, as verification reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Constraints {
    /// `cA`.
    ca: bool,
    /// `pathLenConstraint`, when given.
    path_length: Option<u64>,
}

/// What verification reads of a certificate.
impl Certificate<'_> {
    /// The extension with this identifier.
    fn extension_opt(&self, id: &ObjectId) -> Option<&ExtensionView<'_>> {
        self.extensions.iter().find(|e| e.oid == *id)
    }

    /// The certificate's basic constraints, when it has them.
    fn basic_constraints_opt(&self) -> Result<Option<Constraints>> {
        let Some(view) = self.extension_opt(&ID_CE_BASIC_CONSTRAINTS) else {
            return Ok(None);
        };
        match ExtensionValue::try_from(view)? {
            ExtensionValue::BasicConstraints { ca, path_length } => {
                Ok(Some(Constraints { ca, path_length }))
            }
            // The decoding of a basicConstraints value gives no other kind.
            ExtensionValue::SubjectKeyIdentifier(_)
            | ExtensionValue::AuthorityKeyIdentifier(_)
            | ExtensionValue::KeyUsage(_)
            | ExtensionValue::SubjectAltName(_)
            | ExtensionValue::ExtendedKeyUsage(_)
            | ExtensionValue::Other { .. } => {
                Err(Error::invalid("basicConstraints"))
            }
        }
    }

    /// The certificate's key usage, when it has one.
    fn key_usage_opt(&self) -> Result<Option<KeyUsage>> {
        let Some(view) = self.extension_opt(&ID_CE_KEY_USAGE) else {
            return Ok(None);
        };
        match ExtensionValue::try_from(view)? {
            ExtensionValue::KeyUsage(usage) => Ok(Some(usage)),
            // The decoding of a keyUsage value gives no other kind.
            ExtensionValue::SubjectKeyIdentifier(_)
            | ExtensionValue::AuthorityKeyIdentifier(_)
            | ExtensionValue::SubjectAltName(_)
            | ExtensionValue::BasicConstraints { .. }
            | ExtensionValue::ExtendedKeyUsage(_)
            | ExtensionValue::Other { .. } => Err(Error::invalid("keyUsage")),
        }
    }

    /// The key identifier of `authorityKeyIdentifier`, when it has one.
    fn authority_key_id_opt(&self) -> Result<Option<&[u8]>> {
        let Some(view) = self.extension_opt(&ID_CE_AUTHORITY_KEY_IDENTIFIER)
        else {
            return Ok(None);
        };
        let mut top = Reader::new(view.value);
        let mut seq = top.sequence()?;
        top.finish()?;
        Ok(seq.optional(AKI_KEY_IDENTIFIER)?.map(|t| t.value()))
    }

    /// Whether the key usage, if any, allows signing certificates.
    fn may_sign_certificates(&self) -> Result<bool> {
        Ok(self
            .key_usage_opt()?
            .is_none_or(|usage| usage.contains(KeyUsage::KEY_CERT_SIGN)))
    }

    /// Whether the certificate is valid at `now`, seconds after the Unix
    /// epoch: `None`, or the error. The validity period is notBefore through
    /// notAfter, both included ([RFC 5280, section 4.1.2.5][rfc5280]).
    ///
    /// [rfc5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
    fn time_error_opt(&self, now: i64) -> Option<VerifyError> {
        if self.validity.not_before.to_unix_seconds() > now {
            Some(VerifyError::CertNotYetValid)
        } else if self.validity.not_after.to_unix_seconds() < now {
            Some(VerifyError::CertHasExpired)
        } else {
            None
        }
    }

    /// Whether `issuer`'s key verifies this certificate's signature.
    fn signed_by(&self, issuer: &Certificate<'_>) -> Result<bool> {
        let key = PublicKey::decode(issuer.spki_der)?;
        let algorithm =
            SignatureAlgorithm::try_from(&self.signature_algorithm)?;
        if self.signature.unused() != 0 {
            return Ok(false);
        }
        Ok(key.verify(algorithm, self.tbs_der, self.signature.bytes()))
    }
}

/// A certificate with the canonical forms of its names, computed once:
/// chain building compares them for every candidate at every step.
struct Node<'c, 'a> {
    /// The certificate.
    cert: &'c Certificate<'a>,
    /// Its subject, canonical.
    subject: CanonicalName,
    /// Its issuer, canonical.
    issuer: CanonicalName,
}

impl<'c, 'a> Node<'c, 'a> {
    /// The node of a certificate.
    fn new(cert: &'c Certificate<'a>) -> Result<Self> {
        Ok(Node {
            cert,
            subject: cert.subject.canonical()?,
            issuer: cert.issuer.canonical()?,
        })
    }

    /// Whether the subject is the issuer, as names compare.
    fn is_self_issued(&self) -> bool {
        self.subject == self.issuer
    }

    /// Whether `self` likely issued `subject` (`ossl_x509_likely_issued`):
    /// names chain, and the authority key identifier, when both are there,
    /// is `self`'s subject key identifier.
    fn likely_issued(&self, subject: &Node<'_, '_>) -> Result<bool> {
        if self.subject != subject.issuer {
            return Ok(false);
        }
        Ok(
            match (
                subject.cert.authority_key_id_opt()?,
                self.cert.subject_key_identifier_opt(),
            ) {
                (Some(akid), Some(skid)) => akid == skid.as_slice(),
                _ => true,
            },
        )
    }

    /// Self-signed as OpenSSL means it (`EXFLAG_SS`, no signature check):
    /// self-issued, with consistent key identifiers, and a key usage that
    /// allows signing certificates.
    fn is_self_signed(&self) -> Result<bool> {
        Ok(self.likely_issued(self)? && self.cert.may_sign_certificates()?)
    }

    /// `X509_check_ca`.
    fn ca_kind(&self) -> Result<CaKind> {
        if !self.cert.may_sign_certificates()? {
            return Ok(CaKind::NotCa);
        }
        Ok(match self.cert.basic_constraints_opt()? {
            Some(Constraints { ca: true, .. }) => CaKind::Ca,
            None if self.cert.version.known_opt() == Some(0)
                && self.is_self_signed()? =>
            {
                CaKind::V1SelfSignedRoot
            }
            None if self.cert.key_usage_opt()?.is_some() => {
                CaKind::KeyUsageOnly
            }
            Some(Constraints { ca: false, .. }) | None => CaKind::NotCa,
        })
    }
}

/// The node of `pool` that likely issued `subject`, not already in the
/// chain: one valid at `now` when there is one, as OpenSSL prefers.
fn find_issuer<'n, 'c, 'a>(
    subject: &Node<'_, '_>,
    pool: &'n [Node<'c, 'a>],
    chain: &[&Node<'c, 'a>],
    now: i64,
) -> Result<Option<&'n Node<'c, 'a>>> {
    let mut first = None;
    for candidate in pool {
        if chain.iter().any(|c| c.cert.der == candidate.cert.der)
            || !candidate.likely_issued(subject)?
        {
            continue;
        }
        if candidate.cert.time_error_opt(now).is_none() {
            return Ok(Some(candidate));
        }
        first = first.or(Some(candidate));
    }
    Ok(first)
}

/// The trust anchors and the intermediates a certificate is verified
/// against, as `-CAfile` and `-untrusted` give them.
pub struct TrustStore<'c, 'a> {
    /// The trust anchors.
    trusted: Vec<Node<'c, 'a>>,
    /// The intermediates.
    untrusted: Vec<Node<'c, 'a>>,
}

impl<'c, 'a> TrustStore<'c, 'a> {
    /// The store of these trust anchors and intermediates.
    ///
    /// # Errors
    ///
    /// A name that does not convert to UTF-8.
    pub fn new(
        trusted: &'c [Certificate<'a>],
        untrusted: &'c [Certificate<'a>],
    ) -> Result<Self> {
        Ok(TrustStore {
            trusted: trusted.iter().map(Node::new).collect::<Result<_>>()?,
            untrusted: untrusted
                .iter()
                .map(Node::new)
                .collect::<Result<_>>()?,
        })
    }

    /// Verifies `target` at `now`, seconds after the Unix epoch.
    ///
    /// # Errors
    ///
    /// What baldssl cannot check (see the module).
    pub fn verify(
        &self,
        target: &'c Certificate<'a>,
        now: i64,
    ) -> Result<Verification<'c, 'a>> {
        let target = Node::new(target)?;
        let mut report = Report(Vec::new());
        let mut chain = vec![&target];
        let outcome = self
            .build(&mut chain, now, &mut report)
            .and_then(|()| check(&chain, now, &mut report));
        if let Err(Halt::Error(error)) = outcome {
            return Err(error);
        }
        let chain: Vec<&'c Certificate<'a>> =
            chain.iter().map(|n| n.cert).collect();
        Ok(if report.0.is_empty() {
            Verification::Verified(chain)
        } else {
            Verification::Failed(Failure {
                errors: report.0,
                chain,
            })
        })
    }

    /// Extends `chain` from its target, trusted certificates first, then
    /// the untrusted ones, recording the error of an untrusted end.
    fn build<'n>(
        &'n self,
        chain: &mut Vec<&'n Node<'c, 'a>>,
        now: i64,
        report: &mut Report,
    ) -> core::result::Result<(), Halt> {
        let mut trusted_count = 0usize;
        let anchored = loop {
            let Some(last) = chain.last().copied() else {
                return Ok(());
            };
            if last.is_self_signed()? {
                break self.trusted.iter().any(|t| t.cert.der == last.cert.der);
            }
            if let Some(issuer) = find_issuer(last, &self.trusted, chain, now)?
            {
                chain.push(issuer);
                trusted_count = trusted_count.saturating_add(1);
            } else if let Some(issuer) =
                find_issuer(last, &self.untrusted, chain, now)?
            {
                chain.push(issuer);
            } else {
                break false;
            }
        };
        if anchored {
            return Ok(());
        }
        let top = chain.len().saturating_sub(1);
        let Some(last) = chain.last() else {
            return Ok(());
        };
        let error = if last.is_self_signed()? {
            if top == 0 {
                VerifyError::DepthZeroSelfSignedCert
            } else {
                VerifyError::SelfSignedCertInChain
            }
        } else if trusted_count > 0 {
            VerifyError::UnableToGetIssuerCert
        } else {
            VerifyError::UnableToGetIssuerCertLocally
        };
        report.record(error, top)
    }
}

/// The checks of a built chain, recording errors.
fn check(
    chain: &[&Node<'_, '_>],
    now: i64,
    report: &mut Report,
) -> core::result::Result<(), Halt> {
    let top = chain.len().saturating_sub(1);
    // Extensions, from the target up.
    let mut path_length = 0u64;
    for (i, node) in chain.iter().enumerate() {
        let cert = node.cert;
        for e in &cert.extensions {
            if e.oid == ID_CE_NAME_CONSTRAINTS {
                return Err(Error::unsupported("name constraints").into());
            }
            if e.critical && !HANDLED_CRITICAL.iter().any(|id| e.oid == *id) {
                report.record(VerifyError::UnhandledCriticalExtension, i)?;
            }
        }
        if i > 0 {
            // Only the top may be a CA other than by basic constraints.
            let ca = node.ca_kind()?;
            if ca == CaKind::NotCa || (i < top && ca != CaKind::Ca) {
                report.record(VerifyError::InvalidCa, i)?;
            }
        }
        if i > 1
            && let Some(Constraints {
                path_length: Some(limit),
                ..
            }) = cert.basic_constraints_opt()?
            && path_length > limit
        {
            report.record(VerifyError::PathLengthExceeded, i)?;
        }
        if i > 0 && !node.is_self_issued() {
            path_length = path_length.saturating_add(1);
        }
    }
    // From the top down: the issuer may sign certificates, the signature
    // verifies, the certificate is valid now. The trust anchor's own
    // signature is not checked, as by default in OpenSSL.
    for (n, node) in chain.iter().enumerate().rev() {
        let cert = node.cert;
        if let Some(issuer) = chain.get(n.saturating_add(1)) {
            if !issuer.cert.may_sign_certificates()? {
                report.record(
                    VerifyError::KeyUsageNoCertSign,
                    n.saturating_add(1),
                )?;
            }
            if !cert.signed_by(issuer.cert)? {
                report.record(VerifyError::CertSignatureFailure, n)?;
            }
        }
        if let Some(error) = cert.time_error_opt(now) {
            report.record(error, n)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
