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
//! Not checked, and refused as unsupported rather than passed: name
//! constraints, revocation, policies, purposes, and signatures baldssl
//! does not verify (RSA).
//!
//! [RFC 5280 section 6]: https://www.rfc-editor.org/rfc/rfc5280#section-6

use baldssl_core::{
    Error, Result,
    der::{
        Reader,
        syntax::{NamedBits, ObjectId, RawTlv, decode},
        tag,
    },
    encoding::Decodable,
};
use baldssl_crypto::signature::SignatureAlgorithm;
use baldssl_pkey::PublicKey;

use crate::{Certificate, Compat, algorithm::from_identifier};

/// Why a chain does not verify: OpenSSL's `X509_V_ERR_*` for each check
/// baldssl makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// 2: the chain reaches a trusted certificate that is not self-signed,
    /// and no issuer of it is found.
    UnableToGetIssuerCert,
    /// 7: a signature does not verify under its issuer's key.
    CertSignatureFailure,
    /// 9: `notBefore` is after now.
    CertNotYetValid,
    /// 10: `notAfter` is not after now.
    CertHasExpired,
    /// 18: the target is self-signed and not trusted.
    DepthZeroSelfSignedCert,
    /// 19: the chain ends in a self-signed certificate that is not trusted.
    SelfSignedCertInChain,
    /// 20: no issuer is found for the chain's last certificate.
    UnableToGetIssuerCertLocally,
    /// 25: an issuer's path length constraint is exceeded.
    PathLengthExceeded,
    /// 32: an issuer's key usage does not allow signing certificates.
    KeyUsageNoCertSign,
    /// 34: a critical extension OpenSSL does not handle.
    UnhandledCriticalExtension,
    /// 79: an issuer is not a CA.
    InvalidCa,
}

impl VerifyError {
    /// OpenSSL's error number.
    #[must_use]
    pub fn code(self) -> u32 {
        match self {
            VerifyError::UnableToGetIssuerCert => 2,
            VerifyError::CertSignatureFailure => 7,
            VerifyError::CertNotYetValid => 9,
            VerifyError::CertHasExpired => 10,
            VerifyError::DepthZeroSelfSignedCert => 18,
            VerifyError::SelfSignedCertInChain => 19,
            VerifyError::UnableToGetIssuerCertLocally => 20,
            VerifyError::PathLengthExceeded => 25,
            VerifyError::KeyUsageNoCertSign => 32,
            VerifyError::UnhandledCriticalExtension => 34,
            VerifyError::InvalidCa => 79,
        }
    }

    /// OpenSSL's message (`X509_verify_cert_error_string`), by release
    /// line.
    #[must_use]
    pub fn message(self, compat: Compat) -> &'static str {
        match self {
            VerifyError::UnableToGetIssuerCert => {
                "unable to get issuer certificate"
            }
            VerifyError::CertSignatureFailure => {
                "certificate signature failure"
            }
            VerifyError::CertNotYetValid if compat == Compat::V4 => {
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

/// A verification that failed: its errors in the order found, each with
/// the depth of the certificate it is about (0 for the target), and the
/// chain built, target first.
#[derive(Debug, Clone)]
pub struct Failure<'c, 'a> {
    /// What failed, and where: every error but the last continued
    /// verification; the last ended it, or was the last found.
    pub errors: Vec<(VerifyError, usize)>,
    /// The chain as far as it was built.
    pub chain: Vec<&'c Certificate<'a>>,
}

/// The errors found so far.
struct Report(Vec<(VerifyError, usize)>);

/// That verification ends here.
struct Stop;

impl Report {
    /// Records an error, and whether verification ends with it.
    fn record(
        &mut self,
        error: VerifyError,
        depth: usize,
    ) -> core::result::Result<(), Stop> {
        self.0.push((error, depth));
        if error.continues() { Ok(()) } else { Err(Stop) }
    }
}

/// The extensions OpenSSL handles when critical (`X509_supported_extension`
/// in `crypto/x509/v3_purp.c`), as dotted OIDs: Netscape certificate type,
/// key usage, subject alternative name, basic constraints, certificate
/// policies, extended key usage, policy constraints, proxy certificate
/// information, name constraints, policy mappings, inhibit any-policy, and
/// the RFC 3779 address and AS identifier blocks.
const HANDLED_CRITICAL: [&str; 13] = [
    "2.16.840.1.113730.1.1",
    "2.5.29.15",
    "2.5.29.17",
    "2.5.29.19",
    "2.5.29.32",
    "2.5.29.37",
    "2.5.29.36",
    "1.3.6.1.5.5.7.1.14",
    "2.5.29.30",
    "2.5.29.33",
    "2.5.29.54",
    "1.3.6.1.5.5.7.1.7",
    "1.3.6.1.5.5.7.1.8",
];

/// What verification reads of a certificate's extensions.
impl Certificate<'_> {
    /// The value of the extension with this dotted OID.
    fn extension_value_opt(&self, dotted: &str) -> Result<Option<&[u8]>> {
        for e in &self.extensions {
            if e.oid.to_dotted()? == dotted {
                return Ok(Some(e.value));
            }
        }
        Ok(None)
    }

    /// `basicConstraints`: `cA`, and `pathLenConstraint` when given.
    fn basic_constraints_opt(&self) -> Result<Option<(bool, Option<u64>)>> {
        let Some(value) = self.extension_value_opt("2.5.29.19")? else {
            return Ok(None);
        };
        let mut top = Reader::new(value);
        let mut seq = top.sequence()?;
        top.finish()?;
        let ca = match seq.optional(tag::BOOLEAN)? {
            Some(b) => baldssl_core::der::parse_bool(b.value)?,
            None => false,
        };
        let path_length = match seq.optional(tag::INTEGER)? {
            Some(n) => Some(
                baldssl_core::der::Integer::parse(n.value)?
                    .to_u64_opt()
                    .ok_or_else(|| Error::invalid("pathLenConstraint"))?,
            ),
            None => None,
        };
        seq.finish()?;
        Ok(Some((ca, path_length)))
    }

    /// `keyUsage`, as the set of its bits.
    fn key_usage_opt(&self) -> Result<Option<u64>> {
        self.extension_value_opt("2.5.29.15")?
            .map(|v| decode(&NamedBits, v).map_err(Into::into))
            .transpose()
    }

    /// The key identifier of `authorityKeyIdentifier`, when it has one.
    fn authority_key_id_opt(&self) -> Result<Option<&[u8]>> {
        let Some(value) = self.extension_value_opt("2.5.29.35")? else {
            return Ok(None);
        };
        let mut top = Reader::new(value);
        let mut seq = top.sequence()?;
        top.finish()?;
        Ok(seq.optional(tag::context(0))?.map(|t| t.value))
    }

    /// Whether the subject is the issuer, as names compare.
    fn is_self_issued(&self) -> Result<bool> {
        Ok(self.subject.canonical()? == self.issuer.canonical()?)
    }

    /// Whether the key usage, if any, allows signing certificates.
    fn may_sign_certificates(&self) -> Result<bool> {
        Ok(self.key_usage_opt()?.is_none_or(|ku| ku & (1 << 5) != 0))
    }

    /// Whether `self` likely issued `subject` (`ossl_x509_likely_issued`):
    /// names chain, and the authority key identifier, when both are there,
    /// is `self`'s subject key identifier.
    fn likely_issued(&self, subject: &Certificate<'_>) -> Result<bool> {
        if self.subject.canonical()? != subject.issuer.canonical()? {
            return Ok(false);
        }
        Ok(
            match (
                subject.authority_key_id_opt()?,
                self.subject_key_identifier_opt(),
            ) {
                (Some(akid), Some(skid)) => akid == skid,
                _ => true,
            },
        )
    }

    /// Self-signed as OpenSSL means it (`EXFLAG_SS`, no signature check):
    /// self-issued, with consistent key identifiers, and a key usage that
    /// allows signing certificates.
    fn is_self_signed(&self) -> Result<bool> {
        Ok(self.likely_issued(self)? && self.may_sign_certificates()?)
    }

    /// `X509_check_ca`: 1 for `cA` true, 3 for a version 1 self-signed
    /// root, 4 for a key usage allowing certificate signing without basic
    /// constraints, 0 otherwise (and for a key usage that does not allow
    /// it).
    fn check_ca(&self) -> Result<u8> {
        if !self.may_sign_certificates()? {
            return Ok(0);
        }
        Ok(match self.basic_constraints_opt()? {
            Some((ca, _)) => u8::from(ca),
            None if self.version.known_opt() == Some(0)
                && self.is_self_signed()? =>
            {
                3
            }
            None if self.key_usage_opt()?.is_some() => 4,
            None => 0,
        })
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
        let algorithm = self.signature_algorithm_value()?;
        if self.signature.unused != 0 {
            return Ok(false);
        }
        Ok(key.verify(algorithm, self.tbs_der, self.signature.bytes))
    }

    /// The outer signature algorithm, as baldssl names it.
    fn signature_algorithm_value(&self) -> Result<SignatureAlgorithm> {
        let alg = &self.signature_algorithm;
        let oid = ObjectId::from_dotted_opt(&alg.oid.to_dotted()?)
            .ok_or_else(|| Error::invalid("signature algorithm"))?;
        let params = alg
            .parameters
            .map(|p| RawTlv::parse(p.encoded))
            .transpose()?;
        from_identifier(&(oid, (params, ())))
    }
}

/// The certificate of `pool` that likely issued `subject`, not already in
/// the chain: one valid at `now` when there is one, as OpenSSL prefers.
fn find_issuer<'c, 'a>(
    subject: &Certificate<'_>,
    pool: &'c [Certificate<'a>],
    chain: &[&Certificate<'_>],
    now: i64,
) -> Result<Option<&'c Certificate<'a>>> {
    let mut first = None;
    for candidate in pool {
        if chain.iter().any(|c| c.der == candidate.der)
            || !candidate.likely_issued(subject)?
        {
            continue;
        }
        if candidate.time_error_opt(now).is_none() {
            return Ok(Some(candidate));
        }
        first = first.or(Some(candidate));
    }
    Ok(first)
}

/// Verifies `target` against the trust anchors `trusted`, with the
/// intermediates `untrusted`, at `now` (seconds after the Unix epoch): the
/// chain, or the [`Failure`].
///
/// # Errors
///
/// The outer `Err` for what baldssl cannot check (see the module).
pub fn verify<'c, 'a>(
    target: &'c Certificate<'a>,
    trusted: &'c [Certificate<'a>],
    untrusted: &'c [Certificate<'a>],
    now: i64,
) -> Result<core::result::Result<Vec<&'c Certificate<'a>>, Failure<'c, 'a>>> {
    let mut report = Report(Vec::new());
    let mut chain = build(target, trusted, untrusted, now, &mut report)?;
    if let Ok(chain) = &mut chain {
        // A Stop here only cuts the checks short; the errors are recorded.
        let _: core::result::Result<(), Stop> = check(chain, now, &mut report)?;
    }
    let chain = match chain {
        Ok(chain) | Err((Stop, chain)) => chain,
    };
    if report.0.is_empty() {
        Ok(Ok(chain))
    } else {
        Ok(Err(Failure {
            errors: report.0,
            chain,
        }))
    }
}

/// The chain from `target`, trusted certificates first, then the untrusted
/// ones, with the error of an untrusted end recorded; `Err` when that
/// error ends verification.
#[allow(
    clippy::type_complexity,
    reason = "the chain is returned either way; Err says verification ends"
)]
fn build<'c, 'a>(
    target: &'c Certificate<'a>,
    trusted: &'c [Certificate<'a>],
    untrusted: &'c [Certificate<'a>],
    now: i64,
    report: &mut Report,
) -> Result<
    core::result::Result<
        Vec<&'c Certificate<'a>>,
        (Stop, Vec<&'c Certificate<'a>>),
    >,
> {
    let mut chain = vec![target];
    let mut trusted_count = 0usize;
    let anchored = loop {
        let last = chain.last().copied().unwrap_or(target);
        if last.is_self_signed()? {
            break trusted.iter().any(|t| t.der == last.der);
        }
        if let Some(issuer) = find_issuer(last, trusted, &chain, now)? {
            chain.push(issuer);
            trusted_count = trusted_count.saturating_add(1);
        } else if let Some(issuer) = find_issuer(last, untrusted, &chain, now)?
        {
            chain.push(issuer);
        } else {
            break false;
        }
    };
    if anchored {
        return Ok(Ok(chain));
    }
    let top = chain.len().saturating_sub(1);
    let last = chain.last().copied().unwrap_or(target);
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
    Ok(match report.record(error, top) {
        Ok(()) => Ok(chain),
        Err(stop) => Err((stop, chain)),
    })
}

/// The checks of a built chain, recording errors; `Err(Stop)` when one
/// ends verification.
fn check(
    chain: &[&Certificate<'_>],
    now: i64,
    report: &mut Report,
) -> Result<core::result::Result<(), Stop>> {
    let top = chain.len().saturating_sub(1);
    // Extensions, from the target up.
    let mut path_length = 0u64;
    for (i, cert) in chain.iter().enumerate() {
        for e in &cert.extensions {
            let dotted = e.oid.to_dotted()?;
            if dotted == "2.5.29.30" {
                return Err(Error::unsupported("name constraints"));
            }
            if e.critical
                && !HANDLED_CRITICAL.contains(&dotted.as_str())
                && let Err(stop) =
                    report.record(VerifyError::UnhandledCriticalExtension, i)
            {
                return Ok(Err(stop));
            }
        }
        if i > 0
            && let ca = cert.check_ca()?
            && (ca == 0 || (i < top && ca != 1))
            && let Err(stop) = report.record(VerifyError::InvalidCa, i)
        {
            return Ok(Err(stop));
        }
        if i > 1
            && let Some((_, Some(limit))) = cert.basic_constraints_opt()?
            && path_length > limit
            && let Err(stop) = report.record(VerifyError::PathLengthExceeded, i)
        {
            return Ok(Err(stop));
        }
        if i > 0 && !cert.is_self_issued()? {
            path_length = path_length.saturating_add(1);
        }
    }
    // From the top down: the issuer may sign certificates, the signature
    // verifies, the certificate is valid now. The trust anchor's own
    // signature is not checked, as by default in OpenSSL.
    for n in (0..=top).rev() {
        let Some(cert) = chain.get(n).copied() else {
            continue;
        };
        if let Some(issuer) = chain.get(n.saturating_add(1)).copied() {
            if !issuer.may_sign_certificates()?
                && let Err(stop) = report.record(
                    VerifyError::KeyUsageNoCertSign,
                    n.saturating_add(1),
                )
            {
                return Ok(Err(stop));
            }
            if !cert.signed_by(issuer)?
                && let Err(stop) =
                    report.record(VerifyError::CertSignatureFailure, n)
            {
                return Ok(Err(stop));
            }
        }
        if let Some(error) = cert.time_error_opt(now)
            && let Err(stop) = report.record(error, n)
        {
            return Ok(Err(stop));
        }
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests;
