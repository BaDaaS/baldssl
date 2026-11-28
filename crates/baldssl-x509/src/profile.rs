//! Release-line profiles: where OpenSSL's release lines differ, as types.
//!
//! baldssl reproduces OpenSSL 3.0, 3.2 to 3.5, 3.6 and 4, which differ in
//! observable ways (messages, layouts, encodings, and a few semantics). A
//! [`Profile`] is the signature of those differences: one item per point
//! where release lines differ, the shared behaviour as the item's default,
//! and one type per line ([`OpenSsl30`], [`OpenSsl35`], [`OpenSsl36`],
//! [`OpenSsl4`]) that overrides an item only where its line differs. Code
//! that depends on the line is generic over `P: Profile` and monomorphised
//! for each line, so adding an item without deciding it for every line
//! does not compile, and a line's code is built only with its feature.
//!
//! The modules move onto the profile one by one: path validation
//! ([`TrustStore::verify`](crate::TrustStore::verify)) and issuing
//! ([`CertificateTemplate`](crate::CertificateTemplate)) are on it; the
//! others still
//! ask the methods of [`Compat`], the line as a value, which each profile
//! names ([`Profile::COMPAT`]).
//!
//! Each line is compiled in by its Cargo feature (`openssl-3-0`,
//! `openssl-3-5`, `openssl-3-6`, `openssl-4`). Cargo features are additive,
//! so this crate can compile several lines at once (its tests check each);
//! the `baldssl` binary enables exactly one, the line it imitates. Where a
//! line is chosen from a value ([`Compat`]), [`Compat::run`] applies a
//! computation to its profile, and refuses a line that is not compiled in.
//!
//! # The run-time choice is a rank-2 function
//!
//! A computation that works for any profile is a function
//! `forall P: Profile. R`, which a Rust closure cannot be (its type
//! parameters are fixed when it is created). [`WithProfile`] is that
//! function as a trait with a generic method, and [`Compat::run`] applies
//! it to the profile a value names: the pair (a [`Compat`], a
//! [`WithProfile`]) is the Church encoding of the existential "some `P`
//! with `Profile`", `exists P. Profile P` being `forall R. (forall P.
//! Profile P -> R) -> R`.

#[cfg(not(any(
    feature = "openssl-3-0",
    feature = "openssl-3-5",
    feature = "openssl-3-6",
    feature = "openssl-4"
)))]
compile_error!(
    "baldssl-x509: enable at least one release line: openssl-3-0, \
     openssl-3-5, openssl-3-6 or openssl-4"
);

#[cfg(test)]
mod tests;

use baldssl_core::{Error, Result};

use crate::Compat;

mod sealed {
    /// Only the release lines of this module are profiles.
    pub trait Sealed {}
}

/// How a certificate's validity times are compared with the verification
/// time (`ossl_x509_check_cert_time` in `crypto/x509/x509_vfy.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateTimes {
    /// OpenSSL 3.0 to 3.6: the verification time is converted to an ASN.1
    /// time, which holds the years 0 to 9999 only; outside them the
    /// conversion fails, which `X509_cmp_time` reports as 0, and
    /// `ossl_x509_check_cert_time` as error 13 at the first certificate it
    /// checks. A certificate is valid from its notBefore to the second
    /// before its notAfter: `X509_cmp_time`'s comparison is `<=`, so it has
    /// expired at its notAfter.
    Asn1Compared,
    /// OpenSSL 4.0 and later: any 64-bit time, and a certificate valid from
    /// its notBefore through its notAfter, both included ([RFC 5280,
    /// section 4.1.2.5][rfc5280]). A notAfter of 99991231235959Z, which
    /// RFC 5280 assigns to a certificate with no well-defined expiration
    /// date, never expires.
    ///
    /// [rfc5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
    PosixCompared,
}

/// Whether `req -x509` with the default configuration writes an authority
/// key identifier in a self-signed certificate
/// ([`Profile::SELF_SIGNED_AUTHORITY_KEY_ID`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfSignedAuthorityKeyId {
    /// It does, its own key identifier: the `v3_ca` section of
    /// `apps/openssl.cnf` says `keyid:always,issuer` (OpenSSL 3).
    Written,
    /// It does not: `v3_ca` says `keyid:nonss,issuer:nonss`
    /// ("non-self-signed", OpenSSL 4).
    Omitted,
}

/// When `x509 -req -CA` adds a subject and an authority key identifier
/// ([`Profile::DEFAULT_KEY_IDENTIFIERS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultKeyIdentifiers {
    /// When signing (`do_X509_sign` in `apps/lib/apps.c`), each one
    /// missing, the authority's left out when the request's key is the
    /// CA's (OpenSSL 3.2 to 3.6).
    AtSigning,
    /// As [`DefaultKeyIdentifiers::AtSigning`], and only to a certificate
    /// that has extensions already, so that without any it is version 1
    /// (OpenSSL 3.0).
    AtSigningWithExtensions,
    /// From the `default_skid_akid` section of `apps/openssl.cnf`
    /// (`extensions = default_skid_akid`), after the copied extensions,
    /// and only without an extension file (OpenSSL 4).
    FromConfiguration,
}

/// The message of `X509_V_ERR_CERT_NOT_YET_VALID` (error 9) up to OpenSSL
/// 3.5 (`crypto/x509/x509_txt.c`).
const NOT_YET_VALID: &str = "certificate is not yet valid";

/// The message of error 9 from OpenSSL 3.6, which adds the hint about the
/// clock (`crypto/x509/x509_txt.c`).
#[cfg(any(feature = "openssl-3-6", feature = "openssl-4"))]
const NOT_YET_VALID_OR_CLOCK: &str =
    "certificate is not yet valid or the system clock is incorrect";

/// Where an OpenSSL release line differs from the others: each item's
/// default is the behaviour the lines share, overridden by the lines that
/// differ. See the module documentation.
pub trait Profile: sealed::Sealed + 'static {
    /// The release line, as a value.
    const COMPAT: Compat;
    /// The release line, for people: `OpenSSL 3.5`.
    const NAME: &'static str;
    /// The Cargo feature that compiles it in.
    const FEATURE: &'static str;

    /// The message of `X509_V_ERR_CERT_NOT_YET_VALID` (error 9).
    const NOT_YET_VALID: &'static str = NOT_YET_VALID;

    /// How validity times compare with the verification time.
    const CERTIFICATE_TIMES: CertificateTimes = CertificateTimes::Asn1Compared;

    /// Whether `req -x509` puts an authority key identifier on the
    /// self-signed certificate it writes with the default configuration.
    const SELF_SIGNED_AUTHORITY_KEY_ID: SelfSignedAuthorityKeyId =
        SelfSignedAuthorityKeyId::Written;

    /// Where `x509 -req -CA` takes the key identifiers it adds from.
    const DEFAULT_KEY_IDENTIFIERS: DefaultKeyIdentifiers =
        DefaultKeyIdentifiers::AtSigning;
}

/// OpenSSL 3.0.
#[cfg(feature = "openssl-3-0")]
#[derive(Debug, Clone, Copy)]
pub enum OpenSsl30 {}

#[cfg(feature = "openssl-3-0")]
impl sealed::Sealed for OpenSsl30 {}

#[cfg(feature = "openssl-3-0")]
impl Profile for OpenSsl30 {
    const COMPAT: Compat = Compat::V30;
    const NAME: &'static str = "OpenSSL 3.0";
    const FEATURE: &'static str = "openssl-3-0";
    const DEFAULT_KEY_IDENTIFIERS: DefaultKeyIdentifiers =
        DefaultKeyIdentifiers::AtSigningWithExtensions;
}

/// OpenSSL 3.2 to 3.5, measured on 3.5.
#[cfg(feature = "openssl-3-5")]
#[derive(Debug, Clone, Copy)]
pub enum OpenSsl35 {}

#[cfg(feature = "openssl-3-5")]
impl sealed::Sealed for OpenSsl35 {}

#[cfg(feature = "openssl-3-5")]
impl Profile for OpenSsl35 {
    const COMPAT: Compat = Compat::V3;
    const NAME: &'static str = "OpenSSL 3.5";
    const FEATURE: &'static str = "openssl-3-5";
}

/// OpenSSL 3.6.
#[cfg(feature = "openssl-3-6")]
#[derive(Debug, Clone, Copy)]
pub enum OpenSsl36 {}

#[cfg(feature = "openssl-3-6")]
impl sealed::Sealed for OpenSsl36 {}

#[cfg(feature = "openssl-3-6")]
impl Profile for OpenSsl36 {
    const COMPAT: Compat = Compat::V36;
    const NAME: &'static str = "OpenSSL 3.6";
    const FEATURE: &'static str = "openssl-3-6";
    const NOT_YET_VALID: &'static str = NOT_YET_VALID_OR_CLOCK;
}

/// OpenSSL 4.
#[cfg(feature = "openssl-4")]
#[derive(Debug, Clone, Copy)]
pub enum OpenSsl4 {}

#[cfg(feature = "openssl-4")]
impl sealed::Sealed for OpenSsl4 {}

#[cfg(feature = "openssl-4")]
impl Profile for OpenSsl4 {
    const COMPAT: Compat = Compat::V4;
    const NAME: &'static str = "OpenSSL 4";
    const FEATURE: &'static str = "openssl-4";
    const NOT_YET_VALID: &'static str = NOT_YET_VALID_OR_CLOCK;
    const CERTIFICATE_TIMES: CertificateTimes = CertificateTimes::PosixCompared;
    const SELF_SIGNED_AUTHORITY_KEY_ID: SelfSignedAuthorityKeyId =
        SelfSignedAuthorityKeyId::Omitted;
    const DEFAULT_KEY_IDENTIFIERS: DefaultKeyIdentifiers =
        DefaultKeyIdentifiers::FromConfiguration;
}

/// A release line compiled in, for tests whose subject does not depend on
/// the line: 3.5 when it is compiled in, otherwise the newest that is.
#[cfg(all(test, feature = "openssl-3-5"))]
pub(crate) type AnyProfile = OpenSsl35;
/// See the item of the same name compiled with `openssl-3-5`.
#[cfg(all(test, not(feature = "openssl-3-5"), feature = "openssl-4"))]
pub(crate) type AnyProfile = OpenSsl4;
/// See the item of the same name compiled with `openssl-3-5`.
#[cfg(all(
    test,
    not(feature = "openssl-3-5"),
    not(feature = "openssl-4"),
    feature = "openssl-3-6"
))]
pub(crate) type AnyProfile = OpenSsl36;
/// See the item of the same name compiled with `openssl-3-5`.
#[cfg(all(
    test,
    not(feature = "openssl-3-5"),
    not(feature = "openssl-4"),
    not(feature = "openssl-3-6"),
    feature = "openssl-3-0"
))]
pub(crate) type AnyProfile = OpenSsl30;

/// A computation for any profile, `forall P: Profile. Output`: what
/// [`Compat::run`] applies to the profile chosen at run time.
pub trait WithProfile {
    /// What the computation gives.
    type Output;

    /// The computation for the profile `P`.
    fn call<P>(self) -> Self::Output
    where
        P: Profile;
}

impl Compat {
    /// Applies `f` to the profile of this release line.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] when the line is not compiled in (its Cargo
    /// feature is off).
    pub fn run<F>(self, f: F) -> Result<F::Output>
    where
        F: WithProfile,
    {
        match self {
            #[cfg(feature = "openssl-3-0")]
            Compat::V30 => Ok(f.call::<OpenSsl30>()),
            #[cfg(feature = "openssl-3-5")]
            Compat::V3 => Ok(f.call::<OpenSsl35>()),
            #[cfg(feature = "openssl-3-6")]
            Compat::V36 => Ok(f.call::<OpenSsl36>()),
            #[cfg(feature = "openssl-4")]
            Compat::V4 => Ok(f.call::<OpenSsl4>()),
            #[allow(
                unreachable_patterns,
                reason = "reached only when a release line's feature is off"
            )]
            other => Err(Error::unsupported(format!(
                "the OpenSSL {} profile, which this build leaves out (its \
                 Cargo feature is off)",
                other.name()
            ))),
        }
    }
}
