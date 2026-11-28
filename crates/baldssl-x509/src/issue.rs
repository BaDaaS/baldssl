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
//! depends on the release line
//! ([`Profile::SELF_SIGNED_AUTHORITY_KEY_ID`]): OpenSSL 3's file says
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

use std::str::FromStr;

use baldssl_core::{
    Error, Result,
    der::{
        Time,
        syntax::{
            Any, BitString, Explicit, Natural, Optional, RawTlv, Sequence,
            SequenceOf, Unsigned, encode,
        },
    },
    encoding::Encodable,
    hex::{self, Case},
};
use baldssl_crypto::{
    Digest, hash::Sha1, os_rng, signature::SignatureAlgorithm,
};
use baldssl_pkey::{AnyPrivateKey, PublicKey};

use crate::{
    Certificate, CertificationRequest, DefaultKeyIdentifiers, Profile,
    SelfSignedAuthorityKeyId,
    algorithm::{AlgorithmIdentifier, algorithm_identifier},
    cert::Validity,
    dn::DistinguishedName,
    extension::{Extension, ExtensionValue, Extensions},
    version::{Version, version_field},
};

/// The most octets a serial number takes once encoded
/// ([RFC 5280 section 4.1.2.2]: "Conforming CAs MUST NOT use serialNumber
/// values longer than 20 octets").
///
/// [RFC 5280 section 4.1.2.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
const MAX_SERIAL_OCTETS: usize = 20;

/// The sign bit of the first octet of a DER INTEGER ([X.690] 8.3.3): a
/// positive value whose first magnitude octet has it set takes a leading
/// zero octet.
///
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
const SIGN_BIT: u8 = 0x80;

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
            digits.first().is_some_and(|&b| b & SIGN_BIT != 0),
        ));
        (!digits.is_empty() && octets <= MAX_SERIAL_OCTETS)
            .then_some(SerialNumber(n))
    }

    /// A random serial number of 159 bits, as OpenSSL's `rand_serial`
    /// draws it (`SERIAL_RAND_BITS`): 20 octets once encoded, positive.
    ///
    /// # Errors
    ///
    /// The operating system's randomness failing.
    pub fn random() -> Result<Self> {
        loop {
            let mut bytes = [0u8; MAX_SERIAL_OCTETS];
            os_rng::fill(&mut bytes).map_err(|e| baldssl_core::Error::Io {
                context: "drawing a serial number".into(),
                message: e.to_string(),
            })?;
            // Clearing the sign bit leaves 159 random bits and a positive
            // value that fits in 20 octets.
            if let Some(first) = bytes.first_mut() {
                *first &= !SIGN_BIT;
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

    /// The serial number following the one a serial file holds, as
    /// OpenSSL's `x509` takes it (`load_serial` in `apps/lib/apps.c`): the
    /// file's hexadecimal digits, upper or lower case, as
    /// `a2i_ASN1_INTEGER` reads them, plus one.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] when the file holds no hexadecimal number, and
    /// [`Error::Unsupported`] when the successor is longer than 20 octets.
    pub fn following_file(text: &str) -> Result<Self> {
        let digits = text.trim();
        let held = (!digits.is_empty())
            .then(|| digits_be_opt(digits, HEX))
            .flatten()
            .ok_or_else(|| Error::Usage("unable to load number".into()))?;
        Self::checked(digits, &increment(&held))
    }

    /// The contents of a serial file holding this number, as `save_serial`
    /// in `apps/lib/apps.c` writes it: upper-case hexadecimal digits, an
    /// even number of them, and a newline.
    #[must_use]
    pub fn to_serial_file(&self) -> String {
        let mut text = hex::plain(self.as_be_bytes(), Case::Upper);
        text.push('\n');
        text
    }

    /// The serial number of `bytes`, written `text`, or the error saying
    /// why it cannot be one.
    fn checked(text: &str, bytes: &[u8]) -> Result<Self> {
        Self::new_opt(bytes).ok_or_else(|| {
            Error::unsupported(format!(
                "serial {text}: a serial must be positive and at most 20 \
                 octets"
            ))
        })
    }
}

/// The radix of decimal digits.
const DECIMAL: u16 = 10;
/// The radix of hexadecimal digits.
const HEX: u16 = 16;
/// The prefixes that mark hexadecimal digits in `-set_serial`, as
/// `s2i_ASN1_INTEGER` (`crypto/x509/v3_utl.c`) reads them.
const HEX_PREFIXES: [&str; 2] = ["0x", "0X"];

/// Big-endian bytes of the number written with `digits` in `radix` (10 or
/// 16), without leading zeros; `None` on a character that is not a digit.
fn digits_be_opt(digits: &str, radix: u16) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in digits.chars() {
        let mut carry = u16::try_from(c.to_digit(radix.into())?).ok()?;
        for byte in bytes.iter_mut().rev() {
            let v = u16::from(*byte).checked_mul(radix)?.checked_add(carry)?;
            *byte = v.to_be_bytes()[1];
            carry = v >> 8;
        }
        if carry != 0 {
            bytes.insert(0, carry.to_be_bytes()[1]);
        }
    }
    Some(bytes)
}

/// One more than the big-endian `bytes`.
fn increment(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for byte in out.iter_mut().rev() {
        let (v, overflow) = byte.overflowing_add(1);
        *byte = v;
        if !overflow {
            return out;
        }
    }
    out.insert(0, 1);
    out
}

/// The serial number of `-set_serial`: decimal digits, or hexadecimal ones
/// after `0x`, as OpenSSL's `s2i_ASN1_INTEGER` reads them.
///
/// # Errors
///
/// [`Error::Usage`] on anything else; [`Error::Unsupported`] for zero,
/// negative numbers and serials longer than 20 octets.
impl FromStr for SerialNumber {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let invalid = || Error::Usage(format!("invalid serial number {text}"));
        let (digits, radix) = HEX_PREFIXES
            .iter()
            .find_map(|p| text.strip_prefix(p))
            .map_or((text, DECIMAL), |hex| (hex, HEX));
        if digits.is_empty() {
            return Err(invalid());
        }
        let bytes = digits_be_opt(digits, radix).ok_or_else(invalid)?;
        Self::checked(text, &bytes)
    }
}

impl Validity {
    /// From `not_before` to `not_after`, seconds after the Unix epoch, each
    /// encoded as [RFC 5280 section 4.1.2.5] requires.
    ///
    /// [RFC 5280 section 4.1.2.5]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
    #[must_use]
    pub fn from_unix_seconds(not_before: u64, not_after: u64) -> Self {
        Validity {
            not_before: Time::from_unix_seconds(not_before),
            not_after: Time::from_unix_seconds(not_after),
        }
    }
}

/// Whether `openssl x509 -req` was given an extension file (`-extfile`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtensionFile {
    /// No extension file.
    #[default]
    Absent,
    /// An extension file gave some of the extensions.
    Given,
}

/// The extensions a CA is asked to write, and where they come from:
/// copied from the request ([`CopyExtensions`]), then an extension file's
/// section ([`crate::Config::extensions`]). Whether there was a file decides
/// whether OpenSSL 4 adds its default key identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssuedExtensions {
    /// The extensions, in order.
    pub extensions: Extensions,
    /// Whether an extension file gave some of them.
    pub extension_file: ExtensionFile,
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

/// The mode `-copy_extensions` names, as OpenSSL's `set_ext_copy` reads
/// it: `none`, `copy` or `copyall`, in any case.
///
/// # Errors
///
/// [`Error::Usage`] for any other name.
impl FromStr for CopyExtensions {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self> {
        [
            ("none", CopyExtensions::None),
            ("copy", CopyExtensions::Copy),
            ("copyall", CopyExtensions::CopyAll),
        ]
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, mode)| mode)
        .ok_or_else(|| {
            Error::Usage(format!("unknown extension copy mode {name:?}"))
        })
    }
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
        let requested = request.requested_extensions()?;
        for view in &requested.views()? {
            let extension = Extension::try_from(view)?;
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
    pub issuer: RawTlv,
    /// `validity`.
    pub validity: Validity,
    /// `subject`, a DER `Name`.
    pub subject: RawTlv,
    /// `subjectPublicKeyInfo`.
    pub public_key: PublicKey,
    /// `extensions`, in order.
    pub extensions: Extensions,
}

impl CertificateTemplate {
    /// The self-signed CA certificate `openssl req -x509` of the release
    /// line `P` writes with its default configuration: issuer and
    /// subject the same name, and the extensions of `v3_ca` (see the module
    /// documentation).
    #[must_use]
    pub fn self_signed<P>(
        subject: &DistinguishedName,
        key: &PublicKey,
        serial: SerialNumber,
        validity: Validity,
    ) -> Self
    where
        P: Profile,
    {
        let name = subject.to_raw();
        let id = key_identifier(key);
        let mut extensions = vec![Extension::new(
            ExtensionValue::SubjectKeyIdentifier(id.clone()),
        )];
        match P::SELF_SIGNED_AUTHORITY_KEY_ID {
            SelfSignedAuthorityKeyId::Written => extensions.push(
                Extension::new(ExtensionValue::AuthorityKeyIdentifier(id)),
            ),
            SelfSignedAuthorityKeyId::Omitted => {}
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
    /// of the release line `P` writes it: the request's subject and
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
    pub fn issued<P>(
        request: &CertificationRequest,
        ca: &Certificate<'_>,
        ca_key: &AnyPrivateKey,
        serial: SerialNumber,
        validity: Validity,
        extensions: &IssuedExtensions,
    ) -> Result<Self>
    where
        P: Profile,
    {
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
                .map(ExtensionValue::AuthorityKeyIdentifier)
                .ok_or_else(|| {
                    Error::unsupported(
                        "a CA certificate without a subject key identifier",
                    )
                })
        };
        let given = &extensions.extensions;
        let at_signing = || -> Result<Extensions> {
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
            Ok(given.as_slice().iter().cloned().chain(defaults).collect())
        };
        let all = match P::DEFAULT_KEY_IDENTIFIERS {
            DefaultKeyIdentifiers::FromConfiguration => {
                match extensions.extension_file {
                    ExtensionFile::Given => given.clone(),
                    ExtensionFile::Absent => given.override_with(
                        &[Extension::new(ski()), Extension::new(akid()?)]
                            .into_iter()
                            .collect(),
                    ),
                }
            }
            DefaultKeyIdentifiers::AtSigningWithExtensions
                if given.is_empty() =>
            {
                Extensions::new()
            }
            DefaultKeyIdentifiers::AtSigningWithExtensions
            | DefaultKeyIdentifiers::AtSigning => at_signing()?,
        };
        Ok(CertificateTemplate {
            serial,
            issuer: RawTlv::parse(ca.subject_der)?,
            validity,
            subject: request.subject().clone(),
            public_key: subject_key.clone(),
            extensions: all,
        })
    }

    /// The DER `TBSCertificate`, signed with `algorithm`: version 3 with
    /// its extensions, or version 1, without a version field (its default)
    /// and without extensions, when there are none, as OpenSSL sets it.
    fn tbs(&self, algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
        let tbs = Sequence((
            version_field(),
            (
                Unsigned,
                (
                    algorithm_identifier(),
                    (
                        Any,
                        (
                            Sequence((Any, (Any, ()))),
                            (
                                Any,
                                (
                                    Any,
                                    (
                                        Optional(Explicit::<3, _>(SequenceOf(
                                            Any,
                                        ))),
                                        (),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ));
        let (version, extensions) = if self.extensions.is_empty() {
            (None, None)
        } else {
            (
                Some(Version::v3()),
                Some(self.extensions.iter().map(Extension::to_raw).collect()),
            )
        };
        Ok(encode(
            &tbs,
            &(
                version,
                (
                    self.serial.0.clone(),
                    (
                        AlgorithmIdentifier::from(algorithm),
                        (
                            self.issuer.clone(),
                            (
                                (
                                    self.validity.not_before.to_der(),
                                    (self.validity.not_after.to_der(), ()),
                                ),
                                (
                                    self.subject.clone(),
                                    (
                                        RawTlv::parse(
                                            &self.public_key.encode(),
                                        )?,
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
            Sequence((Any, (algorithm_identifier(), (BitString, ()))));
        Ok(encode(
            &certificate,
            &(
                RawTlv::parse(&tbs)?,
                (AlgorithmIdentifier::from(algorithm), (signature, ())),
            ),
        ))
    }
}

#[cfg(test)]
mod tests;
