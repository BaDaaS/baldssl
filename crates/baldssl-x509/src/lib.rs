//! X.509 certificates and certificate requests: decoding certificates
//! from PEM or DER and printing them in the exact formats of `openssl
//! x509`; writing distinguished names from `-subj` as OpenSSL does
//! ([`DistinguishedName`]); and creating, reading and verifying certificate
//! signing requests ([`CertificationRequest`]).
//!
//! Supported public keys: P-256, P-384, P-521 (`id-ecPublicKey` with a named
//! curve), Ed25519, and RSA for display. Anything else is reported as
//! [`baldssl_core::Error::Unsupported`].
//!
//! # Terms
//!
//! - **X.509**, the ITU-T recommendation ([X.509]) defining certificates,
//!   profiled for the Internet by [RFC 5280].
//! - **PEM**, Privacy-Enhanced Mail: the base64 text armour of [RFC 7468];
//!   **DER**, Distinguished Encoding Rules ([X.690] clause 10), the one
//!   binary encoding of each value.
//! - **PKCS**, Public-Key Cryptography Standards; **CSR**, certificate
//!   signing request, the PKCS#10 structure of [RFC 2986].
//! - **ASN.1**, Abstract Syntax Notation One ([X.680]), the language the
//!   structures are written in.
//! - **RDN**, relative distinguished name, one component of a name; **OID**,
//!   object identifier, the ASN.1 name of an attribute or an algorithm.
//! - **CA**, certificate authority, which signs certificates; **SPKI**,
//!   the `SubjectPublicKeyInfo` of a certificate or a request; **SKI** and
//!   **AKI**, the subject and authority key identifier extensions
//!   ([RFC 5280 section 4.2.1.2], [RFC 5280 section 4.2.1.1]).
//! - **IA5**, International Alphabet No. 5, ASCII, the alphabet of
//!   IA5String.
//! - **UTF-8**, Unicode Transformation Format, 8-bit ([RFC 3629]); **UCS**,
//!   Universal Coded Character Set (ISO/IEC 10646), whose UCS-2 and UCS-4
//!   encodings BMPString and UniversalString use.
//! - **EC**, elliptic curve; **ECDSA**, the Elliptic Curve Digital
//!   Signature Algorithm ([FIPS 186-5]); **NIST**, the National Institute
//!   of Standards and Technology, which names the curves P-256, P-384 and
//!   P-521.
//! - **RSA**, Rivest-Shamir-Adleman ([RFC 8017]); **PSS**, the
//!   Probabilistic Signature Scheme of RSA ([RFC 8017 section 8.1]).
//! - **SM2**, the Chinese elliptic curve signature standard (GB/T 32918),
//!   which OpenSSL pairs with the SM3 hash.
//! - **LP64** and **LLP64**, the C data models of Unix (`long` of 64 bits)
//!   and of Windows (`long` of 32 bits, `long long` of 64).
//!
//! [X.509]: https://www.itu.int/rec/T-REC-X.509
//! [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280
//! [RFC 7468]: https://www.rfc-editor.org/rfc/rfc7468
//! [X.690]: https://www.itu.int/rec/T-REC-X.690
//! [X.680]: https://www.itu.int/rec/T-REC-X.680
//! [RFC 2986]: https://www.rfc-editor.org/rfc/rfc2986
//! [RFC 5280 section 4.2.1.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
//! [RFC 5280 section 4.2.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
//! [RFC 3629]: https://www.rfc-editor.org/rfc/rfc3629
//! [FIPS 186-5]: https://csrc.nist.gov/pubs/fips/186-5/final
//! [RFC 8017]: https://www.rfc-editor.org/rfc/rfc8017
//! [RFC 8017 section 8.1]: https://www.rfc-editor.org/rfc/rfc8017#section-8.1

mod algorithm;
mod cert;
mod conf;
mod csr;
mod dn;
mod ext;
mod extension;
mod issue;
mod name;
mod objects;
mod objects_table;
mod oid;
mod text;
mod verify;
mod version;

pub use baldssl_crypto::signature::SignatureAlgorithm;
pub use cert::{Certificate, Validity};
pub use conf::{ConfValue, Config};
pub use csr::CertificationRequest;
pub use dn::{
    DistinguishedName, InputEncoding, ParsedSubject, RdnMode, RdnPosition,
    StringTypes, SubjError, SubjWarning, UTF8_ONLY,
};
pub use extension::{
    Extension, ExtensionValue, Extensions, GeneralName, Ia5String, KeyUsage,
};
pub use issue::{
    CertificateTemplate, CopyExtensions, ExtensionFile, IssuedExtensions,
    SerialNumber,
};
pub use name::{Name, NameStyle};
pub use text::{
    Compat, CsrSignatureWarning, ExtensionsWithoutFile, KeyLoadMessage,
    OneshotSigning, PublicKeyLoading, Stream, print_private_key_text,
    print_public_key_text, serial_line, time_rfc822,
};
pub use verify::{Failure, Reported, TrustStore, Verification, VerifyError};

use std::str::FromStr;

use baldssl_core::{Error, Result, der::syntax::RawTlv, pem};
use baldssl_crypto::Algorithm;

/// Every certificate of a file: the certificate blocks of PEM, in
/// order, or the one certificate of a DER file, as OpenSSL loads a file of
/// trust anchors or intermediates.
///
/// # Errors
///
/// A PEM file with no certificate, or a malformed block.
pub fn certificates_der(input: &[u8]) -> Result<Vec<RawTlv>> {
    if !pem::looks_like_pem(input) {
        return Ok(vec![RawTlv::parse(input)?]);
    }
    pem::decode_all(input, PEM_LABELS)?
        .into_iter()
        .map(|b| Ok(RawTlv::parse(&b.contents)?))
        .collect()
}

/// The PEM labels `PEM_read_bio_X509` accepts: [`Certificate::LABEL`], and
/// `X509 CERTIFICATE` (`PEM_STRING_X509_OLD` in `include/openssl/pem.h`).
const PEM_LABELS: &[&str] =
    &[Certificate::<'static>::LABEL, "X509 CERTIFICATE"];

/// Input or output encoding (`-inform`, `-outform`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Base64 between `BEGIN`/`END` lines.
    Pem,
    /// Raw DER.
    Der,
}

impl Format {
    /// The format given, or without one the format of `input`: PEM when it
    /// holds a `BEGIN` boundary ([`pem::looks_like_pem`]), as OpenSSL 3
    /// detects it, DER otherwise.
    #[must_use]
    pub fn given_or_detected(given: Option<Format>, input: &[u8]) -> Format {
        given.unwrap_or(if pem::looks_like_pem(input) {
            Format::Pem
        } else {
            Format::Der
        })
    }
}

/// `PEM` or `DER`, in any case, as OpenSSL's `opt_format` reads the value
/// of `-inform` and `-outform` (`apps/lib/opt.c`).
///
/// # Errors
///
/// [`Error::Usage`] for any other name.
impl FromStr for Format {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self> {
        [("PEM", Format::Pem), ("DER", Format::Der)]
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, format)| format)
            .ok_or_else(|| Error::Usage(format!("invalid format {name:?}")))
    }
}

/// Extracts the DER of the first certificate in `input`. With no explicit
/// format, PEM is assumed when a `BEGIN` boundary is present, as OpenSSL 3
/// does.
///
/// # Errors
///
/// When the input holds no decodable certificate framing.
pub fn certificate_der(
    input: &[u8],
    format: Option<Format>,
) -> Result<Vec<u8>> {
    match Format::given_or_detected(format, input) {
        Format::Der => Ok(input.to_vec()),
        Format::Pem => {
            if pem::looks_like_pem(input)
                && pem::decode_first(input, &["TRUSTED CERTIFICATE"]).is_ok()
                && pem::decode_first(input, PEM_LABELS).is_err()
            {
                return Err(Error::unsupported(
                    "TRUSTED CERTIFICATE (certificates with trust settings)",
                ));
            }
            Ok(pem::decode_first(input, PEM_LABELS)?.contents)
        }
    }
}

/// `-fingerprint`: `"<label> Fingerprint=AA:BB:...\n"`, where `label` is the
/// digest name exactly as it was spelled on the command line (OpenSSL echoes
/// it: `-SHA256` prints `SHA256`).
#[must_use]
pub fn fingerprint_line(der: &[u8], alg: Algorithm, label: &str) -> String {
    format!(
        "{label} Fingerprint={}\n",
        baldssl_core::hex::colon(
            &alg.digest(der),
            baldssl_core::hex::Case::Upper
        )
    )
}
