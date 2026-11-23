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
//! - **RDN**, relative distinguished name, one component of a name; **OID**,
//!   object identifier, the ASN.1 name of an attribute or an algorithm.
//!
//! [X.509]: https://www.itu.int/rec/T-REC-X.509
//! [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280
//! [RFC 7468]: https://www.rfc-editor.org/rfc/rfc7468
//! [X.690]: https://www.itu.int/rec/T-REC-X.690
//! [RFC 2986]: https://www.rfc-editor.org/rfc/rfc2986

mod algorithm;
mod cert;
mod csr;
mod dn;
mod ext;
mod name;
mod objects;
mod objects_table;
mod text;
mod version;

pub use baldssl_crypto::signature::SignatureAlgorithm;
pub use cert::{Certificate, Validity};
pub use csr::CertificationRequest;
pub use dn::{
    DistinguishedName, InputEncoding, StringTypes, SubjError, SubjWarning,
    UTF8_ONLY,
};
pub use name::{Name, NameStyle};
pub use text::{Compat, print_text, serial_line, time_rfc822};

use baldssl_core::{Error, Result, pem};
use baldssl_crypto::Algorithm;

/// The PEM labels `PEM_read_bio_X509` accepts.
const PEM_LABELS: &[&str] = &["CERTIFICATE", "X509 CERTIFICATE"];

/// Input encoding (`-inform`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Base64 between `BEGIN`/`END` lines.
    Pem,
    /// Raw DER.
    Der,
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
    let format = format.unwrap_or(if pem::looks_like_pem(input) {
        Format::Pem
    } else {
        Format::Der
    });
    match format {
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
