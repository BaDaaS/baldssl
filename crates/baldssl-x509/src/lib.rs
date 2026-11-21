//! X.509 certificates: decoding from PEM or DER, and printing in the exact
//! formats of `openssl x509`.
//!
//! Supported public keys: P-256, P-384, P-521 (`id-ecPublicKey` with a named
//! curve), Ed25519, and RSA for display. Anything else is reported as
//! [`baldssl_core::Error::Unsupported`].

pub mod cert;
pub mod ext;
pub mod name;
pub mod objects;
mod objects_table;
pub mod text;

pub use cert::Certificate;

use baldssl_core::{Error, Result, pem};
use baldssl_crypto::Algorithm;

/// The PEM labels `PEM_read_bio_X509` accepts.
pub const PEM_LABELS: &[&str] = &["CERTIFICATE", "X509 CERTIFICATE"];

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
