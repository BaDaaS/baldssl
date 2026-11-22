//! PEM framing ([RFC 7468][rfc7468]): `-----BEGIN LABEL-----`, base64, `-----END
//! LABEL-----`.
//!
//! Like OpenSSL, text outside the boundaries is ignored and blocks whose label
//! is not wanted are skipped, so a file holding `openssl x509 -text` output or
//! a key followed by a certificate still yields the certificate. Line endings
//! may be LF or CRLF (files written on Windows).
//!
//! [rfc7468]: https://www.rfc-editor.org/rfc/rfc7468

use crate::{
    base64::{self, Base64Error},
    encoding::Encodable,
};

/// Why a PEM document was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PemError {
    /// No block with an accepted label was found.
    NoBlock,
    /// A `BEGIN` line has no matching `END` line.
    Unterminated,
    /// The block carries [RFC 1421][rfc1421] headers (`Proc-Type:`), which are only used
    /// by legacy encrypted keys.
    ///
    /// [rfc1421]: https://www.rfc-editor.org/rfc/rfc1421
    HeadersUnsupported,
    /// The body is not valid base64.
    Base64(Base64Error),
}

/// One decoded PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// The label between `BEGIN ` and the dashes, e.g. `CERTIFICATE`.
    pub label: String,
    /// The decoded body.
    pub contents: Vec<u8>,
}

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

/// Whether `input` contains a PEM `BEGIN` boundary. Used to tell PEM from DER
/// when no `-inform` is given, the way OpenSSL 3 does.
#[must_use]
pub fn looks_like_pem(input: &[u8]) -> bool {
    input.windows(BEGIN.len()).any(|w| w == BEGIN)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn boundary<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    line.strip_prefix(prefix)?.strip_suffix(DASHES)
}

/// Returns the first block whose label is in `labels`.
///
/// # Errors
///
/// [`PemError::NoBlock`] when there is none, or the error of the first
/// matching block that fails to decode.
pub fn decode_first(
    input: &[u8],
    labels: &[&str],
) -> Result<PemBlock, PemError> {
    let mut lines = input.split(|&b| b == b'\n').map(trim_cr);
    while let Some(line) = lines.next() {
        let Some(label) = boundary(line, BEGIN) else {
            continue;
        };
        let mut body = Vec::new();
        let mut terminated = false;
        for inner in lines.by_ref() {
            if let Some(end) = boundary(inner, END) {
                if end != label {
                    return Err(PemError::Unterminated);
                }
                terminated = true;
                break;
            }
            if inner.contains(&b':') {
                return Err(PemError::HeadersUnsupported);
            }
            body.extend(
                inner.iter().filter(|b| !matches!(b, b' ' | b'\t' | b'\r')),
            );
        }
        if !terminated {
            return Err(PemError::Unterminated);
        }
        if labels.iter().any(|l| l.as_bytes() == label) {
            let contents = base64::decode(&body).map_err(PemError::Base64)?;
            return Ok(PemBlock {
                label: String::from_utf8_lossy(label).into_owned(),
                contents,
            });
        }
    }
    Err(PemError::NoBlock)
}

/// Encodes a PEM block with 64-column lines and LF line endings, as
/// `PEM_write` does.
#[must_use]
pub fn encode(label: &str, contents: &[u8]) -> String {
    let b64 = base64::encode(contents);
    let mut out = String::with_capacity(b64.len().saturating_add(64));
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// A type with a PEM armour ([RFC 7468][rfc7468]): its canonical encoding
/// ([`Encodable`]), base64 between `-----BEGIN` and `-----END` lines naming
/// its label. One label per type, as there is one encoding per type; a
/// second armour (`EC PRIVATE KEY` beside `PRIVATE KEY`) goes on the newtype
/// that carries the second encoding.
///
/// [rfc7468]: https://www.rfc-editor.org/rfc/rfc7468
pub trait Pem: Encodable {
    /// The label of the BEGIN and END lines.
    const LABEL: &'static str;

    /// The PEM armour of the encoding.
    #[must_use]
    fn to_pem(&self) -> String {
        encode(Self::LABEL, self.encode().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const CERT: &[&str] = &["CERTIFICATE"];

    #[test]
    fn skips_text_and_other_blocks() {
        let doc = b"Certificate:\n  junk\n-----BEGIN PRIVATE KEY-----\n\
            AAAA\n-----END PRIVATE KEY-----\n\
            -----BEGIN CERTIFICATE-----\r\nZm9v\r\nYmFy\r\n\
            -----END CERTIFICATE-----\r\n";
        let block = decode_first(doc, CERT).unwrap();
        assert_eq!(block.label, "CERTIFICATE");
        assert_eq!(block.contents, b"foobar");
    }

    #[test]
    fn errors() {
        assert_eq!(decode_first(b"nothing", CERT), Err(PemError::NoBlock));
        assert_eq!(
            decode_first(b"-----BEGIN CERTIFICATE-----\nZm9v\n", CERT),
            Err(PemError::Unterminated)
        );
        assert_eq!(
            decode_first(
                b"-----BEGIN CERTIFICATE-----\nZm9v\n-----END X-----\n",
                CERT
            ),
            Err(PemError::Unterminated)
        );
        assert_eq!(
            decode_first(
                b"-----BEGIN CERTIFICATE-----\nProc-Type: 4\n\
                  -----END CERTIFICATE-----\n",
                CERT
            ),
            Err(PemError::HeadersUnsupported)
        );
        assert!(matches!(
            decode_first(
                b"-----BEGIN CERTIFICATE-----\nZm9\n-----END CERTIFICATE-----",
                CERT
            ),
            Err(PemError::Base64(_))
        ));
    }

    #[test]
    fn detection() {
        assert!(looks_like_pem(b"junk\n-----BEGIN X-----\n"));
        assert!(!looks_like_pem(b"-----BEGIN"));
        assert!(!looks_like_pem(&[0x30, 0x82, 0x01]));
    }

    #[test]
    fn line_width() {
        let pem = encode("CERTIFICATE", &[0u8; 100]);
        for line in pem.lines() {
            assert!(line.len() <= 64);
        }
    }

    proptest! {
        #[test]
        fn roundtrip(data in prop::collection::vec(any::<u8>(), 0..500)) {
            let pem = encode("CERTIFICATE", &data);
            prop_assert!(looks_like_pem(pem.as_bytes()));
            let block = decode_first(pem.as_bytes(), CERT).unwrap();
            prop_assert_eq!(block.contents, data.clone());
            let crlf = pem.replace('\n', "\r\n");
            let block = decode_first(crlf.as_bytes(), CERT).unwrap();
            prop_assert_eq!(block.contents, data);
        }

        #[test]
        fn never_panics(data in prop::collection::vec(any::<u8>(), 0..200)) {
            let _ = decode_first(&data, CERT);
        }
    }
}
