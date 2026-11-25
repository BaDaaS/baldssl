//! PEM (Privacy-Enhanced Mail) framing ([RFC 7468 section 2][rfc7468]):
//! `-----BEGIN LABEL-----`, base64, `-----END LABEL-----`.
//!
//! Like OpenSSL, text outside the boundaries is ignored and blocks whose label
//! is not wanted are skipped, so a file holding `openssl x509 -text` output or
//! a key followed by a certificate still yields the certificate. Line endings
//! may be LF or CRLF (files written on Windows).
//!
//! [rfc7468]: https://www.rfc-editor.org/rfc/rfc7468#section-2

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

/// The start of a BEGIN line, before the label ([RFC 7468 section 2][s2]).
///
/// [s2]: https://www.rfc-editor.org/rfc/rfc7468#section-2
const BEGIN: &str = "-----BEGIN ";
/// The start of an END line, before the label ([RFC 7468 section 2][s2]).
///
/// [s2]: https://www.rfc-editor.org/rfc/rfc7468#section-2
const END: &str = "-----END ";
/// The end of BEGIN and END lines, after the label ([RFC 7468 section
/// 2][s2]).
///
/// [s2]: https://www.rfc-editor.org/rfc/rfc7468#section-2
const DASHES: &str = "-----";
/// Base64 characters per line: "Generators MUST wrap the base64-encoded
/// lines so that each line consists of exactly 64 characters except for the
/// final line" ([RFC 7468 section 2][s2]).
///
/// [s2]: https://www.rfc-editor.org/rfc/rfc7468#section-2
const LINE_WIDTH: usize = 64;

/// Whether `input` contains a PEM `BEGIN` boundary. Used to tell PEM from DER
/// when no `-inform` is given, the way OpenSSL 3 does.
#[must_use]
pub fn looks_like_pem(input: &[u8]) -> bool {
    input.windows(BEGIN.len()).any(|w| w == BEGIN.as_bytes())
}

/// `line` without the CR of a CRLF ending; a line without one is already
/// trimmed.
fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn boundary_opt<'a>(line: &'a [u8], prefix: &str) -> Option<&'a [u8]> {
    line.strip_prefix(prefix.as_bytes())?
        .strip_suffix(DASHES.as_bytes())
}

/// One block as read, before its body is decoded.
struct RawBlock {
    /// The label of its BEGIN and END lines.
    label: Vec<u8>,
    /// The base64 body, spaces removed.
    body: Vec<u8>,
}

/// The blocks of `input`, in order: each between a BEGIN and the matching
/// END boundary, text outside them ignored, as OpenSSL's PEM reader skips
/// it.
fn blocks(
    input: &[u8],
) -> impl Iterator<Item = Result<RawBlock, PemError>> + '_ {
    let mut lines = input.split(|&b| b == b'\n').map(trim_cr);
    core::iter::from_fn(move || {
        let label =
            lines.by_ref().find_map(|line| boundary_opt(line, BEGIN))?;
        let mut body = Vec::new();
        for inner in lines.by_ref() {
            if let Some(end) = boundary_opt(inner, END) {
                if end != label {
                    return Some(Err(PemError::Unterminated));
                }
                return Some(Ok(RawBlock {
                    label: label.to_vec(),
                    body,
                }));
            }
            if inner.contains(&b':') {
                return Some(Err(PemError::HeadersUnsupported));
            }
            body.extend(
                inner.iter().filter(|b| !matches!(b, b' ' | b'\t' | b'\r')),
            );
        }
        Some(Err(PemError::Unterminated))
    })
}

/// A block, decoded, when its label is in `labels`.
fn matching_opt(
    RawBlock { label, body }: RawBlock,
    labels: &[&str],
) -> Option<Result<PemBlock, PemError>> {
    let wanted = labels.iter().find(|l| l.as_bytes() == label)?;
    Some(
        base64::decode(&body)
            .map_err(PemError::Base64)
            .map(|contents| PemBlock {
                label: (*wanted).to_owned(),
                contents,
            }),
    )
}

/// Returns the first block whose label is in `labels`.
///
/// # Errors
///
/// [`PemError::NoBlock`] when there is none, or the error of the first
/// matching block that fails to decode, or of a malformed block before it.
pub fn decode_first(
    input: &[u8],
    labels: &[&str],
) -> Result<PemBlock, PemError> {
    for block in blocks(input) {
        if let Some(found) = matching_opt(block?, labels) {
            return found;
        }
    }
    Err(PemError::NoBlock)
}

/// Every block whose label is in `labels`, in order: a file of several
/// certificates, as `-CAfile` and `-untrusted` take them.
///
/// # Errors
///
/// [`PemError::NoBlock`] when there is none; a malformed block, or a
/// matching block that fails to decode.
pub fn decode_all(
    input: &[u8],
    labels: &[&str],
) -> Result<Vec<PemBlock>, PemError> {
    let mut out = Vec::new();
    for block in blocks(input) {
        if let Some(found) = matching_opt(block?, labels) {
            out.push(found?);
        }
    }
    if out.is_empty() {
        return Err(PemError::NoBlock);
    }
    Ok(out)
}

/// Encodes a PEM block with lines of 64 base64 characters, the last one
/// shorter (RFC 7468 section 2), and LF line endings, as `PEM_write` does.
#[must_use]
pub fn encode(label: &str, contents: &[u8]) -> String {
    let b64 = base64::encode(contents);
    let mut out = String::with_capacity(b64.len().saturating_add(LINE_WIDTH));
    for boundary in [BEGIN, label, DASHES, "\n"] {
        out.push_str(boundary);
    }
    let mut rest = b64.as_str();
    while !rest.is_empty() {
        // The final line is what remains when it is shorter than a line.
        let (line, tail) =
            rest.split_at_checked(LINE_WIDTH).unwrap_or((rest, ""));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    for boundary in [END, label, DASHES, "\n"] {
        out.push_str(boundary);
    }
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
            assert!(line.len() <= LINE_WIDTH);
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

    /// Every matching block, in order, with text between them ignored;
    /// the first malformed block is an error.
    #[test]
    fn all_blocks() {
        let input = format!(
            "intro\n{}between\n{}{}",
            encode("CERTIFICATE", b"one"),
            encode("PRIVATE KEY", b"skipped"),
            encode("CERTIFICATE", b"two"),
        );
        let blocks = decode_all(input.as_bytes(), &["CERTIFICATE"]).unwrap();
        let contents: Vec<&[u8]> =
            blocks.iter().map(|b| b.contents.as_slice()).collect();
        assert_eq!(contents, [&b"one"[..], b"two"]);
        assert_eq!(
            decode_all(b"no blocks", &["CERTIFICATE"]),
            Err(PemError::NoBlock)
        );
        let broken = "-----BEGIN CERTIFICATE-----\nAAAA\n";
        assert_eq!(
            decode_all(broken.as_bytes(), &["CERTIFICATE"]),
            Err(PemError::Unterminated)
        );
    }
}
