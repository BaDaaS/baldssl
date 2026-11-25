//! Shared building blocks for baldssl: the error type, base64, PEM, DER and
//! small formatting helpers.
//!
//! # Acronyms and the standards behind them
//!
//! - **base64**: the base 64 encoding of [RFC 4648 section 4][rfc4648].
//! - **PEM**, Privacy-Enhanced Mail: base64 between `-----BEGIN` and
//!   `-----END` lines, as [RFC 7468 section 2][rfc7468] specifies it.
//! - **ASN.1**, Abstract Syntax Notation One ([ITU-T X.680][x680]): the
//!   language certificates and keys are defined in.
//! - **BER**, the Basic Encoding Rules, and **DER**, the Distinguished
//!   Encoding Rules, its restriction to one encoding per value
//!   ([ITU-T X.690][x690], clauses 8 and 10).
//! - **TLV**, tag-length-value: the shape of every BER and DER element
//!   (X.690 clause 8.1).
//! - **OID**, object identifier: a value of the ASN.1 OBJECT IDENTIFIER
//!   type (X.680), encoded as X.690 clause 8.19 says.
//! - **PKCS**, Public-Key Cryptography Standards: PKCS #8 is the private-key
//!   format of [RFC 5208][rfc5208].
//!
//! [rfc4648]: https://www.rfc-editor.org/rfc/rfc4648#section-4
//! [rfc7468]: https://www.rfc-editor.org/rfc/rfc7468#section-2
//! [x680]: https://www.itu.int/rec/T-REC-X.680
//! [x690]: https://www.itu.int/rec/T-REC-X.690
//! [rfc5208]: https://www.rfc-editor.org/rfc/rfc5208#section-5
//!
//! Everything here is written without third-party crates, in a restricted
//! style (no `unsafe`, no panicking indexing, checked arithmetic) so that the
//! parsers can be extracted to Lean 4 with Charon + Aeneas and proved total.
//! Building with `--cfg aeneas` compiles out the parts Aeneas does not
//! translate (I/O, `Display`, `std::error::Error`).

#![deny(clippy::arithmetic_side_effects)]
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

pub mod base64;
pub mod der;
pub mod encoding;
pub mod error;
pub mod hex;
pub mod num;
pub mod pem;
pub mod text;

pub use error::Error;

/// Convenience alias used across the workspace.
pub type Result<T> = core::result::Result<T, Error>;
