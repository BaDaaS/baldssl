//! Shared building blocks for baldssl: the error type, base64, PEM, DER and
//! small formatting helpers.
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
pub mod pem;

pub use error::Error;

/// Convenience alias used across the workspace.
pub type Result<T> = core::result::Result<T, Error>;
