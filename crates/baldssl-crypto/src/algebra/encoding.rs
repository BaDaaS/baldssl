//! Canonical encodings, as traits: those of [`baldssl_core::encoding`],
//! shared by every crate, re-exported here so the algebra layer names them
//! with the other structures. Their laws are stated there.

pub use baldssl_core::encoding::{Decodable, Encodable, InvalidEncoding};
