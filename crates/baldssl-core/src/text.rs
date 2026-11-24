//! Text forms: a value as an `openssl ... -text` option prints it.
//!
//! [`Text`] is to `-text` output what [`Display`](core::fmt::Display) is to
//! formatting, with three differences that rule `Display` out:
//!
//! - the form depends on a layout (OpenSSL's release lines print the same
//!   value differently), which `Display` cannot take;
//! - printing can fail, with a reason (a structure baldssl cannot yet print
//!   exactly as OpenSSL does), where `Display` only has `fmt::Error`;
//! - the form is bytes, not a `str`: OpenSSL copies the contents of some
//!   strings through unvalidated, and the output must match it byte for
//!   byte.
//!
//! Like the encodings ([`Encodable`](crate::encoding::Encodable),
//! [`Pem`](crate::pem::Pem)), a text form does no I/O; `baldssl-fs` writes
//! it to a writer.

use crate::Result;

/// A value with a text form.
pub trait Text {
    /// What selects among the layouts the form has.
    type Layout: Copy;

    /// The text form of `self` under `layout`.
    ///
    /// # Errors
    ///
    /// When the value has no text form under `layout`, or is malformed.
    fn to_text(&self, layout: Self::Layout) -> Result<Vec<u8>>;
}
