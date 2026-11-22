//! Secret byte strings: owned, never printed, and overwritten when
//! dropped.

use crate::ct::{Choice, CtEq};

/// Bytes that must not outlive their use: a key, a padded key, the state of
/// a random bit generator. [`Debug`](core::fmt::Debug) prints only the
/// length, and the bytes are overwritten with zeros on drop. The overwrite
/// is best effort (`core::hint::black_box` keeps it from being optimised
/// away, but copies the allocator or the compiler made are not reached), as
/// for the key pairs of [`keys`](crate::keys).
/// Equality is only [`CtEq`]: no `==` that could stop at the first
/// difference.
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// The bytes, taken over.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }

    /// `len` bytes equal to `byte`.
    #[must_use]
    pub fn filled(byte: u8, len: usize) -> Self {
        SecretBytes(vec![byte; len])
    }

    /// The bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The length in bytes, which is not secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl CtEq for SecretBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        core::hint::black_box(&self.0);
    }
}
