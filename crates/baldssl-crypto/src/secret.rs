//! Secrets: byte strings ([`SecretBytes`]) and field elements
//! ([`SecretScalar`]), owned, never printed, and overwritten when dropped.

use crate::{
    algebra::field::Field,
    ct::{Choice, CtEq},
};

/// Overwrites `words` with zeros, best effort (see [`SecretBytes`]): the
/// state of a hash engine, a buffer about to be freed.
pub(crate) fn wipe<T>(words: &mut [T])
where
    T: Copy + Default,
{
    words.fill(T::default());
    core::hint::black_box(words);
}

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

    /// The bytes, to be written in place: a buffer that a random source
    /// fills, a key padded where it lies, so that no unwiped copy is made.
    #[must_use]
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
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

impl crate::sealed::Sealed for SecretBytes {}

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
        wipe(&mut self.0);
    }
}

/// A secret element of a field: a private scalar, a nonce, its inverse.
/// The field's elements are `Copy`, so a bare one can be duplicated and is
/// never wiped; this wrapper is not `Copy`, shows nothing in
/// [`Debug`](core::fmt::Debug), compares only by [`CtEq`], and overwrites
/// the element with zero when dropped, with the same best effort as
/// [`SecretBytes`] (copies taken through [`SecretScalar::expose`] are the
/// caller's).
pub struct SecretScalar<F>(F)
where
    F: Field;

impl<F> SecretScalar<F>
where
    F: Field,
{
    /// The element, taken over.
    #[must_use]
    pub fn new(value: F) -> Self {
        SecretScalar(value)
    }

    /// The element.
    #[must_use]
    pub fn expose(&self) -> &F {
        &self.0
    }
}

impl<F> crate::sealed::Sealed for SecretScalar<F> where F: Field {}

impl<F> CtEq for SecretScalar<F>
where
    F: Field,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<F> core::fmt::Debug for SecretScalar<F>
where
    F: Field,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretScalar(..)")
    }
}

impl<F> Drop for SecretScalar<F>
where
    F: Field,
{
    fn drop(&mut self) {
        self.0 = F::ZERO;
        core::hint::black_box(&self.0);
    }
}
