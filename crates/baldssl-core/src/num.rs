//! Integer conversions `From` and `TryFrom` cannot make: in `const` code,
//! where trait methods are not callable, and truncations that must stay
//! branch-free because they run on secret data (a `TryFrom` would branch
//! on the value). This module is the only place an `as` converts integers;
//! each conversion says why it loses nothing, or what it keeps.

/// baldssl builds for 32-bit and 64-bit targets only, so a `usize` holds
/// every `u32` and fits in a `u64`.
const _: () = assert!(
    usize::BITS == 32 || usize::BITS == 64,
    "baldssl supports 32-bit and 64-bit targets"
);

/// A `u32` as a `usize`: lossless, a `usize` being at least 32 bits.
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "lossless on the 32-bit and 64-bit targets asserted above; \
              `usize::try_from` is not callable in const code"
)]
pub const fn u32_to_usize(x: u32) -> usize {
    x as usize
}

/// A `usize` as a `u64`: lossless, a `usize` being at most 64 bits.
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "lossless on the 32-bit and 64-bit targets asserted above; \
              `u64::try_from` is not callable in const code"
)]
pub const fn usize_to_u64(x: usize) -> u64 {
    x as u64
}

/// A `u64` as a `u128`: lossless.
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "a widening; `u128::from` is not callable in const code"
)]
pub const fn u64_to_u128(x: u64) -> u128 {
    x as u128
}

/// A `u8` as a `u64`: lossless.
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "a widening; `u64::from` is not callable in const code"
)]
pub const fn u8_to_u64(x: u8) -> u64 {
    x as u64
}

/// A `u8` as a `u32`: lossless.
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "a widening; `u32::from` is not callable in const code"
)]
pub const fn u8_to_u32(x: u8) -> u32 {
    x as u32
}

/// The low 64 bits of a `u128`, without a branch: the low limb of a
/// double-word product or sum in constant-time arithmetic.
#[allow(
    clippy::cast_possible_truncation,
    reason = "keeping the low bits is the conversion this function names"
)]
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "the truncation is the operation; a checked conversion would \
              branch on secret data"
)]
pub const fn low_u64(x: u128) -> u64 {
    x as u64
}

/// The low 32 bits of a `usize`: callers pass a limb index, far below
/// 2^32.
#[allow(
    clippy::cast_possible_truncation,
    reason = "keeping the low bits is the conversion this function names"
)]
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "callers pass values below 2^32, and `u32::try_from` is not \
              callable in const code"
)]
pub const fn low_u32(x: usize) -> u32 {
    x as u32
}

/// The low 8 bits of a `u32`, without a branch: an octet of a shifted
/// value (a UTF-8 byte of a code point).
#[allow(
    clippy::cast_possible_truncation,
    reason = "keeping the low bits is the conversion this function names"
)]
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "the truncation is the operation: callers mask or shift the \
              value to the octet they want"
)]
pub const fn low_u8(x: u32) -> u8 {
    x as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The widenings are the `From` conversions, and the truncations keep
    /// the low bits.
    #[test]
    fn conversions() {
        for x in [0u32, 1, 0x8000_0000, u32::MAX] {
            assert_eq!(Some(u32_to_usize(x)), usize::try_from(x).ok());
        }
        for x in [0usize, 1, usize::MAX] {
            assert_eq!(Some(usize_to_u64(x)), u64::try_from(x).ok());
        }
        for x in [0u64, 1, u64::MAX] {
            assert_eq!(u64_to_u128(x), u128::from(x));
        }
        for x in [0u8, 1, u8::MAX] {
            assert_eq!(u8_to_u64(x), u64::from(x));
            assert_eq!(u8_to_u32(x), u32::from(x));
        }
        assert_eq!(low_u64(u128::MAX), u64::MAX);
        assert_eq!(low_u64(1 << 64), 0);
        assert_eq!(low_u32(7), 7);
        assert_eq!(low_u8(0x1ff), 0xff);
    }
}
