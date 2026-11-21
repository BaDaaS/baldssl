//! Constant-time building blocks.
//!
//! A [`Choice`] is a secret boolean held as an all-zeros or all-ones 64-bit
//! mask, so selecting between two values is a bitwise blend instead of a
//! branch. `core::hint::black_box` keeps the compiler from turning the masks
//! back into branches; it is a best-effort barrier, not a guarantee, which is
//! the same position the `subtle` crate takes.

/// A secret boolean: the mask is `0` (false) or `u64::MAX` (true).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choice(u64);

impl Choice {
    /// False.
    pub const FALSE: Self = Choice(0);
    /// True.
    pub const TRUE: Self = Choice(u64::MAX);

    /// From the low bit of `bit`, which must be 0 or 1.
    #[must_use]
    pub fn from_bit(bit: u64) -> Self {
        Choice(core::hint::black_box((bit & 1).wrapping_neg()))
    }

    /// The mask.
    #[must_use]
    pub fn mask(self) -> u64 {
        self.0
    }

    /// Declassifies the value. Only for results that are public.
    #[must_use]
    pub fn to_bool_vartime(self) -> bool {
        self.0 != 0
    }
}

impl core::ops::BitAnd for Choice {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Choice(self.0 & rhs.0)
    }
}

impl core::ops::BitOr for Choice {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Choice(self.0 | rhs.0)
    }
}

impl core::ops::Not for Choice {
    type Output = Self;

    fn not(self) -> Self {
        Choice(!self.0)
    }
}

/// `a` if `choice` is false, `b` if it is true, without branching.
#[must_use]
pub fn select(a: u64, b: u64, choice: Choice) -> u64 {
    a ^ ((a ^ b) & choice.0)
}

/// Whether a 64-bit word is zero.
#[must_use]
pub fn is_zero(x: u64) -> Choice {
    // (x | -x) has its top bit set exactly when x != 0.
    let nonzero = (x | x.wrapping_neg()) >> 63;
    Choice::from_bit(nonzero ^ 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn constants() {
        assert_eq!(Choice::from_bit(0), Choice::FALSE);
        assert_eq!(Choice::from_bit(1), Choice::TRUE);
        assert!(Choice::TRUE.to_bool_vartime());
        assert_eq!(!Choice::TRUE, Choice::FALSE);
        assert_eq!(is_zero(0), Choice::TRUE);
        assert_eq!(is_zero(1), Choice::FALSE);
        assert_eq!(is_zero(u64::MAX), Choice::FALSE);
        assert_eq!(is_zero(1 << 63), Choice::FALSE);
    }

    proptest! {
        #[test]
        fn select_is_a_mux(a in any::<u64>(), b in any::<u64>(), c in any::<bool>()) {
            let choice = Choice::from_bit(u64::from(c));
            prop_assert_eq!(select(a, b, choice), if c { b } else { a });
        }

        #[test]
        fn boolean_algebra(x in any::<bool>(), y in any::<bool>()) {
            let (cx, cy) = (Choice::from_bit(u64::from(x)), Choice::from_bit(u64::from(y)));
            prop_assert_eq!((cx & cy).to_bool_vartime(), x && y);
            prop_assert_eq!((cx | cy).to_bool_vartime(), x || y);
            prop_assert_eq!((!cx).to_bool_vartime(), !x);
        }

        #[test]
        fn is_zero_matches(x in any::<u64>()) {
            prop_assert_eq!(is_zero(x).to_bool_vartime(), x == 0);
        }
    }
}
