//! Constant-time building blocks.
//!
//! A [`Choice`] is a secret boolean held as an all-zeros or all-ones 64-bit
//! mask, so selecting between two values is a bitwise blend instead of a
//! branch. `core::hint::black_box` keeps the compiler from turning the masks
//! back into branches; it is a best-effort barrier, not a guarantee, which is
//! the same position the `subtle` crate takes.

/// A secret boolean: the mask is `0` (false) or `u64::MAX` (true).
///
/// [`Debug`](core::fmt::Debug) shows nothing of the value, and there is no
/// `==` outside the tests: a choice is declassified only by
/// [`Choice::to_bool_vartime`], where the caller says it is public.
#[must_use]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Choice(u64);

impl core::fmt::Debug for Choice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Choice(..)")
    }
}

impl Choice {
    /// False.
    pub const FALSE: Self = Choice(0);
    /// True.
    pub const TRUE: Self = Choice(u64::MAX);

    /// From the low bit of `bit`, which must be 0 or 1.
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

/// Exclusive or: addition in $\mathbb{F}_2$, so two choices are equal when
/// their sum is false.
impl core::ops::BitXor for Choice {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Choice(self.0 ^ rhs.0)
    }
}

impl core::ops::Not for Choice {
    type Output = Self;

    fn not(self) -> Self {
        Choice(!self.0)
    }
}

/// Equality without branching on the values: the base of every structure
/// whose elements may be secret (fields, points).
pub trait CtEq: crate::sealed::Sealed {
    /// Whether `self` equals `other`.
    fn ct_eq(&self, other: &Self) -> Choice;
}

/// Byte strings compare in time that depends on their lengths only, which
/// are public: a MAC tag or a padded key is compared without returning at
/// the first difference.
impl crate::sealed::Sealed for [u8] {}

impl CtEq for [u8] {
    fn ct_eq(&self, other: &Self) -> Choice {
        if self.len() != other.len() {
            return Choice::FALSE;
        }
        let diff = self
            .iter()
            .zip(other)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        is_zero(u64::from(core::hint::black_box(diff)))
    }
}

/// Selection without branching: `a` if `choice` is false, `b` if it is
/// true. With [`CtEq`], what a type needs for constant-time code over it.
pub trait CtSelect: Sized + crate::sealed::Sealed {
    /// `a` if `choice` is false, `b` if it is true.
    #[must_use]
    fn select(a: &Self, b: &Self, choice: Choice) -> Self;
}

/// `a` if `choice` is false, `b` if it is true, without branching.
#[must_use]
pub fn select(a: u64, b: u64, choice: Choice) -> u64 {
    a ^ ((a ^ b) & choice.0)
}

/// Whether a 64-bit word is zero.
pub fn is_zero(x: u64) -> Choice {
    // (x | -x) has its top bit set exactly when x != 0.
    let nonzero = (x | x.wrapping_neg()) >> 63;
    Choice::from_bit(nonzero ^ 1)
}

/// A value that may be absent, where whether it is present is a secret
/// [`Choice`]: the constant-time counterpart of [`Option`]. Decoding a field
/// element, taking a square root or checking that coordinates are on the
/// curve gives one; the value is always there (a placeholder when absent),
/// so using it does not branch, and [`CtOption::unwrap_or_ct`] replaces the
/// placeholder without branching either.
#[must_use]
#[derive(Clone, Copy)]
pub struct CtOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> CtOption<T> {
    /// `value`, present when `is_some` is true.
    pub fn new(value: T, is_some: Choice) -> Self {
        CtOption { value, is_some }
    }

    /// Whether the value is present.
    pub fn is_some(&self) -> Choice {
        self.is_some
    }

    /// The value when present, `default` otherwise, without branching.
    #[must_use]
    pub fn unwrap_or_ct(self, default: &T) -> T
    where
        T: CtSelect,
    {
        T::select(default, &self.value, self.is_some)
    }

    /// The value and whether it is present, for tests that look at both.
    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (T, Choice) {
        (self.value, self.is_some)
    }

    /// The value as an [`Option`]: declassifies whether it is present. Only
    /// for results whose presence is public (a decoding of public bytes, a
    /// rejection that leaks only how many candidates were drawn).
    #[must_use]
    pub fn into_vartime_opt(self) -> Option<T> {
        self.is_some.to_bool_vartime().then_some(self.value)
    }
}

/// Shows whether the value is present only in the tests; elsewhere
/// nothing, the presence being secret.
impl<T> core::fmt::Debug for CtOption<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CtOption(..)")
    }
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
