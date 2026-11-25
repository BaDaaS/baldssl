//! Prime fields $\mathbb{F}_p$ in Montgomery form, generic over the number of
//! 64-bit limbs.
//!
//! # Representation
//!
//! With $R = 2^{64N}$, an element $a$ is stored as $\tilde a = a R \bmod p$,
//! the Montgomery form, as $N$ little-endian 64-bit limbs. The map
//! $a \mapsto \tilde a$ is a ring isomorphism onto $\mathbb{F}_p$ for the
//! product $\tilde a \star \tilde b = \tilde a \tilde b R^{-1} \bmod p$, which
//! the Montgomery reduction computes without dividing by $p$ (Montgomery,
//! [*Modular multiplication without trial division*][montgomery], Math. Comp. 44 (1985)).
//! Addition is unchanged, since the map is additive.
//!
//! Everything a modulus needs is derived at compile time from its value,
//! written as the hexadecimal string OpenSSL prints for it: the limbs, $R$,
//! $R^2$ (to enter Montgomery form), $-p^{-1} \bmod 2^{64}$ (the reduction
//! constant) and $p - 2$ (the inversion exponent, by Fermat).
//!
//! # Constant time
//!
//! No operation branches on, or indexes memory by, the value of an element:
//! conditional subtractions are mask blends ([`crate::ct`]). The exponent of
//! [`Fp::invert`] is the public $p - 2$. Validity checks when decoding return
//! a [`Choice`] next to the value.
//!
//! The moduli baldssl uses are defined with their curves, in [`crate::instances`].
//!
//! Indexing is into arrays of length `N` by loop counters below `N`, and the
//! arithmetic is on `u128` products of two `u64`s and explicit wrapping
//! operations, which cannot overflow: hence the first two allowed lints. The
//! one-letter names are the notation of the papers cited.
//!
//! [montgomery]: https://doi.org/10.1090/S0025-5718-1985-0777282-X
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names
)]

use core::{
    fmt,
    marker::PhantomData,
    ops::{Add, Mul, Neg, Sub},
};

use baldssl_core::num::{
    low_u32, low_u64, u8_to_u64, u32_to_usize, u64_to_u128,
};

use super::field::{Field, PrimeField};
use crate::ct::{self, Choice, CtEq, CtOption, CtSelect};

/// A prime modulus with `N` limbs.
pub trait Modulus<const N: usize>: crate::sealed::Sealed + 'static {
    /// The prime in big-endian hexadecimal, as `openssl ecparam -text`
    /// prints it (leading zero digits allowed).
    const HEX: &'static str;
    /// A name for messages and tests.
    const NAME: &'static str;
}

/// `a + b + carry`, the sum and the carry out (0 or 1).
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = u64_to_u128(a) + u64_to_u128(b) + u64_to_u128(carry);
    (low_u64(t), low_u64(t >> 64))
}

/// `a - b - borrow`, the difference and the borrow out (0 or 1).
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = u64_to_u128(a).wrapping_sub(u64_to_u128(b) + u64_to_u128(borrow));
    (low_u64(t), low_u64(t >> 127))
}

/// `a + b * c + carry`, the low word and the high word.
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t =
        u64_to_u128(a) + u64_to_u128(b) * u64_to_u128(c) + u64_to_u128(carry);
    (low_u64(t), low_u64(t >> 64))
}

/// `a + b` over `N` limbs, and the carry out.
const fn add_limbs<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
) -> ([u64; N], u64) {
    let mut out = [0u64; N];
    let mut carry = 0;
    let mut i = 0;
    while i < N {
        let (s, c) = adc(a[i], b[i], carry);
        out[i] = s;
        carry = c;
        i += 1;
    }
    (out, carry)
}

/// `a - b` over `N` limbs, and the borrow out.
const fn sub_limbs<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
) -> ([u64; N], u64) {
    let mut out = [0u64; N];
    let mut borrow = 0;
    let mut i = 0;
    while i < N {
        let (d, b2) = sbb(a[i], b[i], borrow);
        out[i] = d;
        borrow = b2;
        i += 1;
    }
    (out, borrow)
}

/// Parses big-endian hexadecimal into little-endian limbs, at compile time.
/// Panics (a compile error, for constants) on a non-hex digit or a value
/// that does not fit.
#[allow(clippy::panic, clippy::cast_lossless)]
const fn limbs_from_hex<const N: usize>(hex: &str) -> [u64; N] {
    let bytes = hex.as_bytes();
    let mut out = [0u64; N];
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[bytes.len() - 1 - i];
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("modulus: not a hexadecimal digit"),
        };
        if i / 16 < N {
            out[i / 16] |= u8_to_u64(v) << ((i % 16) * 4);
        } else if v != 0 {
            panic!("modulus: does not fit in N limbs");
        }
        i += 1;
    }
    out
}

/// `a >= b`, at compile time.
const fn geq<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    sub_limbs(a, b).1 == 0
}

/// `2^k mod p` by `k` doublings, at compile time.
const fn pow2_mod<const N: usize>(k: usize, p: &[u64; N]) -> [u64; N] {
    let mut x = [0u64; N];
    x[0] = 1;
    let mut i = 0;
    while i < k {
        let (d, carry) = add_limbs(&x, &x);
        x = if carry == 1 || geq(&d, p) {
            sub_limbs(&d, p).0
        } else {
            d
        };
        i += 1;
    }
    x
}

/// `a >> k` for `0 < k < 64`, little-endian limbs.
fn shr<const N: usize>(a: &[u64; N], k: u32) -> [u64; N] {
    let mut out = [0u64; N];
    for i in 0..N {
        let high = if i + 1 < N { a[i + 1] << (64 - k) } else { 0 };
        out[i] = (a[i] >> k) | high;
    }
    out
}

/// `a + 1`, little-endian limbs; the callers' values are far below the top.
fn add_one<const N: usize>(a: &[u64; N]) -> [u64; N] {
    let mut out = *a;
    let mut carry = 1;
    for limb in &mut out {
        let (s, c) = adc(*limb, 0, carry);
        *limb = s;
        carry = c;
    }
    out
}

/// The number of Newton steps in [`neg_inv`]: $2^6 = 64$ correct bits.
const NEWTON_STEPS: u32 = 6;

/// $-p_0^{-1} \bmod 2^{64}$ by Newton's iteration, which doubles the number
/// of correct low bits each step: $x \equiv p_0^{-1}$ holds modulo 2 from
/// $x = 1$ (as $p_0$ is odd), then modulo $2^{2^k}$ after $k$ steps.
const fn neg_inv(p0: u64) -> u64 {
    let mut x: u64 = 1;
    let mut i = 0;
    while i < NEWTON_STEPS {
        x = x.wrapping_mul(2u64.wrapping_sub(p0.wrapping_mul(x)));
        i += 1;
    }
    x.wrapping_neg()
}

/// The number of significant bits.
const fn bit_length<const N: usize>(a: &[u64; N]) -> u32 {
    let mut i = N;
    while i > 0 {
        i -= 1;
        if a[i] != 0 {
            return low_u32(i) * 64 + (64 - a[i].leading_zeros());
        }
    }
    0
}

/// The constants derived from a modulus.
struct Consts<M, const N: usize>(PhantomData<M>);

impl<M, const N: usize> Consts<M, N>
where
    M: Modulus<N>,
{
    const P: [u64; N] = {
        let p = limbs_from_hex::<N>(M::HEX);
        assert!(p[0] & 1 == 1, "Montgomery form needs an odd modulus");
        assert!(p[N - 1] != 0, "the modulus must use all N limbs");
        p
    };
    const INV: u64 = neg_inv(Self::P[0]);
    const R: [u64; N] = pow2_mod(64 * N, &Self::P);
    const R2: [u64; N] = pow2_mod(128 * N, &Self::P);
    const P_MINUS_2: [u64; N] = sub_limbs(&Self::P, &{
        let mut two = [0u64; N];
        two[0] = 2;
        two
    })
    .0;
    const BITS: u32 = bit_length(&Self::P);
}

/// An element of $\mathbb{F}_p$ for the modulus `M`, in Montgomery form.
pub struct Fp<M, const N: usize> {
    mont: [u64; N],
    _modulus: PhantomData<M>,
}

impl<M, const N: usize> Clone for Fp<M, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M, const N: usize> Copy for Fp<M, N> {}

impl<M, const N: usize> Fp<M, N>
where
    M: Modulus<N>,
{
    const fn from_mont(mont: [u64; N]) -> Self {
        Fp {
            mont,
            _modulus: PhantomData,
        }
    }

    /// The modulus, little-endian limbs.
    #[must_use]
    pub fn modulus() -> [u64; N] {
        Consts::<M, N>::P
    }

    /// Montgomery multiplication $a b R^{-1} \bmod p$, by coarsely integrated
    /// operand scanning (Koc, Acar and Kaliski, *Analyzing and comparing
    /// [Montgomery multiplication algorithms*][kak], IEEE Micro 16 (1996)). The
    /// running value stays below $2p < 2R$, so one conditional subtraction
    /// finishes.
    ///
    /// [kak]: https://doi.org/10.1109/40.502403
    fn mont_mul(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let p = &Consts::<M, N>::P;
        let mut t = [0u64; N];
        let mut t_n: u64 = 0;
        for &b_i in b {
            let mut carry = 0;
            for j in 0..N {
                let (lo, hi) = mac(t[j], a[j], b_i, carry);
                t[j] = lo;
                carry = hi;
            }
            let (s, t_n1) = adc(t_n, carry, 0);
            t_n = s;

            let m = t[0].wrapping_mul(Consts::<M, N>::INV);
            let (_, mut carry) = mac(t[0], m, p[0], 0);
            for j in 1..N {
                let (lo, hi) = mac(t[j], m, p[j], carry);
                t[j - 1] = lo;
                carry = hi;
            }
            let (s, c) = adc(t_n, carry, 0);
            t[N - 1] = s;
            t_n = t_n1 + c;
        }
        let (d, borrow) = sub_limbs(&t, p);
        // Keep t only when t < p, that is, a borrow and no extra word.
        let keep = Choice::from_bit(borrow & (t_n ^ 1));
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = ct::select(d[i], t[i], keep);
        }
        out
    }

    /// The canonical value, little-endian limbs.
    fn canonical(&self) -> [u64; N] {
        let mut one = [0u64; N];
        one[0] = 1;
        Self::mont_mul(&self.mont, &one)
    }

    /// A square root for $p \equiv 3 \pmod 4$: $r = a^{(p + 1)/4}$, and
    /// $r^2 = a^{(p + 1)/2} = a \cdot a^{(p - 1)/2}$, which is $a$ exactly when
    /// $a$ is a square (Euler's criterion); squaring $r$ checks it, so no root
    /// is reported for a non-square. $(p + 1)/4 = \lfloor p / 4 \rfloor + 1$,
    /// computed without overflow. Constant time in $a$: one exponentiation by
    /// a public exponent, and a comparison.
    ///
    /// The caller guarantees $p \equiv 3 \pmod 4$; the instance tests check
    /// it.
    pub(crate) fn sqrt_3_mod_4(&self) -> CtOption<Self> {
        let r = self.pow_vartime(&add_one(&shr(&Self::modulus(), 2)));
        CtOption::new(r, r.square().ct_eq(self))
    }

    /// A square root for $p \equiv 5 \pmod 8$ (Atkin's case, as in
    /// [RFC 8032, section 5.1.3][rfc8032-5.1.3]): with $q = (p - 5) / 8$,
    /// $r = a^{q + 1}$ satisfies $r^2 = \pm a$ when $a$ is a square, since
    /// $a^{(p - 1)/4} = \pm 1$; when $r^2 = -a$, $r \sqrt{-1}$ is the root,
    /// with $\sqrt{-1} = 2^{(p - 1)/4}$ because 2 is not a square modulo such
    /// a $p$. Constant time in $a$: two exponentiations by public exponents,
    /// and selections.
    ///
    /// The caller guarantees $p \equiv 5 \pmod 8$; the instance tests check
    /// it.
    ///
    /// [rfc8032-5.1.3]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3
    pub(crate) fn sqrt_5_mod_8(&self) -> CtOption<Self> {
        let p = Self::modulus();
        // (p - 5) / 8 + 1 = (p >> 3) + 1, and (p - 1) / 4 = p >> 2, as p = 5
        // modulo 8.
        let root_exp = add_one(&shr(&p, 3));
        let sqrt_minus_one = Self::from_u64(2).pow_vartime(&shr(&p, 2));
        let r = self.pow_vartime(&root_exp);
        let direct = r.square().ct_eq(self);
        let r = Self::select(&(r * sqrt_minus_one), &r, direct);
        CtOption::new(r, r.square().ct_eq(self))
    }

    /// $a^e$ for a public exponent, little-endian limbs. Constant time in
    /// $a$; the running time depends on $e$ only.
    #[must_use]
    pub fn pow_vartime(&self, exponent: &[u64; N]) -> Self {
        let mut acc = Self::ONE;
        for &limb in exponent.iter().rev() {
            for bit in (0..64).rev() {
                acc = acc.square();
                if (limb >> bit) & 1 == 1 {
                    acc = acc * *self;
                }
            }
        }
        acc
    }
}

impl<M, const N: usize> Add for Fp<M, N>
where
    M: Modulus<N>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let p = &Consts::<M, N>::P;
        let (s, carry) = add_limbs(&self.mont, &rhs.mont);
        let (d, borrow) = sub_limbs(&s, p);
        // s < p exactly when the subtraction borrows and the sum did not
        // carry; then keep s, otherwise s - p.
        let keep = Choice::from_bit(borrow & (carry ^ 1));
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = ct::select(d[i], s[i], keep);
        }
        Self::from_mont(out)
    }
}

// The `&` masks the add-back of p, the point of the operation.
#[allow(clippy::suspicious_arithmetic_impl)]
impl<M, const N: usize> Sub for Fp<M, N>
where
    M: Modulus<N>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        let p = &Consts::<M, N>::P;
        let (d, borrow) = sub_limbs(&self.mont, &rhs.mont);
        let mask = Choice::from_bit(borrow).mask();
        let mut add_back = [0u64; N];
        for i in 0..N {
            add_back[i] = p[i] & mask;
        }
        Self::from_mont(add_limbs(&d, &add_back).0)
    }
}

impl<M, const N: usize> Neg for Fp<M, N>
where
    M: Modulus<N>,
{
    type Output = Self;

    fn neg(self) -> Self {
        Self::ZERO - self
    }
}

impl<M, const N: usize> Mul for Fp<M, N>
where
    M: Modulus<N>,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::from_mont(Self::mont_mul(&self.mont, &rhs.mont))
    }
}

/// Equality for tests and public values; secret comparisons use
/// [`Fp::ct_eq`].
impl<M, const N: usize> PartialEq for Fp<M, N>
where
    M: Modulus<N>,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool_vartime()
    }
}

impl<M, const N: usize> Eq for Fp<M, N> where M: Modulus<N> {}

/// Prints the canonical value in hexadecimal. Elements may be secret; do
/// not format secret values outside tests.
impl<M, const N: usize> fmt::Debug for Fp<M, N>
where
    M: Modulus<N>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(0x", M::NAME)?;
        for byte in self.to_bytes_be() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// $\mathbb{F}_p$ satisfies the field signature; the laws are checked by
/// the property tests against a reference arithmetic on integers.
impl<M, const N: usize> Field for Fp<M, N>
where
    M: Modulus<N>,
{
    const ZERO: Self = Self::from_mont([0; N]);
    /// One is $R \bmod p$ in Montgomery form.
    const ONE: Self = Self::from_mont(Consts::<M, N>::R);

    /// $a^{-1} = a^{p-2}$ (Fermat's little theorem), and $0$ for $a = 0$.
    fn invert(&self) -> Self {
        self.pow_vartime(&Consts::<M, N>::P_MINUS_2)
    }

    fn is_zero(&self) -> Choice {
        let mut acc = 0;
        for &limb in &self.mont {
            acc |= limb;
        }
        ct::is_zero(acc)
    }
}

impl<M, const N: usize> crate::sealed::Sealed for Fp<M, N> where M: Modulus<N> {}

impl<M, const N: usize> CtEq for Fp<M, N>
where
    M: Modulus<N>,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut acc = 0;
        for i in 0..N {
            acc |= self.mont[i] ^ other.mont[i];
        }
        ct::is_zero(acc)
    }
}

impl<M, const N: usize> CtSelect for Fp<M, N>
where
    M: Modulus<N>,
{
    fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = ct::select(a.mont[i], b.mont[i], choice);
        }
        Self::from_mont(out)
    }
}

/// The canonical representative of an element is its value in $[0, p)$.
impl<M, const N: usize> PrimeField for Fp<M, N>
where
    M: Modulus<N>,
{
    const BITS: u32 = Consts::<M, N>::BITS;
    const BYTES: usize = u32_to_usize(Consts::<M, N>::BITS).div_ceil(8);

    fn from_u64(v: u64) -> Self {
        let mut x = [0u64; N];
        x[0] = v;
        // A value below 2^64 may still exceed a one-limb p; the product with
        // R^2 reduces it fully either way.
        Self::from_mont(Self::mont_mul(&x, &Consts::<M, N>::R2))
    }

    fn from_bytes_be(bytes: &[u8]) -> CtOption<Self> {
        if bytes.len() != <Self as PrimeField>::BYTES {
            return CtOption::new(<Self as Field>::ZERO, Choice::FALSE);
        }
        let mut x = [0u64; N];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            x[i / 8] |= u64::from(byte) << ((i % 8) * 8);
        }
        let (_, borrow) = sub_limbs(&x, &Consts::<M, N>::P);
        let valid = Choice::from_bit(borrow);
        let mont = Self::mont_mul(&x, &Consts::<M, N>::R2);
        let mut out = [0u64; N];
        for i in 0..N {
            out[i] = ct::select(0, mont[i], valid);
        }
        CtOption::new(Self::from_mont(out), valid)
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        let limbs = self.canonical();
        let mut out = vec![0u8; <Self as PrimeField>::BYTES];
        for (i, byte) in out.iter_mut().rev().enumerate() {
            *byte = limbs[i / 8].to_le_bytes()[i % 8];
        }
        out
    }

    fn modulus_be() -> Vec<u8> {
        let p = Consts::<M, N>::P;
        let mut out = vec![0u8; <Self as PrimeField>::BYTES];
        for (i, byte) in out.iter_mut().rev().enumerate() {
            *byte = p[i / 8].to_le_bytes()[i % 8];
        }
        out
    }
}

#[cfg(test)]
pub(crate) mod tests;
