//! Fields, as signatures: what the curve code may assume of its coordinates
//! and scalars.
//!
//! [`Field`] is the signature of a commutative field $(K, 0, 1, +, \cdot)$:
//! the carrier is the implementing type, the operations are the operator
//! traits and the methods below, and the laws are the field axioms
//! (associativity, commutativity and distributivity of $+$ and $\cdot$, the
//! neutral elements, additive inverses, and multiplicative inverses of every
//! nonzero element). Nothing in the signature states the laws; the property
//! tests of each implementation check them.
//!
//! [`PrimeField`] refines it for $\mathbb{F}_p$: a prime field has a
//! canonical representative in $[0, p)$ for each element, hence a canonical
//! encoding, which a general field does not. Keeping the two apart lets an
//! extension field ($\mathbb{F}_{p^k}$) implement [`Field`] without an
//! encoding.
//!
//! [`Sqrt`] is a field with square roots computed in constant time; decoding
//! a compressed point (RFC 8032, SEC 1) solves the curve equation for one
//! coordinate with it. The algorithm depends on the modulus, so each field
//! that needs it implements it.
//!
//! Every operation here is constant time in the values: [`Choice`] carries
//! the result of every predicate, never a `bool`.

// The operators are those of the field, modular by definition: they cannot
// overflow.
#![allow(clippy::arithmetic_side_effects)]

use core::{
    fmt,
    ops::{Add, Mul, Neg, Sub},
};

use baldssl_core::num::u32_to_usize;

use crate::{
    ct::{Choice, CtEq, CtOption, CtSelect},
    secret::{SecretBytes, SecretScalar},
};

/// The signature of a field. See the module documentation for the laws.
/// Constant-time equality and selection are part of it: elements may be
/// secret.
pub trait Field:
    crate::sealed::Sealed
    + Copy
    + Eq
    + CtEq
    + CtSelect
    + fmt::Debug
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
{
    /// The additive neutral element.
    const ZERO: Self;
    /// The multiplicative neutral element.
    const ONE: Self;

    /// $2a$.
    #[must_use]
    fn double(&self) -> Self {
        *self + *self
    }

    /// $a^2$.
    #[must_use]
    fn square(&self) -> Self {
        *self * *self
    }

    /// $a^{-1}$ for $a \neq 0$, and $0$ for $a = 0$ (so the map is total and
    /// branch-free; callers that need the inverse to exist check
    /// [`Field::is_zero`] first).
    #[must_use]
    fn invert(&self) -> Self;

    /// Whether $a = 0$.
    fn is_zero(&self) -> Choice;
}

/// A prime field $\mathbb{F}_p$, with its canonical big-endian encoding.
pub trait PrimeField: Field {
    /// The number of bits of $p$.
    const BITS: u32;
    /// The length of the canonical encoding, $\lceil \mathrm{BITS} / 8
    /// \rceil$ bytes.
    const BYTES: usize;
    /// The bits of the encoding above $p$'s, $8 \cdot \mathrm{BYTES} -
    /// \mathrm{BITS}$: below 8 by the definition of
    /// [`PrimeField::BYTES`], so a shift by it never overflows a byte.
    const SPARE_BITS: usize = Self::BYTES * 8 - u32_to_usize(Self::BITS);

    /// The element $v \bmod p$.
    #[must_use]
    fn from_u64(v: u64) -> Self;

    /// Decodes the canonical big-endian encoding of [`PrimeField::BYTES`]
    /// bytes. Absent, with zero as the placeholder, when the length is wrong
    /// or the value is not below $p$; the check does not branch on the
    /// value.
    fn from_bytes_be(bytes: &[u8]) -> CtOption<Self>;

    /// The canonical big-endian encoding, [`PrimeField::BYTES`] bytes.
    fn to_bytes_be(&self) -> Vec<u8>;

    /// Decodes the canonical little-endian encoding of
    /// [`PrimeField::BYTES`] bytes: the big-endian one read backwards, with
    /// the same rejections as [`PrimeField::from_bytes_be`].
    fn from_bytes_le(bytes: &[u8]) -> CtOption<Self> {
        let be: Vec<u8> = bytes.iter().rev().copied().collect();
        Self::from_bytes_be(&be)
    }

    /// The canonical little-endian encoding, [`PrimeField::BYTES`] bytes:
    /// the big-endian one reversed.
    #[must_use]
    fn to_bytes_le(&self) -> Vec<u8> {
        let mut le = self.to_bytes_be();
        le.reverse();
        le
    }

    /// Whether the canonical representative in $[0, p)$ is odd: the sign
    /// that point compression records for the coordinate it drops
    /// ([SEC 1, section 2.3.3][sec1], [RFC 8032, section 5.1.2][rfc8032]).
    /// Negation swaps it on nonzero elements, since $p - v$ is odd exactly
    /// when $v$ is even, $p$ being odd.
    ///
    /// [sec1]: https://www.secg.org/sec1-v2.pdf
    /// [rfc8032]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2
    fn is_odd(&self) -> Choice {
        // The encoding has BYTES >= 1 bytes, so `last` is never None and the
        // fallback is never taken.
        let low = self.to_bytes_be().last().map_or(0, |b| b & 1);
        Choice::from_bit(u64::from(low))
    }

    /// The integer whose little-endian encoding is `bytes`, of any length,
    /// reduced modulo $p$: how RFC 8032 reads a hash as a scalar
    /// ([section 5.1.6][rfc8032-5.1.6], steps 2 and 4). Horner's rule over
    /// the bytes from the most significant, in the field, so constant time
    /// for a given length.
    ///
    /// [rfc8032-5.1.6]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6
    #[must_use]
    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        let radix = Self::from_u64(256);
        bytes.iter().rev().fold(Self::ZERO, |acc, &b| {
            acc * radix + Self::from_u64(u64::from(b))
        })
    }

    /// The characteristic $p$, big-endian at [`PrimeField::BYTES`] bytes. It
    /// is not an element (it is zero in the field); scalar multiplication by
    /// the order of a group uses it.
    fn modulus_be() -> Vec<u8>;

    /// A uniformly random nonzero element, by rejection sampling: draw
    /// [`PrimeField::BITS`] random bits (big-endian, the bits above `BITS`
    /// in the first byte cleared) from `fill`, and draw again while the value
    /// is zero or not below $p$.
    ///
    /// Each value of $[1, p - 1]$ has the same probability on every draw and
    /// the draws are independent, so the value returned is uniform on
    /// $\mathbb{F}_p^*$. A draw is accepted with probability
    /// $(p - 1) / 2^{\mathrm{BITS}} > 1/2$, so the expected number of draws is
    /// below 2, and that number does not depend on the value returned. This
    /// is a process equivalent to [FIPS 186-5, appendix A.2.2][fips186]
    /// (key pair generation by rejection sampling), which returns an error on
    /// the first rejection where this draws again.
    ///
    /// The draws are made in a [`SecretBytes`], wiped on every return,
    /// including the error of `fill`.
    ///
    /// # Errors
    ///
    /// The error of `fill`.
    ///
    /// [fips186]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    fn random_nonzero<F, E>(mut fill: F) -> Result<SecretScalar<Self>, E>
    where
        F: FnMut(&mut [u8]) -> Result<(), E>,
    {
        let mask = 0xffu8 >> Self::SPARE_BITS;
        let mut buf = SecretBytes::filled(0, Self::BYTES);
        loop {
            fill(buf.expose_mut())?;
            // BYTES >= 1, so there is a first byte to mask.
            if let Some(first) = buf.expose_mut().first_mut() {
                *first &= mask;
            }
            let x = SecretScalar::new(
                Self::from_bytes_be(buf.expose()).unwrap_or_ct(&Self::ZERO),
            );
            // Zero is both the placeholder of a value not below p and the
            // one valid value rejected; a rejection is public.
            if (!x.expose().is_zero()).to_bool_vartime() {
                return Ok(x);
            }
        }
    }
}

/// Square roots: half of the nonzero elements of $\mathbb{F}_p$ are squares
/// ($p$ odd), each with two roots $\pm r$.
pub trait Sqrt: Field {
    /// A root $r$ with $r^2 = a$, present when $a$ is a square; when it is
    /// not, the placeholder is unspecified. Which of $\pm r$ is returned is
    /// unspecified too: callers choose by a sign or parity bit. Constant
    /// time.
    fn sqrt(&self) -> CtOption<Self>;
}
