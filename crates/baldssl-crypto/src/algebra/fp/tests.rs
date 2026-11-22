//! Field arithmetic against an independent reference: schoolbook big
//! integers with bitwise long division, too slow for use but simple enough
//! to check by reading. Every operation of [`Fp`] is compared with it on
//! random elements of each of the eight fields, plus the field axioms and
//! the boundary values $0$, $1$, $p - 1$ and the non-canonical encodings.

// The reference truncates u128 products to their low word on purpose, and
// `a - a` is one of the laws under test.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::eq_op
)]

use proptest::prelude::*;

use super::{Fp, Modulus};
use crate::{
    algebra::field::{Field, PrimeField},
    curves::{
        p256::{P256Base, P256Scalar},
        p384::{P384Base, P384Scalar},
        p521::{P521Base, P521Scalar},
    },
    fields::{Curve25519Base, Ed25519Scalar},
};

/// A natural number, little-endian 64-bit limbs without leading zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Nat(Vec<u64>);

/// Numeric order: more limbs is larger (no leading zeros), then the most
/// significant limb first. A derived order would compare the least
/// significant limb first.
impl Ord for Nat {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }
}

impl PartialOrd for Nat {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Nat {
    fn normalized(mut v: Vec<u64>) -> Self {
        while v.last() == Some(&0) {
            v.pop();
        }
        Nat(v)
    }

    pub(crate) fn from_u64(v: u64) -> Self {
        Self::normalized(vec![v])
    }

    pub(crate) fn from_hex(hex: &str) -> Self {
        let digits: Vec<u8> = hex
            .bytes()
            .rev()
            .map(|c| char::from(c).to_digit(16).unwrap() as u8)
            .collect();
        let limbs = digits
            .chunks(16)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u64, |acc, (i, &d)| acc | (u64::from(d) << (4 * i)))
            })
            .collect();
        Self::normalized(limbs)
    }

    fn from_decimal(s: &str) -> Self {
        s.bytes().fold(Nat(vec![]), |acc, c| {
            acc.mul(&Nat::from_u64(10))
                .add(&Nat::from_u64(u64::from(c - b'0')))
        })
    }

    pub(crate) fn from_bytes_be(bytes: &[u8]) -> Self {
        let limbs = bytes
            .rchunks(8)
            .map(|chunk| {
                chunk.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
            })
            .collect();
        Self::normalized(limbs)
    }

    pub(crate) fn to_bytes_be(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for (i, byte) in out.iter_mut().rev().enumerate() {
            *byte = self.0.get(i / 8).map_or(0, |l| l.to_le_bytes()[i % 8]);
        }
        out
    }

    fn pow2(k: usize) -> Self {
        let mut v = vec![0u64; k / 64 + 1];
        v[k / 64] = 1 << (k % 64);
        Self::normalized(v)
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        let n = self.0.len().max(other.0.len()) + 1;
        let mut out = vec![0u64; n];
        let mut carry = 0u128;
        for (i, slot) in out.iter_mut().enumerate() {
            let s = u128::from(*self.0.get(i).unwrap_or(&0))
                + u128::from(*other.0.get(i).unwrap_or(&0))
                + carry;
            *slot = s as u64;
            carry = s >> 64;
        }
        Self::normalized(out)
    }

    /// `self - other`, which must not be negative.
    pub(crate) fn sub(&self, other: &Self) -> Self {
        assert!(self >= other, "negative difference");
        let mut out = vec![0u64; self.0.len()];
        let mut borrow = 0i128;
        for (i, slot) in out.iter_mut().enumerate() {
            let d = i128::from(self.0[i])
                - i128::from(*other.0.get(i).unwrap_or(&0))
                - borrow;
            borrow = i128::from(d < 0);
            *slot = (d + (borrow << 64)) as u64;
        }
        Self::normalized(out)
    }

    pub(crate) fn mul(&self, other: &Self) -> Self {
        let mut out = vec![0u64; self.0.len() + other.0.len() + 1];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.0.iter().enumerate() {
                let t = u128::from(out[i + j])
                    + u128::from(a) * u128::from(b)
                    + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            out[i + other.0.len()] = carry as u64;
        }
        Self::normalized(out)
    }

    fn bit(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|l| (l >> (i % 64)) & 1 == 1)
    }

    fn bits(&self) -> usize {
        self.0.last().map_or(0, |l| {
            (self.0.len() - 1) * 64 + 64 - l.leading_zeros() as usize
        })
    }

    /// `self mod m`, by long division one bit at a time.
    pub(crate) fn rem(&self, m: &Self) -> Self {
        let mut r = Nat(vec![]);
        for i in (0..self.bits()).rev() {
            r = r.add(&r);
            if self.bit(i) {
                r = r.add(&Nat::from_u64(1));
            }
            if r >= *m {
                r = r.sub(m);
            }
        }
        r
    }
}

fn modulus<M, const N: usize>() -> Nat
where
    M: Modulus<N>,
{
    Nat::from_hex(M::HEX)
}

fn element<M, const N: usize>(value: &Nat) -> Fp<M, N>
where
    M: Modulus<N>,
{
    let (x, valid) =
        Fp::<M, N>::from_bytes_be(&value.to_bytes_be(Fp::<M, N>::BYTES));
    assert!(valid.to_bool_vartime(), "{} not below the modulus", M::NAME);
    x
}

fn value<M, const N: usize>(x: &Fp<M, N>) -> Nat
where
    M: Modulus<N>,
{
    Nat::from_bytes_be(&x.to_bytes_be())
}

/// Each modulus equals its defining formula.
#[test]
fn moduli_match_their_definitions() {
    let one = Nat::from_u64(1);
    let p256 = Nat::pow2(256)
        .sub(&Nat::pow2(224))
        .add(&Nat::pow2(192))
        .add(&Nat::pow2(96))
        .sub(&one);
    assert_eq!(modulus::<P256Base, 4>(), p256);
    let p384 = Nat::pow2(384)
        .sub(&Nat::pow2(128))
        .sub(&Nat::pow2(96))
        .add(&Nat::pow2(32))
        .sub(&one);
    assert_eq!(modulus::<P384Base, 6>(), p384);
    assert_eq!(modulus::<P521Base, 9>(), Nat::pow2(521).sub(&one));
    assert_eq!(
        modulus::<Curve25519Base, 4>(),
        Nat::pow2(255).sub(&Nat::from_u64(19))
    );
    let l = Nat::pow2(252)
        .add(&Nat::from_decimal("27742317777372353535851937790883648493"));
    assert_eq!(modulus::<Ed25519Scalar, 4>(), l);
}

/// Bit lengths and encoding lengths.
#[test]
fn sizes() {
    assert_eq!(
        (Fp::<P256Base, 4>::BITS, Fp::<P256Base, 4>::BYTES),
        (256, 32)
    );
    assert_eq!(
        (Fp::<P384Scalar, 6>::BITS, Fp::<P384Scalar, 6>::BYTES),
        (384, 48)
    );
    assert_eq!(
        (Fp::<P521Base, 9>::BITS, Fp::<P521Base, 9>::BYTES),
        (521, 66)
    );
    assert_eq!(
        (
            Fp::<Curve25519Base, 4>::BITS,
            Fp::<Curve25519Base, 4>::BYTES
        ),
        (255, 32)
    );
    assert_eq!(
        (Fp::<Ed25519Scalar, 4>::BITS, Fp::<Ed25519Scalar, 4>::BYTES),
        (253, 32)
    );
}

/// The boundary values, and the encodings that must be rejected.
fn boundaries<M, const N: usize>()
where
    M: Modulus<N>,
{
    type F<M, const N: usize> = Fp<M, N>;
    let p = modulus::<M, N>();
    let p_minus_1 = p.sub(&Nat::from_u64(1));
    assert_eq!(value(&F::<M, N>::ZERO), Nat(vec![]));
    assert_eq!(value(&F::<M, N>::ONE), Nat::from_u64(1));
    assert_eq!(F::<M, N>::from_u64(7), element(&Nat::from_u64(7)));
    let top = element::<M, N>(&p_minus_1);
    assert_eq!(top + F::<M, N>::ONE, F::<M, N>::ZERO);
    assert_eq!(-F::<M, N>::ONE, top);
    assert_eq!(top * top, F::<M, N>::ONE, "(-1)^2 = 1");
    assert_eq!(F::<M, N>::ZERO.invert(), F::<M, N>::ZERO);
    assert!(F::<M, N>::ZERO.is_zero().to_bool_vartime());
    assert!(!F::<M, N>::ONE.is_zero().to_bool_vartime());
    for bad in [p.clone(), p.add(&Nat::from_u64(1))] {
        let (x, valid) =
            F::<M, N>::from_bytes_be(&bad.to_bytes_be(F::<M, N>::BYTES));
        assert!(!valid.to_bool_vartime(), "{}: accepted p or p + 1", M::NAME);
        assert_eq!(x, F::<M, N>::ZERO);
    }
    let all_ones = vec![0xffu8; F::<M, N>::BYTES];
    assert!(!F::<M, N>::from_bytes_be(&all_ones).1.to_bool_vartime());
    assert!(!F::<M, N>::from_bytes_be(&[0u8; 3]).1.to_bool_vartime());
}

#[test]
fn boundary_values() {
    boundaries::<P256Base, 4>();
    boundaries::<P256Scalar, 4>();
    boundaries::<P384Base, 6>();
    boundaries::<P384Scalar, 6>();
    boundaries::<P521Base, 9>();
    boundaries::<P521Scalar, 9>();
    boundaries::<Curve25519Base, 4>();
    boundaries::<Ed25519Scalar, 4>();
}

/// Every operation agrees with the reference on `a` and `b`, given as
/// arbitrary bytes reduced modulo `p`; and the field axioms hold.
fn agrees<M, const N: usize>(a_bytes: &[u8], b_bytes: &[u8])
where
    M: Modulus<N>,
{
    let p = modulus::<M, N>();
    let (ra, rb) = (
        Nat::from_bytes_be(a_bytes).rem(&p),
        Nat::from_bytes_be(b_bytes).rem(&p),
    );
    let (a, b) = (element::<M, N>(&ra), element::<M, N>(&rb));

    assert_eq!(value(&(a + b)), ra.add(&rb).rem(&p), "{} add", M::NAME);
    assert_eq!(
        value(&(a - b)),
        ra.add(&p).sub(&rb).rem(&p),
        "{} sub",
        M::NAME
    );
    assert_eq!(value(&(a * b)), ra.mul(&rb).rem(&p), "{} mul", M::NAME);
    assert_eq!(
        value(&a.square()),
        ra.mul(&ra).rem(&p),
        "{} square",
        M::NAME
    );
    assert_eq!(value(&-a), p.sub(&ra).rem(&p), "{} neg", M::NAME);
    assert_eq!(a.double(), a + a);
    assert_eq!(
        a.to_bytes_be(),
        ra.to_bytes_be(Fp::<M, N>::BYTES),
        "{} bytes",
        M::NAME
    );

    // Ring axioms.
    assert_eq!(a + b, b + a);
    assert_eq!(a * b, b * a);
    assert_eq!((a + b) * a, a * a + b * a, "distributivity");
    assert_eq!(a - a, Fp::ZERO);
    assert_eq!(a * Fp::ONE, a);
    // Inverses. An inverse is unique, and the product is checked against
    // the reference above, so a * a^-1 = 1 proves a^-1 correct.
    let inv = a.invert();
    if ra == Nat(vec![]) {
        assert_eq!(inv, Fp::ZERO);
    } else {
        assert_eq!(a * inv, Fp::ONE, "{} invert", M::NAME);
    }
    // Constant-time helpers.
    assert_eq!(a.ct_eq(&b).to_bool_vartime(), ra == rb);
    assert_eq!(Fp::select(&a, &b, crate::ct::Choice::TRUE), b);
    assert_eq!(Fp::select(&a, &b, crate::ct::Choice::FALSE), a);
}

fn bytes(len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), len)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn p256(a in bytes(40), b in bytes(40)) {
        agrees::<P256Base, 4>(&a, &b);
        agrees::<P256Scalar, 4>(&a, &b);
    }

    #[test]
    fn p384(a in bytes(56), b in bytes(56)) {
        agrees::<P384Base, 6>(&a, &b);
        agrees::<P384Scalar, 6>(&a, &b);
    }

    #[test]
    fn p521(a in bytes(72), b in bytes(72)) {
        agrees::<P521Base, 9>(&a, &b);
        agrees::<P521Scalar, 9>(&a, &b);
    }

    #[test]
    fn curve25519(a in bytes(40), b in bytes(40)) {
        agrees::<Curve25519Base, 4>(&a, &b);
        agrees::<Ed25519Scalar, 4>(&a, &b);
    }

    /// Values near the top of the range, where the final conditional
    /// subtractions matter: p - 1 - k for small k.
    #[test]
    fn near_the_modulus(k in 0u64..1000) {
        fn near<M, const N: usize>(k: u64)
where
    M: Modulus<N>,
{
            let p = modulus::<M, N>();
            let a = p.sub(&Nat::from_u64(1 + k));
            let bytes = a.to_bytes_be(Fp::<M, N>::BYTES);
            agrees::<M, N>(&bytes, &bytes);
        }
        near::<P256Base, 4>(k);
        near::<P384Base, 6>(k);
        near::<P521Base, 9>(k);
        near::<Curve25519Base, 4>(k);
        near::<Ed25519Scalar, 4>(k);
    }
}
