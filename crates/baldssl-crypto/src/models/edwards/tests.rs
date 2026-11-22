//! The Edwards models on edwards25519, against the curve's definitions and
//! the affine addition law.

// The carry addition truncates to bytes on purpose.
#![allow(clippy::cast_possible_truncation)]

use proptest::prelude::*;

use super::{affine::Affine as AffineOf, d, extended::Extended as ExtendedOf};
use crate::{
    algebra::{
        encoding::Encodable,
        field::{Field, PrimeField},
        group::{Group, scalar_mul},
        laws,
        model::{AffineModel, CurveModel},
    },
    instances::{
        Edwards25519,
        edwards25519::{Field25519, ScalarEd25519},
    },
};

type Affine = AffineOf<Edwards25519>;
type Extended = ExtendedOf<Edwards25519>;

/// $k B$ for $k$ given little-endian.
fn mul_le(k: &[u8]) -> Extended {
    let mut be = k.to_vec();
    be.reverse();
    scalar_mul(&Extended::generator(), &be)
}

fn f(v: u64) -> Field25519 {
    Field25519::from_u64(v)
}

/// The affine twisted Edwards law for $a = -1$ ([Bernstein, Birkner, Joye,][bbjlp]
/// Lange and Peters, *Twisted Edwards curves*, AFRICACRYPT 2008):
/// $x_3 = (x_1 y_2 + y_1 x_2) / (1 + d x_1 x_2 y_1 y_2)$,
/// $y_3 = (y_1 y_2 + x_1 x_2) / (1 - d x_1 x_2 y_1 y_2)$. It is complete, so
/// it covers doubling and the identity as well.
///
/// [bbjlp]: https://eprint.iacr.org/2008/013
fn reference_add(p: &Affine, q: &Affine) -> Affine {
    let (x1, y1) = p.coordinates().unwrap();
    let (x2, y2) = q.coordinates().unwrap();
    let t = d::<Edwards25519>() * x1 * x2 * y1 * y2;
    let x3 = (x1 * y2 + y1 * x2) * (Field25519::ONE + t).invert();
    let y3 = (y1 * y2 + x1 * x2) * (Field25519::ONE - t).invert();
    let (r, on_curve) = Affine::from_coordinates(x3, y3);
    assert!(on_curve.to_bool_vartime(), "reference left the curve");
    r
}

#[test]
fn constants() {
    // d = -121665 / 121666, and B has y = 4/5, x even, and order l.
    assert_eq!(d::<Edwards25519>(), -f(121_665) * f(121_666).invert());
    let b = Affine::generator();
    assert_eq!(b.coordinates().unwrap().1, f(4) * f(5).invert());
    assert_eq!(
        b.coordinates().unwrap().0.to_bytes_be()[31] & 1,
        0,
        "x even"
    );
    assert!(b.is_on_curve().to_bool_vartime());
    assert!(!Affine::from_coordinates(f(1), f(1)).1.to_bool_vartime());
    let lb = scalar_mul(&Extended::generator(), &ScalarEd25519::modulus_be());
    assert_eq!(lb, Extended::identity(), "l B = O");
    // d is not a square (Euler's criterion), which makes the addition
    // complete: d^((p-1)/2) = -1.
    let mut exponent = [u64::MAX; 4];
    exponent[0] = 0xffff_ffff_ffff_fff6; // (p - 1) / 2 = 2^254 - 10
    exponent[3] = 0x3fff_ffff_ffff_ffff;
    assert_eq!(d::<Edwards25519>().pow_vartime(&exponent), -Field25519::ONE);
}

#[test]
fn small_multiples() {
    let b = Affine::generator();
    let mut acc = Extended::identity();
    let mut expected = Affine::identity();
    for k in 1..=16u8 {
        acc = acc.add(&Extended::generator());
        expected = reference_add(&expected, &b);
        assert_eq!(Affine::from(acc), expected, "{k}B by addition");
        assert_eq!(Affine::from(mul_le(&[k])), expected, "{k}B by mul");
        assert_eq!(
            Affine::from(acc.double()),
            reference_add(&expected, &expected),
            "2({k}B)"
        );
    }
    let o = Extended::identity();
    assert_eq!(o.add(&Extended::generator()), Extended::generator());
    assert_eq!(o.double(), o);
    let minus_b = Extended::from(b.neg());
    assert_eq!(Extended::generator().add(&minus_b), o);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Addition and doubling agree with the affine law on random points, and
    /// the scalar multiplication is additive.
    #[test]
    fn laws(a in prop::collection::vec(any::<u8>(), 32), b in prop::collection::vec(any::<u8>(), 32)) {
        let p = mul_le(&a);
        let q = mul_le(&b);
        let (ap, aq) = (Affine::from(p), Affine::from(q));
        prop_assert!(ap.is_on_curve().to_bool_vartime());
        prop_assert_eq!(Affine::from(p.add(&q)), reference_add(&ap, &aq));
        prop_assert_eq!(Affine::from(p.double()), reference_add(&ap, &ap));
        // (a + b) B = a B + b B, over the integers (little-endian, with carry).
        let mut sum = vec![0u8; 33];
        let mut carry = 0u16;
        for i in 0..32 {
            let s = u16::from(a[i]) + u16::from(b[i]) + carry;
            sum[i] = s as u8;
            carry = s >> 8;
        }
        sum[32] = carry as u8;
        prop_assert_eq!(mul_le(&sum), p.add(&q));
    }
}

/// $\sqrt{-1} = 2^{(p - 1) / 4}$: 2 is not a square modulo $p$, as
/// $p \equiv 5 \pmod 8$, so $2^{(p - 1)/2} = -1$.
fn sqrt_minus_one() -> Field25519 {
    // (p - 1) / 4 = 2^253 - 5, little-endian limbs.
    let exponent = [
        0xffff_ffff_ffff_fffb,
        u64::MAX,
        u64::MAX,
        0x1fff_ffff_ffff_ffff,
    ];
    f(2).pow_vartime(&exponent)
}

/// The torsion: points on the curve that are not in the subgroup of order
/// $\ell$. Being on the variety and being in $G = \ker [\ell]$ differ, by the
/// cofactor 8: $E(\mathbb{F}_p) = G \oplus T$ with $T$ cyclic of order 8.
#[test]
fn torsion_is_on_the_curve_but_not_in_the_subgroup() {
    let i = sqrt_minus_one();
    assert_eq!(i.square(), -Field25519::ONE);
    let order_2 = Affine::from_coordinates(Field25519::ZERO, -Field25519::ONE);
    let order_4 = Affine::from_coordinates(i, Field25519::ZERO);
    for (name, (t, on_curve)) in [("order 2", order_2), ("order 4", order_4)] {
        assert!(on_curve.to_bool_vartime(), "{name} on the curve");
        assert!(!t.is_identity().to_bool_vartime());
        assert!(
            !t.is_in_prime_subgroup().to_bool_vartime(),
            "{name} not in G"
        );
        let e = Extended::from(t);
        assert!(e.is_on_curve().to_bool_vartime());
        assert!(!e.is_in_prime_subgroup().to_bool_vartime());
        // B + T is on the curve, and not in G either: G is a subgroup.
        let shifted = Extended::generator().add(&e);
        assert!(shifted.is_on_curve().to_bool_vartime());
        assert!(
            !shifted.is_in_prime_subgroup().to_bool_vartime(),
            "B + {name}"
        );
        // [8] T = O: the torsion is killed by the cofactor.
        assert!(scalar_mul(&e, &[8]).is_identity().to_bool_vartime());
    }
    let (two_t, _) = order_2;
    assert!(
        Extended::from(two_t)
            .double()
            .is_identity()
            .to_bool_vartime()
    );
    assert!(
        Extended::generator()
            .is_in_prime_subgroup()
            .to_bool_vartime()
    );
    assert!(
        Extended::identity()
            .is_in_prime_subgroup()
            .to_bool_vartime()
    );
}

/// A point off the curve is neither on the curve nor in the subgroup.
#[test]
fn off_curve() {
    let b = Affine::generator();
    let (x, y) = b.coordinates().unwrap();
    let off = Extended::new(
        x,
        y + Field25519::ONE,
        Field25519::ONE,
        x * (y + Field25519::ONE),
    );
    assert!(!off.is_on_curve().to_bool_vartime());
    assert!(!off.is_in_prime_subgroup().to_bool_vartime());
    // T must equal X Y / Z.
    let bad_t = Extended::new(x, y, Field25519::ONE, x);
    assert!(!bad_t.is_on_curve().to_bool_vartime());
}

/// The encoding of the base point given in [RFC 8032, section 5.1][rfc8032-5.1]
/// ($y = 4/5$, $x$ even): `58` followed by 31 bytes `66`.
///
/// [rfc8032-5.1]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1
#[test]
fn golden_encoding() {
    let mut expected = vec![0x66u8; 32];
    expected[0] = 0x58;
    assert_eq!(Affine::generator().encode(), expected);
    assert_eq!(Extended::generator().encode(), expected);
    // The identity (0, 1): y = 1, x even.
    let mut one = vec![0u8; 32];
    one[0] = 1;
    assert_eq!(Affine::identity().encode(), one);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// The group axioms and the isomorphism with the affine chart, on random
    /// multiples of B, and on points shifted by torsion (outside G).
    #[test]
    fn group_and_model_laws(
        a in prop::collection::vec(any::<u8>(), 32),
        b in prop::collection::vec(any::<u8>(), 32),
        c in prop::collection::vec(any::<u8>(), 32),
    ) {
        let (p, q, r) = (mul_le(&a), mul_le(&b), mul_le(&c));
        laws::group(&p, &q, &r);
        laws::projective_model(&p);
        laws::projective_model(&p.add(&q));
        prop_assert!(p.is_in_prime_subgroup().to_bool_vartime());
        let (t, _) = Affine::from_coordinates(Field25519::ZERO, -Field25519::ONE);
        let shifted = p.add(&Extended::from(t));
        laws::group(&shifted, &q, &r);
        laws::projective_model(&shifted);
        prop_assert!(!shifted.is_in_prime_subgroup().to_bool_vartime());
        // [l] P = O on G.
        prop_assert!(scalar_mul(&p, &ScalarEd25519::modulus_be()).is_identity().to_bool_vartime());
    }
}
