//! Key pairs: the graph condition Q = d G, rejection of d = 0, uniform
//! sampling of the secret (by its rejections, and P-521's top byte), and
//! that no secret is printed.

use std::{cell::Cell, collections::VecDeque};

use proptest::prelude::*;

use super::{EcKeyPair, EdDsaKeyPair};
use crate::{
    algebra::{
        curve::{Curve, ShortWeierstrass},
        field::{Field, PrimeField},
        model::{CurveModel, ProjectiveModel},
    },
    instances::{P256, P384, P521},
    models::weierstrass::projective::Projective,
    os_rng,
    signature::{
        DigitalSignature,
        eddsa::{Ed25519, Ed25519Parameters},
    },
};

/// A `fill` that hands out the given draws in order, and counts them.
fn scripted(
    draws: Vec<Vec<u8>>,
    count: &Cell<usize>,
) -> impl FnMut(&mut [u8]) -> Result<(), ()> + '_ {
    let mut draws: VecDeque<Vec<u8>> = draws.into();
    move |buf: &mut [u8]| {
        count.set(count.get() + 1);
        let draw = draws.pop_front().ok_or(())?;
        buf.copy_from_slice(&draw);
        Ok(())
    }
}

#[test]
fn zero_is_not_a_secret() {
    assert!(
        EcKeyPair::<P256>::from_secret_opt(<P256 as Curve>::Scalar::ZERO)
            .is_none()
    );
}

/// Q = d G, computed independently, and in the prime-order subgroup.
fn check_graph<C>(k: u64)
where
    C: ShortWeierstrass,
{
    let d = C::Scalar::from_u64(k);
    let pair = EcKeyPair::<C>::from_secret_opt(d).unwrap();
    assert_eq!(pair.secret().expose(), &d);
    let q = C::scalar_mul(&Projective::<C>::generator(), &d).to_affine();
    assert_eq!(pair.public().point(), &q);
    assert!(
        pair.public()
            .point()
            .is_in_prime_subgroup()
            .to_bool_vartime()
    );
}

#[test]
fn public_point_is_d_g() {
    for k in [1, 2, 3, 0xffff_ffff] {
        check_graph::<P256>(k);
        check_graph::<P384>(k);
        check_graph::<P521>(k);
    }
}

/// Rejection sampling: a draw of zero and a draw not below n are both
/// rejected, and the first valid draw is the secret.
#[test]
fn rejections() {
    let len = <P256 as Curve>::Scalar::BYTES;
    let mut valid = vec![0u8; len];
    valid[len - 1] = 7;
    let count = Cell::new(0);
    let pair = EcKeyPair::<P256>::generate(scripted(
        vec![vec![0; len], vec![0xff; len], valid],
        &count,
    ))
    .unwrap();
    assert_eq!(count.get(), 3, "two rejections, then the valid draw");
    assert_eq!(
        pair.secret().expose(),
        &<P256 as Curve>::Scalar::from_u64(7)
    );
    // A fill that fails: its error comes back.
    let failing = |_: &mut [u8]| Err::<(), _>("no randomness");
    assert_eq!(
        EcKeyPair::<P256>::generate(failing).err(),
        Some("no randomness")
    );
}

/// P-521's order has 521 bits, so the top byte of a scalar is 0 or 1, and
/// both occur, each with probability close to 1/2: the mask keeps exactly
/// the bits below the bit length of n. A mask that always yields 0, or
/// always 1, fails; 64 draws all equal has probability about 2^-63.
#[test]
fn p521_secrets_use_both_top_byte_values() {
    let mut tops = [false; 2];
    for _ in 0..64 {
        let pair = EcKeyPair::<P521>::generate(os_rng::fill).unwrap();
        let top = pair.secret().expose().to_bytes_be()[0];
        assert!(top <= 1, "top byte {top}");
        tops[usize::from(top)] = true;
    }
    assert_eq!(tops, [true, true], "both top bytes occur");
}

proptest! {
    /// Whatever the random bytes, a secret drawn is valid and nonzero.
    #[test]
    fn secrets_are_nonzero(
        draws in prop::collection::vec(prop::collection::vec(any::<u8>(), 32), 1..4),
    ) {
        let count = Cell::new(0);
        if let Ok(pair) = EcKeyPair::<P256>::generate(scripted(draws, &count)) {
            prop_assert!(!pair.secret().expose().is_zero().to_bool_vartime());
        }
    }
}

#[test]
fn ed25519_pairs() {
    let seed = [7u8; 32];
    let pair = EdDsaKeyPair::<Ed25519Parameters>::from_seed(seed);
    assert_eq!(
        pair.public().as_bytes(),
        Ed25519::public_key(&seed).as_slice()
    );
    assert_eq!(pair.seed(), &seed);
    let count = Cell::new(0);
    let generated = EdDsaKeyPair::<Ed25519Parameters>::generate(scripted(
        vec![vec![7; 32]],
        &count,
    ))
    .unwrap();
    assert_eq!(generated.public(), pair.public());
}

/// Debug shows the public part, never the secret.
#[test]
fn no_secret_in_debug() {
    let d = <P256 as Curve>::Scalar::from_u64(0x1234_5678);
    let pair = EcKeyPair::<P256>::from_secret_opt(d).unwrap();
    let shown = format!("{pair:?}");
    assert!(shown.contains("prime256v1"), "{shown}");
    assert!(!shown.to_lowercase().contains("12345678"), "{shown}");
    let ed = EdDsaKeyPair::<Ed25519Parameters>::from_seed([0xab; 32]);
    assert!(!format!("{ed:?}").contains("171, 171"), "seed bytes");
}
