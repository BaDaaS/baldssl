//! What a curve is, independently of how its points are represented: its
//! fields, its equation's coefficients, its base point and its cofactor.
//!
//! An elliptic curve $E$ over $\mathbb{F}_p$ is given by an equation; its
//! points over $\mathbb{F}_p$ form a finite abelian group $E(\mathbb{F}_p)$ of
//! order $h \ell$, with $\ell$ prime and $h$ the *cofactor*. The base point
//! generates the subgroup $G$ of order $\ell$, the group the cryptography
//! uses; when $h > 1$, $E(\mathbb{F}_p) = G \oplus T$ with $T$ the small
//! torsion (orders dividing $h$), whose points satisfy the equation without
//! being in $G$.
//!
//! [`Curve`] is the data every curve has; [`ShortWeierstrass`] and
//! [`TwistedEdwards`] refine it with the coefficients of their equation.
//! The models in `crate::models` are generic over these traits, and the
//! instances in `crate::instances` implement them.

use crate::algebra::field::PrimeField;

/// A curve: its fields, its base point and its cofactor.
pub trait Curve: 'static {
    /// The base field $\mathbb{F}_p$ of the coordinates.
    type Base: PrimeField;
    /// The scalar field $\mathbb{F}_\ell$, $\ell$ the order of the base point.
    type Scalar: PrimeField;
    /// The name OpenSSL uses.
    const NAME: &'static str;
    /// The cofactor $h = |E(\mathbb{F}_p)| / \ell$.
    const COFACTOR: u64;
    /// The base point's $x$, big-endian hexadecimal.
    const GX: &'static str;
    /// The base point's $y$, big-endian hexadecimal.
    const GY: &'static str;
}

/// A short Weierstrass curve $y^2 = x^3 + a x + b$ with $a = -3$, as all the
/// NIST curves are; the models' formulas assume it. A curve with another
/// $a$ (secp256k1 has $a = 0$) needs its own formulas.
pub trait ShortWeierstrass: Curve {
    /// The constant $b$, big-endian hexadecimal.
    const B: &'static str;
}

/// A twisted Edwards curve $a x^2 + y^2 = 1 + d x^2 y^2$ with $a = -1$, as
/// edwards25519 is; the models' formulas assume it.
pub trait TwistedEdwards: Curve {
    /// The constant $d$, big-endian hexadecimal.
    const D: &'static str;
}

/// Decodes a big-endian hexadecimal constant into a field element; `None`
/// if it is not a canonical element. The instances' constants are checked
/// by their tests, so callers may treat `None` as unreachable.
pub(crate) fn element<F>(hex: &str) -> Option<F>
where
    F: PrimeField,
{
    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let padding = F::BYTES.checked_sub(digits.len() / 2)?;
    let mut bytes = vec![0u8; padding];
    for pair in digits.chunks(2) {
        let s = core::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(s, 16).ok()?);
    }
    let (value, valid) = F::from_bytes_be(&bytes);
    valid.to_bool_vartime().then_some(value)
}

/// [`element`], with zero for a constant that is not canonical (which the
/// instances' tests rule out).
pub(crate) fn constant<F>(hex: &str) -> F
where
    F: PrimeField,
{
    element(hex).unwrap_or(F::ZERO)
}
