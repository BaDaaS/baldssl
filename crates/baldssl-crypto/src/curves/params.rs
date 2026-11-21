//! What a curve is to the models: a type implementing [`CurveParams`], which
//! every model reads. Each curve, with its fields, is defined in its own
//! module: [`super::p256`], [`super::p384`], [`super::p521`].

use crate::field::PrimeField;

/// A short Weierstrass curve $y^2 = x^3 - 3x + b$ over `Self::Base` (the
/// NIST curves all have $a = -3$), of prime order `Self::Scalar`'s modulus,
/// with a fixed generator.
pub trait CurveParams: 'static {
    /// The base field $\mathbb{F}_p$.
    type Base: PrimeField;
    /// The scalar field $\mathbb{F}_n$, $n$ the order of the generator.
    type Scalar: PrimeField;
    /// The name OpenSSL uses (`ASN1 OID:` in `-text`).
    const NAME: &'static str;
    /// The constant $b$, big-endian hexadecimal.
    const B: &'static str;
    /// The generator's $x$, big-endian hexadecimal.
    const GX: &'static str;
    /// The generator's $y$, big-endian hexadecimal.
    const GY: &'static str;
}

/// Decodes a big-endian hexadecimal constant into a field element; `None`
/// if it is not a canonical element. The constants above are checked by the
/// tests, so callers may treat `None` as unreachable.
pub(crate) fn element<F>(hex: &str) -> Option<F>
where
    F: PrimeField,
{
    let digits = hex.as_bytes();
    if digits.len() > 2 * F::BYTES || !digits.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = vec![0u8; F::BYTES - digits.len() / 2];
    for pair in digits.chunks(2) {
        let s = core::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(s, 16).ok()?);
    }
    let (value, valid) = F::from_bytes_be(&bytes);
    valid.to_bool_vartime().then_some(value)
}
