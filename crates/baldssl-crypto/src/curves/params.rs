//! The parameters of the curves: each curve is a type implementing
//! [`CurveParams`], which every model of the curve reads.
//!
//! The values are those of `openssl ecparam -name <curve> -param_enc explicit
//! -noout -text` (OpenSSL 3.5.9), the same as FIPS 186-5 and SEC 2. The tests
//! check that each generator is on its curve and has the stated order.

use crate::{
    field::PrimeField,
    fields::{
        FieldP256, FieldP384, FieldP521, ScalarP256, ScalarP384, ScalarP521,
    },
};

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

/// NIST P-256 (`prime256v1`, `secp256r1`).
pub enum P256 {}

impl CurveParams for P256 {
    type Base = FieldP256;
    type Scalar = ScalarP256;
    const NAME: &'static str = "prime256v1";
    const B: &'static str =
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
    const GX: &'static str =
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const GY: &'static str =
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
}

/// NIST P-384 (`secp384r1`).
pub enum P384 {}

impl CurveParams for P384 {
    type Base = FieldP384;
    type Scalar = ScalarP384;
    const NAME: &'static str = "secp384r1";
    const B: &'static str = "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112\
        0314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef";
    const GX: &'static str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98\
        59f741e082542a385502f25dbf55296c3a545e3872760ab7";
    const GY: &'static str = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c\
        e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
}

/// NIST P-521 (`secp521r1`).
pub enum P521 {}

impl CurveParams for P521 {
    type Base = FieldP521;
    type Scalar = ScalarP521;
    const NAME: &'static str = "secp521r1";
    const B: &'static str = "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b3\
        15f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef\
        451fd46b503f00";
    const GX: &'static str = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053f\
        b521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf9\
        7e7e31c2e5bd66";
    const GY: &'static str = "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b\
        446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088\
        be94769fd16650";
}
