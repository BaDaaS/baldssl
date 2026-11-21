//! Reading keys: PKCS#8, SEC 1 and SubjectPublicKeyInfo, in DER and PEM.
//!
//! | Encoding | PEM label | Structure |
//! | --- | --- | --- |
//! | PKCS#8 | `PRIVATE KEY` | `OneAsymmetricKey` ([RFC 5958]), around [RFC 5915] for EC and [RFC 8410] for Ed25519 |
//! | SEC 1 | `EC PRIVATE KEY` | `ECPrivateKey` ([RFC 5915]) |
//! | SubjectPublicKeyInfo | `PUBLIC KEY` | [RFC 5480] for EC, [RFC 8410] for Ed25519 |
//!
//! The validation rules, and where they differ from OpenSSL, are in the
//! crate documentation (section "Reading keys"), where callers see them.
//!
//! [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480
//! [RFC 5915]: https://www.rfc-editor.org/rfc/rfc5915
//! [RFC 5958]: https://www.rfc-editor.org/rfc/rfc5958
//! [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410

use baldssl_core::{
    Error, Result,
    der::{
        BitString as BitStringContents, DerError, Integer, Reader,
        syntax::{ObjectId, ObjectIdentifier, RawTlv, decode, encode},
        tag,
    },
    encoding::Encodable,
    pem::{self, Pem, PemError},
};

use crate::{
    Algorithm, AnyPrivateKey,
    asn1::{
        ALGORITHM_IDENTIFIER, ID_EC_PUBLIC_KEY, ID_ED25519,
        SUBJECT_PUBLIC_KEY_INFO,
    },
};

/// The PEM labels of private keys, as OpenSSL reads them.
const PRIVATE_LABELS: &[&str] =
    &["PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"];

/// Other key algorithms, named in the unsupported error.
const OTHER_ALGORITHMS: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.1", "RSA"),
    ("1.2.840.113549.1.1.10", "RSA-PSS"),
    ("1.3.101.110", "X25519"),
    ("1.3.101.111", "X448"),
    ("1.3.101.113", "Ed448"),
];

/// A public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    algorithm: Algorithm,
    /// The uncompressed point, or the 32-byte Ed25519 public key.
    bytes: Vec<u8>,
}

impl PublicKey {
    /// The key type.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The public key: an uncompressed point (`04 || x || y`, whatever
    /// form it was read in), or the 32-byte Ed25519 encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reads a DER SubjectPublicKeyInfo.
    ///
    /// # Errors
    ///
    /// [`Error::Der`] for malformed DER or trailing bytes,
    /// [`Error::Invalid`] for a point that is not on the curve, the identity,
    /// or an Ed25519 key that is not 32 bytes, and [`Error::Unsupported`] for
    /// other algorithms and explicit curve parameters.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let ((alg, (key, ())), ()) = match decode(&SUBJECT_PUBLIC_KEY_INFO, der)
        {
            Ok(v) => (v, ()),
            Err(DerError::UnexpectedValue) => {
                // The only refinement in the description: a BIT STRING of
                // whole bytes.
                return Err(Error::invalid(
                    "public key: not a whole number of bytes",
                ));
            }
            Err(e) => return Err(e.into()),
        };
        let algorithm = algorithm(&alg)?;
        let bytes = match algorithm.curve_opt() {
            Some(curve) => curve.decode_point_opt(&key).ok_or_else(|| {
                Error::invalid("public key: not a point of the curve")
            })?,
            None if key.len() == 32 => key,
            None => {
                return Err(Error::invalid("Ed25519 public key: not 32 bytes"));
            }
        };
        Ok(PublicKey { algorithm, bytes })
    }

    /// Reads the first `PUBLIC KEY` block of a PEM input.
    ///
    /// # Errors
    ///
    /// [`Error::Pem`] when there is no such block, and the errors of
    /// [`PublicKey::from_der`].
    pub fn from_pem(input: &[u8]) -> Result<Self> {
        Self::from_der(&pem::decode_first(input, &["PUBLIC KEY"])?.contents)
    }
}

/// The DER SubjectPublicKeyInfo ([RFC 5280] section 4.1), as OpenSSL writes
/// it: the point uncompressed, the curve named.
///
/// [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
impl Encodable for PublicKey {
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        encode(
            &SUBJECT_PUBLIC_KEY_INFO,
            &(algorithm_value(self.algorithm), (self.bytes.clone(), ())),
        )
    }
}

/// SubjectPublicKeyInfo in PEM: `-----BEGIN PUBLIC KEY-----` ([RFC 7468,
/// section 13][rfc7468]).
///
/// [rfc7468]: https://www.rfc-editor.org/rfc/rfc7468#section-13
impl Pem for PublicKey {
    const LABEL: &'static str = "PUBLIC KEY";
}

impl AnyPrivateKey {
    /// Reads a DER private key: PKCS#8 (`PrivateKeyInfo` or
    /// `OneAsymmetricKey`) or SEC 1 (`ECPrivateKey`), told apart by their
    /// structure as OpenSSL does.
    ///
    /// # Errors
    ///
    /// [`Error::Der`] for malformed DER or trailing bytes,
    /// [`Error::Invalid`] for an invalid key (see [Reading
    /// keys](crate#reading-keys)), and [`Error::Unsupported`] for other
    /// algorithms and explicit curve parameters.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let mut outer = Reader::new(der);
        let mut seq = outer.sequence()?;
        outer.finish()?;
        let version = small_integer(&mut seq, "version")?;
        // PKCS#8 has an AlgorithmIdentifier (a SEQUENCE) next; SEC 1 has
        // the private key (an OCTET STRING), and only version 1.
        if seq.peek_octet_opt() == Some(tag::SEQUENCE) {
            pkcs8(version, seq)
        } else {
            sec1(version, seq, None)
        }
    }

    /// Reads the first private key block of a PEM input: `PRIVATE KEY`
    /// (PKCS#8) or `EC PRIVATE KEY` (SEC 1).
    ///
    /// # Errors
    ///
    /// [`Error::Pem`] when there is no such block,
    /// [`Error::Unsupported`] for an encrypted key, and the errors of
    /// [`AnyPrivateKey::from_der`].
    pub fn from_pem(input: &[u8]) -> Result<Self> {
        let block =
            pem::decode_first(input, PRIVATE_LABELS).map_err(|e| match e {
                PemError::HeadersUnsupported => Error::unsupported(
                    "encrypted PEM keys (Proc-Type and DEK-Info headers)",
                ),
                other => Error::Pem(other),
            })?;
        match block.label.as_str() {
            "ENCRYPTED PRIVATE KEY" => Err(Error::unsupported(
                "encrypted private keys (ENCRYPTED PRIVATE KEY)",
            )),
            "EC PRIVATE KEY" => {
                let mut outer = Reader::new(&block.contents);
                let mut seq = outer.sequence()?;
                outer.finish()?;
                let version = small_integer(&mut seq, "version")?;
                sec1(version, seq, None)
            }
            _ => {
                let mut outer = Reader::new(&block.contents);
                let mut seq = outer.sequence()?;
                outer.finish()?;
                let version = small_integer(&mut seq, "version")?;
                pkcs8(version, seq)
            }
        }
    }
}

/// A small non-negative INTEGER.
fn small_integer(r: &mut Reader<'_>, what: &str) -> Result<u64> {
    let int = Integer::parse(r.expect(tag::INTEGER)?.value)?;
    if int.negative {
        return Err(Error::invalid(format!("{what}: negative")));
    }
    int.to_u64_opt()
        .ok_or_else(|| Error::invalid(format!("{what}: too large")))
}

/// The curve named by an OID.
fn named_curve(oid: &str) -> Result<Algorithm> {
    [Algorithm::P256, Algorithm::P384, Algorithm::P521]
        .into_iter()
        .find(|a| {
            a.curve_oid_opt()
                .and_then(|o| o.to_dotted().ok())
                .as_deref()
                == Some(oid)
        })
        .ok_or_else(|| Error::unsupported(format!("EC curve {oid}")))
}

/// ECParameters ([RFC 5480] section 2.1.1), one TLV: only a `namedCurve`.
///
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
fn ec_parameters(params: &RawTlv) -> Result<Algorithm> {
    match params.as_bytes().first() {
        Some(&tag::OID) => named_curve(
            &decode(&ObjectIdentifier, params.as_bytes())?.to_dotted()?,
        ),
        Some(&tag::SEQUENCE) => {
            Err(Error::unsupported("explicit EC curve parameters"))
        }
        // NULL is implicitCA: the curve is inherited from elsewhere, which
        // RFC 5480 forbids in certificates and keys.
        _ => Err(Error::invalid("EC parameters: not a named curve")),
    }
}

/// The key algorithm an AlgorithmIdentifier names, with its parameters
/// checked: for EC ([RFC 5480] section 2.1.1) only a `namedCurve`; for
/// Ed25519 ([RFC 8410] section 3) no parameters.
///
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
/// [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410#section-3
fn algorithm(
    (oid, (params, ())): &(ObjectId, (Option<RawTlv>, ())),
) -> Result<Algorithm> {
    if *oid == ID_EC_PUBLIC_KEY {
        return match params {
            Some(params) => ec_parameters(params),
            None => Err(Error::invalid("EC parameters: not a named curve")),
        };
    }
    if *oid == ID_ED25519 {
        return match params {
            None => Ok(Algorithm::Ed25519),
            Some(_) => {
                Err(Error::invalid("Ed25519: parameters must be absent"))
            }
        };
    }
    let dotted = oid.to_dotted()?;
    let name = OTHER_ALGORITHMS
        .iter()
        .find(|(o, _)| *o == dotted)
        .map_or(dotted.as_str(), |(_, n)| n);
    Err(Error::unsupported(format!("{name} keys")))
}

/// The AlgorithmIdentifier that comes next in `r`, read with its
/// description.
fn algorithm_identifier(r: &mut Reader<'_>) -> Result<Algorithm> {
    let tlv = r.read()?;
    algorithm(&decode(&ALGORITHM_IDENTIFIER, tlv.encoded)?)
}

/// The AlgorithmIdentifier of a key type, as written by OpenSSL.
fn algorithm_value(algorithm: Algorithm) -> (ObjectId, (Option<RawTlv>, ())) {
    match algorithm.curve_oid_opt() {
        Some(curve) => (
            ID_EC_PUBLIC_KEY,
            (Some(RawTlv::encode(&ObjectIdentifier, &curve)), ()),
        ),
        None => (ID_ED25519, (None, ())),
    }
}

/// The scalar of an OCTET STRING of any length, at the full length of the
/// group order: leading zero bytes removed, then left-padded. `None` when
/// it is longer than the order once leading zeros are removed.
fn full_length_opt(bytes: &[u8], len: usize) -> Option<Vec<u8>> {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let digits = bytes.get(first..)?;
    let pad = len.checked_sub(digits.len())?;
    let mut out = vec![0u8; pad];
    out.extend_from_slice(digits);
    Some(out)
}

/// OneAsymmetricKey ([RFC 5958] section 2), after its version:
/// AlgorithmIdentifier, OCTET STRING privateKey, `[0]` attributes
/// (ignored), `[1]` publicKey (version 1, called v2, only).
///
/// [RFC 5958]: https://www.rfc-editor.org/rfc/rfc5958
fn pkcs8(version: u64, mut seq: Reader<'_>) -> Result<AnyPrivateKey> {
    if version > 1 {
        return Err(Error::invalid(format!("PKCS#8: version {version}")));
    }
    let algorithm = algorithm_identifier(&mut seq)?;
    let private = seq.expect(tag::OCTET_STRING)?.value;
    seq.optional(tag::context_constructed(0))?;
    let public = seq.optional(tag::context(1))?;
    seq.finish()?;
    if public.is_some() && version == 0 {
        return Err(Error::invalid("PKCS#8: a public key needs version 1"));
    }
    let key = if algorithm == Algorithm::Ed25519 {
        // CurvePrivateKey ::= OCTET STRING (RFC 8410 section 7).
        let mut inner = Reader::new(private);
        let seed = inner.expect(tag::OCTET_STRING)?.value;
        inner.finish()?;
        if seed.len() != 32 {
            return Err(Error::invalid("Ed25519 private key: not 32 bytes"));
        }
        AnyPrivateKey::from_secret(Algorithm::Ed25519, seed)?
    } else {
        let mut inner = Reader::new(private);
        let mut ec = inner.sequence()?;
        inner.finish()?;
        let ec_version = small_integer(&mut ec, "ECPrivateKey version")?;
        sec1(ec_version, ec, Some(algorithm))?
    };
    if let Some(public) = public {
        let bits = BitStringContents::parse(public.value)?;
        if bits.unused != 0 || !matches_public(&key, bits.bytes) {
            return Err(Error::invalid(
                "the public key does not match the private key",
            ));
        }
    }
    Ok(key)
}

/// ECPrivateKey ([RFC 5915] section 3), after its version: OCTET STRING
/// privateKey, `[0]` parameters, `[1]` publicKey. `curve` is the curve of
/// the enclosing PKCS#8 AlgorithmIdentifier; standalone, `[0]` names it.
///
/// [RFC 5915]: https://www.rfc-editor.org/rfc/rfc5915
fn sec1(
    version: u64,
    mut seq: Reader<'_>,
    curve: Option<Algorithm>,
) -> Result<AnyPrivateKey> {
    if version != 1 {
        return Err(Error::invalid(format!("ECPrivateKey: version {version}")));
    }
    let scalar = seq.expect(tag::OCTET_STRING)?.value;
    let parameters = match seq.optional(tag::context_constructed(0))? {
        Some(params) => Some(ec_parameters(&RawTlv::parse(params.value)?)?),
        None => None,
    };
    let public = match seq.optional(tag::context_constructed(1))? {
        Some(public) => {
            let mut inner = Reader::new(public.value);
            let bits =
                BitStringContents::parse(inner.expect(tag::BIT_STRING)?.value)?;
            inner.finish()?;
            if bits.unused != 0 {
                return Err(Error::invalid(
                    "public key: not a whole number of bytes",
                ));
            }
            Some(bits.bytes)
        }
        None => None,
    };
    seq.finish()?;

    let algorithm = match (curve, parameters) {
        (Some(outer), Some(inner)) if outer != inner => {
            return Err(Error::invalid(
                "ECPrivateKey: its curve is not the one of PKCS#8",
            ));
        }
        (Some(a), _) | (None, Some(a)) => a,
        (None, None) => return Err(Error::invalid("ECPrivateKey: no curve")),
    };
    let secret = full_length_opt(scalar, algorithm.secret_len())
        .ok_or_else(|| Error::invalid("private scalar not in [1, n - 1]"))?;
    let key = AnyPrivateKey::from_secret(algorithm, &secret)?;
    if let Some(public) = public
        && !matches_public(&key, public)
    {
        return Err(Error::invalid(
            "the public key does not match the private key",
        ));
    }
    Ok(key)
}

/// Whether `encoded` (any SEC 1 form, or Ed25519 bytes) is the public key
/// of `key`.
fn matches_public(key: &AnyPrivateKey, encoded: &[u8]) -> bool {
    let public = key.public_key_bytes();
    match key.algorithm().curve_opt() {
        Some(curve) => curve.decode_point_opt(encoded) == Some(public),
        // A seed has exactly one public key, the one the pair holds.
        None => encoded == public.as_slice(),
    }
}

#[cfg(test)]
mod tests;
