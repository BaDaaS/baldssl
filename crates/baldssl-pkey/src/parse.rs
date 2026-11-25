//! Reading keys: PKCS#8, SEC 1 and SubjectPublicKeyInfo, in DER and PEM.
//!
//! | Encoding | PEM label | Structure |
//! | --- | --- | --- |
//! | PKCS#8 | `PRIVATE KEY` | `OneAsymmetricKey` ([RFC 5958, section 2][rfc5958]), around [RFC 5915][rfc5915] for EC and [RFC 8410, section 7][rfc8410-7] for Ed25519 |
//! | SEC 1 | `EC PRIVATE KEY` | `ECPrivateKey` ([RFC 5915, section 3][rfc5915]) |
//! | SubjectPublicKeyInfo | `PUBLIC KEY` | [RFC 5480, section 2][rfc5480] for EC, [RFC 8410, section 4][rfc8410-4] for Ed25519 |
//!
//! The validation rules, and where they differ from OpenSSL, are in the
//! crate documentation (section "Reading keys"), where callers see them.
//!
//! # The reader of private keys is lenient
//!
//! A SubjectPublicKeyInfo is read with its syntax description, the inverse
//! of its writer. Private keys are read by the hand reader below instead of
//! the `PRIVATE_KEY_INFO` and `EC_PRIVATE_KEY` descriptions, because it
//! accepts more than the writer writes, as OpenSSL reads it: a
//! `OneAsymmetricKey` of version 1 with its `[1]` public key, `[0]`
//! attributes (skipped without being read, as baldssl uses none), `[0]`
//! curve parameters inside PKCS#8, either structure where the other is
//! expected in DER (told apart by their second field), and each rejection
//! with the field it concerns. What it reads re-encodes to the one record
//! the writer writes for the key; the tests show inputs where the two
//! differ.
//!
//! [rfc5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2
//! [rfc5915]: https://www.rfc-editor.org/rfc/rfc5915#section-3
//! [rfc5958]: https://www.rfc-editor.org/rfc/rfc5958#section-2
//! [rfc8410-4]: https://www.rfc-editor.org/rfc/rfc8410#section-4
//! [rfc8410-7]: https://www.rfc-editor.org/rfc/rfc8410#section-7

use baldssl_core::{
    Error, Result,
    der::{
        BitString as BitStringContents, Integer, Reader,
        syntax::{ObjectId, ObjectIdentifier, RawTlv, decode},
        tag,
    },
    encoding::{Decodable, Encodable},
    pem::{self, Pem, PemBlock, PemError},
};
use baldssl_crypto::{
    instances::{P256, P384, P521},
    secret::SecretBytes,
    signature::{
        ecdsa::PublicKey as EcdsaPublicKey,
        eddsa::{Ed25519, Ed25519Parameters, PublicKey as EddsaPublicKey},
    },
};

use crate::{
    Algorithm, AnyPrivateKey, ED25519_KEY_LEN, PublicOf, ReadPublic, Signing,
    asn1::{
        ALGORITHM_IDENTIFIER, AlgorithmIdentifierValue, EC_PRIVATE_KEY_VERSION,
        ID_EC_PUBLIC_KEY, ID_ED25519, OTHER_ALGORITHMS, SubjectPublicKeyInfo,
    },
};

/// The PEM labels of private keys, as OpenSSL reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateKeyLabel {
    /// `PRIVATE KEY`, PKCS#8 ([RFC 7468, section 10][rfc7468-10]).
    ///
    /// [rfc7468-10]: https://www.rfc-editor.org/rfc/rfc7468#section-10
    Pkcs8,
    /// `EC PRIVATE KEY`, SEC 1's `ECPrivateKey` ([RFC 5915, section
    /// 4][rfc5915-4]).
    ///
    /// [rfc5915-4]: https://www.rfc-editor.org/rfc/rfc5915#section-4
    Sec1,
    /// `ENCRYPTED PRIVATE KEY`, PKCS#8's `EncryptedPrivateKeyInfo` ([RFC
    /// 7468, section 11][rfc7468-11]).
    ///
    /// [rfc7468-11]: https://www.rfc-editor.org/rfc/rfc7468#section-11
    Encrypted,
}

impl PrivateKeyLabel {
    /// Every label.
    const ALL: [PrivateKeyLabel; 3] = [
        PrivateKeyLabel::Pkcs8,
        PrivateKeyLabel::Sec1,
        PrivateKeyLabel::Encrypted,
    ];

    /// The label of the BEGIN and END lines.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            PrivateKeyLabel::Pkcs8 => "PRIVATE KEY",
            PrivateKeyLabel::Sec1 => "EC PRIVATE KEY",
            PrivateKeyLabel::Encrypted => "ENCRYPTED PRIVATE KEY",
        }
    }

    /// The label a PEM block has, when it is one of a private key.
    fn from_label_opt(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.label() == label)
    }
}

/// The versions of `OneAsymmetricKey` ([RFC 5958, section 2][rfc5958]):
/// `Version ::= INTEGER { v1(0), v2(1) }`.
///
/// [rfc5958]: https://www.rfc-editor.org/rfc/rfc5958#section-2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
enum OneAsymmetricKeyVersion {
    /// `v1(0)`: PKCS#8's `PrivateKeyInfo`, with no public key.
    V1 = 0,
    /// `v2(1)`: may carry the `[1]` public key.
    V2 = 1,
}

/// A version number, when it is one of [RFC 5958].
///
/// # Errors
///
/// [`Error::Invalid`] for any other number.
///
/// [RFC 5958]: https://www.rfc-editor.org/rfc/rfc5958#section-2
impl TryFrom<u64> for OneAsymmetricKeyVersion {
    type Error = Error;

    fn try_from(version: u64) -> Result<Self> {
        OneAsymmetricKeyVersion::ALL
            .into_iter()
            .find(|v| v.number() == version)
            .ok_or_else(|| Error::invalid(format!("PKCS#8: version {version}")))
    }
}

impl OneAsymmetricKeyVersion {
    /// Every version.
    const ALL: [OneAsymmetricKeyVersion; 2] =
        [OneAsymmetricKeyVersion::V1, OneAsymmetricKeyVersion::V2];

    /// The INTEGER the version is.
    #[allow(
        clippy::as_conversions,
        reason = "reads the discriminant, which is the version's number"
    )]
    fn number(self) -> u64 {
        self as u64
    }
}

/// An Ed25519 public key as a SubjectPublicKeyInfo holds it: the
/// [`ED25519_KEY_LEN`] bytes of [RFC 8032, section 5.1.2][rfc8032]
/// (little-endian), not decoded, as OpenSSL reads it, so any 32 bytes are
/// one. Verifying decodes them.
///
/// [rfc8032]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey(Vec<u8>);

impl Ed25519PublicKey {
    /// The 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The encoding of a typed key: $b = 256$ bits, [`ED25519_KEY_LEN`] bytes,
/// by RFC 8032 section 5.1.2, which the tests check of every key.
impl From<&EddsaPublicKey<Ed25519Parameters>> for Ed25519PublicKey {
    fn from(key: &EddsaPublicKey<Ed25519Parameters>) -> Self {
        Ed25519PublicKey(key.as_bytes().to_vec())
    }
}

/// Any [`ED25519_KEY_LEN`] bytes.
///
/// # Errors
///
/// [`Error::Invalid`] for another length.
impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == ED25519_KEY_LEN {
            Ok(Ed25519PublicKey(bytes.to_vec()))
        } else {
            Err(Error::invalid("Ed25519 public key: not 32 bytes"))
        }
    }
}

/// The 32 bytes.
impl Encodable for Ed25519PublicKey {
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// A public key, read from a SubjectPublicKeyInfo: the point for the EC
/// curves, whatever SEC 1 form it was read in, and the 32 bytes of an
/// [`Ed25519PublicKey`] for Ed25519. Each variant holds the
/// [`KeyAlgorithm::SubjectPublicKey`](crate::KeyAlgorithm::SubjectPublicKey)
/// of its algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// A point of P-256 other than the identity.
    P256(EcdsaPublicKey<P256>),
    /// A point of P-384 other than the identity.
    P384(EcdsaPublicKey<P384>),
    /// A point of P-521 other than the identity.
    P521(EcdsaPublicKey<P521>),
    /// An Ed25519 public key.
    Ed25519(Ed25519PublicKey),
}

/// A computation generic over the key algorithm, which [`PublicKey::with`]
/// runs on the typed public key it holds.
pub(crate) trait WithPublicKey {
    /// What the computation gives.
    type Output;

    /// The computation on a typed public key.
    fn run<A>(self, key: &A::SubjectPublicKey) -> Self::Output
    where
        A: Signing;
}

/// The algorithm of a typed public key.
struct AlgorithmOf;

impl WithPublicKey for AlgorithmOf {
    type Output = Algorithm;

    fn run<A>(self, _key: &A::SubjectPublicKey) -> Algorithm
    where
        A: Signing,
    {
        A::ALGORITHM
    }
}

/// The encoding of a typed public key.
struct KeyBytes;

impl WithPublicKey for KeyBytes {
    type Output = Vec<u8>;

    fn run<A>(self, key: &A::SubjectPublicKey) -> Vec<u8>
    where
        A: Signing,
    {
        key.encode()
    }
}

impl PublicKey {
    /// Runs `computation` on the typed public key this value holds: the only
    /// place a run-time public key becomes a typed one, the inverse of
    /// [`KeyAlgorithm::public_into_any`](crate::KeyAlgorithm::public_into_any).
    pub(crate) fn with<W>(&self, computation: W) -> W::Output
    where
        W: WithPublicKey,
    {
        match self {
            PublicKey::P256(q) => computation.run::<P256>(q),
            PublicKey::P384(q) => computation.run::<P384>(q),
            PublicKey::P521(q) => computation.run::<P521>(q),
            PublicKey::Ed25519(key) => computation.run::<Ed25519>(key),
        }
    }

    /// The key type.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.with(AlgorithmOf)
    }

    /// The key's own encoding: the point's (SEC 1 uncompressed, `04 || x ||
    /// y`, big-endian, through its [`Encodable`]), or the 32 bytes of an
    /// Ed25519 key.
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.with(KeyBytes)
    }

    /// Reads the first `PUBLIC KEY` block of a PEM input.
    ///
    /// # Errors
    ///
    /// [`Error::Pem`] when there is no such block, and the errors of
    /// [`PublicKey::try_from`] a [`PemBlock`].
    pub fn from_pem(input: &[u8]) -> Result<Self> {
        Self::try_from(&pem::decode_first(input, &[Self::LABEL])?)
    }
}

/// The checks that make a SubjectPublicKeyInfo a public key.
///
/// # Errors
///
/// [`Error::Invalid`] for a point that is not on the curve, the identity, or
/// an Ed25519 key that is not 32 bytes, and [`Error::Unsupported`] for other
/// algorithms and explicit curve parameters.
impl TryFrom<SubjectPublicKeyInfo> for PublicKey {
    type Error = Error;

    fn try_from(spki: SubjectPublicKeyInfo) -> Result<Self> {
        Algorithm::try_from(&spki.algorithm)?.with(ReadPublic(&spki.key))
    }
}

/// The public key of a private key.
impl From<&AnyPrivateKey> for PublicKey {
    fn from(key: &AnyPrivateKey) -> Self {
        key.with(PublicOf)
    }
}

/// The SubjectPublicKeyInfo OpenSSL writes: the curve named, the point
/// uncompressed.
impl From<&PublicKey> for SubjectPublicKeyInfo {
    fn from(key: &PublicKey) -> Self {
        SubjectPublicKeyInfo {
            algorithm: key.algorithm().algorithm_identifier(),
            key: key.public_key_bytes(),
        }
    }
}

/// A DER SubjectPublicKeyInfo ([RFC 5280] section 4.1): the record, then
/// its checks ([`PublicKey::try_from`]).
///
/// [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
impl Decodable for PublicKey {
    type Error = Error;

    fn decode(der: &[u8]) -> Result<Self> {
        SubjectPublicKeyInfo::decode(der)?.try_into()
    }
}

/// The DER SubjectPublicKeyInfo ([RFC 5280] section 4.1), as OpenSSL writes
/// it: the point uncompressed, the curve named.
///
/// [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
impl Encodable for PublicKey {
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        SubjectPublicKeyInfo::from(self).encode()
    }
}

/// SubjectPublicKeyInfo in PEM: `-----BEGIN PUBLIC KEY-----` ([RFC 7468,
/// section 13][rfc7468]).
///
/// [rfc7468]: https://www.rfc-editor.org/rfc/rfc7468#section-13
impl Pem for PublicKey {
    const LABEL: &'static str = "PUBLIC KEY";
}

/// A `PUBLIC KEY` PEM block: its contents, decoded.
///
/// # Errors
///
/// [`Error::Invalid`] for a block with another label, and the errors of
/// [`PublicKey::decode`].
impl TryFrom<&PemBlock> for PublicKey {
    type Error = Error;

    fn try_from(block: &PemBlock) -> Result<Self> {
        if block.label != Self::LABEL {
            return Err(Error::invalid(format!(
                "PEM: {} where PUBLIC KEY was expected",
                block.label
            )));
        }
        Self::decode(&block.contents)
    }
}

impl AnyPrivateKey {
    /// Reads the first private key block of a PEM input: `PRIVATE KEY`
    /// (PKCS#8) or `EC PRIVATE KEY` (SEC 1).
    ///
    /// # Errors
    ///
    /// [`Error::Pem`] when there is no such block,
    /// [`Error::Unsupported`] for an encrypted key, and the errors of
    /// [`AnyPrivateKey::try_from`] a [`PemBlock`].
    pub fn from_pem(input: &[u8]) -> Result<Self> {
        let labels = PrivateKeyLabel::ALL.map(PrivateKeyLabel::label);
        let block = pem::decode_first(input, &labels).map_err(|e| match e {
            PemError::HeadersUnsupported => Error::unsupported(
                "encrypted PEM keys (Proc-Type and DEK-Info headers)",
            ),
            other @ (PemError::NoBlock
            | PemError::Unterminated
            | PemError::Base64(_)) => Error::Pem(other),
        })?;
        Self::try_from(&block)
    }
}

/// A DER private key: PKCS#8 (`PrivateKeyInfo` or `OneAsymmetricKey`) or
/// SEC 1 (`ECPrivateKey`), told apart by their structure as OpenSSL does.
/// The lenient reader (see the module documentation).
///
/// # Errors
///
/// [`Error::Der`] for malformed DER or trailing bytes, [`Error::Invalid`]
/// for an invalid key (see [Reading keys](crate#reading-keys)), and
/// [`Error::Unsupported`] for other algorithms and explicit curve
/// parameters.
impl Decodable for AnyPrivateKey {
    type Error = Error;

    fn decode(der: &[u8]) -> Result<Self> {
        let mut seq = outer_sequence(der)?;
        let version = small_integer(&mut seq, "version")?;
        // PKCS#8 has an AlgorithmIdentifier (a SEQUENCE) next; SEC 1 has
        // the private key (an OCTET STRING), and only version 1.
        if seq.peek_octet_opt() == Some(tag::SEQUENCE) {
            pkcs8(version, seq)
        } else {
            sec1(version, seq, None)
        }
    }
}

/// A private key PEM block, read as its label says: `PRIVATE KEY` as
/// PKCS#8, `EC PRIVATE KEY` as SEC 1.
///
/// # Errors
///
/// [`Error::Unsupported`] for `ENCRYPTED PRIVATE KEY`, [`Error::Invalid`]
/// for any other label, and the errors of [`AnyPrivateKey::decode`].
impl TryFrom<&PemBlock> for AnyPrivateKey {
    type Error = Error;

    fn try_from(block: &PemBlock) -> Result<Self> {
        let label =
            PrivateKeyLabel::from_label_opt(&block.label).ok_or_else(|| {
                Error::invalid(format!(
                    "PEM: {} where a private key was expected",
                    block.label
                ))
            })?;
        match label {
            PrivateKeyLabel::Pkcs8 => {
                let mut seq = outer_sequence(&block.contents)?;
                let version = small_integer(&mut seq, "version")?;
                pkcs8(version, seq)
            }
            PrivateKeyLabel::Sec1 => {
                let mut seq = outer_sequence(&block.contents)?;
                let version = small_integer(&mut seq, "version")?;
                sec1(version, seq, None)
            }
            PrivateKeyLabel::Encrypted => Err(Error::unsupported(
                "encrypted private keys (ENCRYPTED PRIVATE KEY)",
            )),
        }
    }
}

/// The one SEQUENCE `der` holds, with nothing after it.
fn outer_sequence(der: &[u8]) -> Result<Reader<'_>> {
    let mut outer = Reader::new(der);
    let seq = outer.sequence()?;
    outer.finish()?;
    Ok(seq)
}

/// A small non-negative INTEGER.
fn small_integer(r: &mut Reader<'_>, what: &str) -> Result<u64> {
    let int = Integer::parse(r.expect(tag::INTEGER)?.value())?;
    if int.is_negative() {
        return Err(Error::invalid(format!("{what}: negative")));
    }
    int.to_u64_opt()
        .ok_or_else(|| Error::invalid(format!("{what}: too large")))
}

/// The EC curve named by an object identifier, compared as a value; the
/// dotted form is for the error message only.
fn named_curve(oid: &ObjectId) -> Result<Algorithm> {
    match Algorithm::ALL
        .into_iter()
        .find(|a| a.curve_oid_opt().as_ref() == Some(oid))
    {
        Some(algorithm) => Ok(algorithm),
        None => {
            Err(Error::unsupported(format!("EC curve {}", oid.to_dotted()?)))
        }
    }
}

/// The curve DER `ECParameters` ([RFC 5480] section 2.1.1) name, only a
/// `namedCurve`, as `openssl ecparam` writes them (the contents of an `EC
/// PARAMETERS` PEM block) and as the AlgorithmIdentifier of an EC key and
/// the `[0]` of an `ECPrivateKey` hold them. A `TryFrom`, not a `From`: not
/// every TLV names a curve baldssl implements.
///
/// # Errors
///
/// Explicit curve parameters, `implicitCA`, or a curve baldssl does not
/// implement.
///
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
impl TryFrom<&RawTlv> for Algorithm {
    type Error = Error;

    fn try_from(params: &RawTlv) -> Result<Self> {
        match params.as_bytes().first() {
            Some(&tag::OID) => {
                named_curve(&decode(&ObjectIdentifier, params.as_bytes())?)
            }
            Some(&tag::SEQUENCE) => {
                Err(Error::unsupported("explicit EC curve parameters"))
            }
            // NULL is implicitCA: the curve is inherited from elsewhere,
            // which RFC 5480 forbids in certificates and keys.
            _ => Err(Error::invalid("EC parameters: not a named curve")),
        }
    }
}

/// The key algorithm an AlgorithmIdentifier names, with its parameters
/// checked: for EC ([RFC 5480] section 2.1.1) only a `namedCurve`; for
/// Ed25519 ([RFC 8410] section 3) no parameters.
///
/// # Errors
///
/// [`Error::Invalid`] for parameters the algorithm does not take, and
/// [`Error::Unsupported`] for another algorithm.
///
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
/// [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410#section-3
impl TryFrom<&AlgorithmIdentifierValue> for Algorithm {
    type Error = Error;

    fn try_from(
        (oid, (params, ())): &AlgorithmIdentifierValue,
    ) -> Result<Self> {
        if *oid == ID_EC_PUBLIC_KEY {
            return match params {
                Some(params) => Algorithm::try_from(params),
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
        let name = match OTHER_ALGORITHMS.iter().find(|(o, _)| o == oid) {
            Some((_, name)) => (*name).to_owned(),
            None => oid.to_dotted()?,
        };
        Err(Error::unsupported(format!("{name} keys")))
    }
}

/// The AlgorithmIdentifier that comes next in `r`, read with its
/// description.
fn algorithm_identifier(r: &mut Reader<'_>) -> Result<Algorithm> {
    let tlv = r.read()?;
    Algorithm::try_from(&decode(&ALGORITHM_IDENTIFIER, tlv.encoded())?)
}

/// The scalar of an OCTET STRING of any length, at the full length of the
/// group order: leading zero bytes removed, then left-padded, in memory
/// that is wiped. `None` when it is longer than the order once leading
/// zeros are removed.
fn full_length_opt(bytes: &[u8], len: usize) -> Option<SecretBytes> {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let digits = bytes.get(first..)?;
    let pad = len.checked_sub(digits.len())?;
    let mut out = SecretBytes::filled(0, len);
    // `pad + digits.len() == len`, so the tail is exactly as long as the
    // digits and `copy_from_slice` cannot fail.
    out.expose_mut().get_mut(pad..)?.copy_from_slice(digits);
    Some(out)
}

/// OneAsymmetricKey ([RFC 5958] section 2), after its version:
/// AlgorithmIdentifier, OCTET STRING privateKey, `[0]` attributes
/// (skipped), `[1]` publicKey (version v2 only).
///
/// [RFC 5958]: https://www.rfc-editor.org/rfc/rfc5958#section-2
fn pkcs8(version: u64, mut seq: Reader<'_>) -> Result<AnyPrivateKey> {
    let version = OneAsymmetricKeyVersion::try_from(version)?;
    let algorithm = algorithm_identifier(&mut seq)?;
    let private = seq.expect(tag::OCTET_STRING)?.value();
    seq.optional(tag::context_constructed(0))?;
    let public = seq.optional(tag::context(1))?;
    seq.finish()?;
    let public = match (version, public) {
        (OneAsymmetricKeyVersion::V1, Some(_)) => {
            return Err(Error::invalid("PKCS#8: a public key needs version 1"));
        }
        (OneAsymmetricKeyVersion::V1 | OneAsymmetricKeyVersion::V2, None) => {
            None
        }
        (OneAsymmetricKeyVersion::V2, Some(public)) => Some(public),
    };
    let key = match algorithm {
        Algorithm::Ed25519 => {
            // CurvePrivateKey ::= OCTET STRING (RFC 8410 section 7).
            let mut inner = Reader::new(private);
            let seed = inner.expect(tag::OCTET_STRING)?.value();
            inner.finish()?;
            if seed.len() != ED25519_KEY_LEN {
                return Err(Error::invalid(
                    "Ed25519 private key: not 32 bytes",
                ));
            }
            AnyPrivateKey::from_secret(Algorithm::Ed25519, seed)?
        }
        Algorithm::P256 | Algorithm::P384 | Algorithm::P521 => {
            let mut inner = Reader::new(private);
            let mut ec = inner.sequence()?;
            inner.finish()?;
            let ec_version = small_integer(&mut ec, "ECPrivateKey version")?;
            sec1(ec_version, ec, Some(algorithm))?
        }
    };
    if let Some(public) = public {
        let bits = BitStringContents::parse(public.value())?;
        if bits.unused() != 0 || !matches_public(&key, bits.bytes()) {
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
/// [RFC 5915]: https://www.rfc-editor.org/rfc/rfc5915#section-3
fn sec1(
    version: u64,
    mut seq: Reader<'_>,
    curve: Option<Algorithm>,
) -> Result<AnyPrivateKey> {
    if version != EC_PRIVATE_KEY_VERSION {
        return Err(Error::invalid(format!("ECPrivateKey: version {version}")));
    }
    let scalar = seq.expect(tag::OCTET_STRING)?.value();
    let parameters = match seq.optional(tag::context_constructed(0))? {
        Some(params) => {
            Some(Algorithm::try_from(&RawTlv::parse(params.value())?)?)
        }
        None => None,
    };
    let public = match seq.optional(tag::context_constructed(1))? {
        Some(public) => {
            let mut inner = Reader::new(public.value());
            let bits = BitStringContents::parse(
                inner.expect(tag::BIT_STRING)?.value(),
            )?;
            inner.finish()?;
            if bits.unused() != 0 {
                return Err(Error::invalid(
                    "public key: not a whole number of bytes",
                ));
            }
            Some(bits.bytes())
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
    let key = AnyPrivateKey::from_secret(algorithm, secret.expose())?;
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
/// of `key`: read as a public key of its algorithm and compared as a value.
fn matches_public(key: &AnyPrivateKey, encoded: &[u8]) -> bool {
    key.algorithm()
        .with(ReadPublic(encoded))
        .is_ok_and(|public| public == PublicKey::from(key))
}

#[cfg(test)]
mod tests;
