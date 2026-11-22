//! The ASN.1 (Abstract Syntax Notation One) of keys, as DER (Distinguished
//! Encoding Rules) syntax descriptions: each gives both the reader and the
//! writer of its structure (`baldssl_core::der::syntax`).
//!
//! The descriptions are of the *syntax*: their values keep everything the
//! encoding holds (the optional fields, the version), so the law of a
//! description holds exactly. Turning a record into a key is a separate
//! step that checks it (the public key is the private key's, the scalar is
//! in range); several records denote one key (with or without the optional
//! public key), and the writer picks the one `openssl genpkey` writes.

use baldssl_core::{
    Error,
    der::{
        DerError,
        syntax::{
            Any, BitString, Explicit, ObjectId, ObjectIdentifier, OctetString,
            Optional, OptionalLast, RawTlv, Sequence, Small, decode, encode,
        },
    },
    encoding::{Decodable, Encodable},
};

/// `id-ecPublicKey`, 1.2.840.10045.2.1 ([RFC 5480] section 2.1.1).
///
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
pub(crate) const ID_EC_PUBLIC_KEY: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
/// `id-Ed25519`, 1.3.101.112 ([RFC 8410] section 3).
///
/// [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410#section-3
pub(crate) const ID_ED25519: ObjectId =
    ObjectId::from_static(&[0x2b, 0x65, 0x70]);
/// `prime256v1` (`secp256r1`), 1.2.840.10045.3.1.7 ([RFC 5480] section
/// 2.1.1.1).
///
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1
pub(crate) const PRIME256V1: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
/// `secp384r1`, 1.3.132.0.34 ([RFC 5480] section 2.1.1.1).
///
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1
pub(crate) const SECP384R1: ObjectId =
    ObjectId::from_static(&[0x2b, 0x81, 0x04, 0x00, 0x22]);
/// `secp521r1`, 1.3.132.0.35 ([RFC 5480] section 2.1.1.1).
///
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1
pub(crate) const SECP521R1: ObjectId =
    ObjectId::from_static(&[0x2b, 0x81, 0x04, 0x00, 0x23]);

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
/// parameters ANY OPTIONAL }` ([RFC 5280] section 4.1.1.2).
///
/// [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2
pub(crate) type AlgorithmIdentifier =
    Sequence<(ObjectIdentifier, (OptionalLast<Any>, ()))>;

pub(crate) const ALGORITHM_IDENTIFIER: AlgorithmIdentifier =
    Sequence((ObjectIdentifier, (OptionalLast(Any), ())));

/// The value of an AlgorithmIdentifier: the algorithm, and its parameters
/// as one TLV when present.
pub(crate) type AlgorithmIdentifierValue = (ObjectId, (Option<RawTlv>, ()));

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }` ([RFC 5280] section 4.1), the key a whole
/// number of bytes ([RFC 5480] section 2 for EC, [RFC 8410] section 4 for
/// Ed25519).
///
/// [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
/// [RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480#section-2
/// [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410#section-4
pub(crate) type SubjectPublicKeyInfoSyntax =
    Sequence<(AlgorithmIdentifier, (BitString, ()))>;

pub(crate) const SUBJECT_PUBLIC_KEY_INFO: SubjectPublicKeyInfoSyntax =
    Sequence((ALGORITHM_IDENTIFIER, (BitString, ())));

/// A SubjectPublicKeyInfo as the DER holds it, before any check of the key:
/// the AlgorithmIdentifier, and the bytes of the BIT STRING.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubjectPublicKeyInfo {
    /// The key type and its parameters.
    pub(crate) algorithm: AlgorithmIdentifierValue,
    /// The key, as the algorithm encodes it.
    pub(crate) key: Vec<u8>,
}

/// Read with [`SUBJECT_PUBLIC_KEY_INFO`].
impl Decodable for SubjectPublicKeyInfo {
    type Error = Error;

    fn decode(der: &[u8]) -> Result<Self, Error> {
        match decode(&SUBJECT_PUBLIC_KEY_INFO, der) {
            Ok((algorithm, (key, ()))) => {
                Ok(SubjectPublicKeyInfo { algorithm, key })
            }
            // The only refinement in the description: a BIT STRING of whole
            // bytes.
            Err(DerError::UnexpectedValue) => {
                Err(Error::invalid("public key: not a whole number of bytes"))
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Written with [`SUBJECT_PUBLIC_KEY_INFO`].
impl Encodable for SubjectPublicKeyInfo {
    type Bytes = Vec<u8>;

    fn encode(&self) -> Vec<u8> {
        encode(
            &SUBJECT_PUBLIC_KEY_INFO,
            &(self.algorithm.clone(), (self.key.clone(), ())),
        )
    }
}

/// `PrivateKeyInfo` ([RFC 5208] section 5): version, algorithm, and the
/// private key as an OCTET STRING, whose contents the algorithm determines
/// (an `ECPrivateKey` for EC, a `CurvePrivateKey` for Ed25519). The
/// optional `[0]` attributes are not described: OpenSSL writes none, and a
/// reader that meets them reports them (reading keys is separate).
///
/// [RFC 5208]: https://www.rfc-editor.org/rfc/rfc5208#section-5
pub(crate) type PrivateKeyInfo =
    Sequence<(Small, (AlgorithmIdentifier, (OctetString, ())))>;

pub(crate) const PRIVATE_KEY_INFO: PrivateKeyInfo =
    Sequence((Small, (ALGORITHM_IDENTIFIER, (OctetString, ()))));

/// `ECPrivateKey ::= SEQUENCE { version INTEGER (1), privateKey OCTET
/// STRING, parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING
/// OPTIONAL }` ([RFC 5915] section 3, explicit tags): $d$ big-endian at the
/// full length of the group order, and the public point.
///
/// [RFC 5915]: https://www.rfc-editor.org/rfc/rfc5915#section-3
pub(crate) type EcPrivateKey = Sequence<(
    Small,
    (
        OctetString,
        (
            Optional<Explicit<0, Any>>,
            (Optional<Explicit<1, BitString>>, ()),
        ),
    ),
)>;

pub(crate) const EC_PRIVATE_KEY: EcPrivateKey = Sequence((
    Small,
    (
        OctetString,
        (Optional(Explicit(Any)), (Optional(Explicit(BitString)), ())),
    ),
));

/// `CurvePrivateKey ::= OCTET STRING` ([RFC 8410] section 7): the seed.
///
/// [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410#section-7
pub(crate) const CURVE_PRIVATE_KEY: OctetString = OctetString;
