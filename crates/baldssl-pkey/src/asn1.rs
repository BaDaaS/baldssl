//! The ASN.1 (Abstract Syntax Notation One) of keys, as DER (Distinguished
//! Encoding Rules) syntax descriptions (`baldssl_core::der::syntax`): each
//! gives the writer of its structure and a reader that is its inverse on
//! what the writer writes. baldssl reads a SubjectPublicKeyInfo with its
//! description; it reads private keys with the lenient reader of `parse`,
//! which accepts more than these descriptions do (the reasons are there),
//! and the tests read what the writer writes back with the descriptions.
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

/// `PrivateKeyInfo`'s version, `v1(0)` ([RFC 5958] section 2), the one
/// OpenSSL writes.
///
/// [RFC 5958]: https://www.rfc-editor.org/rfc/rfc5958#section-2
pub(crate) const PRIVATE_KEY_INFO_VERSION: u64 = 0;

/// `ECPrivateKey`'s version, `ecPrivkeyVer1(1)` ([RFC 5915] section 3), its
/// only one.
///
/// [RFC 5915]: https://www.rfc-editor.org/rfc/rfc5915#section-3
pub(crate) const EC_PRIVATE_KEY_VERSION: u64 = 1;

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

/// `rsaEncryption`, 1.2.840.113549.1.1.1 ([RFC 8017] appendix C).
///
/// [RFC 8017]: https://www.rfc-editor.org/rfc/rfc8017#appendix-C
pub(crate) const RSA_ENCRYPTION: ObjectId = ObjectId::from_static(&[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
]);
/// `id-RSASSA-PSS`, 1.2.840.113549.1.1.10 ([RFC 8017] appendix C).
///
/// [RFC 8017]: https://www.rfc-editor.org/rfc/rfc8017#appendix-C
pub(crate) const ID_RSASSA_PSS: ObjectId = ObjectId::from_static(&[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
]);
/// `id-X25519`, 1.3.101.110 ([RFC 8410] section 3).
///
/// [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410#section-3
pub(crate) const ID_X25519: ObjectId =
    ObjectId::from_static(&[0x2b, 0x65, 0x6e]);
/// `id-X448`, 1.3.101.111 ([RFC 8410] section 3).
///
/// [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410#section-3
pub(crate) const ID_X448: ObjectId = ObjectId::from_static(&[0x2b, 0x65, 0x6f]);
/// `id-Ed448`, 1.3.101.113 ([RFC 8410] section 3).
///
/// [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410#section-3
pub(crate) const ID_ED448: ObjectId =
    ObjectId::from_static(&[0x2b, 0x65, 0x71]);

/// The key algorithms baldssl does not implement, with the name the
/// unsupported error gives them.
pub(crate) const OTHER_ALGORITHMS: [(ObjectId, &str); 5] = [
    (RSA_ENCRYPTION, "RSA"),
    (ID_RSASSA_PSS, "RSA-PSS"),
    (ID_X25519, "X25519"),
    (ID_X448, "X448"),
    (ID_ED448, "Ed448"),
];

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
/// optional `[0]` attributes are not described: OpenSSL writes none, and
/// the reader of `parse`, which reads private keys, skips them.
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
