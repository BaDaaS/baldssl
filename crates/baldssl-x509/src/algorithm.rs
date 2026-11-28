//! The X.509 names of the signature algorithms: the `AlgorithmIdentifier`
//! of each [`SignatureAlgorithm`], with absent parameters: ECDSA with a
//! SHA hash ([RFC 3279 section 2.2.3], [RFC 5758 section 3.2]) and Ed25519
//! ([RFC 8410 section 3]).
//!
//! [`oid_opt`] is an exhaustive `match`, so every algorithm is decided by
//! construction: it has its name, or none (ECDSA with SHA-512/224 or
//! SHA-512/256, which RFC 5758 does not name). The `TryFrom` of
//! [`SignatureAlgorithm`] is its inverse, found by searching the finite set
//! of algorithms, so the two cannot disagree.
//!
//! [RFC 3279 section 2.2.3]: https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3
//! [RFC 5758 section 3.2]: https://www.rfc-editor.org/rfc/rfc5758#section-3.2
//! [RFC 8410 section 3]: https://www.rfc-editor.org/rfc/rfc8410#section-3

use baldssl_core::{
    Error, Result,
    der::syntax::{
        Any, Map, ObjectId, ObjectIdentifier, OptionalLast, RawTlv, Sequence,
    },
};
use baldssl_crypto::{hash::Algorithm as Hash, signature::SignatureAlgorithm};

use crate::oid::ID_ED25519;

/// `ecdsa-with-SHA1`, 1.2.840.10045.4.1.
const ECDSA_WITH_SHA1: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01]);
/// `ecdsa-with-SHA224`, 1.2.840.10045.4.3.1.
const ECDSA_WITH_SHA224: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01]);
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
const ECDSA_WITH_SHA256: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
/// `ecdsa-with-SHA384`, 1.2.840.10045.4.3.3.
const ECDSA_WITH_SHA384: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);
/// `ecdsa-with-SHA512`, 1.2.840.10045.4.3.4.
const ECDSA_WITH_SHA512: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]);

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
/// parameters ANY OPTIONAL }` ([RFC 5280 section 4.1.1.2]): of a
/// signature, or of a public key. The one model of the structure, for
/// certificates, requests and keys alike.
///
/// [RFC 5280 section 4.1.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlgorithmIdentifier {
    /// The algorithm.
    pub(crate) oid: ObjectId,
    /// The parameters, one TLV of any type, when present.
    pub(crate) parameters: Option<RawTlv>,
}

/// The fields of [`AlgorithmIdentifier`], as the description reads them.
type Fields = (ObjectId, (Option<RawTlv>, ()));

/// The description of [`AlgorithmIdentifier`].
pub(crate) type AlgorithmIdentifierSyntax = Map<
    Sequence<(ObjectIdentifier, (OptionalLast<Any>, ()))>,
    AlgorithmIdentifier,
>;

/// The description of [`AlgorithmIdentifier`]: the SEQUENCE, seen as the
/// struct. Every pair of fields is an identifier, so the law holds.
pub(crate) fn algorithm_identifier() -> AlgorithmIdentifierSyntax {
    Map::new(
        Sequence((ObjectIdentifier, (OptionalLast(Any), ()))),
        |(oid, (parameters, ())): Fields| {
            Some(AlgorithmIdentifier { oid, parameters })
        },
        |id| (id.oid.clone(), (id.parameters.clone(), ())),
    )
}

/// Every signature algorithm: ECDSA with each hash, and Ed25519. Not every
/// one has an identifier ([`oid_opt`]).
fn all() -> impl Iterator<Item = SignatureAlgorithm> {
    Hash::ALL
        .into_iter()
        .map(SignatureAlgorithm::Ecdsa)
        .chain([SignatureAlgorithm::Ed25519])
}

/// The object identifier of an algorithm, when it has one. ECDSA with
/// SHA-512/224 or SHA-512/256 has none: RFC 5758 section 3.2 names ECDSA
/// with SHA-224 to SHA-512 only, and OpenSSL refuses to sign a certificate
/// or a request with them, while `dgst` signs with them.
pub(crate) fn oid_opt(algorithm: SignatureAlgorithm) -> Option<ObjectId> {
    match algorithm {
        SignatureAlgorithm::Ecdsa(Hash::Sha1) => Some(ECDSA_WITH_SHA1),
        SignatureAlgorithm::Ecdsa(Hash::Sha224) => Some(ECDSA_WITH_SHA224),
        SignatureAlgorithm::Ecdsa(Hash::Sha256) => Some(ECDSA_WITH_SHA256),
        SignatureAlgorithm::Ecdsa(Hash::Sha384) => Some(ECDSA_WITH_SHA384),
        SignatureAlgorithm::Ecdsa(Hash::Sha512) => Some(ECDSA_WITH_SHA512),
        SignatureAlgorithm::Ecdsa(Hash::Sha512_224 | Hash::Sha512_256) => None,
        SignatureAlgorithm::Ed25519 => Some(ID_ED25519),
    }
}

/// The `AlgorithmIdentifier` of a signature algorithm: its OID, no
/// parameters.
///
/// # Errors
///
/// [`Error::Unsupported`] for an algorithm without one ([`oid_opt`]).
impl TryFrom<SignatureAlgorithm> for AlgorithmIdentifier {
    type Error = Error;

    fn try_from(algorithm: SignatureAlgorithm) -> Result<Self> {
        let oid = oid_opt(algorithm).ok_or_else(|| {
            Error::unsupported(format!(
                "signing a certificate or request with {algorithm:?}, which \
                 has no algorithm identifier"
            ))
        })?;
        Ok(AlgorithmIdentifier {
            oid,
            parameters: None,
        })
    }
}

/// The signature algorithm an `AlgorithmIdentifier` names; its parameters
/// must be absent. The inverse of the `From` above, found by searching the
/// finite set of algorithms, so the two cannot disagree.
///
/// # Errors
///
/// [`Error::Invalid`] for parameters, [`Error::Unsupported`] for any other
/// algorithm.
impl TryFrom<&AlgorithmIdentifier> for SignatureAlgorithm {
    type Error = Error;

    fn try_from(id: &AlgorithmIdentifier) -> Result<Self> {
        let Some(algorithm) =
            all().find(|&a| oid_opt(a) == Some(id.oid.clone()))
        else {
            return Err(Error::unsupported(format!(
                "signature algorithm {}",
                id.oid.to_dotted()?
            )));
        };
        if id.parameters.is_some() {
            return Err(Error::invalid(
                "signature algorithm: parameters must be absent",
            ));
        }
        Ok(algorithm)
    }
}

#[cfg(test)]
mod tests {
    use baldssl_core::der::syntax::{
        Null, decode, encode,
        laws::{canonical, round_trip},
    };

    use super::*;

    /// Reading an identifier inverts writing it, so the OIDs are distinct;
    /// the algorithms without one are exactly ECDSA with SHA-512/224 and
    /// SHA-512/256.
    #[test]
    fn identifiers_round_trip() {
        for a in all() {
            match AlgorithmIdentifier::try_from(a) {
                Ok(id) => {
                    assert_eq!(
                        SignatureAlgorithm::try_from(&id),
                        Ok(a),
                        "{a:?}"
                    );
                }
                Err(e) => {
                    assert!(matches!(e, Error::Unsupported(_)), "{a:?}");
                    assert!(
                        matches!(
                            a,
                            SignatureAlgorithm::Ecdsa(
                                Hash::Sha512_224 | Hash::Sha512_256
                            )
                        ),
                        "{a:?}"
                    );
                }
            }
        }
    }

    /// The description is canonical: it reads what it writes, with and
    /// without parameters, and rejects what is not one identifier.
    #[test]
    fn description() {
        let syntax = algorithm_identifier();
        let with_null = AlgorithmIdentifier {
            oid: ID_ED25519,
            parameters: Some(RawTlv::encode(&Null, &())),
        };
        for id in [
            AlgorithmIdentifier::try_from(SignatureAlgorithm::Ed25519).unwrap(),
            with_null,
        ] {
            round_trip(&syntax, &id, b"");
            canonical(&syntax, &encode(&syntax, &id));
        }
        // SEQUENCE { OID 1.3.101.112 }, as RFC 8410 writes Ed25519.
        assert_eq!(
            decode(&syntax, &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]),
            Ok(AlgorithmIdentifier::try_from(SignatureAlgorithm::Ed25519)
                .unwrap())
        );
        for bad in [
            // No algorithm.
            &[0x30, 0x00][..],
            // Two parameters.
            &[
                0x30, 0x09, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x05,
                0x00,
            ],
            // A SET, not a SEQUENCE.
            &[0x31, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70],
        ] {
            assert!(decode(&syntax, bad).is_err(), "{bad:02x?}");
        }
        assert!(
            SignatureAlgorithm::try_from(&AlgorithmIdentifier {
                oid: ID_ED25519,
                parameters: Some(RawTlv::encode(&Null, &())),
            })
            .is_err()
        );
    }

    /// The dotted names, from RFC 3279, RFC 5758 and RFC 8410.
    #[test]
    fn dotted_names() {
        let dotted = |a| oid_opt(a).unwrap().to_dotted().unwrap();
        assert_eq!(
            dotted(SignatureAlgorithm::Ecdsa(Hash::Sha1)),
            "1.2.840.10045.4.1"
        );
        assert_eq!(
            dotted(SignatureAlgorithm::Ecdsa(Hash::Sha256)),
            "1.2.840.10045.4.3.2"
        );
        assert_eq!(dotted(SignatureAlgorithm::Ed25519), "1.3.101.112");
    }
}
