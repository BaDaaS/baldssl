//! The X.509 names of the signature algorithms: the `AlgorithmIdentifier`
//! of each [`SignatureAlgorithm`], with absent parameters: ECDSA with a
//! SHA hash ([RFC 3279 section 2.2.3], [RFC 5758 section 3.2]) and Ed25519
//! ([RFC 8410 section 3]).
//!
//! [`identifier`] is an exhaustive `match`, so every algorithm has a name
//! by construction; [`from_identifier`] is its inverse, found by searching
//! the finite set of algorithms, so the two cannot disagree.
//!
//! [RFC 3279 section 2.2.3]: https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3
//! [RFC 5758 section 3.2]: https://www.rfc-editor.org/rfc/rfc5758#section-3.2
//! [RFC 8410 section 3]: https://www.rfc-editor.org/rfc/rfc8410#section-3

use baldssl_core::{
    Error, Result,
    der::syntax::{
        Any, ObjectId, ObjectIdentifier, OptionalLast, RawTlv, Sequence,
    },
};
use baldssl_crypto::{hash::Algorithm as Hash, signature::SignatureAlgorithm};

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
/// `id-Ed25519`, 1.3.101.112.
const ID_ED25519: ObjectId = ObjectId::from_static(&[0x2b, 0x65, 0x70]);

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
/// parameters ANY OPTIONAL }`.
pub(crate) type AlgorithmIdentifier =
    Sequence<(ObjectIdentifier, (OptionalLast<Any>, ()))>;

/// The description of [`AlgorithmIdentifier`].
pub(crate) const ALGORITHM_IDENTIFIER: AlgorithmIdentifier =
    Sequence((ObjectIdentifier, (OptionalLast(Any), ())));

/// An `AlgorithmIdentifier`'s value: the OID and the parameters.
pub(crate) type Identifier = (ObjectId, (Option<RawTlv>, ()));

/// Every signature algorithm: ECDSA with each hash, and Ed25519.
fn all() -> impl Iterator<Item = SignatureAlgorithm> {
    Hash::ALL
        .into_iter()
        .map(SignatureAlgorithm::Ecdsa)
        .chain([SignatureAlgorithm::Ed25519])
}

/// The object identifier of an algorithm.
pub(crate) fn oid(algorithm: SignatureAlgorithm) -> ObjectId {
    match algorithm {
        SignatureAlgorithm::Ecdsa(Hash::Sha1) => ECDSA_WITH_SHA1,
        SignatureAlgorithm::Ecdsa(Hash::Sha224) => ECDSA_WITH_SHA224,
        SignatureAlgorithm::Ecdsa(Hash::Sha256) => ECDSA_WITH_SHA256,
        SignatureAlgorithm::Ecdsa(Hash::Sha384) => ECDSA_WITH_SHA384,
        SignatureAlgorithm::Ecdsa(Hash::Sha512) => ECDSA_WITH_SHA512,
        SignatureAlgorithm::Ed25519 => ID_ED25519,
    }
}

/// The `AlgorithmIdentifier` of an algorithm: its OID, no parameters.
pub(crate) fn identifier(algorithm: SignatureAlgorithm) -> Identifier {
    (oid(algorithm), (None, ()))
}

/// The algorithm an `AlgorithmIdentifier` names; its parameters must be
/// absent.
///
/// # Errors
///
/// [`Error::Invalid`] for parameters, [`Error::Unsupported`] for any other
/// algorithm.
pub(crate) fn from_identifier(
    (id, (params, ())): &Identifier,
) -> Result<SignatureAlgorithm> {
    let algorithm = all().find(|&a| oid(a) == *id).ok_or_else(|| {
        Error::unsupported(format!(
            "signature algorithm {}",
            id.to_dotted().unwrap_or_default()
        ))
    })?;
    if params.is_some() {
        return Err(Error::invalid(
            "signature algorithm: parameters must be absent",
        ));
    }
    Ok(algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `from_identifier` inverts `identifier`, so the OIDs are distinct.
    #[test]
    fn identifiers_round_trip() {
        for a in all() {
            assert_eq!(from_identifier(&identifier(a)), Ok(a), "{a:?}");
        }
    }

    /// The dotted names, from RFC 3279, RFC 5758 and RFC 8410.
    #[test]
    fn dotted_names() {
        let dotted = |a| oid(a).to_dotted().unwrap();
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
