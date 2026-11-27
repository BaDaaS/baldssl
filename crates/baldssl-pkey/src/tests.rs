//! PKCS#8 against the keys OpenSSL wrote, and key generation.

use baldssl_core::{
    Error,
    der::syntax::{ObjectId, decode, encode},
    encoding::{Decodable, Encodable},
    pem::{self, Pem},
};
use baldssl_test_utils::{fixture, hex};
use proptest::prelude::*;

use baldssl_crypto::{
    instances::{P256, P384, P521},
    signature::eddsa::Ed25519,
};

use super::{
    Algorithm, AnyPrivateKey, ED25519_KEY_LEN, KeyAlgorithm, PrivateKey,
    PrivateKeyDer, PublicKey, PublicKeyField, Signing, WithKeyAlgorithm,
};
use crate::asn1::{
    CURVE_PRIVATE_KEY, EC_PRIVATE_KEY, ID_EC_PUBLIC_KEY, ID_ED448, ID_ED25519,
    ID_RSASSA_PSS, ID_X448, ID_X25519, PRIME256V1, PRIVATE_KEY_INFO,
    RSA_ENCRYPTION, SECP384R1, SECP521R1,
};

fn algorithm_opt(name: &str) -> Option<Algorithm> {
    match name {
        "P-256" => Some(Algorithm::P256),
        "P-384" => Some(Algorithm::P384),
        "P-521" => Some(Algorithm::P521),
        "ED25519" => Some(Algorithm::Ed25519),
        _ => None,
    }
}

/// The scalar as OpenSSL printed it (possibly with a leading `00`), at the
/// full length of the group order.
fn secret(alg: Algorithm, printed: &str) -> Vec<u8> {
    let bytes = hex(printed);
    let skip = bytes.len().saturating_sub(alg.secret_len());
    let mut out = vec![0u8; alg.secret_len().saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// Same public key and byte-identical PKCS#8 for the sixteen keys OpenSSL
/// generated (`scripts/gen-ec-vectors.sh`).
#[test]
fn pkcs8_matches_openssl() {
    let mut seen = 0;
    for line in fixture("keys/keypairs.txt").lines() {
        let [name, private, public, der] =
            line.split_whitespace().collect::<Vec<_>>()[..]
        else {
            continue;
        };
        let Some(alg) = algorithm_opt(name) else {
            continue;
        };
        let key =
            AnyPrivateKey::from_secret(alg, &secret(alg, private)).unwrap();
        assert_eq!(key.algorithm(), alg);
        assert_eq!(key.public_key_bytes(), hex(public), "{name} public key");
        assert_eq!(key.encode(), hex(der), "{name} PKCS#8");
        records_round_trip(&key.encode());
        seen += 1;
    }
    assert_eq!(seen, 16);
}

/// For one algorithm, as a type: two generated keys differ, re-deriving
/// from the secret gives the same key, the encodings read back, and the
/// Debug output cannot contain the secret. Keys of another algorithm are
/// another type, so they cannot be compared here by mistake.
fn check_generated<A>()
where
    A: KeyAlgorithm,
{
    let a = PrivateKey::<A>::generate().unwrap();
    let b = PrivateKey::<A>::generate().unwrap();
    assert_ne!(a.public_key(), b.public_key(), "{:?}", A::ALGORITHM);
    let again = PrivateKey::<A>::from_secret(a.secret().expose()).unwrap();
    assert_eq!(again.public_key(), a.public_key());
    assert_eq!(again.encode(), a.encode());
    records_round_trip(&a.encode());
    assert!(a.to_pem().starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert_eq!(
        format!("{a:?}"),
        format!("PrivateKey {{ algorithm: {:?}, .. }}", A::ALGORITHM)
    );
}

#[test]
fn generated_keys_are_valid_and_distinct() {
    check_generated::<P256>();
    check_generated::<P384>();
    check_generated::<P521>();
    check_generated::<Ed25519>();
}

/// The run-time enum dispatches to the typed key of the algorithm named.
#[test]
fn any_private_key_dispatches() {
    for alg in Algorithm::ALL {
        let key = AnyPrivateKey::generate(alg).unwrap();
        assert_eq!(key.algorithm(), alg);
        let again =
            AnyPrivateKey::from_secret(alg, key.secret().expose()).unwrap();
        assert_eq!(again.encode(), key.encode());
        assert_eq!(again.public_key_bytes(), key.public_key_bytes());
        assert_eq!(
            format!("{key:?}"),
            format!("PrivateKey {{ algorithm: {alg:?}, .. }}")
        );
    }
}

/// [`AnyPrivateKey::der`] writes PKCS#8 for [`PrivateKeyDer::Pkcs8`], and
/// for [`PrivateKeyDer::Traditional`] the traditional form where the
/// algorithm has one and PKCS#8 where it has none; in both forms the key
/// decodes back to itself.
#[test]
fn der_forms() {
    for alg in Algorithm::ALL {
        let key = AnyPrivateKey::generate(alg).unwrap();
        let pkcs8 = key.der(PrivateKeyDer::Pkcs8);
        assert_eq!(pkcs8.expose(), key.pkcs8().expose());
        let traditional = key.der(PrivateKeyDer::Traditional);
        let expected = key.traditional_opt().unwrap_or_else(|| key.pkcs8());
        assert_eq!(traditional.expose(), expected.expose());
        match alg {
            Algorithm::P256 | Algorithm::P384 | Algorithm::P521 => {
                assert_ne!(traditional.expose(), pkcs8.expose());
            }
            Algorithm::Ed25519 => {
                assert_eq!(traditional.expose(), pkcs8.expose());
            }
        }
        for der in [pkcs8, traditional] {
            let back = AnyPrivateKey::decode(der.expose()).unwrap();
            assert_eq!(back.secret().expose(), key.secret().expose());
        }
    }
}

/// Each invalid secret is refused with the error of its rule.
#[test]
fn invalid_secrets() {
    let range = Some(Error::invalid("private scalar not in [1, n - 1]"));
    let length = Some(Error::invalid("private key length"));
    assert_eq!(PrivateKey::<P256>::from_secret(&[0u8; 32]).err(), range);
    assert_eq!(PrivateKey::<P256>::from_secret(&[0xffu8; 32]).err(), range);
    assert_eq!(PrivateKey::<P256>::from_secret(&[1u8; 31]).err(), length);
    assert_eq!(PrivateKey::<P256>::from_secret(&[1u8; 33]).err(), length);
    assert_eq!(PrivateKey::<Ed25519>::from_secret(&[1u8; 31]).err(), length);
    assert_eq!(
        AnyPrivateKey::from_secret(Algorithm::P384, &[0u8; 48]).err(),
        range
    );
    let mut one = vec![0u8; 66];
    one[65] = 1;
    assert!(PrivateKey::<P521>::from_secret(&one).is_ok(), "d = 1");
}

/// The PKCS#8 written reads back, with the descriptions, to records that
/// write the same bytes: the outer PrivateKeyInfo, and the ECPrivateKey or
/// CurvePrivateKey inside it.
fn records_round_trip(der: &[u8]) {
    let (version, ((oid, (params, ())), (inner, ()))) =
        decode(&PRIVATE_KEY_INFO, der).expect("PrivateKeyInfo");
    assert_eq!(version, 0);
    let record = (
        version,
        ((oid.clone(), (params.clone(), ())), (inner.clone(), ())),
    );
    assert_eq!(encode(&PRIVATE_KEY_INFO, &record), der);
    if oid == ID_EC_PUBLIC_KEY {
        let ec = decode(&EC_PRIVATE_KEY, &inner).expect("ECPrivateKey");
        assert_eq!(ec.0, 1, "ECPrivateKey version");
        assert!(ec.1.1.0.is_none(), "no [0] parameters");
        assert!(ec.1.1.1.0.is_some(), "[1] public key");
        assert_eq!(encode(&EC_PRIVATE_KEY, &ec), inner);
    } else {
        assert_eq!(oid, ID_ED25519);
        assert!(params.is_none(), "Ed25519 has no parameters");
        let seed = decode(&CURVE_PRIVATE_KEY, &inner).expect("CurvePrivateKey");
        assert_eq!(seed.len(), 32);
    }
}

/// The identifiers, written as contents octets, are the ones their dotted
/// forms name.
#[test]
fn object_identifiers() {
    for (id, dotted) in [
        (ID_EC_PUBLIC_KEY, "1.2.840.10045.2.1"),
        (ID_ED25519, "1.3.101.112"),
        (PRIME256V1, "1.2.840.10045.3.1.7"),
        (SECP384R1, "1.3.132.0.34"),
        (SECP521R1, "1.3.132.0.35"),
        (RSA_ENCRYPTION, "1.2.840.113549.1.1.1"),
        (ID_RSASSA_PSS, "1.2.840.113549.1.1.10"),
        (ID_X25519, "1.3.101.110"),
        (ID_X448, "1.3.101.111"),
        (ID_ED448, "1.3.101.113"),
    ] {
        assert_eq!(Some(id), ObjectId::from_dotted_opt(dotted), "{dotted}");
    }
}

/// Names parse as OpenSSL spells them, in any case; `secp256r1` does not.
#[test]
fn algorithm_names() {
    for (name, algorithm) in [
        ("P-256", Algorithm::P256),
        ("prime256v1", Algorithm::P256),
        ("PRIME256V1", Algorithm::P256),
        ("p-384", Algorithm::P384),
        ("secp384r1", Algorithm::P384),
        ("P-521", Algorithm::P521),
        ("secp521r1", Algorithm::P521),
        ("ED25519", Algorithm::Ed25519),
        ("ed25519", Algorithm::Ed25519),
    ] {
        assert_eq!(name.parse::<Algorithm>().unwrap(), algorithm, "{name}");
    }
    for name in ["secp256r1", "P256", "ec", ""] {
        assert!(matches!(
            name.parse::<Algorithm>(),
            Err(Error::Unsupported(_))
        ));
    }
}

/// The algorithm a type is, through the eliminator: `a.with(Name) == a` for
/// every `a` is the law that the eliminator picks the type `a` names.
struct Name;

impl WithKeyAlgorithm for Name {
    type Output = Algorithm;

    fn run<A>(self) -> Algorithm
    where
        A: Signing,
    {
        A::ALGORITHM
    }
}

#[test]
fn the_eliminator_names_its_type() {
    for alg in Algorithm::ALL {
        assert_eq!(alg.with(Name), alg);
    }
}

/// The run-time key and the typed key of one secret agree on every
/// operation: the dispatch of [`AnyPrivateKey`] and [`PublicKey`] is the
/// typed path. `None` when the secret is not a key.
struct Agrees<'a>(&'a [u8]);

impl WithKeyAlgorithm for Agrees<'_> {
    type Output = Option<()>;

    fn run<A>(self) -> Self::Output
    where
        A: Signing,
    {
        let typed = PrivateKey::<A>::from_secret(self.0).ok()?;
        let any = AnyPrivateKey::from_secret(A::ALGORITHM, self.0).unwrap();
        assert_eq!(any.algorithm(), A::ALGORITHM);
        assert_eq!(
            any.traditional_opt().map(|t| t.expose().to_vec()),
            A::traditional_opt(typed.key_pair(), typed.public_key_field())
                .map(|t| t.expose().to_vec())
        );
        assert_eq!(any.pkcs8().expose(), typed.pkcs8().expose());
        assert_eq!(any.public_key_field(), typed.public_key_field());
        assert_eq!(any.encode(), typed.encode());
        assert_eq!(any.secret().expose(), typed.secret().expose());
        assert_eq!(any.public_key_bytes(), typed.public_key_bytes());
        assert_eq!(
            PublicKey::from(&any),
            A::public_into_any(A::subject_public_key(typed.key_pair()))
        );
        assert_eq!(
            PublicKey::from(&any).public_key_bytes(),
            typed.public_key_bytes()
        );
        assert_eq!(PublicKey::from(&any).algorithm(), A::ALGORITHM);
        assert_eq!(any.default_signature_algorithm(), A::algorithm(A::DEFAULT));
        assert_eq!(
            any.sign(A::algorithm(A::DEFAULT), b"m").unwrap(),
            typed.sign(A::DEFAULT, b"m").unwrap()
        );
        Some(())
    }
}

/// The laws of [`KeyAlgorithm`], for one algorithm and one secret: `None`
/// when the secret is not a key.
struct Laws<'a>(&'a [u8]);

impl WithKeyAlgorithm for Laws<'_> {
    type Output = Option<()>;

    fn run<A>(self) -> Self::Output
    where
        A: Signing,
    {
        let pair = A::from_secret(self.0).ok()?;
        // from_secret(secret(p)) is p.
        let again = A::from_secret(A::secret(&pair).expose()).unwrap();
        assert_eq!(A::secret(&again).expose(), A::secret(&pair).expose());
        assert_eq!(A::public_key(&again), A::public_key(&pair));
        assert_eq!(A::secret(&pair).expose(), self.0);
        // pkcs8 decodes, and re-encodes to the same bytes, its public key
        // written or not; the public key is the secret's either way.
        let pkcs8 = A::pkcs8(&pair, PublicKeyField::Included);
        records_round_trip(pkcs8.expose());
        for field in [PublicKeyField::Included, PublicKeyField::Omitted] {
            let pkcs8 = A::pkcs8(&pair, field);
            let read = AnyPrivateKey::decode(pkcs8.expose()).unwrap();
            assert_eq!(read.algorithm(), A::ALGORITHM);
            assert_eq!(
                PublicKey::from(&read),
                A::public_into_any(A::subject_public_key(&pair))
            );
            assert_eq!(read.pkcs8().expose(), pkcs8.expose());
            // traditional_opt round-trips through SEC 1, in DER and in PEM,
            // to the key whose PKCS#8 is pkcs8.
            if let Some(sec1) = A::traditional_opt(&pair, field) {
                let from_der = AnyPrivateKey::decode(sec1.expose()).unwrap();
                assert_eq!(from_der.public_key_field(), field);
                assert_eq!(from_der.pkcs8().expose(), pkcs8.expose());
                assert_eq!(
                    from_der.traditional_opt().map(|t| t.expose().to_vec()),
                    Some(sec1.expose().to_vec())
                );
                let block = pem::encode("EC PRIVATE KEY", sec1.expose());
                let from_pem =
                    AnyPrivateKey::from_pem(block.as_bytes()).unwrap();
                assert_eq!(from_pem.pkcs8().expose(), pkcs8.expose());
            }
        }
        // The key a SubjectPublicKeyInfo holds reads back to itself.
        let public = A::subject_public_key(&pair);
        assert_eq!(A::read_public(&public.encode()).unwrap(), public);
        Some(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// The laws of `KeyAlgorithm` and the dispatch, for every algorithm,
    /// over secrets: the first bytes of `bytes`, as many as the algorithm
    /// takes.
    #[test]
    fn key_algorithm_laws(bytes in prop::collection::vec(any::<u8>(), 66)) {
        for alg in Algorithm::ALL {
            let secret = &bytes[..alg.secret_len()];
            let laws = alg.with(Laws(secret));
            prop_assert_eq!(laws, alg.with(Agrees(secret)));
        }
    }
}

/// Every Ed25519 public key a typed key gives is `ED25519_KEY_LEN` bytes,
/// which [`crate::Ed25519PublicKey`]'s conversion from it relies on.
#[test]
fn ed25519_public_keys_are_32_bytes() {
    for seed in 0..=u8::MAX {
        let key = PrivateKey::<Ed25519>::from_secret(&[seed; 32]).unwrap();
        assert_eq!(key.public_key().as_bytes().len(), ED25519_KEY_LEN);
        assert_eq!(key.public_key_bytes().len(), ED25519_KEY_LEN);
    }
}
