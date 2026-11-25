//! Reading keys: every encoding OpenSSL writes, round trips, and each
//! rejection rule of the module documentation.

use baldssl_core::{
    Error,
    der::{
        syntax::{ObjectIdentifier, RawTlv, decode},
        tag, write,
    },
    encoding::{Decodable, Encodable},
    pem::{self, Pem, PemBlock},
};
use baldssl_test_utils::{fixture, hex};
use proptest::prelude::*;

use baldssl_crypto::models::weierstrass::COMPRESSED_EVEN;

use crate::{
    Algorithm, AnyPrivateKey, PublicKey,
    asn1::{PRIVATE_KEY_INFO, SubjectPublicKeyInfo},
};

/// `id-ecPublicKey` and `id-Ed25519`, dotted: the hand-built encodings
/// below name them independently of the constants under test.
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const ID_ED25519: &str = "1.3.101.112";

fn algorithm(name: &str) -> Algorithm {
    match name {
        "P-256" => Algorithm::P256,
        "P-384" => Algorithm::P384,
        "P-521" => Algorithm::P521,
        "ED25519" => Algorithm::Ed25519,
        other => panic!("unknown curve {other}"),
    }
}

/// `-` marks a format that does not apply.
fn optional_opt(s: &str) -> Option<Vec<u8>> {
    (s != "-").then(|| hex(s))
}

/// Every encoding of `tests/fixtures/keys/encodings.txt`
/// (`scripts/gen-key-encodings.sh`, OpenSSL 3.5 and 4.1 agree) reads back
/// to the same key, and the PKCS#8 one re-encodes byte for byte.
#[test]
fn reads_every_openssl_encoding() {
    let mut seen = 0;
    for line in fixture("keys/encodings.txt").lines() {
        if line.starts_with('#') {
            continue;
        }
        let [name, pkcs8, sec1, sec1_nopub, spki, spki_compressed] =
            line.split_whitespace().collect::<Vec<_>>()[..]
        else {
            panic!("bad line {line}");
        };
        let alg = algorithm(name);
        let pkcs8 = hex(pkcs8);
        let key = AnyPrivateKey::decode(&pkcs8).unwrap();
        assert_eq!(key.algorithm(), alg);
        assert_eq!(key.encode(), pkcs8, "{name}: PKCS#8 round trip");
        let pem_key = AnyPrivateKey::from_pem(
            pem::encode("PRIVATE KEY", &pkcs8).as_bytes(),
        )
        .unwrap();
        assert_eq!(pem_key.encode(), pkcs8, "{name}: PEM");

        for sec1 in [optional_opt(sec1), optional_opt(sec1_nopub)]
            .into_iter()
            .flatten()
        {
            let from_der = AnyPrivateKey::decode(&sec1).unwrap();
            assert_eq!(from_der.encode(), pkcs8, "{name}: SEC 1");
            let pem = pem::encode("EC PRIVATE KEY", &sec1);
            let from_pem = AnyPrivateKey::from_pem(pem.as_bytes()).unwrap();
            assert_eq!(from_pem.encode(), pkcs8, "{name}: SEC 1 PEM");
        }

        // The writer, from the same description as the reader: OpenSSL's
        // uncompressed SubjectPublicKeyInfo byte for byte, also from a
        // compressed input.
        let uncompressed = hex(spki);
        for spki in [Some(uncompressed.clone()), optional_opt(spki_compressed)]
            .into_iter()
            .flatten()
        {
            let public = PublicKey::decode(&spki).unwrap();
            assert_eq!(public.encode(), uncompressed, "{name}: SPKI writer");
            assert_eq!(public.algorithm(), alg);
            assert_eq!(
                public.public_key_bytes(),
                key.public_key_bytes(),
                "{name}: SPKI"
            );
            let pem = pem::encode("PUBLIC KEY", &spki);
            assert_eq!(PublicKey::from_pem(pem.as_bytes()).unwrap(), public);
        }
        seen += 1;
    }
    assert_eq!(seen, 16);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Reading what baldssl writes gives the same key, in DER and PEM.
    #[test]
    fn round_trip(index in 0usize..4, bytes in prop::collection::vec(any::<u8>(), 66)) {
        let alg = Algorithm::ALL[index];
        let Ok(key) = AnyPrivateKey::from_secret(alg, &bytes[..alg.secret_len()]) else {
            return Ok(());
        };
        let der = key.encode();
        prop_assert_eq!(AnyPrivateKey::decode(&der).unwrap().encode(), der.clone());
        let from_pem = AnyPrivateKey::from_pem(key.to_pem().as_bytes()).unwrap();
        prop_assert_eq!(from_pem.encode(), der);
    }
}

// --- Rejections ------------------------------------------------------------

const P256: &str = "1.2.840.10045.3.1.7";
const P384: &str = "1.3.132.0.34";
/// The order n of P-256.
const N_P256: &str =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// One TLV, for the elements the DER writer has no function for (an
/// IMPLICIT `[1]` BIT STRING, NULL).
fn tlv(tag: u8, contents: &[u8]) -> RawTlv {
    RawTlv::from_tag_and_contents(tag, contents)
}

fn oid(dotted: &str) -> RawTlv {
    write::oid_opt(dotted).unwrap()
}

/// An `ECPrivateKey` with the given parts.
fn ec_private_key(
    version: u64,
    d: &[u8],
    params: Option<RawTlv>,
    public: Option<&[u8]>,
) -> RawTlv {
    let mut parts = vec![write::small_integer(version), write::octet_string(d)];
    if let Some(params) = params {
        parts.push(write::context_constructed(0, &[params]));
    }
    if let Some(public) = public {
        parts.push(write::context_constructed(1, &[write::bit_string(public)]));
    }
    write::sequence(&parts)
}

/// A PKCS#8 EC key on `curve` around `inner`.
fn ec_pkcs8(curve: &str, inner: &RawTlv) -> RawTlv {
    write::sequence(&[
        write::small_integer(0),
        write::sequence(&[oid(ID_EC_PUBLIC_KEY), oid(curve)]),
        write::octet_string(inner.as_bytes()),
    ])
}

/// d = 1 on P-256 at full length, and its public key G.
fn one() -> (Vec<u8>, Vec<u8>) {
    let mut d = vec![0u8; 32];
    d[31] = 1;
    let g = AnyPrivateKey::from_secret(Algorithm::P256, &d)
        .unwrap()
        .public_key_bytes();
    (d, g)
}

/// SEC 1 compressed form of an uncompressed point.
fn compressed(point: &[u8]) -> Vec<u8> {
    let len = (point.len() - 1) / 2;
    let mut out = vec![COMPRESSED_EVEN | (point[2 * len] & 1)];
    out.extend_from_slice(&point[1..=len]);
    out
}

fn invalid(r: &Result<AnyPrivateKey, Error>) -> bool {
    matches!(r, Err(Error::Invalid(_)))
}

fn unsupported<T>(r: &Result<T, Error>, what: &str) -> bool
where
    T: core::fmt::Debug,
{
    matches!(r, Err(Error::Unsupported(m)) if m.contains(what))
}

/// The scalar must be in [1, n - 1]; its OCTET STRING may be shorter or
/// longer than the order, as OpenSSL reads it.
#[test]
fn scalar_range_and_length() {
    let (d, g) = one();
    let p8 = |d: &[u8]| ec_pkcs8(P256, &ec_private_key(1, d, None, None));
    assert!(
        invalid(&AnyPrivateKey::decode(p8(&[0u8; 32]).as_bytes())),
        "d = 0"
    );
    assert!(
        invalid(&AnyPrivateKey::decode(p8(&hex(N_P256)).as_bytes())),
        "d = n"
    );
    assert!(
        invalid(&AnyPrivateKey::decode(p8(&[1u8; 33]).as_bytes())),
        "too long"
    );
    assert!(invalid(&AnyPrivateKey::decode(p8(&[]).as_bytes())), "empty");
    for short_or_long in [vec![1u8], [&[0u8][..], &d].concat()] {
        let key = AnyPrivateKey::decode(p8(&short_or_long).as_bytes()).unwrap();
        assert_eq!(key.public_key_bytes(), g);
        assert_eq!(
            key.encode(),
            ec_pkcs8(P256, &ec_private_key(1, &d, None, Some(&g))).as_bytes()
        );
    }
}

/// The embedded public key must be the private key's, in either SEC 1 form.
#[test]
fn embedded_public_key() {
    let (d, g) = one();
    let with = |public: &[u8]| {
        ec_pkcs8(P256, &ec_private_key(1, &d, None, Some(public)))
    };
    assert!(AnyPrivateKey::decode(with(&g).as_bytes()).is_ok());
    assert!(
        AnyPrivateKey::decode(with(&compressed(&g)).as_bytes()).is_ok(),
        "compressed"
    );
    let other = AnyPrivateKey::generate(Algorithm::P256).unwrap();
    assert!(
        invalid(&AnyPrivateKey::decode(
            with(&other.public_key_bytes()).as_bytes()
        )),
        "mismatch"
    );
    let mut off = g.clone();
    *off.last_mut().unwrap() ^= 1;
    assert!(
        invalid(&AnyPrivateKey::decode(with(&off).as_bytes())),
        "off the curve"
    );
    assert!(
        invalid(&AnyPrivateKey::decode(with(&[0x00]).as_bytes())),
        "identity"
    );
}

/// The curve: named in PKCS#8, in `[0]`, or both, but then the same.
#[test]
fn curve_parameters() {
    let (d, _) = one();
    let named = |c: &str| Some(oid(c));
    let mismatch = ec_pkcs8(P256, &ec_private_key(1, &d, named(P384), None));
    assert!(
        invalid(&AnyPrivateKey::decode(mismatch.as_bytes())),
        "two curves"
    );
    let same = ec_pkcs8(P256, &ec_private_key(1, &d, named(P256), None));
    assert!(AnyPrivateKey::decode(same.as_bytes()).is_ok());

    let standalone = ec_private_key(1, &d, named(P256), None);
    assert_eq!(
        AnyPrivateKey::decode(standalone.as_bytes())
            .unwrap()
            .algorithm(),
        Algorithm::P256
    );
    let no_curve = ec_private_key(1, &d, None, None);
    assert!(
        invalid(&AnyPrivateKey::decode(no_curve.as_bytes())),
        "no curve"
    );
    let explicit = ec_private_key(
        1,
        &d,
        Some(write::sequence(&[write::small_integer(1)])),
        None,
    );
    assert!(unsupported(
        &AnyPrivateKey::decode(explicit.as_bytes()),
        "explicit"
    ));
    let unknown_curve = ec_pkcs8("1.2.3.4", &ec_private_key(1, &d, None, None));
    assert!(unsupported(
        &AnyPrivateKey::decode(unknown_curve.as_bytes()),
        "EC curve"
    ));
}

#[test]
fn versions() {
    let (d, g) = one();
    assert!(invalid(&AnyPrivateKey::decode(
        ec_private_key(2, &d, Some(oid(P256)), None).as_bytes()
    )));
    let v2 = write::sequence(&[
        write::small_integer(2),
        write::sequence(&[oid(ID_EC_PUBLIC_KEY), oid(P256)]),
        write::octet_string(ec_private_key(1, &d, None, None).as_bytes()),
    ]);
    assert!(
        invalid(&AnyPrivateKey::decode(v2.as_bytes())),
        "PKCS#8 version 2"
    );
    // A [1] public key needs OneAsymmetricKey version 1 (RFC 5958).
    let v0_with_public = write::sequence(&[
        write::small_integer(0),
        write::sequence(&[oid(ID_EC_PUBLIC_KEY), oid(P256)]),
        write::octet_string(ec_private_key(1, &d, None, None).as_bytes()),
        tlv(tag::context(1), &[&[0u8][..], &g].concat()),
    ]);
    assert!(invalid(&AnyPrivateKey::decode(v0_with_public.as_bytes())));
}

/// Ed25519 (RFC 8410): no parameters, a 32-byte seed, and in version 1
/// an optional public key that must be the seed's.
#[test]
fn ed25519_rules() {
    let seed = [7u8; 32];
    let key = AnyPrivateKey::from_secret(Algorithm::Ed25519, &seed).unwrap();
    let p8 = |version: u64, alg: RawTlv, seed: &[u8], public: Option<&[u8]>| {
        let mut parts = vec![
            write::small_integer(version),
            alg,
            write::octet_string(write::octet_string(seed).as_bytes()),
        ];
        if let Some(public) = public {
            parts.push(tlv(tag::context(1), &[&[0u8][..], public].concat()));
        }
        write::sequence(&parts)
    };
    let alg = || write::sequence(&[oid(ID_ED25519)]);
    assert_eq!(
        AnyPrivateKey::decode(p8(0, alg(), &seed, None).as_bytes())
            .unwrap()
            .encode(),
        key.encode()
    );
    assert!(
        AnyPrivateKey::decode(
            p8(1, alg(), &seed, Some(&key.public_key_bytes())).as_bytes()
        )
        .is_ok()
    );
    assert!(invalid(&AnyPrivateKey::decode(
        p8(1, alg(), &seed, Some(&[0u8; 32])).as_bytes()
    )));
    assert!(invalid(&AnyPrivateKey::decode(
        p8(0, alg(), &seed[..31], None).as_bytes()
    )));
    let with_null = write::sequence(&[oid(ID_ED25519), tlv(tag::NULL, &[])]);
    assert!(invalid(&AnyPrivateKey::decode(
        p8(0, with_null, &seed, None).as_bytes()
    )));
}

#[test]
fn other_algorithms_are_unsupported() {
    for (dotted, name) in [
        ("1.2.840.113549.1.1.1", "RSA"),
        ("1.3.101.110", "X25519"),
        ("1.3.101.113", "Ed448"),
        ("1.2.3.4", "1.2.3.4"),
    ] {
        let p8 = write::sequence(&[
            write::small_integer(0),
            write::sequence(&[oid(dotted)]),
            write::octet_string(&[0; 4]),
        ]);
        assert!(
            unsupported(&AnyPrivateKey::decode(p8.as_bytes()), name),
            "{name}"
        );
        let spki = write::sequence(&[
            write::sequence(&[oid(dotted)]),
            write::bit_string(&[0; 4]),
        ]);
        assert!(
            unsupported(&PublicKey::decode(spki.as_bytes()), name),
            "{name}"
        );
    }
}

#[test]
fn framing() {
    let key = AnyPrivateKey::generate(Algorithm::P256).unwrap();
    let mut trailing = key.encode();
    trailing.push(0);
    assert!(matches!(
        AnyPrivateKey::decode(&trailing),
        Err(Error::Der(_))
    ));
    let encrypted = pem::encode("ENCRYPTED PRIVATE KEY", &[0x30, 0x00]);
    assert!(unsupported(
        &AnyPrivateKey::from_pem(encrypted.as_bytes()),
        "encrypted"
    ));
    let legacy = "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
         DEK-Info: AES-128-CBC,00\n\nAAAA\n-----END EC PRIVATE KEY-----\n";
    assert!(unsupported(
        &AnyPrivateKey::from_pem(legacy.as_bytes()),
        "encrypted"
    ));
    assert!(matches!(
        AnyPrivateKey::from_pem(b"no key"),
        Err(Error::Pem(_))
    ));
    assert!(matches!(PublicKey::from_pem(b"no key"), Err(Error::Pem(_))));
}

#[test]
fn public_key_rules() {
    let (_, g) = one();
    let spki = |key: &[u8]| {
        write::sequence(&[
            write::sequence(&[oid(ID_EC_PUBLIC_KEY), oid(P256)]),
            write::bit_string(key),
        ])
    };
    assert_eq!(
        PublicKey::decode(spki(&g).as_bytes())
            .unwrap()
            .public_key_bytes(),
        g
    );
    assert_eq!(
        PublicKey::decode(spki(&compressed(&g)).as_bytes())
            .unwrap()
            .public_key_bytes(),
        g
    );
    let mut off = g.clone();
    *off.last_mut().unwrap() ^= 1;
    for bad in [off, vec![0x00], g[..g.len() - 1].to_vec()] {
        assert!(matches!(
            PublicKey::decode(spki(&bad).as_bytes()),
            Err(Error::Invalid(_))
        ));
    }
    let ed = |key: &[u8]| {
        write::sequence(&[
            write::sequence(&[oid(ID_ED25519)]),
            write::bit_string(key),
        ])
    };
    // Any 32 bytes, as OpenSSL: the point is not decoded.
    assert!(PublicKey::decode(ed(&[0xff; 32]).as_bytes()).is_ok());
    assert!(matches!(
        PublicKey::decode(ed(&[1; 31]).as_bytes()),
        Err(Error::Invalid(_))
    ));
}

/// A PEM block becomes a key only under its own label: a public key from
/// `PUBLIC KEY`, a private key from `PRIVATE KEY` (as PKCS#8) or
/// `EC PRIVATE KEY` (as SEC 1), each with the exact error otherwise.
#[test]
fn pem_blocks() {
    let key = AnyPrivateKey::generate(Algorithm::P256).unwrap();
    let pkcs8 = key.encode();
    let public = PublicKey::decode(spki_of(&key).as_bytes()).unwrap();
    let block = |label: &str, contents: &[u8]| PemBlock {
        label: label.to_owned(),
        contents: contents.to_vec(),
    };

    assert_eq!(
        PublicKey::try_from(&block("PUBLIC KEY", &public.encode())),
        Ok(public.clone())
    );
    assert_eq!(
        PublicKey::try_from(&block("CERTIFICATE", &public.encode())),
        Err(Error::invalid(
            "PEM: CERTIFICATE where PUBLIC KEY was expected"
        ))
    );
    assert_eq!(
        AnyPrivateKey::try_from(&block("PRIVATE KEY", &pkcs8))
            .map(|k| k.encode()),
        Ok(pkcs8.clone())
    );
    assert_eq!(
        AnyPrivateKey::try_from(&block("PUBLIC KEY", &pkcs8)).err(),
        Some(Error::invalid(
            "PEM: PUBLIC KEY where a private key was expected"
        ))
    );
    assert_eq!(
        AnyPrivateKey::try_from(&block("ENCRYPTED PRIVATE KEY", &pkcs8)).err(),
        Some(Error::unsupported(
            "encrypted private keys (ENCRYPTED PRIVATE KEY)"
        ))
    );
    // The label decides the structure: PKCS#8 under `EC PRIVATE KEY` is not
    // read, although `decode` alone, which tells the two apart by their
    // structure, accepts it.
    assert!(AnyPrivateKey::decode(&pkcs8).is_ok());
    assert!(AnyPrivateKey::try_from(&block("EC PRIVATE KEY", &pkcs8)).is_err());
}

/// A public key and its SubjectPublicKeyInfo record convert into each
/// other, and the record re-encodes to the bytes it was read from.
#[test]
fn public_key_records() {
    for alg in Algorithm::ALL {
        let spki = spki_of(&AnyPrivateKey::generate(alg).unwrap());
        let record = SubjectPublicKeyInfo::decode(spki.as_bytes()).unwrap();
        assert_eq!(record.encode(), spki.as_bytes(), "{alg:?}: record");
        let public = PublicKey::try_from(record.clone()).unwrap();
        assert_eq!(SubjectPublicKeyInfo::from(&public), record, "{alg:?}");
        assert_eq!(public.encode(), spki.as_bytes(), "{alg:?}: key");
    }
}

/// The SubjectPublicKeyInfo OpenSSL writes for `key`.
fn spki_of(key: &AnyPrivateKey) -> RawTlv {
    let point = key.public_key_bytes();
    let algorithm = match key.algorithm().curve_oid_opt() {
        Some(curve) => write::sequence(&[
            write::oid_opt(ID_EC_PUBLIC_KEY).unwrap(),
            RawTlv::encode(&ObjectIdentifier, &curve),
        ]),
        None => write::sequence(&[write::oid_opt(ID_ED25519).unwrap()]),
    };
    write::sequence(&[algorithm, write::bit_string(&point)])
}

/// Where the lenient reader of private keys accepts more than the writer
/// writes: each input reads to a key and re-encodes to the one record the
/// writer writes for it, which differs from the input. The first two are
/// not even a `PrivateKeyInfo` as its description reads it.
#[test]
fn the_reader_is_lenient() {
    let (d, g) = one();
    let algorithm = || write::sequence(&[oid(ID_EC_PUBLIC_KEY), oid(P256)]);
    let ec = ec_private_key(1, &d, None, Some(&g));
    let canonical = ec_pkcs8(P256, &ec);
    // Two attributes out of the order of a DER SET OF: skipped unread.
    let with_attributes = write::sequence(&[
        write::small_integer(0),
        algorithm(),
        write::octet_string(ec.as_bytes()),
        write::context_constructed(
            0,
            &[
                write::sequence(&[oid("1.2.3.5")]),
                write::sequence(&[oid("1.2.3.4")]),
            ],
        ),
    ]);
    let v2_with_public = write::sequence(&[
        write::small_integer(1),
        algorithm(),
        write::octet_string(ec.as_bytes()),
        tlv(tag::context(1), &[&[0u8][..], &g].concat()),
    ]);
    for input in [&with_attributes, &v2_with_public] {
        assert!(decode(&PRIVATE_KEY_INFO, input.as_bytes()).is_err());
    }
    let curve_inside =
        ec_pkcs8(P256, &ec_private_key(1, &d, Some(oid(P256)), Some(&g)));
    let short_scalar = ec_pkcs8(P256, &ec_private_key(1, &[1], None, Some(&g)));
    let compressed_point =
        ec_pkcs8(P256, &ec_private_key(1, &d, None, Some(&compressed(&g))));
    for input in [
        with_attributes,
        v2_with_public,
        curve_inside,
        short_scalar,
        compressed_point,
    ] {
        let key = AnyPrivateKey::decode(input.as_bytes()).unwrap();
        assert_eq!(key.encode(), canonical.as_bytes());
        assert_ne!(input, canonical);
    }
}
