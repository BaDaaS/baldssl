//! HMAC_DRBG against NIST's CAVP vectors, and each limit of SP 800-90A.
//!
//! Known answers: the `HMAC_DRBG.rsp` files of the [CAVP DRBG test
//! vectors] (`drbgtestvectors.zip`), in `cavp/drbg/` of the fixtures, one
//! per mode: no reseed, reseed without prediction resistance, and with it.
//! The procedure is the one of the DRBG Validation System: instantiate,
//! then two requests, the second's output being `ReturnedBits`.
//!
//! [CAVP DRBG test vectors]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators

use baldssl_test_utils::{fixture, hex};

use super::{
    AdditionalInput, Drbg, DrbgError, DrbgHash, Entropy, HmacDrbg,
    MAX_BITS_PER_REQUEST, Nonce, Personalization, RESEED_INTERVAL,
};
use crate::hash::{Sha1, Sha224, Sha256, Sha384, Sha512};

/// How a vector reseeds.
#[derive(Clone, Copy, Debug)]
enum Mode {
    /// Never.
    NoReseed,
    /// Once, before the two requests.
    Reseed,
    /// Before each request, with that request's additional input
    /// (prediction resistance, SP 800-90A section 9.3.1).
    PredictionResistance,
}

/// One vector: every field in file order (`AdditionalInput` and
/// `EntropyInputPR` repeat).
struct Vector {
    fields: Vec<(String, Vec<u8>)>,
}

impl Vector {
    fn one(&self, name: &str) -> &[u8] {
        &self.fields.iter().find(|(n, _)| n == name).unwrap().1
    }

    fn all(&self, name: &str) -> Vec<&[u8]> {
        self.fields
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
            .collect()
    }
}

/// The vectors of `hash` (`SHA-256`) in a `.rsp` file.
fn vectors(text: &str, hash: &str) -> Vec<Vector> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut current: Option<Vector> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with("[SHA") {
            section = line.trim_matches(|c| c == '[' || c == ']').to_owned();
            continue;
        }
        if section != hash || line.starts_with('[') {
            continue;
        }
        if line.starts_with("COUNT") {
            out.extend(current.take());
            current = Some(Vector { fields: Vec::new() });
        } else if let (Some(v), Some((name, value))) = (
            current.as_mut(),
            line.split_once(" = ")
                .or_else(|| line.strip_suffix(" =").map(|n| (n, ""))),
        ) {
            v.fields.push((name.to_owned(), hex(value)));
        }
    }
    out.extend(current);
    out
}

/// Runs the DRBGVS procedure on one vector and returns the second output.
fn run<H>(v: &Vector, mode: Mode) -> Vec<u8>
where
    H: DrbgHash,
{
    let expected = v.one("ReturnedBits");
    let mut drbg = HmacDrbg::<H>::new(
        Entropy(v.one("EntropyInput")),
        Nonce(v.one("Nonce")),
        Personalization(v.one("PersonalizationString")),
    )
    .unwrap();
    let additional = v.all("AdditionalInput");
    let mut out = vec![0u8; expected.len()];
    if let Mode::Reseed = mode {
        drbg.reseed(
            Entropy(v.one("EntropyInputReseed")),
            AdditionalInput(v.one("AdditionalInputReseed")),
        )
        .unwrap();
    }
    for (i, input) in additional.iter().enumerate() {
        let input = AdditionalInput(input);
        match mode {
            Mode::PredictionResistance => {
                drbg.reseed(Entropy(v.all("EntropyInputPR")[i]), input)
                    .unwrap();
                drbg.generate(&mut out, AdditionalInput::NONE).unwrap();
            }
            Mode::NoReseed | Mode::Reseed => {
                drbg.generate(&mut out, input).unwrap();
            }
        }
    }
    out
}

/// Every vector of `hash` in the three files.
fn check<H>(hash: &str)
where
    H: DrbgHash,
{
    for (file, mode) in [
        ("no_reseed", Mode::NoReseed),
        ("pr_false", Mode::Reseed),
        ("pr_true", Mode::PredictionResistance),
    ] {
        let text = fixture(&format!("cavp/drbg/HMAC_DRBG_{file}.rsp"));
        let vs = vectors(&text, hash);
        assert_eq!(vs.len(), 240, "{hash} {file}: 16 sections of 15");
        for (i, v) in vs.iter().enumerate() {
            assert_eq!(
                run::<H>(v, mode),
                v.one("ReturnedBits"),
                "{hash} {file} vector {i}"
            );
        }
    }
}

#[test]
fn cavp_sha1() {
    check::<Sha1>("SHA-1");
}

#[test]
fn cavp_sha224() {
    check::<Sha224>("SHA-224");
}

#[test]
fn cavp_sha256() {
    check::<Sha256>("SHA-256");
}

#[test]
fn cavp_sha384() {
    check::<Sha384>("SHA-384");
}

#[test]
fn cavp_sha512() {
    check::<Sha512>("SHA-512");
}

/// The limits of SP 800-90A, each refused with its own error.
#[test]
fn limits() {
    let entropy = [1u8; 32];
    let nonce = [2u8; 16];
    let new = |e: &[u8], n: &[u8]| {
        HmacDrbg::<Sha256>::new(Entropy(e), Nonce(n), Personalization(&[]))
            .err()
    };
    assert_eq!(
        new(&entropy[..31], &nonce),
        Some(DrbgError::EntropyTooShort {
            bits: 248,
            required: 256
        })
    );
    assert_eq!(
        new(&entropy, &nonce[..15]),
        Some(DrbgError::NonceTooShort {
            bits: 120,
            required: 128
        })
    );
    assert_eq!(new(&entropy, &nonce), None);

    let mut drbg = HmacDrbg::<Sha256>::new(
        Entropy(&entropy),
        Nonce(&nonce),
        Personalization(&[]),
    )
    .unwrap();
    assert_eq!(
        drbg.reseed(Entropy(&entropy[..1]), AdditionalInput::NONE),
        Err(DrbgError::EntropyTooShort {
            bits: 8,
            required: 256
        })
    );
    let mut big = vec![0u8; MAX_BITS_PER_REQUEST / 8 + 1];
    assert_eq!(
        drbg.generate(&mut big, AdditionalInput::NONE),
        Err(DrbgError::RequestTooLarge)
    );
    assert!(big.iter().all(|&b| b == 0), "unchanged on an error");
    let mut max = vec![0u8; MAX_BITS_PER_REQUEST / 8];
    assert_eq!(drbg.generate(&mut max, AdditionalInput::NONE), Ok(()));

    // The interval itself cannot be reached in a test: the counter is set.
    drbg.reseed_counter = RESEED_INTERVAL;
    let mut out = [0u8; 8];
    assert_eq!(drbg.generate(&mut out, AdditionalInput::NONE), Ok(()));
    assert_eq!(
        drbg.generate(&mut out, AdditionalInput::NONE),
        Err(DrbgError::ReseedRequired)
    );
    drbg.reseed(Entropy(&entropy), AdditionalInput::NONE)
        .unwrap();
    assert_eq!(drbg.generate(&mut out, AdditionalInput::NONE), Ok(()));
}

/// Determinism: the same seed gives the same stream, an empty request is
/// allowed, and the state does not print.
#[test]
fn determinism() {
    let seed = |p: &[u8]| {
        HmacDrbg::<Sha512>::new(
            Entropy(&[9; 32]),
            Nonce(&[8; 16]),
            Personalization(p),
        )
        .unwrap()
    };
    let (mut first, mut second) = (seed(b"x"), seed(b"x"));
    let (mut out1, mut out2) = ([0u8; 100], [0u8; 100]);
    first.generate(&mut out1, AdditionalInput::NONE).unwrap();
    second.generate(&mut out2, AdditionalInput::NONE).unwrap();
    assert_eq!(out1, out2);
    let mut other = [0u8; 100];
    seed(b"y")
        .generate(&mut other, AdditionalInput::NONE)
        .unwrap();
    assert_ne!(out1, other, "the personalization string matters");
    assert_eq!(first.generate(&mut [], AdditionalInput(&[])), Ok(()));
    assert_eq!(format!("{first:?}"), "HmacDrbg { reseed_counter: 3, .. }");
}
