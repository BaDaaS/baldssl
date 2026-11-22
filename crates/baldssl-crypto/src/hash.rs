//! Hash functions: SHA-1 and SHA-2 ([FIPS 180-4][fips180]).
//!
//! Every hash here is a Merkle-Damgard iteration: a compression function
//! `f : State x Block -> State` folded over the padded message. Updating is
//! therefore a right action of the free monoid of byte strings on the
//! buffered state, `(s . a) . b = s . (a ++ b)`, which is the law the
//! streaming property tests check.
//!
//! [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final

mod sha1;
mod sha256;
mod sha512;

pub use sha1::Sha1;
pub use sha256::{Sha224, Sha256};
pub use sha512::{Sha384, Sha512};

use crate::drbg::DrbgHash;

/// A hash function with incremental input.
pub trait Digest: Sized {
    /// Digest length in bytes.
    const OUTPUT_LEN: usize;
    /// Block length in bytes: what the compression function absorbs at a
    /// time, the `B` of HMAC ([RFC 2104 section 2][rfc2104]).
    ///
    /// [rfc2104]: https://www.rfc-editor.org/rfc/rfc2104#section-2
    const BLOCK_LEN: usize;
    /// A fresh state.
    #[must_use]
    fn new() -> Self;
    /// Absorbs more input.
    fn update(&mut self, data: &[u8]);
    /// Pads and returns the digest.
    #[must_use]
    fn finalize(self) -> Vec<u8>;

    /// One-shot hash.
    #[must_use]
    fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    /// The hash of the concatenation of `parts`, without building it: the
    /// fold of [`Digest::update`] over them, which the action law makes the
    /// same as [`Digest::digest`] of their concatenation.
    #[must_use]
    fn digest_parts(parts: &[&[u8]]) -> Vec<u8> {
        let mut h = Self::new();
        for part in parts {
            h.update(part);
        }
        h.finalize()
    }
}

/// The digests the CLI can select by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA-1 (collision-broken; for fingerprints and legacy only).
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl Algorithm {
    /// Every supported algorithm.
    pub const ALL: [Algorithm; 5] = [
        Algorithm::Sha1,
        Algorithm::Sha224,
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
    ];

    /// The lower-case name OpenSSL accepts as `-<name>`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha224 => "sha224",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
        }
    }

    /// Looks an algorithm up by its OpenSSL name, ignoring ASCII case.
    #[must_use]
    pub fn from_name_opt(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.name().eq_ignore_ascii_case(name))
    }

    /// Runs `computation` on the hash this name names: the only place a
    /// run-time hash name becomes a type. [`Algorithm`] is the run-time
    /// representation of the finite set of hash types; `with` is its
    /// eliminator, the Church encoding of the existential
    /// `exists H: DrbgHash` as `forall R. (forall H: DrbgHash. R) -> R`
    /// ([TAPL] section 24.3), with the inner polymorphic function made a
    /// trait so Rust can quantify over `H`.
    ///
    /// [TAPL]: https://www.cis.upenn.edu/~bcpierce/tapl/
    pub fn with<W>(self, computation: W) -> W::Output
    where
        W: WithHash,
    {
        match self {
            Algorithm::Sha1 => computation.run::<Sha1>(),
            Algorithm::Sha224 => computation.run::<Sha224>(),
            Algorithm::Sha256 => computation.run::<Sha256>(),
            Algorithm::Sha384 => computation.run::<Sha384>(),
            Algorithm::Sha512 => computation.run::<Sha512>(),
        }
    }

    /// Hashes `data`.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        self.with(Hashing(data))
    }
}

/// Hashing bytes, with any hash.
struct Hashing<'a>(&'a [u8]);

impl WithHash for Hashing<'_> {
    type Output = Vec<u8>;

    fn run<H>(self) -> Vec<u8>
    where
        H: DrbgHash,
    {
        H::digest(self.0)
    }
}

/// A computation generic over the hash, which [`Algorithm::with`] runs on
/// the hash a run-time name names.
pub trait WithHash {
    /// What the computation gives.
    type Output;

    /// The computation with the hash `H`.
    fn run<H>(self) -> Self::Output
    where
        H: DrbgHash;
}

#[cfg(test)]
mod tests {
    use baldssl_test_utils::hex;
    use proptest::prelude::*;

    use super::*;

    /// Known answers from the [FIPS 180-4 example documents][examples] (NIST CSRC,
    /// "Examples with Intermediate Values"): "abc", the empty string, the
    /// two-block message, and one million 'a'.
    ///
    /// [examples]: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    #[test]
    fn known_answers() {
        let abc = b"abc";
        let two_block_256 =
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let cases: &[(Algorithm, &[u8], &str)] = &[
            (
                Algorithm::Sha1,
                abc,
                "a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            (
                Algorithm::Sha1,
                b"",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ),
            (
                Algorithm::Sha1,
                two_block_256,
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
            (
                Algorithm::Sha224,
                abc,
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            ),
            (
                Algorithm::Sha256,
                abc,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                Algorithm::Sha256,
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                Algorithm::Sha256,
                two_block_256,
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                Algorithm::Sha384,
                abc,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                Algorithm::Sha512,
                abc,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                Algorithm::Sha512,
                b"",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
        ];
        for (alg, msg, want) in cases {
            assert_eq!(alg.digest(msg), hex(want), "{alg:?} {msg:?}");
        }
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            Sha1::digest(&million),
            hex("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        );
        assert_eq!(
            Sha256::digest(&million),
            hex(
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
            )
        );
    }

    /// The padding boundaries: lengths around one block, where the length
    /// field does or does not fit after the `0x80` byte. Checked against
    /// streaming one byte at a time, which shares no buffering decisions with
    /// the one-shot path.
    #[test]
    fn padding_boundaries() {
        for len in [55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129] {
            let msg = vec![0x5au8; len];
            for alg in Algorithm::ALL {
                let bytewise = stream_alg(alg, &msg, 1);
                assert_eq!(alg.digest(&msg), bytewise, "{alg:?} {len}");
            }
        }
    }

    #[test]
    fn names() {
        for alg in Algorithm::ALL {
            assert_eq!(Algorithm::from_name_opt(alg.name()), Some(alg));
            assert_eq!(
                Algorithm::from_name_opt(&alg.name().to_uppercase()),
                Some(alg)
            );
        }
        assert_eq!(Algorithm::from_name_opt("md5"), None);
        assert_eq!(Sha1::OUTPUT_LEN, 20);
        assert_eq!(Sha224::OUTPUT_LEN, 28);
        assert_eq!(Sha256::OUTPUT_LEN, 32);
        assert_eq!(Sha384::OUTPUT_LEN, 48);
        assert_eq!(Sha512::OUTPUT_LEN, 64);
        for alg in Algorithm::ALL {
            let len = match alg {
                Algorithm::Sha1 => 20,
                Algorithm::Sha224 => 28,
                Algorithm::Sha256 => 32,
                Algorithm::Sha384 => 48,
                Algorithm::Sha512 => 64,
            };
            assert_eq!(alg.digest(b"x").len(), len);
        }
    }

    fn stream<D>(data: &[u8], chunk: usize) -> Vec<u8>
    where
        D: Digest,
    {
        let mut h = D::new();
        for c in data.chunks(chunk.max(1)) {
            h.update(c);
        }
        h.finalize()
    }

    fn stream_alg(alg: Algorithm, data: &[u8], chunk: usize) -> Vec<u8> {
        match alg {
            Algorithm::Sha1 => stream::<Sha1>(data, chunk),
            Algorithm::Sha224 => stream::<Sha224>(data, chunk),
            Algorithm::Sha256 => stream::<Sha256>(data, chunk),
            Algorithm::Sha384 => stream::<Sha384>(data, chunk),
            Algorithm::Sha512 => stream::<Sha512>(data, chunk),
        }
    }

    fn split<D>(data: &[u8], cut: usize) -> Vec<u8>
    where
        D: Digest,
    {
        let cut = cut.min(data.len());
        let mut h = D::new();
        h.update(&data[..cut]);
        h.update(&data[cut..]);
        h.finalize()
    }

    proptest! {
        /// Monoid-action law: `update(a); update(b) == update(a ++ b)`.
        #[test]
        fn streaming_is_an_action(
            data in prop::collection::vec(any::<u8>(), 0..400),
            cut in 0usize..400,
            chunk in 1usize..150,
        ) {
            prop_assert_eq!(split::<Sha1>(&data, cut), Sha1::digest(&data));
            prop_assert_eq!(split::<Sha256>(&data, cut), Sha256::digest(&data));
            prop_assert_eq!(split::<Sha512>(&data, cut), Sha512::digest(&data));
            prop_assert_eq!(stream::<Sha224>(&data, chunk), Sha224::digest(&data));
            prop_assert_eq!(stream::<Sha384>(&data, chunk), Sha384::digest(&data));
        }

        /// `digest_parts` is the digest of the concatenation, for any way of
        /// cutting the input into parts, the empty ones included.
        #[test]
        fn parts_are_concatenated(
            data in prop::collection::vec(any::<u8>(), 0..400),
            mut cuts in prop::collection::vec(0usize..400, 0..5),
        ) {
            cuts.push(0);
            cuts.push(data.len());
            for c in &mut cuts {
                *c = (*c).min(data.len());
            }
            cuts.sort_unstable();
            let parts: Vec<&[u8]> =
                cuts.windows(2).filter_map(|w| data.get(w[0]..w[1])).collect();
            prop_assert_eq!(Sha512::digest_parts(&parts), Sha512::digest(&data));
            prop_assert_eq!(Sha256::digest_parts(&parts), Sha256::digest(&data));
        }
    }
}
