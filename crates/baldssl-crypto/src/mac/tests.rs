//! HMAC against the test cases of the RFCs, and its laws.
//!
//! Known answers: [RFC 4231 section 4] for SHA-224, SHA-256, SHA-384 and
//! SHA-512, and [RFC 2202 section 3] for SHA-1, extracted from the RFC
//! texts (each key and data length checked against the RFC's own).
//!
//! [RFC 4231 section 4]: https://www.rfc-editor.org/rfc/rfc4231#section-4
//! [RFC 2202 section 3]: https://www.rfc-editor.org/rfc/rfc2202#section-3

use baldssl_test_utils::hex;
use proptest::prelude::*;

use super::{Hmac, Mac, Tag};
use crate::{
    ct::CtEq,
    hash::{Algorithm, Digest, Sha1, Sha224, Sha256, Sha384, Sha512},
};

/// One test case: key, data, and the expected tag in hexadecimal. A
/// truncated case (RFC 4231 test case 5, RFC 2202 test case 5) gives only
/// the leftmost bytes of the tag.
struct Case {
    number: u32,
    key: &'static str,
    data: &'static str,
    tag: &'static str,
}

/// Whether HMAC-`H` gives the expected tag (or its leftmost bytes) on
/// every case.
fn check<H>(cases: &[Case])
where
    H: Digest,
{
    for case in cases {
        let tag = Hmac::<H>::mac(&hex(case.key), &hex(case.data));
        let expected = hex(case.tag);
        let got = tag.as_bytes().get(..expected.len()).unwrap();
        assert_eq!(got, expected.as_slice(), "case {}", case.number);
        assert_eq!(tag.as_bytes().len(), H::OUTPUT_LEN);
    }
}
/// RFC 4231 section 4, HMAC-SHA-224; case 5 truncated to 128 bits.
const RFC4231_SHA224: &[Case] = &[
    Case {
        number: 1,
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        tag: "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
    },
    Case {
        number: 2,
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        tag: "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
    },
    Case {
        number: 3,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: concat!(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "dddddddddddddddddddddddddddddddddddd",
        ),
        tag: "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
    },
    Case {
        number: 4,
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: concat!(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        ),
        tag: "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
    },
    Case {
        number: 5,
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        tag: "0e2aea68a90c8d37c988bcdb9fca6fa8",
    },
    Case {
        number: 6,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaa",
        ),
        data: concat!(
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a",
            "65204b6579202d2048617368204b6579204669727374",
        ),
        tag: "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
    },
    Case {
        number: 7,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaa",
        ),
        data: concat!(
            "5468697320697320612074657374207573696e672061206c6172676572207468",
            "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074",
            "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565",
            "647320746f20626520686173686564206265666f7265206265696e6720757365",
            "642062792074686520484d414320616c676f726974686d2e",
        ),
        tag: "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
    },
];

/// RFC 4231 section 4, HMAC-SHA-256; case 5 truncated to 128 bits.
const RFC4231_SHA256: &[Case] = &[
    Case {
        number: 1,
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        tag: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    Case {
        number: 2,
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        tag: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    Case {
        number: 3,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: concat!(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "dddddddddddddddddddddddddddddddddddd",
        ),
        tag: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    },
    Case {
        number: 4,
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: concat!(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        ),
        tag: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    },
    Case {
        number: 5,
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        tag: "a3b6167473100ee06e0c796c2955552b",
    },
    Case {
        number: 6,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaa",
        ),
        data: concat!(
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a",
            "65204b6579202d2048617368204b6579204669727374",
        ),
        tag: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    },
    Case {
        number: 7,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaa",
        ),
        data: concat!(
            "5468697320697320612074657374207573696e672061206c6172676572207468",
            "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074",
            "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565",
            "647320746f20626520686173686564206265666f7265206265696e6720757365",
            "642062792074686520484d414320616c676f726974686d2e",
        ),
        tag: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    },
];

/// RFC 4231 section 4, HMAC-SHA-384; case 5 truncated to 128 bits.
const RFC4231_SHA384: &[Case] = &[
    Case {
        number: 1,
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        tag: concat!(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c",
            "faea9ea9076ede7f4af152e8b2fa9cb6",
        ),
    },
    Case {
        number: 2,
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        tag: concat!(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e",
            "8e2240ca5e69e2c78b3239ecfab21649",
        ),
    },
    Case {
        number: 3,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: concat!(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "dddddddddddddddddddddddddddddddddddd",
        ),
        tag: concat!(
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b",
            "2a5ab39dc13814b94e3ab6e101a34f27",
        ),
    },
    Case {
        number: 4,
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: concat!(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        ),
        tag: concat!(
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e",
            "6801dd23c4a7d679ccf8a386c674cffb",
        ),
    },
    Case {
        number: 5,
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        tag: "3abf34c3503b2a23a46efc619baef897",
    },
    Case {
        number: 6,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaa",
        ),
        data: concat!(
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a",
            "65204b6579202d2048617368204b6579204669727374",
        ),
        tag: concat!(
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6",
            "0c2ef6ab4030fe8296248df163f44952",
        ),
    },
    Case {
        number: 7,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaa",
        ),
        data: concat!(
            "5468697320697320612074657374207573696e672061206c6172676572207468",
            "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074",
            "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565",
            "647320746f20626520686173686564206265666f7265206265696e6720757365",
            "642062792074686520484d414320616c676f726974686d2e",
        ),
        tag: concat!(
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5",
            "a678cc31e799176d3860e6110c46523e",
        ),
    },
];

/// RFC 4231 section 4, HMAC-SHA-512; case 5 truncated to 128 bits.
const RFC4231_SHA512: &[Case] = &[
    Case {
        number: 1,
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        tag: concat!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
    },
    Case {
        number: 2,
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        tag: concat!(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
    },
    Case {
        number: 3,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: concat!(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "dddddddddddddddddddddddddddddddddddd",
        ),
        tag: concat!(
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39",
            "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        ),
    },
    Case {
        number: 4,
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: concat!(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        ),
        tag: concat!(
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db",
            "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        ),
    },
    Case {
        number: 5,
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        tag: "415fad6271580a531d4179bc891d87a6",
    },
    Case {
        number: 6,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaa",
        ),
        data: concat!(
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a",
            "65204b6579202d2048617368204b6579204669727374",
        ),
        tag: concat!(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        ),
    },
    Case {
        number: 7,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaa",
        ),
        data: concat!(
            "5468697320697320612074657374207573696e672061206c6172676572207468",
            "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074",
            "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565",
            "647320746f20626520686173686564206265666f7265206265696e6720757365",
            "642062792074686520484d414320616c676f726974686d2e",
        ),
        tag: concat!(
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944",
            "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        ),
    },
];

/// RFC 2202 section 3, HMAC-SHA-1.
const RFC2202_SHA1: &[Case] = &[
    Case {
        number: 1,
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        data: "4869205468657265",
        tag: "b617318655057264e28bc0b6fb378c8ef146be00",
    },
    Case {
        number: 2,
        key: "4a656665",
        data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        tag: "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
    },
    Case {
        number: 3,
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        data: concat!(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "dddddddddddddddddddddddddddddddddddd",
        ),
        tag: "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    },
    Case {
        number: 4,
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        data: concat!(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        ),
        tag: "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    },
    Case {
        number: 5,
        key: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        data: "546573742057697468205472756e636174696f6e",
        tag: "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
    },
    Case {
        number: 6,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        data: concat!(
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a",
            "65204b6579202d2048617368204b6579204669727374",
        ),
        tag: "aa4ae5e15272d00e95705637ce8a3b55ed402112",
    },
    Case {
        number: 7,
        key: concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        data: concat!(
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a",
            "65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d",
            "53697a652044617461",
        ),
        tag: "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
    },
];

#[test]
fn rfc4231() {
    check::<Sha224>(RFC4231_SHA224);
    check::<Sha256>(RFC4231_SHA256);
    check::<Sha384>(RFC4231_SHA384);
    check::<Sha512>(RFC4231_SHA512);
}

#[test]
fn rfc2202() {
    check::<Sha1>(RFC2202_SHA1);
}

/// The laws of a MAC built from `H`, on one key and message: streaming
/// equals one-shot at any split; a key longer than the block equals its
/// hash (RFC 2104 section 2, step 1); a key equals itself padded with zeros
/// up to the block (step 2).
fn laws<H>(key: &[u8], message: &[u8], split: usize)
where
    H: Digest,
{
    let tag = Hmac::<H>::mac(key, message);
    let at = split % (message.len() + 1);
    let (a, b) = message.split_at(at);
    let mut m = Hmac::<H>::new(key);
    m.update(a);
    m.update(b);
    assert_eq!(m.finalize(), tag, "streaming");
    if key.len() > H::BLOCK_LEN {
        assert_eq!(Hmac::<H>::mac(&H::digest(key), message), tag, "long key");
    } else {
        let mut padded = key.to_vec();
        padded.resize(H::BLOCK_LEN, 0);
        assert_eq!(Hmac::<H>::mac(&padded, message), tag, "zero padding");
    }
}

/// A tag accepts itself and rejects any single-bit change, and a prefix of
/// another length.
fn verification(tag: &Tag, bit: usize) {
    assert!(tag.verify_ct(tag.as_bytes()).to_bool_vartime());
    let mut flipped = tag.as_bytes().to_vec();
    let i = bit % (flipped.len() * 8);
    flipped[i / 8] ^= 1 << (i % 8);
    assert!(!tag.verify_ct(&flipped).to_bool_vartime());
    let short = &tag.as_bytes()[..tag.as_bytes().len() - 1];
    assert!(!tag.verify_ct(short).to_bool_vartime());
    assert!(tag.ct_eq(tag).to_bool_vartime());
}

proptest! {
    #[test]
    fn hmac_laws(
        key in prop::collection::vec(any::<u8>(), 0..300),
        message in prop::collection::vec(any::<u8>(), 0..300),
        split in any::<usize>(),
        bit in any::<usize>(),
    ) {
        laws::<Sha1>(&key, &message, split);
        laws::<Sha224>(&key, &message, split);
        laws::<Sha256>(&key, &message, split);
        laws::<Sha384>(&key, &message, split);
        laws::<Sha512>(&key, &message, split);
        verification(&Hmac::<Sha256>::mac(&key, &message), bit);
    }
}

/// The empty key and the empty message, and keys exactly one block long:
/// the boundaries of RFC 2104's key handling.
#[test]
fn boundaries() {
    laws::<Sha256>(&[], &[], 0);
    laws::<Sha512>(&[], &[], 0);
    // The empty key is the all-zero block.
    assert_eq!(
        Hmac::<Sha256>::mac(&[], b"m"),
        Hmac::<Sha256>::mac(&[0; 64], b"m")
    );
    // A key of exactly B bytes is used as it is, not hashed.
    let block = [7u8; 64];
    assert_ne!(
        Hmac::<Sha256>::mac(&block, b"m"),
        Hmac::<Sha256>::mac(&Sha256::digest(&block), b"m")
    );
    let block = [7u8; 128];
    assert_ne!(
        Hmac::<Sha512>::mac(&block, b"m"),
        Hmac::<Sha512>::mac(&Sha512::digest(&block), b"m")
    );
}

proptest! {
    /// HMAC with a hash named at run time is HMAC with that hash's type:
    /// `Algorithm::with` commutes with the construction.
    #[test]
    fn named_hmac_is_typed_hmac(
        key in prop::collection::vec(any::<u8>(), 0..200),
        message in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let typed = [
            Hmac::<Sha1>::mac(&key, &message),
            Hmac::<Sha224>::mac(&key, &message),
            Hmac::<Sha256>::mac(&key, &message),
            Hmac::<Sha384>::mac(&key, &message),
            Hmac::<Sha512>::mac(&key, &message),
        ];
        for (algorithm, expected) in Algorithm::ALL.into_iter().zip(typed) {
            prop_assert_eq!(algorithm.hmac(&key, &message), expected);
        }
    }
}
