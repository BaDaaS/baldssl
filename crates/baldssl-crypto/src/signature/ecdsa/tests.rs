//! ECDSA against RFC 6979's vectors, its laws, and the rules of the
//! signature encoding.
//!
//! Known answers: [RFC 6979 appendix A.2.5 to A.2.7] (P-256, P-384, P-521,
//! with SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512, on the messages
//! "sample" and "test"), extracted from the RFC text. Each gives the key
//! pair, the nonce $k$ and the signature $(r, s)$.
//!
//! [RFC 6979 appendix A.2.5 to A.2.7]: https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5

use baldssl_test_utils::hex;
use proptest::prelude::*;

use super::{
    Ecdsa, Rfc6979, Signature, bits2int, sign_with_hash, verify_with_hash,
};
use crate::{
    algebra::{
        curve::{Curve, ShortWeierstrass},
        encoding::{Decodable, Encodable, InvalidEncoding},
        field::{Field, PrimeField},
        model::AffineModel,
    },
    drbg::DrbgHash,
    hash::{Algorithm, Sha1, Sha224, Sha256, Sha384, Sha512},
    instances::{P256, P384, P521},
    keys::EcKeyPair,
    signature::{SignEncoded, Signer, Verifier},
};

/// One curve's vectors: the key pair, then the signatures.
struct Vectors {
    x: &'static str,
    ux: &'static str,
    uy: &'static str,
    signatures: &'static [Rfc6979Signature],
}

/// One signature of RFC 6979: hash, message, nonce, and $(r, s)$.
struct Rfc6979Signature {
    hash: &'static str,
    message: &'static str,
    k: &'static str,
    r: &'static str,
    s: &'static str,
}

/// RFC 6979 appendix A.2.5, P-256.
const P256_VECTORS: Vectors = Vectors {
    x: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    ux: "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    uy: "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    signatures: &[
        Rfc6979Signature {
            hash: "SHA-1",
            message: "sample",
            k: concat!(
                "882905f1227fd620fbf2abf21244f0ba83d0dc3a9103dbbee43a1fb85810",
                "9db4",
            ),
            r: concat!(
                "61340c88c3aaebeb4f6d667f672ca9759a6ccaa9fa8811313039ee4a3547",
                "1d32",
            ),
            s: concat!(
                "6d7f147dac089441bb2e2fe8f7a3fa264b9c475098fdcf6e00d7c996e1b8",
                "b7eb",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-224",
            message: "sample",
            k: concat!(
                "103f90ee9dc52e5e7fb5132b7033c63066d194321491862059967c715985",
                "d473",
            ),
            r: concat!(
                "53b2fff5d1752b2c689df257c04c40a587fababb3f6fc2702f1343af7ca9",
                "aa3f",
            ),
            s: concat!(
                "b9afb64fdc03dc1a131c7d2386d11e349f070aa432a4acc918bea988bf75",
                "c74c",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-256",
            message: "sample",
            k: concat!(
                "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8a",
                "ad60",
            ),
            r: concat!(
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf",
                "3716",
            ),
            s: concat!(
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843a",
                "cda8",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-384",
            message: "sample",
            k: concat!(
                "09f634b188cefd98e7ec88b1aa9852d734d0bc272f7d2a47decc6ebeb375",
                "aad4",
            ),
            r: concat!(
                "0eafea039b20e9b42309fb1d89e213057cbf973dc0cfc8f129edddc800ef",
                "7719",
            ),
            s: concat!(
                "4861f0491e6998b9455193e34e7b0d284ddd7149a74b95b9261f13abde94",
                "0954",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-512",
            message: "sample",
            k: concat!(
                "5fa81c63109badb88c1f367b47da606da28cad69aa22c4fe6ad7df73a717",
                "3aa5",
            ),
            r: concat!(
                "8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb9",
                "7f00",
            ),
            s: concat!(
                "2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae33",
                "02fe",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-1",
            message: "test",
            k: concat!(
                "8c9520267c55d6b980df741e56b4adee114d84fbfa2e6213795416402863",
                "2a2e",
            ),
            r: concat!(
                "0cbcc86fd6abd1d99e703e1ec50069ee5c0b4ba4b9ac60e409e8ec5910d8",
                "1a89",
            ),
            s: concat!(
                "01b9d7b73dfaa60d5651ec4591a0136f87653e0fd780c3b1bc872ffdeae4",
                "79b1",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-224",
            message: "test",
            k: concat!(
                "669f4426f2688b8be0db3a6bd1989bdaefff84b649eeb84f3dd26080f667",
                "faa7",
            ),
            r: concat!(
                "c37edb6f0ae79d47c3c27e962fa269bb4f441770357e114ee511f662ec34",
                "a692",
            ),
            s: concat!(
                "c820053a05791e521fcaad6042d40aea1d6b1a540138558f47d0719800e1",
                "8f2d",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-256",
            message: "test",
            k: concat!(
                "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee00",
                "08e0",
            ),
            r: concat!(
                "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d3",
                "8367",
            ),
            s: concat!(
                "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f",
                "0083",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-384",
            message: "test",
            k: concat!(
                "16aeffa357260b04b1dd199693960740066c1a8f3e8edd79070aa914d361",
                "b3b8",
            ),
            r: concat!(
                "83910e8b48bb0c74244ebdf7f07a1c5413d61472bd941ef3920e623fbcce",
                "beb6",
            ),
            s: concat!(
                "8ddbec54cf8cd5874883841d712142a56a8d0f218f5003cb0296b6b50961",
                "9f2c",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-512",
            message: "test",
            k: concat!(
                "6915d11632aca3c40d5d51c08daf9c555933819548784480e93499000d9f",
                "0b7f",
            ),
            r: concat!(
                "461d93f31b6540894788fd206c07cfa0cc35f46fa3c91816fff1040ad158",
                "1a04",
            ),
            s: concat!(
                "39af9f15de0db8d97e72719c74820d304ce5226e32dedae67519e840d119",
                "4e55",
            ),
        },
    ],
};

/// RFC 6979 appendix A.2.6, P-384.
const P384_VECTORS: Vectors = Vectors {
    x: concat!(
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5",
        "724e4c70a825f872c9ea60d2edf5",
    ),
    ux: concat!(
        "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8",
        "f0ea9055866064a254515480bc13",
    ),
    uy: concat!(
        "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b",
        "231c3ae0d4fe7344fd2533264720",
    ),
    signatures: &[
        Rfc6979Signature {
            hash: "SHA-1",
            message: "sample",
            k: concat!(
                "4471ef7518bb2c7c20f62eae1c387ad0c5e8e470995db4acf694466e6ab0",
                "96630f29e5938d25106c3c340045a2db01a7",
            ),
            r: concat!(
                "ec748d839243d6fbef4fc5c4859a7dffd7f3abddf72014540c16d7330983",
                "4fa37b9ba002899f6fda3a4a9386790d4eb2",
            ),
            s: concat!(
                "a3bcfa947beef4732bf247ac17f71676cb31a847b9ff0cbc9c9ed4c1a5b3",
                "facf26f49ca031d4857570ccb5ca4424a443",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-224",
            message: "sample",
            k: concat!(
                "a4e4d2f0e729eb786b31fc20ad5d849e304450e0ae8e3e341134a5c1afa0",
                "3cab8083ee4e3c45b06a5899ea56c51b5879",
            ),
            r: concat!(
                "42356e76b55a6d9b4631c865445dbe54e056d3b3431766d0509244793c3f",
                "9366450f76ee3de43f5a125333a6be060122",
            ),
            s: concat!(
                "9da0c81787064021e78df658f2fbb0b042bf304665db721f077a4298b095",
                "e4834c082c03d83028efbf93a3c23940ca8d",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-256",
            message: "sample",
            k: concat!(
                "180ae9f9aec5438a44bc159a1fcb277c7be54fa20e7cf404b490650a8acc",
                "414e375572342863c899f9f2edf9747a9b60",
            ),
            r: concat!(
                "21b13d1e013c7fa1392d03c5f99af8b30c570c6f98d4ea8e354b63a21d3d",
                "aa33bde1e888e63355d92fa2b3c36d8fb2cd",
            ),
            s: concat!(
                "f3aa443fb107745bf4bd77cb3891674632068a10ca67e3d45db2266fa7d1",
                "feebefdc63eccd1ac42ec0cb8668a4fa0ab0",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-384",
            message: "sample",
            k: concat!(
                "94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10",
                "fbca2907e3e83ba95368623b8c4686915cf9",
            ),
            r: concat!(
                "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad",
                "133c81a648152e44acf96e36dd1e80fabe46",
            ),
            s: concat!(
                "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3",
                "a94fa329c145786e679e7b82c71a38628ac8",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-512",
            message: "sample",
            k: concat!(
                "92fc3c7183a883e24216d1141f1a8976c5b0dd797dfa597e3d7b32198bd3",
                "5331a4e966532593a52980d0e3aaa5e10ec3",
            ),
            r: concat!(
                "ed0959d5880ab2d869ae7f6c2915c6d60f96507f9cb3e047c0046861da4a",
                "799cfe30f35cc900056d7c99cd7882433709",
            ),
            s: concat!(
                "512c8cceee3890a84058ce1e22dbc2198f42323ce8aca9135329f03c068e",
                "5112dc7cc3ef3446defceb01a45c2667fdd5",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-1",
            message: "test",
            k: concat!(
                "66cc2c8f4d303fc962e5ff6a27bd79f84ec812ddae58cf5243b64a4ad809",
                "4d47ec3727f3a3c186c15054492e30698497",
            ),
            r: concat!(
                "4bc35d3a50ef4e30576f58cd96ce6bf638025ee624004a1f7789a8b8e43d",
                "0678acd9d29876daf46638645f7f404b11c7",
            ),
            s: concat!(
                "d5a6326c494ed3ff614703878961c0fde7b2c278f9a65fd8c4b7186201a2",
                "991695ba1c84541327e966fa7b50f7382282",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-224",
            message: "test",
            k: concat!(
                "18fa39db95aa5f561f30fa3591dc59c0fa3653a80daffa0b48d1a4c6dfcb",
                "ff6e3d33be4dc5eb8886a8ecd093f2935726",
            ),
            r: concat!(
                "e8c9d0b6ea72a0e7837fea1d14a1a9557f29faa45d3e7ee888fc5bf954b5",
                "e62464a9a817c47ff78b8c11066b24080e72",
            ),
            s: concat!(
                "07041d4a7a0379ac7232ff72e6f77b6ddb8f09b16cce0ec3286b2bd43fa8",
                "c6141c53ea5abef0d8231077a04540a96b66",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-256",
            message: "test",
            k: concat!(
                "0cfac37587532347dc3389fdc98286bba8c73807285b184c83e62e26c401",
                "c0faa48dd070ba79921a3457abff2d630ad7",
            ),
            r: concat!(
                "6d6defac9ab64dabafe36c6bf510352a4cc27001263638e5b16d9bb51d45",
                "1559f918eedaf2293be5b475cc8f0188636b",
            ),
            s: concat!(
                "2d46f3becbcc523d5f1a1256bf0c9b024d879ba9e838144c8ba6baeb4b53",
                "b47d51ab373f9845c0514eefb14024787265",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-384",
            message: "test",
            k: concat!(
                "015ee46a5bf88773ed9123a5ab0807962d193719503c527b031b4c2d2250",
                "92ada71f4a459bc0da98adb95837db8312ea",
            ),
            r: concat!(
                "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a",
                "5feb0542a7f0812998da8f1dd3ca3cf023db",
            ),
            s: concat!(
                "ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f131739",
                "23e06a739f040649a667bf3b828246baa5a5",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-512",
            message: "test",
            k: concat!(
                "3780c4f67cb15518b6acae34c9f83568d2e12e47deab6c50a4e4ee5319d1",
                "e8ce0e2cc8a136036dc4b9c00e6888f66b6c",
            ),
            r: concat!(
                "a0d5d090c9980faf3c2ce57b7ae951d31977dd11c775d314af55f76c6764",
                "47d06fb6495cd21b4b6e340fc236584fb277",
            ),
            s: concat!(
                "976984e59b4c77b0e8e4460dca3d9f20e07b9bb1f63beefaf576f6b2e8b2",
                "24634a2092cd3792e0159ad9cee37659c736",
            ),
        },
    ],
};

/// RFC 6979 appendix A.2.7, P-521.
const P521_VECTORS: Vectors = Vectors {
    x: concat!(
        "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa8",
        "96eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
    ),
    ux: concat!(
        "01894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd3711",
        "23d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a4",
    ),
    uy: concat!(
        "00493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0",
        "db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5",
    ),
    signatures: &[
        Rfc6979Signature {
            hash: "SHA-1",
            message: "sample",
            k: concat!(
                "0089c071b419e1c2820962321787258469511958e80582e95d8378e0c2cc",
                "db3cb42bede42f50e3fa3c71f5a76724281d31d9c89f0f91fc1be4918db1",
                "c03a5838d0f9",
            ),
            r: concat!(
                "00343b6ec45728975ea5cba6659bbb6062a5ff89eea58be3c80b619f322c",
                "87910fe092f7d45bb0f8eee01ed3f20babec079d202ae677b243ab40b543",
                "1d497c55d75d",
            ),
            s: concat!(
                "00e7b0e675a9b24413d448b8cc119d2bf7b2d2df032741c096634d6d65d0",
                "dbe3d5694625fb9e8104d3b842c1b0e2d0b98bea19341e8676aef66ae4eb",
                "a3d5475d5d16",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-224",
            message: "sample",
            k: concat!(
                "0121415ec2cd7726330a61f7f3fa5de14be9436019c4db8cb4041f3b54cf",
                "31be0493ee3f427fb906393d895a19c9523f3a1d54bb8702bd4aa9c99dab",
                "2597b92113f3",
            ),
            r: concat!(
                "01776331cfcdf927d666e032e00cf776187bc9fdd8e69d0dabb4109ffe1b",
                "5e2a30715f4cc923a4a5e94d2503e9acfed92857b7f31d7152e0f8c00c15",
                "ff3d87e2ed2e",
            ),
            s: concat!(
                "0050cb5265417fe2320bbb5a122b8e1a32bd699089851128e360e620a30c",
                "7e17ba41a666af126ce100e5799b153b60528d5300d08489ca9178fb610a",
                "2006c254b41f",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-256",
            message: "sample",
            k: concat!(
                "00edf38afcaaecab4383358b34d67c9f2216c8382aaea44a3dad5fdc9c32",
                "575761793fef24eb0fc276dfc4f6e3ec476752f043cf01415387470bcbd8",
                "678ed2c7e1a0",
            ),
            r: concat!(
                "01511bb4d675114fe266fc4372b87682baecc01d3cc62cf2303c92b35260",
                "12659d16876e25c7c1e57648f23b73564d67f61c6f14d527d54972810421",
                "e7d87589e1a7",
            ),
            s: concat!(
                "004a171143a83163d6df460aaf61522695f207a58b95c0644d87e52aa1a3",
                "47916e4f7a72930b1bc06dbe22ce3f58264afd23704cbb63b29b931f7de6",
                "c9d949a7ecfc",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-384",
            message: "sample",
            k: concat!(
                "01546a108bc23a15d6f21872f7ded661fa8431ddbd922d0dcdb77cc878c8",
                "553ffad064c95a920a750ac9137e527390d2d92f153e66196966ea554d9a",
                "dfcb109c4211",
            ),
            r: concat!(
                "01ea842a0e17d2de4f92c15315c63ddf72685c18195c2bb95e572b9c5136",
                "ca4b4b576ad712a52be9730627d16054ba40cc0b8d3ff035b12ae7516839",
                "7f5d50c67451",
            ),
            s: concat!(
                "01f21a3cee066e1961025fb048bd5fe2b7924d0cd797babe0a83b66f1e35",
                "eeaf5fde143fa85dc394a7dee766523393784484bdf3e00114a1c857cde1",
                "aa203db65d61",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-512",
            message: "sample",
            k: concat!(
                "01dae2ea071f8110dc26882d4d5eae0621a3256fc8847fb9022e2b7d28e6",
                "f10198b1574fdd03a9053c08a1854a168aa5a57470ec97dd5ce090124ef5",
                "2a2f7ecbffd3",
            ),
            r: concat!(
                "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d",
                "4c5f174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf",
                "05ec36e377fa",
            ),
            s: concat!(
                "00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b",
                "68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1e",
                "e0e44da4a67a",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-1",
            message: "test",
            k: concat!(
                "00bb9f2bf4fe1038ccf4dabd7139a56f6fd8bb1386561bd3c6a4fc818b20",
                "df5ddba80795a947107a1ab9d12daa615b1ade4f7a9dc05e8e6311150f47",
                "f5c57ce8b222",
            ),
            r: concat!(
                "013bad9f29abe20de37ebeb823c252ca0f63361284015a3bf430a46aaa80",
                "b87b0693f0694bd88afe4e661fc33b094cd3b7963bed5a727ed8bd6a3a20",
                "2abe009d0367",
            ),
            s: concat!(
                "01e9bb81ff7944ca409ad138dbbee228e1afcc0c890fc78ec8604639cb0d",
                "bdc90f717a99ead9d272855d00162ee9527567dd6a92cbd629805c044528",
                "2bbc916797ff",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-224",
            message: "test",
            k: concat!(
                "0040d09fcf3c8a5f62cf4fb223cbbb2b9937f6b0577c27020a99602c25a0",
                "1136987e452988781484edbbcf1c47e554e7fc901bc3085e5206d9f619cf",
                "f07e73d6f706",
            ),
            r: concat!(
                "01c7ed902e123e6815546065a2c4af977b22aa8eaddb68b2c1110e7ea44d",
                "42086bfe4a34b67ddc0e17e96536e358219b23a706c6a6e16ba77b65e1c5",
                "95d43cae17fb",
            ),
            s: concat!(
                "0177336676304fcb343ce028b38e7b4fba76c1c1b277da18cad2a8478b2a",
                "9a9f5bec0f3ba04f35db3e4263569ec6aade8c92746e4c82f8299ae1b8f1",
                "739f8fd519a4",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-256",
            message: "test",
            k: concat!(
                "001de74955efaabc4c4f17f8e84d881d1310b5392d7700275f82f145c61e",
                "843841af09035bf7a6210f5a431a6a9e81c9323354a9e69135d44ebd2fca",
                "a7731b909258",
            ),
            r: concat!(
                "000e871c4a14f993c6c7369501900c4bc1e9c7b0b4ba44e04868b30b41d8",
                "071042eb28c4c250411d0ce08cd197e4188ea4876f279f90b3d8d74a3c76",
                "e6f1e4656aa8",
            ),
            s: concat!(
                "00cd52dbaa33b063c3a6cd8058a1fb0a46a4754b034fcc644766ca14da8c",
                "a5ca9fde00e88c1ad60ccba759025299079d7a427ec3cc5b619bfbc828e7",
                "769bcd694e86",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-384",
            message: "test",
            k: concat!(
                "01f1fc4a349a7da9a9e116bfdd055dc08e78252ff8e23ac276ac88b1770a",
                "e0b5dceb1ed14a4916b769a523ce1e90ba22846af11df8b300c38818f713",
                "dadd85de0c88",
            ),
            r: concat!(
                "014bee21a18b6d8b3c93fab08d43e739707953244fdbe924fa926d76669e",
                "7ac8c89df62ed8975c2d8397a65a49dcc09f6b0ac62272741924d479354d",
                "74ff6075578c",
            ),
            s: concat!(
                "0133330865c067a0eaf72362a65e2d7bc4e461e8c8995c3b6226a21bd1aa",
                "78f0ed94fe536a0dca35534f0cd1510c41525d163fe9d74d134881e35141",
                "ed5e8e95b979",
            ),
        },
        Rfc6979Signature {
            hash: "SHA-512",
            message: "test",
            k: concat!(
                "016200813020ec986863bedfc1b121f605c1215645018aea1a7b215a564d",
                "e9eb1b38a67aa1128b80ce391c4fb71187654aaa3431027bfc7f395766ca",
                "988c964dc56d",
            ),
            r: concat!(
                "013e99020abf5cee7525d16b69b229652ab6bdf2affcaef38773b4b7d087",
                "25f10cdb93482fdcc54edcee91eca4166b2a7c6265ef0ce2bd7051b7cef9",
                "45babd47ee6d",
            ),
            s: concat!(
                "01fbd0013c674aa79cb39849527916ce301c66ea7ce8b80682786ad60f98",
                "f7e78a19ca69eff5c57400e3b3a0ad66ce0978214d13baf4e9ac60752f7b",
                "155e2de4dce3",
            ),
        },
    ],
};

/// The scalar with this hexadecimal, big-endian.
fn scalar<C>(hex_be: &str) -> C::Scalar
where
    C: ShortWeierstrass,
{
    let (s, valid) = C::Scalar::from_bytes_be(&hex(hex_be));
    assert!(valid.to_bool_vartime(), "{hex_be} is not below n");
    s
}

/// The key pair of the vectors, and every signature made with `H`.
fn check<C, H>(vectors: &Vectors, hash: &str)
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    let pair = EcKeyPair::<C>::from_secret_opt(scalar::<C>(vectors.x)).unwrap();
    let (ux, uy) = pair.public().coordinates_opt().unwrap();
    assert_eq!(ux.to_bytes_be(), hex(vectors.ux), "{} Ux", C::NAME);
    assert_eq!(uy.to_bytes_be(), hex(vectors.uy), "{} Uy", C::NAME);
    let mut seen = 0;
    for v in vectors.signatures.iter().filter(|v| v.hash == hash) {
        let what = format!("{} {} {}", C::NAME, v.hash, v.message);
        let digest = H::digest(v.message.as_bytes());
        let mut nonces = Rfc6979::<C, H>::new(pair.secret(), &digest).unwrap();
        assert_eq!(nonces.next_nonce().unwrap(), scalar::<C>(v.k), "{what}: k");
        let signature =
            Ecdsa::<C, H>::sign(&pair, v.message.as_bytes()).unwrap();
        assert_eq!(*signature.r(), scalar::<C>(v.r), "{what}: r");
        assert_eq!(*signature.s(), scalar::<C>(v.s), "{what}: s");
        assert!(
            Ecdsa::<C, H>::verify(
                pair.public(),
                v.message.as_bytes(),
                &signature
            ),
            "{what}: verifies"
        );
        seen += 1;
    }
    assert_eq!(seen, 2, "{} {hash}: sample and test", C::NAME);
}

/// Every hash on one curve.
fn check_curve<C>(vectors: &Vectors)
where
    C: ShortWeierstrass,
{
    check::<C, Sha1>(vectors, "SHA-1");
    check::<C, Sha224>(vectors, "SHA-224");
    check::<C, Sha256>(vectors, "SHA-256");
    check::<C, Sha384>(vectors, "SHA-384");
    check::<C, Sha512>(vectors, "SHA-512");
}

#[test]
fn rfc6979_p256() {
    check_curve::<P256>(&P256_VECTORS);
}

#[test]
fn rfc6979_p384() {
    check_curve::<P384>(&P384_VECTORS);
}

#[test]
fn rfc6979_p521() {
    check_curve::<P521>(&P521_VECTORS);
}

/// Correctness, determinism, and soundness on mutations, for one key
/// and message: the signature verifies; signing twice gives the same
/// signature; another message, another key, or $r$ or $s$ changed do not
/// verify; the DER encoding reads back to the same signature.
fn laws<C, H>(secret: &[u8], message: &[u8], other: &[u8])
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    let mut bytes = vec![0u8; C::Scalar::BYTES];
    let take = secret.len().min(bytes.len());
    bytes[..take].copy_from_slice(&secret[..take]);
    let (d, _) = C::Scalar::from_bytes_be(&bits2int::<C>(&bytes));
    let Some(pair) = EcKeyPair::<C>::from_secret_opt(d) else {
        return;
    };
    let signature = Ecdsa::<C, H>::sign(&pair, message).unwrap();
    assert!(Ecdsa::<C, H>::verify(pair.public(), message, &signature));
    assert_eq!(Ecdsa::<C, H>::sign(&pair, message).unwrap(), signature);
    if other != message {
        assert!(!Ecdsa::<C, H>::verify(pair.public(), other, &signature));
    }
    let other_pair =
        EcKeyPair::<C>::from_secret_opt(d + C::Scalar::ONE).unwrap();
    assert!(!Ecdsa::<C, H>::verify(
        other_pair.public(),
        message,
        &signature
    ));
    let bumped_r = Signature::<C>::new_opt(
        *signature.r() + C::Scalar::ONE,
        *signature.s(),
    );
    let bumped_s = Signature::<C>::new_opt(
        *signature.r(),
        *signature.s() + C::Scalar::ONE,
    );
    for changed in [bumped_r, bumped_s].into_iter().flatten() {
        assert!(!Ecdsa::<C, H>::verify(pair.public(), message, &changed));
    }
    assert_eq!(Signature::<C>::decode(&signature.encode()), Ok(signature));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn signature_laws(
        secret in prop::collection::vec(any::<u8>(), 1..66),
        message in prop::collection::vec(any::<u8>(), 0..200),
        other in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        laws::<P256, Sha256>(&secret, &message, &other);
        laws::<P384, Sha384>(&secret, &message, &other);
        laws::<P521, Sha512>(&secret, &message, &other);
        // A hash longer than n (truncated) and one shorter (padded).
        laws::<P256, Sha512>(&secret, &message, &other);
        laws::<P521, Sha256>(&secret, &message, &other);
    }
}

/// The run-time hash dispatch is the static scheme: for every hash name,
/// `sign_with_hash` gives what `Ecdsa::<C, H>` gives for its `H` (signing
/// is deterministic), and the signature verifies under that name only.
fn run_time_hash<C>(message: &[u8])
where
    C: ShortWeierstrass,
{
    let pair = EcKeyPair::<C>::from_secret_opt(C::Scalar::ONE + C::Scalar::ONE)
        .unwrap();
    let typed = [
        Ecdsa::<C, Sha1>::sign_encoded(&pair, message),
        Ecdsa::<C, Sha224>::sign_encoded(&pair, message),
        Ecdsa::<C, Sha256>::sign_encoded(&pair, message),
        Ecdsa::<C, Sha384>::sign_encoded(&pair, message),
        Ecdsa::<C, Sha512>::sign_encoded(&pair, message),
    ];
    for (hash, typed) in Algorithm::ALL.into_iter().zip(typed) {
        let signature = sign_with_hash(hash, &pair, message).unwrap();
        assert_eq!(signature, typed.unwrap(), "{hash:?}");
        for other in Algorithm::ALL {
            assert_eq!(
                verify_with_hash(other, pair.public(), message, &signature),
                other == hash,
                "{hash:?} verified as {other:?}"
            );
        }
    }
}

#[test]
fn run_time_hashes() {
    run_time_hash::<P256>(b"sample");
    run_time_hash::<P384>(b"");
    run_time_hash::<P521>(b"test");
}

/// The empty message, and the secret scalars 1 and $n - 1$.
#[test]
fn boundaries() {
    let one = <C1 as Curve>::Scalar::ONE;
    for d in [one, -one] {
        let pair = EcKeyPair::<C1>::from_secret_opt(d).unwrap();
        let signature = Ecdsa::<C1, Sha256>::sign(&pair, b"").unwrap();
        assert!(Ecdsa::<C1, Sha256>::verify(pair.public(), b"", &signature));
    }
}

/// The curve of the boundary and encoding tests.
type C1 = P256;

/// The DER of `ECDSA-Sig-Value` with these integer contents.
fn sig_value(r: &[u8], s: &[u8]) -> Vec<u8> {
    let int = |c: &[u8]| {
        let mut v = vec![0x02, u8::try_from(c.len()).unwrap()];
        v.extend_from_slice(c);
        v
    };
    let body = [int(r), int(s)].concat();
    let mut v = vec![0x30, u8::try_from(body.len()).unwrap()];
    v.extend(body);
    v
}

/// What the decoder rejects: zero, $n$ or more, a negative or non-minimal
/// INTEGER, trailing bytes. And a known encoding (RFC 6979 A.2.5, SHA-256,
/// "sample") written exactly.
#[test]
fn encoding() {
    let n = <C1 as Curve>::Scalar::modulus_be();
    let one = [0x01];
    let decode = Signature::<C1>::decode;
    assert_eq!(
        decode(&sig_value(&one, &one)).map(|s| *s.r()),
        Ok(<C1 as Curve>::Scalar::ONE)
    );
    assert_eq!(
        decode(&sig_value(&[0x00], &one)),
        Err(InvalidEncoding),
        "r = 0"
    );
    assert_eq!(
        decode(&sig_value(&one, &[0x00])),
        Err(InvalidEncoding),
        "s = 0"
    );
    let n_int = [&[0x00][..], &n].concat();
    assert_eq!(
        decode(&sig_value(&n_int, &one)),
        Err(InvalidEncoding),
        "r = n"
    );
    assert_eq!(
        decode(&sig_value(&[0xff], &one)),
        Err(InvalidEncoding),
        "negative"
    );
    assert_eq!(
        decode(&sig_value(&[0x00, 0x01], &one)),
        Err(InvalidEncoding),
        "padded"
    );
    let mut trailing = sig_value(&one, &one);
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(InvalidEncoding), "trailing");

    let v = &P256_VECTORS.signatures[2];
    assert_eq!((v.hash, v.message), ("SHA-256", "sample"));
    let expected = sig_value(
        &[&[0x00][..], &hex(v.r)].concat(),
        &[&[0x00][..], &hex(v.s)].concat(),
    );
    let signature =
        Signature::<C1>::new_opt(scalar::<C1>(v.r), scalar::<C1>(v.s)).unwrap();
    assert_eq!(signature.encode(), expected);
}

/// The syntax and the range: zero and $n$ are signature values that do not
/// decode, the malformed encodings are not signature values. OpenSSL fails
/// verification for the first kind and errs for the second.
#[test]
fn syntax_and_range() {
    let n = <C1 as Curve>::Scalar::modulus_be();
    let one = [0x01];
    let n_int = [&[0x00][..], &n].concat();
    for out_of_range in [sig_value(&[0x00], &one), sig_value(&n_int, &one)] {
        assert!(super::is_sig_value(&out_of_range));
        assert_eq!(
            Signature::<C1>::decode(&out_of_range),
            Err(InvalidEncoding)
        );
    }
    let mut trailing = sig_value(&one, &one);
    trailing.push(0);
    for malformed in [
        sig_value(&[0xff], &one),
        sig_value(&[0x00, 0x01], &one),
        trailing,
        vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        Vec::new(),
    ] {
        assert!(!super::is_sig_value(&malformed), "{malformed:02x?}");
    }
}

proptest! {
    /// What decodes is a signature value: decoding is the syntax, then
    /// the range.
    #[test]
    fn decoding_refines_the_syntax(bytes in prop::collection::vec(any::<u8>(), 0..80)) {
        if Signature::<C1>::decode(&bytes).is_ok() {
            prop_assert!(super::is_sig_value(&bytes));
        }
    }
}

/// The records of one `[P-256,SHA-256]` section of a CAVP `.rsp` file, each
/// field name with its value as text.
fn cavp_records(text: &str, section: &str) -> Vec<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut inside = false;
    let mut record: Vec<(String, String)> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == format!("[{section}]");
            continue;
        }
        if !inside {
            continue;
        }
        if line.is_empty() {
            if !record.is_empty() {
                out.push(std::mem::take(&mut record));
            }
        } else if let Some((name, value)) = line.split_once(" = ") {
            record.push((name.to_owned(), value.to_owned()));
        }
    }
    if inside && !record.is_empty() {
        out.push(record);
    }
    out
}

fn field<'a>(record: &'a [(String, String)], name: &str) -> &'a str {
    &record.iter().find(|(n, _)| n == name).unwrap().1
}

/// The bytes of a CAVP hexadecimal integer, which omits a leading zero
/// digit (P-521 values have an odd number of digits).
fn hex_int(digits: &str) -> Vec<u8> {
    if digits.len() % 2 == 1 {
        hex(&format!("0{digits}"))
    } else {
        hex(digits)
    }
}

/// The point `04 || x || y`, when it is one of the curve.
fn point_opt<C>(
    x: &str,
    y: &str,
) -> Option<crate::models::weierstrass::affine::Affine<C>>
where
    C: ShortWeierstrass,
{
    let mut bytes = vec![0x04];
    bytes.extend(coordinate::<C>(x));
    bytes.extend(coordinate::<C>(y));
    crate::models::weierstrass::affine::Affine::<C>::decode_opt(&bytes)
}

/// The scalar a hexadecimal integer is, when it is in $[0, n - 1]$.
fn scalar_opt<C>(hex_be: &str) -> Option<C::Scalar>
where
    C: ShortWeierstrass,
{
    let digits = hex_int(hex_be);
    let mut bytes = vec![0u8; C::Scalar::BYTES.checked_sub(digits.len())?];
    bytes.extend(digits);
    let (s, valid) = C::Scalar::from_bytes_be(&bytes);
    valid.to_bool_vartime().then_some(s)
}

/// A coordinate's bytes at the base field's width.
fn coordinate<C>(digits: &str) -> Vec<u8>
where
    C: ShortWeierstrass,
{
    let width = 2 * C::Base::BYTES;
    hex(&format!("{digits:0>width$}"))
}

/// SigVer: NIST's verdict for every vector of one section. A changed key
/// that is not on the curve cannot be a verifying key, which counts as a
/// rejection.
fn sigver<C, H>(text: &str, section: &str)
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    let records = cavp_records(text, section);
    assert_eq!(records.len(), 15, "{section}");
    for (i, r) in records.iter().enumerate() {
        let expected = field(r, "Result").starts_with('P');
        let verdict = match (
            point_opt::<C>(field(r, "Qx"), field(r, "Qy")),
            scalar_opt::<C>(field(r, "R")).zip(scalar_opt::<C>(field(r, "S"))),
        ) {
            (Some(key), Some((rr, ss))) => Signature::<C>::new_opt(rr, ss)
                .is_some_and(|sig| {
                    Ecdsa::<C, H>::verify(&key, &hex(field(r, "Msg")), &sig)
                }),
            _ => false,
        };
        assert_eq!(
            verdict,
            expected,
            "{section} vector {i}: {}",
            field(r, "Result")
        );
    }
}

/// SigGen: with NIST's nonce $k$, signing gives NIST's $(R, S)$, and $d$
/// gives $Q$.
fn siggen<C, H>(text: &str, section: &str)
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    let records = cavp_records(text, section);
    assert_eq!(records.len(), 15, "{section}");
    for (i, r) in records.iter().enumerate() {
        let d = scalar_opt::<C>(field(r, "d")).unwrap();
        let pair = EcKeyPair::<C>::from_secret_opt(d).unwrap();
        let (qx, qy) = pair.public().coordinates_opt().unwrap();
        assert_eq!(
            qx.to_bytes_be(),
            coordinate::<C>(field(r, "Qx")),
            "{section} {i} Qx"
        );
        assert_eq!(
            qy.to_bytes_be(),
            coordinate::<C>(field(r, "Qy")),
            "{section} {i} Qy"
        );
        let digest = super::reduce_once::<C>(&bits2int::<C>(&H::digest(&hex(
            field(r, "Msg"),
        ))));
        let k = scalar_opt::<C>(field(r, "k")).unwrap();
        let signature = Ecdsa::<C, H>::sign_with_opt(&d, &digest, &k).unwrap();
        assert_eq!(
            *signature.r(),
            scalar_opt::<C>(field(r, "R")).unwrap(),
            "{section} {i} R"
        );
        assert_eq!(
            *signature.s(),
            scalar_opt::<C>(field(r, "S")).unwrap(),
            "{section} {i} S"
        );
        assert!(Ecdsa::<C, H>::verify(
            pair.public(),
            &hex(field(r, "Msg")),
            &signature
        ));
    }
}

/// One curve, every SHA-2 hash, in SigVer and SigGen (`cavp/ecdsa/` of the
/// fixtures: `SigVer.rsp`, and `SigGen.txt`, the one with $d$ and $k$, of
/// NIST's
/// [`186-4ecdsatestvectors.zip`], unchanged).
///
/// [`186-4ecdsatestvectors.zip`]: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
fn cavp<C>(curve: &str)
where
    C: ShortWeierstrass,
{
    let ver = baldssl_test_utils::fixture("cavp/ecdsa/SigVer.rsp");
    let gen_ = baldssl_test_utils::fixture("cavp/ecdsa/SigGen.txt");
    sigver::<C, Sha224>(&ver, &format!("{curve},SHA-224"));
    sigver::<C, Sha256>(&ver, &format!("{curve},SHA-256"));
    sigver::<C, Sha384>(&ver, &format!("{curve},SHA-384"));
    sigver::<C, Sha512>(&ver, &format!("{curve},SHA-512"));
    siggen::<C, Sha224>(&gen_, &format!("{curve},SHA-224"));
    siggen::<C, Sha256>(&gen_, &format!("{curve},SHA-256"));
    siggen::<C, Sha384>(&gen_, &format!("{curve},SHA-384"));
    siggen::<C, Sha512>(&gen_, &format!("{curve},SHA-512"));
}

#[test]
fn cavp_p256() {
    cavp::<P256>("P-256");
}

#[test]
fn cavp_p384() {
    cavp::<P384>("P-384");
}

#[test]
fn cavp_p521() {
    cavp::<P521>("P-521");
}

/// Signatures made by OpenSSL (`ecdsa/openssl-signatures.txt`,
/// `scripts/gen-ecdsa-signatures.sh`, random nonces) verify, and do not on
/// another message.
fn openssl_signatures<C, H>(curve: &str, hash: &str) -> usize
where
    C: ShortWeierstrass,
    H: DrbgHash,
{
    let text = baldssl_test_utils::fixture("ecdsa/openssl-signatures.txt");
    let mut seen = 0;
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] != curve || f[1] != hash {
            continue;
        }
        let message = if f[2] == "-" { Vec::new() } else { hex(f[2]) };
        let key = crate::models::weierstrass::affine::Affine::<C>::decode_opt(
            &hex(f[3]),
        )
        .unwrap();
        let signature = Signature::<C>::decode(&hex(f[4])).unwrap();
        assert!(Ecdsa::<C, H>::verify(&key, &message, &signature), "{line}");
        assert_eq!(signature.encode(), hex(f[4]), "re-encodes: {line}");
        let mut other = message.clone();
        other.push(0);
        assert!(!Ecdsa::<C, H>::verify(&key, &other, &signature));
        seen += 1;
    }
    seen
}

#[test]
fn openssl() {
    let mut seen = 0;
    for (curve, f) in [
        (
            "P-256",
            openssl_signatures::<P256, Sha256> as fn(&str, &str) -> usize,
        ),
        ("P-384", openssl_signatures::<P384, Sha256>),
        ("P-521", openssl_signatures::<P521, Sha256>),
    ] {
        seen += f(curve, "SHA-256");
    }
    seen += openssl_signatures::<P256, Sha224>("P-256", "SHA-224");
    seen += openssl_signatures::<P256, Sha384>("P-256", "SHA-384");
    seen += openssl_signatures::<P256, Sha512>("P-256", "SHA-512");
    seen += openssl_signatures::<P384, Sha224>("P-384", "SHA-224");
    seen += openssl_signatures::<P384, Sha384>("P-384", "SHA-384");
    seen += openssl_signatures::<P384, Sha512>("P-384", "SHA-512");
    seen += openssl_signatures::<P521, Sha224>("P-521", "SHA-224");
    seen += openssl_signatures::<P521, Sha384>("P-521", "SHA-384");
    seen += openssl_signatures::<P521, Sha512>("P-521", "SHA-512");
    assert_eq!(seen, 144, "every signature of the fixture");
}
