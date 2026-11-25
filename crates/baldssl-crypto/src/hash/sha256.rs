//! SHA-224 and SHA-256, [FIPS 180-4][fips180] sections 5.3.2, 5.3.3 and 6.2.
//!
//! Indexing is into fixed-size arrays with loop bounds equal to their length,
//! so it cannot fail; the arithmetic is explicitly `wrapping_*` (addition
//! modulo 2^32 is the specification, not an overflow).
//! Single-letter names (`a` to `h`, `w`, `t`) are the specification's.
//!
//! [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names
)]

use baldssl_core::num::usize_to_u64;

use super::PADDING_START;
use crate::{Digest, secret::wipe};

/// The constants $K_0, \dots, K_{63}$ ([FIPS 180-4][fips180], section
/// 4.2.2).
///
/// [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial hash value of SHA-256 ([FIPS 180-4][fips180], section
/// 5.3.3).
///
/// [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
const H256: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The initial hash value of SHA-224 ([FIPS 180-4][fips180], section
/// 5.3.2).
///
/// [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
const H224: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

/// The compression function ([FIPS 180-4][fips180], section 6.2.2).
///
/// [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7)
            ^ w[t - 15].rotate_right(18)
            ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17)
            ^ w[t - 2].rotate_right(19)
            ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(v);
    }
    wipe(&mut w);
}

/// Shared SHA-256 engine; the variants differ in IV and truncation.
#[derive(Clone)]
struct Engine {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    /// Message length in bytes, modulo 2^64 (the bit length is modulo 2^64
    /// as the standard requires once multiplied by 8).
    len: u64,
}

/// Overwrites the chaining value and the buffer.
impl Drop for Engine {
    fn drop(&mut self) {
        wipe(&mut self.h);
        wipe(&mut self.buf);
    }
}

impl Engine {
    fn new(iv: [u32; 8]) -> Self {
        Engine {
            h: iv,
            buf: [0; 64],
            buf_len: 0,
            len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(usize_to_u64(data.len()));
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take]
                .copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            compress(&mut self.h, &self.buf);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            compress(&mut self.h, block);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    fn finalize(mut self) -> [u32; 8] {
        let bits = self.len.wrapping_mul(8);
        let mut pad = [0u8; 72];
        pad[0] = PADDING_START;
        let zeros = (119 - self.buf_len) % 64;
        let mut tail = Vec::with_capacity(zeros + 9);
        tail.extend_from_slice(&pad[..=zeros]);
        tail.extend_from_slice(&bits.to_be_bytes());
        self.update(&tail);
        debug_assert_eq!(self.buf_len, 0);
        self.h
    }
}

fn output(h: &[u32; 8], words: usize) -> Vec<u8> {
    h[..words].iter().flat_map(|w| w.to_be_bytes()).collect()
}

/// SHA-256.
#[derive(Clone)]
pub struct Sha256(Engine);

impl crate::sealed::Sealed for Sha256 {}

impl Digest for Sha256 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
    fn new() -> Self {
        Sha256(Engine::new(H256))
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> Vec<u8> {
        output(&self.0.finalize(), 8)
    }
}

/// SHA-224: SHA-256 with another IV, truncated to 224 bits.
#[derive(Clone)]
pub struct Sha224(Engine);

impl crate::sealed::Sealed for Sha224 {}

impl Digest for Sha224 {
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 64;
    fn new() -> Self {
        Sha224(Engine::new(H224))
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> Vec<u8> {
        output(&self.0.finalize(), 7)
    }
}
