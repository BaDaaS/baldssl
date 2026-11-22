//! SHA-1, [FIPS 180-4][fips180] sections 5.3.1 and 6.1.
//!
//! SHA-1 is collision-broken (Stevens et al., "The first collision for full
//! SHA-1", CRYPTO 2017; Leurent and Peyrin, "SHA-1 is a Shambles", USENIX
//! Security 2020). It is provided only for fingerprints and for reading
//! legacy signatures, never for producing new ones.
//! Single-letter names (`a` to `h`, `w`, `t`) are the specification's.
//!
//! [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names
)]

use crate::Digest;

const H: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (t, &wt) in w.iter().enumerate() {
        let (f, k) = match t {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wt);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e]) {
        *x = x.wrapping_add(v);
    }
}

/// SHA-1.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    len: u64,
}

impl Digest for Sha1 {
    const OUTPUT_LEN: usize = 20;
    const BLOCK_LEN: usize = 64;

    fn new() -> Self {
        Sha1 {
            h: H,
            buf: [0; 64],
            buf_len: 0,
            len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take]
                .copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            let block = self.buf;
            compress(&mut self.h, &block);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            compress(&mut self.h, block);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    fn finalize(mut self) -> Vec<u8> {
        let bits = self.len.wrapping_mul(8);
        let mut pad = [0u8; 64];
        pad[0] = 0x80;
        let zeros = (119 - self.buf_len) % 64;
        let mut tail = Vec::with_capacity(zeros + 9);
        tail.extend_from_slice(&pad[..=zeros]);
        tail.extend_from_slice(&bits.to_be_bytes());
        self.update(&tail);
        debug_assert_eq!(self.buf_len, 0);
        self.h.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}
