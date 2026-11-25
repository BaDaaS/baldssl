//! SHA-1, [FIPS 180-4][fips180] sections 5.3.1 and 6.1.
//!
//! SHA-1 is collision-broken (Stevens, Bursztein, Karpman, Albertini and
//! Markov, [*The first collision for full SHA-1*][stevens], CRYPTO 2017;
//! Leurent and Peyrin, [*SHA-1 is a Shambles*][shambles], USENIX Security
//! 2020). It is provided only for fingerprints and for reading
//! legacy signatures, never for producing new ones.
//! Single-letter names (`a` to `h`, `w`, `t`) are the specification's.
//!
//! [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
//! [stevens]: https://doi.org/10.1007/978-3-319-63688-7_19
//! [shambles]: https://www.usenix.org/conference/usenixsecurity20/presentation/leurent
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names
)]

use baldssl_core::num::usize_to_u64;

use super::PADDING_START;
use crate::{Digest, secret::wipe};

/// The initial hash value $H^{(0)}$ ([FIPS 180-4][fips180], section 5.3.1).
///
/// [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
const H: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// The constants $K_t$ of rounds 0 to 19, 20 to 39, 40 to 59 and 60 to 79
/// ([FIPS 180-4][fips180], section 4.2.1).
///
/// [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
const K: [u32; 4] = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6];

/// The block length in bytes, 512 bits.
const BLOCK: usize = 64;

/// The compression function ([FIPS 180-4][fips180], section 6.1.2).
///
/// [fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
fn compress(h: &mut [u32; 5], block: &[u8; BLOCK]) {
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
            0..=19 => ((b & c) | (!b & d), K[0]),
            20..=39 => (b ^ c ^ d, K[1]),
            40..=59 => ((b & c) | (b & d) | (c & d), K[2]),
            _ => (b ^ c ^ d, K[3]),
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
    wipe(&mut w);
}

/// SHA-1.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; BLOCK],
    buf_len: usize,
    len: u64,
}

impl crate::sealed::Sealed for Sha1 {}

/// Overwrites the chaining value and the buffer.
impl Drop for Sha1 {
    fn drop(&mut self) {
        wipe(&mut self.h);
        wipe(&mut self.buf);
    }
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

    fn finalize(mut self) -> Vec<u8> {
        let bits = self.len.wrapping_mul(8);
        let mut pad = [0u8; 64];
        pad[0] = PADDING_START;
        let zeros = (119 - self.buf_len) % 64;
        let mut tail = Vec::with_capacity(zeros + 9);
        tail.extend_from_slice(&pad[..=zeros]);
        tail.extend_from_slice(&bits.to_be_bytes());
        self.update(&tail);
        debug_assert_eq!(self.buf_len, 0);
        self.h.iter().flat_map(|w| w.to_be_bytes()).collect()
    }
}
