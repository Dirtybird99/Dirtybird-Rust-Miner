//! Byte-exact crypto primitives for AstroBWTv3, ported from the validated reference
//! pipeline. SHA-256 (sha2) and XXH64
//! (xxhash-rust) are canonical; Salsa20/20, RC4, FNV1a, SipHash-2-4 are hand-ported to
//! match the oracle bit-for-bit. Every function carries its KAT in the tests below.

use sha2::{Digest, Sha256};

#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Canonical XXH64 with the pipeline's fixed seed of 0.
#[inline]
pub fn xxh64(data: &[u8]) -> u64 {
    xxhash_rust::xxh64::xxh64(data, 0)
}

// ---------------------------------------------------------------------------
// Salsa20/20 — key=32B, IV=0, block counter=0; emits 256 bytes (4 blocks).
// ---------------------------------------------------------------------------
#[inline(always)]
fn rd(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

pub fn salsa20_expand(key: &[u8; 32], out: &mut [u8; 256]) {
    let sigma = b"expand 32-byte k";
    let mut v: [u32; 16] = [
        rd(&sigma[0..4]), rd(&key[0..4]),   rd(&key[4..8]),    rd(&key[8..12]),
        rd(&key[12..16]), rd(&sigma[4..8]), 0,                 0,
        0,                0,                rd(&sigma[8..12]),  rd(&key[16..20]),
        rd(&key[20..24]), rd(&key[24..28]), rd(&key[28..32]),  rd(&sigma[12..16]),
    ];

    let mut off = 0usize;
    for _ in 0..4 {
        let mut x = v;
        let mut i = 20i32;
        while i > 0 {
            x[4]  ^= x[0].wrapping_add(x[12]).rotate_left(7);
            x[8]  ^= x[4].wrapping_add(x[0]).rotate_left(9);
            x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
            x[0]  ^= x[12].wrapping_add(x[8]).rotate_left(18);
            x[9]  ^= x[5].wrapping_add(x[1]).rotate_left(7);
            x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
            x[1]  ^= x[13].wrapping_add(x[9]).rotate_left(13);
            x[5]  ^= x[1].wrapping_add(x[13]).rotate_left(18);
            x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
            x[2]  ^= x[14].wrapping_add(x[10]).rotate_left(9);
            x[6]  ^= x[2].wrapping_add(x[14]).rotate_left(13);
            x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);
            x[3]  ^= x[15].wrapping_add(x[11]).rotate_left(7);
            x[7]  ^= x[3].wrapping_add(x[15]).rotate_left(9);
            x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
            x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);
            x[1]  ^= x[0].wrapping_add(x[3]).rotate_left(7);
            x[2]  ^= x[1].wrapping_add(x[0]).rotate_left(9);
            x[3]  ^= x[2].wrapping_add(x[1]).rotate_left(13);
            x[0]  ^= x[3].wrapping_add(x[2]).rotate_left(18);
            x[6]  ^= x[5].wrapping_add(x[4]).rotate_left(7);
            x[7]  ^= x[6].wrapping_add(x[5]).rotate_left(9);
            x[4]  ^= x[7].wrapping_add(x[6]).rotate_left(13);
            x[5]  ^= x[4].wrapping_add(x[7]).rotate_left(18);
            x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
            x[8]  ^= x[11].wrapping_add(x[10]).rotate_left(9);
            x[9]  ^= x[8].wrapping_add(x[11]).rotate_left(13);
            x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);
            x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
            x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
            x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
            x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
            i -= 2;
        }
        for j in 0..16 {
            let w = x[j].wrapping_add(v[j]);
            out[off..off + 4].copy_from_slice(&w.to_le_bytes());
            off += 4;
        }
        v[8] = v[8].wrapping_add(1);
        if v[8] == 0 {
            v[9] = v[9].wrapping_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// RC4 — state persists across process() calls; setKey resets perm + x/y cursors.
// ---------------------------------------------------------------------------
pub struct Rc4 {
    x: u32,
    y: u32,
    s: [u32; 256],
}

impl Rc4 {
    #[inline]
    pub fn new() -> Self {
        Rc4 { x: 0, y: 0, s: [0; 256] }
    }

    pub fn set_key(&mut self, key: &[u8]) {
        self.x = 0;
        self.y = 0;
        for i in 0..256 {
            self.s[i] = i as u32;
        }
        let mut j: u32 = 0;
        for i in 0..256 {
            j = (j + self.s[i] + key[i % key.len()] as u32) & 0xff;
            self.s.swap(i, j as usize);
        }
    }

    /// In-place RC4 (the only mode the pipeline uses: process(buf, buf)).
    pub fn process(&mut self, data: &mut [u8]) {
        let mut x = self.x;
        let mut y = self.y;
        for b in data.iter_mut() {
            x = (x + 1) & 0xff;
            y = (y + self.s[x as usize]) & 0xff;
            self.s.swap(x as usize, y as usize);
            let k = self.s[((self.s[x as usize] + self.s[y as usize]) & 0xff) as usize];
            *b ^= k as u8;
        }
        self.x = x;
        self.y = y;
    }
}

impl Default for Rc4 {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FNV-1a 64-bit.
// ---------------------------------------------------------------------------
const FNV_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[inline]
pub fn fnv1a(data: &[u8]) -> u64 {
    let mut h = FNV_BASIS;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

// ---------------------------------------------------------------------------
// SipHash-2-4 — k0,k1 used directly (k0=tries, k1=prev_lhash). HighwayHash variant.
// ---------------------------------------------------------------------------
#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

pub fn siphash(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0 = 0x736f6d6570736575u64 ^ k0;
    let mut v1 = 0x646f72616e646f6du64 ^ k1;
    let mut v2 = 0x6c7967656e657261u64 ^ k0;
    let mut v3 = 0x7465646279746573u64 ^ k1;

    let full = data.len() - (data.len() % 8);
    let mut i = 0;
    while i < full {
        let m = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 8;
    }

    let mut b: u64 = (data.len() as u64 & 0xff) << 56;
    let mut j = 0;
    while full + j < data.len() {
        b |= (data[full + j] as u64) << (8 * j);
        j += 1;
    }
    v3 ^= b;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha256_kat() {
        assert_eq!(hex(&sha256(b"a")), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
    }

    #[test]
    fn fnv1a_kat() {
        assert_eq!(fnv1a(b""), FNV_BASIS);
        assert_eq!(fnv1a(b"a"), 0xaf63dc4c8601ec8c);
    }

    #[test]
    fn xxh64_kat() {
        assert_eq!(xxh64(b""), 0xef46db3751d8e999);
        assert_eq!(xxh64(b"abc"), 0x44bc2cf5ad770999);
    }

    #[test]
    fn siphash_kat() {
        assert_eq!(siphash(1, 0, b""), 0x54e761ac4b1ca3de);
        assert_eq!(siphash(1, 2, b"abc"), 0xd15ad05b2871319d);
        let pat: [u8; 48] = std::array::from_fn(|i| i as u8);
        assert_eq!(siphash(7, 0xdeadbeef, &pat), 0xfdfd6564cd6cb327);
        let p15: [u8; 15] = std::array::from_fn(|i| i as u8);
        assert_eq!(siphash(0xabcdef, 0x12345, &p15), 0x71bfad869ecfeeca);
    }

    #[test]
    fn rc4_kat() {
        let mut rc4 = Rc4::new();
        rc4.set_key(b"Key");
        let mut ct = *b"Plaintext";
        rc4.process(&mut ct);
        assert_eq!(ct, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
    }

    #[test]
    fn salsa20_against_pipeline_checkpoint() {
        // key = SHA256("a"); first 32 bytes of the 256-byte keystream must match the
        // "a" SALSA golden checkpoint (checkpoints.txt case "a").
        let key = sha256(b"a");
        let mut out = [0u8; 256];
        salsa20_expand(&key, &mut out);
        assert_eq!(hex(&out[..32]), "be3aeb212c8aebc3452acdb2d339c7bf1bcd8bde1ec79a2da222771158c61f94");
    }
}
