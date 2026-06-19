//! wolfCompute — the 278-iteration byte-permutation core (astrobwt.zig:187).
//!
//! Each iteration copies the previous 256-byte chunk, edits a ≤32-byte window via a
//! CodeLUT opcode, conditionally re-mixes the rolling hash (xxh64/fnv1a/siphash), and
//! occasionally RC4-re-encrypts the whole chunk (recording a template group marker).
//! Byte-exact to the validated oracle; correctness is gated by the golden DATALEN/OUT
//! vectors in the selftest.

use crate::codelut::{wolf_branch, Reglut, CODELUT};
use crate::primitives::{fnv1a, siphash, xxh64, Rc4};
#[cfg(target_arch = "x86_64")]
use std::sync::Once;

// AVX2 wolfPermute (vendor/wolf/wolf_avx2.cpp → reference simd_wolf.h). x86-only: processes
// the ≤32-byte window in one pass, byte-identical to the scalar wolf_branch (gated by the
// `avx2_matches_scalar` test). It reads/writes 32 bytes from p1, so the working buffers are
// padded to 288. On non-x86 there is no AVX2 TU — the scalar wolf_branch path runs instead.
#[cfg(target_arch = "x86_64")]
extern "C" {
    fn wolf_init_lut(codelut: *const u32);
    fn wolf_permute_avx2(input: *const u8, out: *mut u8, op: u8, p1: u8, p2: u8);
}

#[cfg(target_arch = "x86_64")]
static LUT_INIT: Once = Once::new();
#[cfg(target_arch = "x86_64")]
#[inline]
fn ensure_lut_init() {
    LUT_INIT.call_once(|| unsafe { wolf_init_lut(CODELUT.as_ptr()) });
}
#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn ensure_lut_init() {}

/// MAX_LENGTH (72000) + 64 padding. sData/sa scratch size.
pub const SCRATCH: usize = 72000 + 64;
/// Working-buffer size: 256-byte chunk + 32-byte tail so the AVX2 permute can read/write
/// a full 32-byte vector from any p1 ≤ 255 without overrunning.
const WBUF: usize = 256 + 32;

pub struct Worker {
    pub s_data: Vec<u8>,
    pub sa: Vec<i32>,
    pub key: Rc4,
    pub lhash: u64,
    pub prev_lhash: u64,
    pub tries: u16,
    pub template_markers: [u16; 320],
    pub n_templates: u32,
    pub data_len: u32,
    pub a: u8,
}

impl Worker {
    pub fn new() -> Self {
        Worker {
            s_data: vec![0u8; SCRATCH],
            sa: vec![0i32; SCRATCH],
            key: Rc4::new(),
            lhash: 0,
            prev_lhash: 0,
            tries: 0,
            template_markers: [0u16; 320],
            n_templates: 0,
            data_len: 0,
            a: 0,
        }
    }

    /// Run wolfCompute over `self.s_data` (seeded with the 256-byte RC4 block, lhash/
    /// prev_lhash set, tries=0). Fills s_data[0..data_len], sets data_len, template
    /// markers, n_templates.
    pub fn wolf_compute(&mut self, reglut: &Reglut) {
        ensure_lut_init();
        #[cfg(target_arch = "x86_64")]
        let use_avx2 = std::is_x86_feature_detected!("avx2");
        #[cfg(not(target_arch = "x86_64"))]
        let use_avx2 = false;

        let mut template_idx: u32 = 0;
        let mut chunk_count: u32 = 1;
        let mut first_chunk: i32 = 0;
        self.tries = 0;

        let mut prev = [0u8; WBUF];
        let mut chunk = [0u8; WBUF];

        for _it in 0..278u32 {
            self.tries = self.tries.wrapping_add(1);
            let tries = self.tries;

            // Step A — control bytes.
            let random_switcher = self.prev_lhash ^ self.lhash ^ (tries as u64);
            let op = random_switcher as u8;
            let mut p1 = (random_switcher >> 8) as u8;
            let mut p2 = (random_switcher >> 16) as u8;

            // Step B — sort + clamp window to ≤32 bytes.
            if p1 > p2 {
                std::mem::swap(&mut p1, &mut p2);
            }
            if p2 - p1 > 32 {
                p2 = p1.wrapping_add((p2 - p1) & 0x1f);
            }
            let p1u = p1 as usize;
            let p2u = p2 as usize;

            // Step C — snapshot previous chunk, copy into the current chunk slot.
            let chunk_off = (tries as usize - 1) * 256;
            let prev_off = if tries == 1 { 0 } else { (tries as usize - 2) * 256 };
            prev[..256].copy_from_slice(&self.s_data[prev_off..prev_off + 256]);
            chunk.copy_from_slice(&prev);

            // Step D — apply the opcode to chunk[p1..p2).
            if op == 253 {
                let pv = prev[p2u];
                for i in p1u..p2u {
                    let mut c = chunk[i].rotate_left(3);
                    c ^= c.rotate_left(2);
                    c ^= pv;
                    c = c.rotate_left(3);
                    chunk[i] = c;
                    self.prev_lhash = self.lhash.wrapping_add(self.prev_lhash);
                    self.lhash = xxh64(&chunk[0..p2u]);
                }
            } else if op == 53 || op == 55 || op == 188 || op == 249 {
                for c in &mut chunk[p1u..p2u] {
                    *c = 0;
                }
            } else {
                if op >= 254 {
                    self.key.set_key(&prev[..256]);
                }
                let ridx = reglut.reg_idx[op as usize];
                if ridx != 0xFF {
                    let base = ridx as usize * 256;
                    for i in p1u..p2u {
                        chunk[i] = reglut.lut[base + prev[i] as usize];
                    }
                } else if use_avx2 {
                    // AVX2: 32 bytes/op (reads prev[p1..p1+32], writes chunk[p1..p1+32] blended).
                    // x86-only; on other arches use_avx2 is always false and this is dead.
                    #[cfg(target_arch = "x86_64")]
                    unsafe {
                        wolf_permute_avx2(prev.as_ptr(), chunk.as_mut_ptr(), op, p1, p2)
                    };
                } else {
                    let pv = prev[p2u];
                    let code = CODELUT[op as usize];
                    for i in p1u..p2u {
                        chunk[i] = wolf_branch(prev[i], pv, code);
                    }
                }
                if op == 0 && (p2 - p1) % 2 == 1 {
                    let t1 = chunk[p1u];
                    let t2 = chunk[p2u];
                    chunk[p1u] = t2.reverse_bits();
                    chunk[p2u] = t1.reverse_bits();
                }
            }

            // Step E — conditional rolling-hash re-mix (independent ifs, in order).
            let a = chunk[p1u].wrapping_sub(chunk[p2u]);
            self.a = a;
            if a < 0x10 {
                self.prev_lhash = self.lhash.wrapping_add(self.prev_lhash);
                self.lhash = xxh64(&chunk[0..p2u]);
            }
            if a < 0x20 {
                self.prev_lhash = self.lhash.wrapping_add(self.prev_lhash);
                self.lhash = fnv1a(&chunk[0..p2u]);
            }
            if a < 0x30 {
                self.prev_lhash = self.lhash.wrapping_add(self.prev_lhash);
                self.lhash = siphash(tries as u64, self.prev_lhash, &chunk[0..p2u]);
            }

            // Step F — RC4 re-encrypt + template marker on small A (group boundary).
            if a <= 0x40 {
                self.key.process(&mut chunk[..256]);
                self.template_markers[template_idx as usize] =
                    (((first_chunk as u32) << 7) | chunk_count) as u16;
                template_idx += if tries > 1 { 1 } else { 0 };
                first_chunk = tries as i32 - 1;
                chunk_count = 1;
            } else {
                chunk_count += 1;
            }

            // Step G — byte-255 mixing.
            chunk[255] ^= chunk[p1u] ^ chunk[p2u];

            // Write the finished chunk back.
            self.s_data[chunk_off..chunk_off + 256].copy_from_slice(&chunk[..256]);

            // Step H — early exit.
            if tries > 276 || (chunk[255] >= 0xf0 && tries > 260) {
                break;
            }
        }

        // Final template marker flush.
        self.template_markers[template_idx as usize] = (((first_chunk as u32) << 7) | chunk_count) as u16;
        template_idx += 1;
        self.n_templates = template_idx;

        // data_len from the last chunk's bytes [253],[254], then strip trailing zeros.
        let chunk_off = (self.tries as usize - 1) * 256;
        let last = &self.s_data[chunk_off..chunk_off + 256];
        let tail = (((last[253] as u64) << 8) | (last[254] as u64)) & 0x3ff;
        let mut data_len = ((self.tries as i64 - 4) * 256 + tail as i64) as u32;
        while data_len > 0 && self.s_data[data_len as usize - 1] == 0 {
            data_len -= 1;
        }
        self.data_len = data_len;
    }
}

impl Default for Worker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codelut::is_branched;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn avx2_matches_scalar() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        ensure_lut_init();
        let mut prev = [0u8; WBUF];
        let mut s = 0x1234_5678_9abc_def0u64;
        for b in prev.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = s as u8;
        }
        let windows: &[(u8, u8)] =
            &[(0, 32), (5, 20), (10, 42), (0, 1), (200, 232), (224, 255), (100, 131), (50, 82), (7, 7)];
        for op in 0u16..256 {
            let op = op as u8;
            if !is_branched(op) {
                continue;
            }
            for &(p1, p2) in windows {
                let mut c_avx = prev;
                let mut c_scal = prev;
                unsafe { wolf_permute_avx2(prev.as_ptr(), c_avx.as_mut_ptr(), op, p1, p2) };
                let pv = prev[p2 as usize];
                let code = CODELUT[op as usize];
                for i in p1 as usize..p2 as usize {
                    c_scal[i] = wolf_branch(prev[i], pv, code);
                }
                assert_eq!(&c_avx[..256], &c_scal[..256], "op={op} p1={p1} p2={p2}");
            }
        }
    }
}
