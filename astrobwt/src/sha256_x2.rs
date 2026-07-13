//! Experimental two-stream SHA-256 using x86_64 SHA-NI.

use sha2::{Digest, Sha256};

/// Hash two independent byte strings, interleaving their SHA-NI rounds when
/// available and otherwise using the portable `sha2` implementation.
pub fn sha256_x2(a: &[u8], b: &[u8]) -> ([u8; 32], [u8; 32]) {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("sha") {
        // SAFETY: the runtime check above guarantees SHA-NI; x86_64 guarantees
        // SSE2 and the function declares its other required target features.
        return unsafe { shani_x2(a, b) };
    }

    (Sha256::digest(a).into(), Sha256::digest(b).into())
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::arch::x86_64::*;

    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const K: [[u32; 4]; 16] = [
        [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5],
        [0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5],
        [0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3],
        [0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174],
        [0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc],
        [0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da],
        [0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7],
        [0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967],
        [0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13],
        [0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85],
        [0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3],
        [0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070],
        [0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5],
        [0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3],
        [0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208],
        [0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
    ];

    #[inline(always)]
    unsafe fn schedule2(
        a0: __m128i,
        a1: __m128i,
        a2: __m128i,
        a3: __m128i,
        b0: __m128i,
        b1: __m128i,
        b2: __m128i,
        b3: __m128i,
    ) -> (__m128i, __m128i) {
        let at1 = _mm_sha256msg1_epu32(a0, a1);
        let bt1 = _mm_sha256msg1_epu32(b0, b1);
        let at2 = _mm_alignr_epi8(a3, a2, 4);
        let bt2 = _mm_alignr_epi8(b3, b2, 4);
        let at3 = _mm_add_epi32(at1, at2);
        let bt3 = _mm_add_epi32(bt1, bt2);
        (_mm_sha256msg2_epu32(at3, a3), _mm_sha256msg2_epu32(bt3, b3))
    }

    macro_rules! rounds4_x2 {
        ($abefa:ident, $cdgha:ident, $wa:expr,
         $abefb:ident, $cdghb:ident, $wb:expr, $i:expr) => {{
            let k = K[$i];
            let kv = _mm_set_epi32(k[3] as i32, k[2] as i32, k[1] as i32, k[0] as i32);
            let ta = _mm_add_epi32($wa, kv);
            let tb = _mm_add_epi32($wb, kv);
            $cdgha = _mm_sha256rnds2_epu32($cdgha, $abefa, ta);
            $cdghb = _mm_sha256rnds2_epu32($cdghb, $abefb, tb);
            let ta = _mm_shuffle_epi32(ta, 0x0e);
            let tb = _mm_shuffle_epi32(tb, 0x0e);
            $abefa = _mm_sha256rnds2_epu32($abefa, $cdgha, ta);
            $abefb = _mm_sha256rnds2_epu32($abefb, $cdghb, tb);
        }};
    }

    macro_rules! schedule_rounds4_x2 {
        ($abefa:ident, $cdgha:ident, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr,
         $abefb:ident, $cdghb:ident, $b0:expr, $b1:expr, $b2:expr, $b3:expr, $b4:expr,
         $i:expr) => {{
            ($a4, $b4) = schedule2($a0, $a1, $a2, $a3, $b0, $b1, $b2, $b3);
            rounds4_x2!($abefa, $cdgha, $a4, $abefb, $cdghb, $b4, $i);
        }};
    }

    #[inline(always)]
    unsafe fn load_state(state: &[u32; 8]) -> (__m128i, __m128i) {
        let p = state.as_ptr().cast::<__m128i>();
        let dcba = _mm_loadu_si128(p);
        let efgh = _mm_shuffle_epi32(_mm_loadu_si128(p.add(1)), 0x1b);
        let cdab = _mm_shuffle_epi32(dcba, 0xb1);
        (
            _mm_alignr_epi8(cdab, efgh, 8),
            _mm_blend_epi16(efgh, cdab, 0xf0),
        )
    }

    #[inline(always)]
    unsafe fn store_state(state: &mut [u32; 8], abef: __m128i, cdgh: __m128i) {
        let feba = _mm_shuffle_epi32(abef, 0x1b);
        let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
        let p = state.as_mut_ptr().cast::<__m128i>();
        _mm_storeu_si128(p, _mm_blend_epi16(feba, dchg, 0xf0));
        _mm_storeu_si128(p.add(1), _mm_alignr_epi8(dchg, feba, 8));
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn hash(a: &[u8], b: &[u8]) -> ([u8; 32], [u8; 32]) {
        let (atail, an) = tail(a);
        let (btail, bn) = tail(b);
        let afull = a.len() / 64;
        let bfull = b.len() / 64;
        let blocks = (afull + an).max(bfull + bn);
        let zero = [0u8; 64];
        let mut sa = INITIAL;
        let mut sb = INITIAL;
        let (mut abefa, mut cdgha) = load_state(&sa);
        let (mut abefb, mut cdghb) = load_state(&sb);

        for i in 0..blocks {
            let active_a = i < afull + an;
            let active_b = i < bfull + bn;
            let ba = if i < afull {
                &*(a.as_ptr().add(i * 64).cast::<[u8; 64]>())
            } else if active_a {
                &atail[i - afull]
            } else {
                &zero
            };
            let bb = if i < bfull {
                &*(b.as_ptr().add(i * 64).cast::<[u8; 64]>())
            } else if active_b {
                &btail[i - bfull]
            } else {
                &zero
            };

            let save_abefa = abefa;
            let save_cdgha = cdgha;
            let save_abefb = abefb;
            let save_cdghb = cdghb;
            let mask = _mm_set_epi64x(
                0x0c0d_0e0f_0809_0a0bu64 as i64,
                0x0405_0607_0001_0203u64 as i64,
            );
            let pa = ba.as_ptr().cast::<__m128i>();
            let pb = bb.as_ptr().cast::<__m128i>();
            let mut a0 = _mm_shuffle_epi8(_mm_loadu_si128(pa), mask);
            let mut b0 = _mm_shuffle_epi8(_mm_loadu_si128(pb), mask);
            let mut a1 = _mm_shuffle_epi8(_mm_loadu_si128(pa.add(1)), mask);
            let mut b1 = _mm_shuffle_epi8(_mm_loadu_si128(pb.add(1)), mask);
            let mut a2 = _mm_shuffle_epi8(_mm_loadu_si128(pa.add(2)), mask);
            let mut b2 = _mm_shuffle_epi8(_mm_loadu_si128(pb.add(2)), mask);
            let mut a3 = _mm_shuffle_epi8(_mm_loadu_si128(pa.add(3)), mask);
            let mut b3 = _mm_shuffle_epi8(_mm_loadu_si128(pb.add(3)), mask);
            let mut a4;
            let mut b4;

            rounds4_x2!(abefa, cdgha, a0, abefb, cdghb, b0, 0);
            rounds4_x2!(abefa, cdgha, a1, abefb, cdghb, b1, 1);
            rounds4_x2!(abefa, cdgha, a2, abefb, cdghb, b2, 2);
            rounds4_x2!(abefa, cdgha, a3, abefb, cdghb, b3, 3);
            schedule_rounds4_x2!(
                abefa, cdgha, a0, a1, a2, a3, a4, abefb, cdghb, b0, b1, b2, b3, b4, 4
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a1, a2, a3, a4, a0, abefb, cdghb, b1, b2, b3, b4, b0, 5
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a2, a3, a4, a0, a1, abefb, cdghb, b2, b3, b4, b0, b1, 6
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a3, a4, a0, a1, a2, abefb, cdghb, b3, b4, b0, b1, b2, 7
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a4, a0, a1, a2, a3, abefb, cdghb, b4, b0, b1, b2, b3, 8
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a0, a1, a2, a3, a4, abefb, cdghb, b0, b1, b2, b3, b4, 9
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a1, a2, a3, a4, a0, abefb, cdghb, b1, b2, b3, b4, b0, 10
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a2, a3, a4, a0, a1, abefb, cdghb, b2, b3, b4, b0, b1, 11
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a3, a4, a0, a1, a2, abefb, cdghb, b3, b4, b0, b1, b2, 12
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a4, a0, a1, a2, a3, abefb, cdghb, b4, b0, b1, b2, b3, 13
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a0, a1, a2, a3, a4, abefb, cdghb, b0, b1, b2, b3, b4, 14
            );
            schedule_rounds4_x2!(
                abefa, cdgha, a1, a2, a3, a4, a0, abefb, cdghb, b1, b2, b3, b4, b0, 15
            );

            if active_a {
                abefa = _mm_add_epi32(abefa, save_abefa);
                cdgha = _mm_add_epi32(cdgha, save_cdgha);
            } else {
                abefa = save_abefa;
                cdgha = save_cdgha;
            }
            if active_b {
                abefb = _mm_add_epi32(abefb, save_abefb);
                cdghb = _mm_add_epi32(cdghb, save_cdghb);
            } else {
                abefb = save_abefb;
                cdghb = save_cdghb;
            }
        }

        store_state(&mut sa, abefa, cdgha);
        store_state(&mut sb, abefb, cdghb);
        (finish(sa), finish(sb))
    }

    fn tail(input: &[u8]) -> ([[u8; 64]; 2], usize) {
        let rem = input.len() % 64;
        let mut out = [[0u8; 64]; 2];
        out[0][..rem].copy_from_slice(&input[input.len() - rem..]);
        out[0][rem] = 0x80;
        let blocks = if rem < 56 { 1 } else { 2 };
        out[blocks - 1][56..].copy_from_slice(&((input.len() as u64) * 8).to_be_bytes());
        (out, blocks)
    }

    fn finish(state: [u32; 8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (dst, word) in out.chunks_exact_mut(4).zip(state) {
            dst.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(target_arch = "x86_64")]
use x86::hash as shani_x2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_x2_matches_sha2_for_varied_lengths() {
        let boundaries = [0usize, 55, 56, 63, 64, 65, 119, 120];
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng = rng.wrapping_mul(0x2545_f491_4f6c_dd1d);
            rng
        };

        for case in 0..2_000 {
            let alen = if case < boundaries.len() {
                boundaries[case]
            } else {
                (next() % 300_001) as usize
            };
            let blen = if case < boundaries.len() {
                boundaries[boundaries.len() - 1 - case]
            } else {
                (next() % 300_001) as usize
            };
            let mut a = vec![0u8; alen];
            let mut b = vec![0u8; blen];
            for chunk in a.chunks_mut(8).chain(b.chunks_mut(8)) {
                let bytes = next().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }

            let got = sha256_x2(&a, &b);
            let want: ([u8; 32], [u8; 32]) = (Sha256::digest(&a).into(), Sha256::digest(&b).into());
            assert_eq!(got, want, "case {case}, lengths ({alen}, {blen})");
        }
    }
}
