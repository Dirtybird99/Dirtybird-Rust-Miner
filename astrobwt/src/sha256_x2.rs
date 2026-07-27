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

    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        // SAFETY: the runtime check above guarantees the ARMv8 crypto
        // extensions, which is all `aarch64::hash` requires.
        return unsafe { aarch64::hash(a, b) };
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

    // SHA-256 round constants K[0..63], flat and 16-byte aligned. The 2-way asm
    // adds K via `paddd off(%k), %xmm` (a legacy-SSE memory operand), which #GPs
    // on an unaligned address; the default `[u32; 64]` alignment is only 4.
    #[repr(align(16))]
    struct AlignedK([u32; 64]);
    static K: AlignedK = AlignedK([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ]);

    /// Clear the upper 128 bits of every YMM register. Called once at the top of
    /// the SHA-NI path so an AVX2 caller's dirty YMM upper does not force each
    /// legacy-SSE `sha256rnds2` in the compress loop to pay an AVX->SSE blend.
    #[target_feature(enable = "avx")]
    unsafe fn zeroupper() {
        _mm256_zeroupper();
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
        // Drop any dirty YMM upper left by an AVX2 caller before the legacy-SSE
        // SHA-NI loop; #UD-safe because it is gated on runtime AVX detection.
        if std::is_x86_feature_detected!("avx") {
            zeroupper();
        }
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
            // Byte-swap each 16-byte message window to big-endian words (kept in
            // Rust; VEX-128 leaves the YMM upper clean). These preloaded lanes are
            // exactly what an in-asm `pshufb SHUF_MASK` would produce.
            let a0 = _mm_shuffle_epi8(_mm_loadu_si128(pa), mask);
            let a1 = _mm_shuffle_epi8(_mm_loadu_si128(pa.add(1)), mask);
            let a2 = _mm_shuffle_epi8(_mm_loadu_si128(pa.add(2)), mask);
            let a3 = _mm_shuffle_epi8(_mm_loadu_si128(pa.add(3)), mask);
            let b0 = _mm_shuffle_epi8(_mm_loadu_si128(pb), mask);
            let b1 = _mm_shuffle_epi8(_mm_loadu_si128(pb.add(1)), mask);
            let b2 = _mm_shuffle_epi8(_mm_loadu_si128(pb.add(2)), mask);
            let b3 = _mm_shuffle_epi8(_mm_loadu_si128(pb.add(3)), mask);

            // One 64-byte block, both lanes, as hand-scheduled PURE LEGACY-SSE
            // (no VEX): 16 four-round groups emitted per lane and interleaved at
            // group granularity, so the OoO core overlaps the two independent
            // sha256rnds2 latency chains. Direct port of the Zig `compress2` body
            // (sha256_mb.zig) minus its data-load/pshufb (done above), state
            // prologue/epilogue (load_state/store_state), loop, and add-back
            // (done in Rust). xmm map: xmm1/2 = lane A ABEF/CDGH, xmm3/4 = lane B
            // ABEF/CDGH, xmm5..8 = lane A MSG0..3, xmm9..12 = lane B MSG0..3,
            // xmm0 = shared MSG scratch, xmm14/15 = per-lane schedule temps. The
            // asm outputs the post-64-round working state in xmm1..4; the caller
            // adds the saved pre-block state.
            core::arch::asm!(
                // ---- group 0 (rounds 0-3) ----
                "movdqa %xmm5, %xmm0",
                "paddd 0({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm9, %xmm0",
                "paddd 0({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 1 (rounds 4-7) ----
                "movdqa %xmm6, %xmm0",
                "paddd 16({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "sha256msg1 %xmm6, %xmm5",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm10, %xmm0",
                "paddd 16({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "sha256msg1 %xmm10, %xmm9",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 2 (rounds 8-11) ----
                "movdqa %xmm7, %xmm0",
                "paddd 32({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "sha256msg1 %xmm7, %xmm6",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm11, %xmm0",
                "paddd 32({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "sha256msg1 %xmm11, %xmm10",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 3 (rounds 12-15) ----
                "movdqa %xmm8, %xmm0",
                "paddd 48({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm8, %xmm14",
                "palignr $4, %xmm7, %xmm14",
                "paddd %xmm14, %xmm5",
                "sha256msg2 %xmm8, %xmm5",
                "sha256msg1 %xmm8, %xmm7",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm12, %xmm0",
                "paddd 48({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm12, %xmm15",
                "palignr $4, %xmm11, %xmm15",
                "paddd %xmm15, %xmm9",
                "sha256msg2 %xmm12, %xmm9",
                "sha256msg1 %xmm12, %xmm11",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 4 (rounds 16-19)  A:MSG0=5,1=6,2=7,3=8 ----
                "movdqa %xmm5, %xmm0",
                "paddd 64({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm5, %xmm14",
                "palignr $4, %xmm8, %xmm14",
                "paddd %xmm14, %xmm6",
                "sha256msg2 %xmm5, %xmm6",
                "sha256msg1 %xmm5, %xmm8",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm9, %xmm0",
                "paddd 64({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm9, %xmm15",
                "palignr $4, %xmm12, %xmm15",
                "paddd %xmm15, %xmm10",
                "sha256msg2 %xmm9, %xmm10",
                "sha256msg1 %xmm9, %xmm12",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 5 (rounds 20-23)  A:MSG0=6,1=7,2=8,3=5 ----
                "movdqa %xmm6, %xmm0",
                "paddd 80({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm6, %xmm14",
                "palignr $4, %xmm5, %xmm14",
                "paddd %xmm14, %xmm7",
                "sha256msg2 %xmm6, %xmm7",
                "sha256msg1 %xmm6, %xmm5",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm10, %xmm0",
                "paddd 80({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm10, %xmm15",
                "palignr $4, %xmm9, %xmm15",
                "paddd %xmm15, %xmm11",
                "sha256msg2 %xmm10, %xmm11",
                "sha256msg1 %xmm10, %xmm9",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 6 (rounds 24-27)  A:MSG0=7,1=8,2=5,3=6 ----
                "movdqa %xmm7, %xmm0",
                "paddd 96({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm7, %xmm14",
                "palignr $4, %xmm6, %xmm14",
                "paddd %xmm14, %xmm8",
                "sha256msg2 %xmm7, %xmm8",
                "sha256msg1 %xmm7, %xmm6",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm11, %xmm0",
                "paddd 96({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm11, %xmm15",
                "palignr $4, %xmm10, %xmm15",
                "paddd %xmm15, %xmm12",
                "sha256msg2 %xmm11, %xmm12",
                "sha256msg1 %xmm11, %xmm10",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 7 (rounds 28-31)  A:MSG0=8,1=5,2=6,3=7 ----
                "movdqa %xmm8, %xmm0",
                "paddd 112({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm8, %xmm14",
                "palignr $4, %xmm7, %xmm14",
                "paddd %xmm14, %xmm5",
                "sha256msg2 %xmm8, %xmm5",
                "sha256msg1 %xmm8, %xmm7",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm12, %xmm0",
                "paddd 112({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm12, %xmm15",
                "palignr $4, %xmm11, %xmm15",
                "paddd %xmm15, %xmm9",
                "sha256msg2 %xmm12, %xmm9",
                "sha256msg1 %xmm12, %xmm11",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 8 (rounds 32-35)  A:MSG0=5,1=6,2=7,3=8 ----
                "movdqa %xmm5, %xmm0",
                "paddd 128({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm5, %xmm14",
                "palignr $4, %xmm8, %xmm14",
                "paddd %xmm14, %xmm6",
                "sha256msg2 %xmm5, %xmm6",
                "sha256msg1 %xmm5, %xmm8",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm9, %xmm0",
                "paddd 128({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm9, %xmm15",
                "palignr $4, %xmm12, %xmm15",
                "paddd %xmm15, %xmm10",
                "sha256msg2 %xmm9, %xmm10",
                "sha256msg1 %xmm9, %xmm12",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 9 (rounds 36-39)  A:MSG0=6,1=7,2=8,3=5 ----
                "movdqa %xmm6, %xmm0",
                "paddd 144({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm6, %xmm14",
                "palignr $4, %xmm5, %xmm14",
                "paddd %xmm14, %xmm7",
                "sha256msg2 %xmm6, %xmm7",
                "sha256msg1 %xmm6, %xmm5",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm10, %xmm0",
                "paddd 144({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm10, %xmm15",
                "palignr $4, %xmm9, %xmm15",
                "paddd %xmm15, %xmm11",
                "sha256msg2 %xmm10, %xmm11",
                "sha256msg1 %xmm10, %xmm9",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 10 (rounds 40-43)  A:MSG0=7,1=8,2=5,3=6 ----
                "movdqa %xmm7, %xmm0",
                "paddd 160({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm7, %xmm14",
                "palignr $4, %xmm6, %xmm14",
                "paddd %xmm14, %xmm8",
                "sha256msg2 %xmm7, %xmm8",
                "sha256msg1 %xmm7, %xmm6",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm11, %xmm0",
                "paddd 160({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm11, %xmm15",
                "palignr $4, %xmm10, %xmm15",
                "paddd %xmm15, %xmm12",
                "sha256msg2 %xmm11, %xmm12",
                "sha256msg1 %xmm11, %xmm10",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 11 (rounds 44-47)  A:MSG0=8,1=5,2=6,3=7 ----
                "movdqa %xmm8, %xmm0",
                "paddd 176({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm8, %xmm14",
                "palignr $4, %xmm7, %xmm14",
                "paddd %xmm14, %xmm5",
                "sha256msg2 %xmm8, %xmm5",
                "sha256msg1 %xmm8, %xmm7",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm12, %xmm0",
                "paddd 176({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm12, %xmm15",
                "palignr $4, %xmm11, %xmm15",
                "paddd %xmm15, %xmm9",
                "sha256msg2 %xmm12, %xmm9",
                "sha256msg1 %xmm12, %xmm11",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 12 (rounds 48-51)  A:MSG0=5,1=6,2=7,3=8 ----
                "movdqa %xmm5, %xmm0",
                "paddd 192({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm5, %xmm14",
                "palignr $4, %xmm8, %xmm14",
                "paddd %xmm14, %xmm6",
                "sha256msg2 %xmm5, %xmm6",
                "sha256msg1 %xmm5, %xmm8",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm9, %xmm0",
                "paddd 192({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm9, %xmm15",
                "palignr $4, %xmm12, %xmm15",
                "paddd %xmm15, %xmm10",
                "sha256msg2 %xmm9, %xmm10",
                "sha256msg1 %xmm9, %xmm12",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 13 (rounds 52-55)  A:MSG0=6 (msg2 only) ----
                "movdqa %xmm6, %xmm0",
                "paddd 208({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm6, %xmm14",
                "palignr $4, %xmm5, %xmm14",
                "paddd %xmm14, %xmm7",
                "sha256msg2 %xmm6, %xmm7",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm10, %xmm0",
                "paddd 208({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm10, %xmm15",
                "palignr $4, %xmm9, %xmm15",
                "paddd %xmm15, %xmm11",
                "sha256msg2 %xmm10, %xmm11",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 14 (rounds 56-59)  A:MSG0=7 (msg2 only) ----
                "movdqa %xmm7, %xmm0",
                "paddd 224({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "movdqa %xmm7, %xmm14",
                "palignr $4, %xmm6, %xmm14",
                "paddd %xmm14, %xmm8",
                "sha256msg2 %xmm7, %xmm8",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm11, %xmm0",
                "paddd 224({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "movdqa %xmm11, %xmm15",
                "palignr $4, %xmm10, %xmm15",
                "paddd %xmm15, %xmm12",
                "sha256msg2 %xmm11, %xmm12",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                // ---- group 15 (rounds 60-63)  no schedule ----
                "movdqa %xmm8, %xmm0",
                "paddd 240({k}), %xmm0",
                "sha256rnds2 %xmm1, %xmm2",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm2, %xmm1",
                "movdqa %xmm12, %xmm0",
                "paddd 240({k}), %xmm0",
                "sha256rnds2 %xmm3, %xmm4",
                "pshufd $0x0E, %xmm0, %xmm0",
                "sha256rnds2 %xmm4, %xmm3",
                k = in(reg) K.0.as_ptr(),
                inout("xmm1") abefa,
                inout("xmm2") cdgha,
                inout("xmm3") abefb,
                inout("xmm4") cdghb,
                inout("xmm5") a0 => _,
                inout("xmm6") a1 => _,
                inout("xmm7") a2 => _,
                inout("xmm8") a3 => _,
                inout("xmm9") b0 => _,
                inout("xmm10") b1 => _,
                inout("xmm11") b2 => _,
                inout("xmm12") b3 => _,
                out("xmm0") _,
                out("xmm14") _,
                out("xmm15") _,
                options(att_syntax, nostack),
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

/// Two-stream SHA-256 on the ARMv8 crypto extensions.
///
/// Motivation is Amdahl, measured: on a Neoverse-N2 the final SHA-256 over the
/// suffix array is 21% of an AstroBWTv3 hash (~4,200 compressions of ~270 KB),
/// second only to the suffix array itself. A single SHA-256 stream cannot fill
/// the pipeline because SHA256H is multi-cycle and every round depends on the
/// last; two independent messages can. The instruction count is unchanged --
/// the win, if any, is purely scheduling.
///
/// Self-contained rather than sharing the x86 module's constants and helpers,
/// so the proven SHA-NI path is not touched at all.
#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use core::arch::aarch64::*;

    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// Four rounds: add the round constants, then the two ARMv8 hash steps.
    macro_rules! quad {
        ($abcd:ident, $efgh:ident, $w:expr, $k:expr) => {{
            let tmp = vaddq_u32($w, vld1q_u32(K.as_ptr().add($k)));
            let prev = $abcd;
            $abcd = vsha256hq_u32(prev, $efgh, tmp);
            $efgh = vsha256h2q_u32($efgh, prev, tmp);
        }};
    }

    /// One 64-byte block for ONE lane, expanded inline at the call site.
    ///
    /// A macro rather than an `#[inline(always)]` helper because rustc rejects
    /// `#[inline(always)]` together with `#[target_feature]`, and a plain
    /// `#[inline]` hint on a 64-round body is one cost-model decision away from
    /// not inlining -- which would put the two lanes in separate scheduling
    /// regions and delete the entire point of this kernel. Macro hygiene gives
    /// each expansion its own temporaries, so the lanes cannot collide.
    macro_rules! block {
        ($abcd:ident, $efgh:ident, $ptr:expr) => {{
            let p: *const u8 = $ptr;
            let abcd0 = $abcd;
            let efgh0 = $efgh;

            let mut w0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));
            let mut w1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16))));
            let mut w2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(32))));
            let mut w3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(48))));

            quad!($abcd, $efgh, w0, 0);
            quad!($abcd, $efgh, w1, 4);
            quad!($abcd, $efgh, w2, 8);
            quad!($abcd, $efgh, w3, 12);

            let mut k = 16usize;
            while k < 64 {
                w0 = vsha256su1q_u32(vsha256su0q_u32(w0, w1), w2, w3);
                quad!($abcd, $efgh, w0, k);
                w1 = vsha256su1q_u32(vsha256su0q_u32(w1, w2), w3, w0);
                quad!($abcd, $efgh, w1, k + 4);
                w2 = vsha256su1q_u32(vsha256su0q_u32(w2, w3), w0, w1);
                quad!($abcd, $efgh, w2, k + 8);
                w3 = vsha256su1q_u32(vsha256su0q_u32(w3, w0), w1, w2);
                quad!($abcd, $efgh, w3, k + 12);
                k += 16;
            }

            $abcd = vaddq_u32($abcd, abcd0);
            $efgh = vaddq_u32($efgh, efgh0);
        }};
    }

    /// Padding block(s). Identical arithmetic to the x86 sibling's `tail`.
    fn tail(input: &[u8]) -> ([[u8; 64]; 2], usize) {
        let rem = input.len() % 64;
        let mut out = [[0u8; 64]; 2];
        out[0][..rem].copy_from_slice(&input[input.len() - rem..]);
        out[0][rem] = 0x80;
        let blocks = if rem < 56 { 1 } else { 2 };
        out[blocks - 1][56..].copy_from_slice(&((input.len() as u64) * 8).to_be_bytes());
        (out, blocks)
    }

    fn finish(abcd: uint32x4_t, efgh: uint32x4_t) -> [u8; 32] {
        let mut s = [0u32; 8];
        // SAFETY: two vector stores into an eight-word buffer.
        unsafe {
            vst1q_u32(s.as_mut_ptr(), abcd);
            vst1q_u32(s.as_mut_ptr().add(4), efgh);
        }
        let mut out = [0u8; 32];
        for (dst, word) in out.chunks_exact_mut(4).zip(s) {
            dst.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Hash two independent messages, interleaving their common run of full
    /// blocks.
    ///
    /// Unequal lengths pair only `min(blocks_a, blocks_b)` and finish each
    /// remainder single-stream, rather than the x86 module's per-lane masking:
    /// AstroBWTv3 hands this two suffix arrays whose lengths differ by a few
    /// percent at most, so the unpaired tail is negligible and this shape is far
    /// easier to argue correct.
    ///
    /// # Safety
    /// The caller must have verified the `sha2` hwcap.
    #[target_feature(enable = "sha2")]
    pub unsafe fn hash(a: &[u8], b: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut aa = vld1q_u32(INITIAL.as_ptr());
        let mut ae = vld1q_u32(INITIAL.as_ptr().add(4));
        let mut ba = aa;
        let mut be = ae;

        let na = a.len() / 64;
        let nb = b.len() / 64;
        let paired = na.min(nb);

        for i in 0..paired {
            block!(aa, ae, a.as_ptr().add(i * 64));
            block!(ba, be, b.as_ptr().add(i * 64));
        }
        for i in paired..na {
            block!(aa, ae, a.as_ptr().add(i * 64));
        }
        for i in paired..nb {
            block!(ba, be, b.as_ptr().add(i * 64));
        }

        let (ta, tan) = tail(a);
        for blk in ta.iter().take(tan) {
            block!(aa, ae, blk.as_ptr());
        }
        let (tb, tbn) = tail(b);
        for blk in tb.iter().take(tbn) {
            block!(ba, be, blk.as_ptr());
        }

        (finish(aa, ae), finish(ba, be))
    }
}

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
