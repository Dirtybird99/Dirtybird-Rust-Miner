// SHA-256 via Intel SHA-NI. Single-buffer (sha256_process_x86, public-domain
// Gulley/Walton) + a 2-way multi-buffer path (compress2) that interleaves two
// independent message chains so the OoO engine overlaps the latency-bound
// sha256rnds2 dependency chains (~1.3x throughput on Raptor Cove; capped by the
// single shared SHA port). Ported from the validated Zig sha256_mb.zig.
//
// All ops are 128-bit _mm_ intrinsics; under AVX2 clang VEX-encodes them (which
// zero the YMM upper), so the legacy-only sha256rnds2 never sees a dirty upper —
// no AVX->SSE transition penalty. Output byte-identical to standard SHA-256.
#include <immintrin.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static const uint32_t SHA256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// 16-byte aligned: the 2-way asm adds K via `paddd N(%[k]), %%xmm` (aligned memory operand).
static const uint32_t K[64] __attribute__((aligned(16))) = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define R2 _mm_sha256rnds2_epu32
#define M1 _mm_sha256msg1_epu32
#define M2 _mm_sha256msg2_epu32
#define SH(x) _mm_shuffle_epi32((x), 0x0E)
#define LDK(i) _mm_loadu_si128((const __m128i *)(K + (i)))

// ---- single-buffer (validated; canonical Intel sequence) -------------------
static void sha256_process_x86(uint32_t state[8], const uint8_t *data, size_t length) {
    __m128i STATE0, STATE1, MSG, TMP, MSG0, MSG1, MSG2, MSG3, ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    TMP = _mm_loadu_si128((const __m128i *)&state[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);
    TMP = _mm_shuffle_epi32(TMP, 0xB1);
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);

    while (length >= 64) {
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 0)), MASK);
        MSG = _mm_add_epi32(MSG0, LDK(0));
        STATE1 = R2(STATE1, STATE0, MSG);
        MSG = SH(MSG);
        STATE0 = R2(STATE0, STATE1, MSG);

        MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 16)), MASK);
        MSG = _mm_add_epi32(MSG1, LDK(4));
        STATE1 = R2(STATE1, STATE0, MSG);
        MSG0 = M1(MSG0, MSG1);
        MSG = SH(MSG);
        STATE0 = R2(STATE0, STATE1, MSG);

        MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 32)), MASK);
        MSG = _mm_add_epi32(MSG2, LDK(8));
        STATE1 = R2(STATE1, STATE0, MSG);
        MSG1 = M1(MSG1, MSG2);
        MSG = SH(MSG);
        STATE0 = R2(STATE0, STATE1, MSG);

        MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 48)), MASK);
        MSG = _mm_add_epi32(MSG3, LDK(12));
        STATE1 = R2(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = M2(MSG0, MSG3);
        MSG = SH(MSG);
        STATE0 = R2(STATE0, STATE1, MSG);
        MSG2 = M1(MSG2, MSG3);

        // schedule groups 4..12 (cur,next,prev rotate; msg1 on prev)
        #define SBODY(cur, next, prev, ki)                          \
            MSG = _mm_add_epi32(cur, LDK(ki));                       \
            STATE1 = R2(STATE1, STATE0, MSG);                        \
            TMP = _mm_alignr_epi8(cur, prev, 4);                     \
            next = _mm_add_epi32(next, TMP);                         \
            next = M2(next, cur);                                    \
            MSG = SH(MSG);                                           \
            STATE0 = R2(STATE0, STATE1, MSG);                        \
            prev = M1(prev, cur);
        SBODY(MSG0, MSG1, MSG3, 16)
        SBODY(MSG1, MSG2, MSG0, 20)
        SBODY(MSG2, MSG3, MSG1, 24)
        SBODY(MSG3, MSG0, MSG2, 28)
        SBODY(MSG0, MSG1, MSG3, 32)
        SBODY(MSG1, MSG2, MSG0, 36)
        SBODY(MSG2, MSG3, MSG1, 40)
        SBODY(MSG3, MSG0, MSG2, 44)
        SBODY(MSG0, MSG1, MSG3, 48)
        #undef SBODY
        // groups 13,14 (no msg1)
        #define SBODY0(cur, next, prev, ki)                         \
            MSG = _mm_add_epi32(cur, LDK(ki));                       \
            STATE1 = R2(STATE1, STATE0, MSG);                        \
            TMP = _mm_alignr_epi8(cur, prev, 4);                     \
            next = _mm_add_epi32(next, TMP);                         \
            next = M2(next, cur);                                    \
            MSG = SH(MSG);                                           \
            STATE0 = R2(STATE0, STATE1, MSG);
        SBODY0(MSG1, MSG2, MSG0, 52)
        SBODY0(MSG2, MSG3, MSG1, 56)
        #undef SBODY0
        // group 15
        MSG = _mm_add_epi32(MSG3, LDK(60));
        STATE1 = R2(STATE1, STATE0, MSG);
        MSG = SH(MSG);
        STATE0 = R2(STATE0, STATE1, MSG);

        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
        data += 64;
        length -= 64;
    }

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);
    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

// Byte-swap mask for the SHA-NI big-endian message load (pshufb).
static const uint8_t SHUF_MASK[16] __attribute__((aligned(16))) = {
    0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04,
    0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c,
};

// ---- 2-way: nblocks blocks of two messages, interleaved at 4-round-group
// granularity. PURE LEGACY-SSE inline asm with manual 16-XMM allocation (the 4
// per-block state saves spill to an aligned stack buffer). Ported verbatim from
// the validated Zig sha256_mb.zig compress2; intrinsics here spill / hit the
// AVX->SSE transition and run ~5x slower. xmm map: shared xmm0 MSG, xmm13 mask;
// lane A xmm1/2 state, xmm5-8 windows, xmm14 tmp; lane B xmm3/4 state, xmm9-12
// windows, xmm15 tmp.
static void compress2(uint32_t st0[8], uint32_t st1[8],
                      const uint8_t *d0, const uint8_t *d1, size_t nblocks) {
    if (nblocks == 0) return;
    const uint8_t *data0 = d0;
    const uint8_t *data1 = d1;
    size_t n = nblocks;
    uint32_t save[16] __attribute__((aligned(16)));
    __asm__ volatile(
        "movdqu (%[mask]), %%xmm13\n\t"
        "movdqu (%[st0]), %%xmm1\n\t"
        "movdqu 16(%[st0]), %%xmm2\n\t"
        "pshufd $0xB1, %%xmm1, %%xmm1\n\t"
        "pshufd $0x1B, %%xmm2, %%xmm2\n\t"
        "movdqa %%xmm1, %%xmm14\n\t"
        "palignr $8, %%xmm2, %%xmm1\n\t"
        "pblendw $0xF0, %%xmm14, %%xmm2\n\t"
        "movdqu (%[st1]), %%xmm3\n\t"
        "movdqu 16(%[st1]), %%xmm4\n\t"
        "pshufd $0xB1, %%xmm3, %%xmm3\n\t"
        "pshufd $0x1B, %%xmm4, %%xmm4\n\t"
        "movdqa %%xmm3, %%xmm15\n\t"
        "palignr $8, %%xmm4, %%xmm3\n\t"
        "pblendw $0xF0, %%xmm15, %%xmm4\n\t"
        "1:\n\t"
        "movdqa %%xmm1, 0(%[sv])\n\t"
        "movdqa %%xmm2, 16(%[sv])\n\t"
        "movdqa %%xmm3, 32(%[sv])\n\t"
        "movdqa %%xmm4, 48(%[sv])\n\t"
        // group 0
        "movdqu 0(%[data0]), %%xmm5\n\t  pshufb %%xmm13, %%xmm5\n\t  movdqa %%xmm5, %%xmm0\n\t  paddd 0(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm1, %%xmm2\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqu 0(%[data1]), %%xmm9\n\t  pshufb %%xmm13, %%xmm9\n\t  movdqa %%xmm9, %%xmm0\n\t  paddd 0(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm3, %%xmm4\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 1
        "movdqu 16(%[data0]), %%xmm6\n\t  pshufb %%xmm13, %%xmm6\n\t  movdqa %%xmm6, %%xmm0\n\t  paddd 16(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm1, %%xmm2\n\t  sha256msg1 %%xmm6, %%xmm5\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqu 16(%[data1]), %%xmm10\n\t pshufb %%xmm13, %%xmm10\n\t movdqa %%xmm10, %%xmm0\n\t paddd 16(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  sha256msg1 %%xmm10, %%xmm9\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 2
        "movdqu 32(%[data0]), %%xmm7\n\t  pshufb %%xmm13, %%xmm7\n\t  movdqa %%xmm7, %%xmm0\n\t  paddd 32(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm1, %%xmm2\n\t  sha256msg1 %%xmm7, %%xmm6\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqu 32(%[data1]), %%xmm11\n\t pshufb %%xmm13, %%xmm11\n\t movdqa %%xmm11, %%xmm0\n\t paddd 32(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  sha256msg1 %%xmm11, %%xmm10\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 3
        "movdqu 48(%[data0]), %%xmm8\n\t  pshufb %%xmm13, %%xmm8\n\t  movdqa %%xmm8, %%xmm0\n\t  paddd 48(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm8, %%xmm14\n\t  palignr $4, %%xmm7, %%xmm14\n\t  paddd %%xmm14, %%xmm5\n\t  sha256msg2 %%xmm8, %%xmm5\n\t  sha256msg1 %%xmm8, %%xmm7\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqu 48(%[data1]), %%xmm12\n\t pshufb %%xmm13, %%xmm12\n\t movdqa %%xmm12, %%xmm0\n\t paddd 48(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm12, %%xmm15\n\t palignr $4, %%xmm11, %%xmm15\n\t paddd %%xmm15, %%xmm9\n\t  sha256msg2 %%xmm12, %%xmm9\n\t sha256msg1 %%xmm12, %%xmm11\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 4 : A m0..3 = 5,6,7,8
        "movdqa %%xmm5, %%xmm0\n\t  paddd 64(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm5, %%xmm14\n\t  palignr $4, %%xmm8, %%xmm14\n\t  paddd %%xmm14, %%xmm6\n\t  sha256msg2 %%xmm5, %%xmm6\n\t  sha256msg1 %%xmm5, %%xmm8\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm9, %%xmm0\n\t  paddd 64(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm9, %%xmm15\n\t  palignr $4, %%xmm12, %%xmm15\n\t paddd %%xmm15, %%xmm10\n\t sha256msg2 %%xmm9, %%xmm10\n\t sha256msg1 %%xmm9, %%xmm12\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 5 : A 6,7,8,5
        "movdqa %%xmm6, %%xmm0\n\t  paddd 80(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm6, %%xmm14\n\t  palignr $4, %%xmm5, %%xmm14\n\t  paddd %%xmm14, %%xmm7\n\t  sha256msg2 %%xmm6, %%xmm7\n\t  sha256msg1 %%xmm6, %%xmm5\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm10, %%xmm0\n\t paddd 80(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm10, %%xmm15\n\t palignr $4, %%xmm9, %%xmm15\n\t  paddd %%xmm15, %%xmm11\n\t sha256msg2 %%xmm10, %%xmm11\n\t sha256msg1 %%xmm10, %%xmm9\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 6 : A 7,8,5,6
        "movdqa %%xmm7, %%xmm0\n\t  paddd 96(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm7, %%xmm14\n\t  palignr $4, %%xmm6, %%xmm14\n\t  paddd %%xmm14, %%xmm8\n\t  sha256msg2 %%xmm7, %%xmm8\n\t  sha256msg1 %%xmm7, %%xmm6\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm11, %%xmm0\n\t paddd 96(%[k]), %%xmm0\n\t  sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm11, %%xmm15\n\t palignr $4, %%xmm10, %%xmm15\n\t paddd %%xmm15, %%xmm12\n\t sha256msg2 %%xmm11, %%xmm12\n\t sha256msg1 %%xmm11, %%xmm10\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 7 : A 8,5,6,7
        "movdqa %%xmm8, %%xmm0\n\t  paddd 112(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm8, %%xmm14\n\t  palignr $4, %%xmm7, %%xmm14\n\t  paddd %%xmm14, %%xmm5\n\t  sha256msg2 %%xmm8, %%xmm5\n\t  sha256msg1 %%xmm8, %%xmm7\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm12, %%xmm0\n\t paddd 112(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm12, %%xmm15\n\t palignr $4, %%xmm11, %%xmm15\n\t paddd %%xmm15, %%xmm9\n\t  sha256msg2 %%xmm12, %%xmm9\n\t sha256msg1 %%xmm12, %%xmm11\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 8 : A 5,6,7,8
        "movdqa %%xmm5, %%xmm0\n\t  paddd 128(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm5, %%xmm14\n\t  palignr $4, %%xmm8, %%xmm14\n\t  paddd %%xmm14, %%xmm6\n\t  sha256msg2 %%xmm5, %%xmm6\n\t  sha256msg1 %%xmm5, %%xmm8\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm9, %%xmm0\n\t  paddd 128(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm9, %%xmm15\n\t  palignr $4, %%xmm12, %%xmm15\n\t paddd %%xmm15, %%xmm10\n\t sha256msg2 %%xmm9, %%xmm10\n\t sha256msg1 %%xmm9, %%xmm12\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 9 : A 6,7,8,5
        "movdqa %%xmm6, %%xmm0\n\t  paddd 144(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm6, %%xmm14\n\t  palignr $4, %%xmm5, %%xmm14\n\t  paddd %%xmm14, %%xmm7\n\t  sha256msg2 %%xmm6, %%xmm7\n\t  sha256msg1 %%xmm6, %%xmm5\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm10, %%xmm0\n\t paddd 144(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm10, %%xmm15\n\t palignr $4, %%xmm9, %%xmm15\n\t  paddd %%xmm15, %%xmm11\n\t sha256msg2 %%xmm10, %%xmm11\n\t sha256msg1 %%xmm10, %%xmm9\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 10 : A 7,8,5,6
        "movdqa %%xmm7, %%xmm0\n\t  paddd 160(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm7, %%xmm14\n\t  palignr $4, %%xmm6, %%xmm14\n\t  paddd %%xmm14, %%xmm8\n\t  sha256msg2 %%xmm7, %%xmm8\n\t  sha256msg1 %%xmm7, %%xmm6\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm11, %%xmm0\n\t paddd 160(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm11, %%xmm15\n\t palignr $4, %%xmm10, %%xmm15\n\t paddd %%xmm15, %%xmm12\n\t sha256msg2 %%xmm11, %%xmm12\n\t sha256msg1 %%xmm11, %%xmm10\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 11 : A 8,5,6,7
        "movdqa %%xmm8, %%xmm0\n\t  paddd 176(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm8, %%xmm14\n\t  palignr $4, %%xmm7, %%xmm14\n\t  paddd %%xmm14, %%xmm5\n\t  sha256msg2 %%xmm8, %%xmm5\n\t  sha256msg1 %%xmm8, %%xmm7\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm12, %%xmm0\n\t paddd 176(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm12, %%xmm15\n\t palignr $4, %%xmm11, %%xmm15\n\t paddd %%xmm15, %%xmm9\n\t  sha256msg2 %%xmm12, %%xmm9\n\t sha256msg1 %%xmm12, %%xmm11\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 12 : A 5,6,7,8
        "movdqa %%xmm5, %%xmm0\n\t  paddd 192(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm5, %%xmm14\n\t  palignr $4, %%xmm8, %%xmm14\n\t  paddd %%xmm14, %%xmm6\n\t  sha256msg2 %%xmm5, %%xmm6\n\t  sha256msg1 %%xmm5, %%xmm8\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm9, %%xmm0\n\t  paddd 192(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm9, %%xmm15\n\t  palignr $4, %%xmm12, %%xmm15\n\t paddd %%xmm15, %%xmm10\n\t sha256msg2 %%xmm9, %%xmm10\n\t sha256msg1 %%xmm9, %%xmm12\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 13 : A 6,7,8,5 (no msg1)
        "movdqa %%xmm6, %%xmm0\n\t  paddd 208(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm6, %%xmm14\n\t  palignr $4, %%xmm5, %%xmm14\n\t  paddd %%xmm14, %%xmm7\n\t  sha256msg2 %%xmm6, %%xmm7\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm10, %%xmm0\n\t paddd 208(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm10, %%xmm15\n\t palignr $4, %%xmm9, %%xmm15\n\t  paddd %%xmm15, %%xmm11\n\t sha256msg2 %%xmm10, %%xmm11\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 14 : A 7,8,5,6 (no msg1)
        "movdqa %%xmm7, %%xmm0\n\t  paddd 224(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  movdqa %%xmm7, %%xmm14\n\t  palignr $4, %%xmm6, %%xmm14\n\t  paddd %%xmm14, %%xmm8\n\t  sha256msg2 %%xmm7, %%xmm8\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm11, %%xmm0\n\t paddd 224(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  movdqa %%xmm11, %%xmm15\n\t palignr $4, %%xmm10, %%xmm15\n\t paddd %%xmm15, %%xmm12\n\t sha256msg2 %%xmm11, %%xmm12\n\t pshufd $0x0E, %%xmm0, %%xmm0\n\t sha256rnds2 %%xmm4, %%xmm3\n\t"
        // group 15 : A 8 (final)
        "movdqa %%xmm8, %%xmm0\n\t  paddd 240(%[k]), %%xmm0\n\t sha256rnds2 %%xmm1, %%xmm2\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm2, %%xmm1\n\t"
        "movdqa %%xmm12, %%xmm0\n\t paddd 240(%[k]), %%xmm0\n\t sha256rnds2 %%xmm3, %%xmm4\n\t  pshufd $0x0E, %%xmm0, %%xmm0\n\t  sha256rnds2 %%xmm4, %%xmm3\n\t"
        // add back
        "paddd 0(%[sv]), %%xmm1\n\t"
        "paddd 16(%[sv]), %%xmm2\n\t"
        "paddd 32(%[sv]), %%xmm3\n\t"
        "paddd 48(%[sv]), %%xmm4\n\t"
        "addq $64, %[data0]\n\t"
        "addq $64, %[data1]\n\t"
        "subq $1, %[n]\n\t"
        "jne 1b\n\t"
        // store lane A
        "pshufd $0x1B, %%xmm1, %%xmm1\n\t"
        "pshufd $0xB1, %%xmm2, %%xmm2\n\t"
        "movdqa %%xmm1, %%xmm14\n\t"
        "pblendw $0xF0, %%xmm2, %%xmm1\n\t"
        "palignr $8, %%xmm14, %%xmm2\n\t"
        "movdqu %%xmm1, (%[st0])\n\t"
        "movdqu %%xmm2, 16(%[st0])\n\t"
        // store lane B
        "pshufd $0x1B, %%xmm3, %%xmm3\n\t"
        "pshufd $0xB1, %%xmm4, %%xmm4\n\t"
        "movdqa %%xmm3, %%xmm15\n\t"
        "pblendw $0xF0, %%xmm4, %%xmm3\n\t"
        "palignr $8, %%xmm15, %%xmm4\n\t"
        "movdqu %%xmm3, (%[st1])\n\t"
        "movdqu %%xmm4, 16(%[st1])\n\t"
        : [data0] "+r"(data0), [data1] "+r"(data1), [n] "+r"(n)
        : [st0] "r"(st0), [st1] "r"(st1), [k] "r"(K), [mask] "r"(SHUF_MASK), [sv] "r"(save)
        : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
          "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "memory", "cc");
}

static void write_digest(const uint32_t st[8], uint8_t out[32]) {
    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(st[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(st[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(st[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(st[i]);
    }
}

// Process remaining whole blocks (beyond done_blocks) + padding for one message.
static void finish_one(uint32_t state[8], const uint8_t *msg, size_t len, size_t done_blocks) {
    size_t total_whole = len / 64;
    if (total_whole > done_blocks) {
        sha256_process_x86(state, msg + done_blocks * 64, (total_whole - done_blocks) * 64);
    }
    size_t rem = len % 64;
    uint8_t block[128];
    memcpy(block, msg + total_whole * 64, rem);
    block[rem] = 0x80;
    size_t padlen = (rem >= 56) ? 128 : 64;
    memset(block + rem + 1, 0, padlen - rem - 1 - 8);
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        block[padlen - 1 - i] = (uint8_t)(bits >> (8 * i));
    }
    sha256_process_x86(state, block, padlen);
}

// ---- public API ------------------------------------------------------------
void sha256_ni(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8];
    memcpy(state, SHA256_H0, sizeof(state));
    finish_one(state, data, len, 0);
    write_digest(state, out);
}

void sha256_ni_2x(const uint8_t *d0, size_t len0, const uint8_t *d1, size_t len1,
                  uint8_t out0[32], uint8_t out1[32]) {
    uint32_t st0[8], st1[8];
    memcpy(st0, SHA256_H0, sizeof(st0));
    memcpy(st1, SHA256_H0, sizeof(st1));
    size_t w0 = len0 / 64, w1 = len1 / 64;
    size_t common = (w0 < w1) ? w0 : w1;
    if (common) {
        compress2(st0, st1, d0, d1, common);
    }
    finish_one(st0, d0, len0, common);
    finish_one(st1, d1, len1, common);
    write_digest(st0, out0);
    write_digest(st1, out1);
}
