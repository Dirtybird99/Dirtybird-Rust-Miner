#pragma once
// Pike Miner -- AVX2 vectorized wolfBranch
//
// Processes up to 32 bytes in parallel through the 4-sub-instruction
// opcode pipeline. Based on TNN's multiply-via-shuffle approach for
// per-byte variable shifts (far cheaper than blend chains).

#include <cstdint>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#define PIKE_HAS_AVX2_HEADER 1
#else
#define PIKE_HAS_AVX2_HEADER 0
#endif

// ---------------------------------------------------------------------------
// Compressed CodeLUT: 16-bit entries (4 nibbles, one per sub-opcode)
// ---------------------------------------------------------------------------
extern uint16_t CodeLUT_16[256];
extern uint32_t CodeLUT[256];

void init_code_lut_16();

// ---------------------------------------------------------------------------
// AVX2 byte-level operations
// ---------------------------------------------------------------------------
#if PIKE_HAS_AVX2_HEADER

// 8-bit multiply: split even/odd bytes, multiply as 16-bit, recombine
__attribute__((target("avx2")))
static inline __m256i mm256_mul_epi8(__m256i x, __m256i y) {
    __m256i mask_hi = _mm256_set1_epi16((short)0xFF00);
    __m256i mask_lo = _mm256_set1_epi16(0x00FF);

    __m256i a_hi = _mm256_srli_epi16(_mm256_and_si256(x, mask_hi), 8);
    __m256i b_hi = _mm256_srli_epi16(_mm256_and_si256(y, mask_hi), 8);
    __m256i a_lo = _mm256_and_si256(x, mask_lo);
    __m256i b_lo = _mm256_and_si256(y, mask_lo);

    __m256i p_hi = _mm256_slli_epi16(_mm256_mullo_epi16(a_hi, b_hi), 8);
    __m256i p_lo = _mm256_mullo_epi16(a_lo, b_lo);

    p_hi = _mm256_and_si256(p_hi, mask_hi);
    p_lo = _mm256_and_si256(p_lo, mask_lo);

    return _mm256_or_si256(p_hi, p_lo);
}

// Per-byte variable left shift via multiply-by-power-of-2 LUT (TNN technique)
// Shift amounts can be 0-8; uses _mm256_shuffle_epi8 to select 2^count as multiplier
__attribute__((target("avx2")))
static inline __m256i mm256_sllv_epi8(__m256i a, __m256i count) {
    __m256i mask_hi = _mm256_set1_epi32((int)0xFF00FF00);
    // LUT: index i -> 2^i (for i=0..8; 2^8=0 since we only keep low 8 bits)
    __m256i multiplier_lut = _mm256_set_epi8(
        0,0,0,0, 0,0,0,0, (char)0x80,0x40,0x20,0x10, 0x08,0x04,0x02,0x01,
        0,0,0,0, 0,0,0,0, (char)0x80,0x40,0x20,0x10, 0x08,0x04,0x02,0x01);

    __m256i count_sat  = _mm256_min_epu8(count, _mm256_set1_epi8(8));
    __m256i multiplier = _mm256_shuffle_epi8(multiplier_lut, count_sat);

    // Low bytes: multiply directly
    __m256i x_lo = _mm256_mullo_epi16(a, multiplier);

    // High bytes: need separate multiply to avoid cross-byte contamination
    __m256i multiplier_hi = _mm256_srli_epi16(multiplier, 8);
    __m256i a_hi = _mm256_and_si256(a, mask_hi);
    __m256i x_hi = _mm256_mullo_epi16(a_hi, multiplier_hi);

    return _mm256_blendv_epi8(x_lo, x_hi, mask_hi);
}

// Per-byte variable right shift via multiply-by-power-of-2 LUT (TNN technique)
__attribute__((target("avx2")))
static inline __m256i mm256_srlv_epi8(__m256i a, __m256i count) {
    __m256i mask_hi = _mm256_set1_epi32((int)0xFF00FF00);
    // Reversed LUT: index i -> 2^(7-i) for right shift trick
    __m256i multiplier_lut = _mm256_set_epi8(
        0,0,0,0, 0,0,0,0, 0x01,0x02,0x04,0x08, 0x10,0x20,0x40,(char)0x80,
        0,0,0,0, 0,0,0,0, 0x01,0x02,0x04,0x08, 0x10,0x20,0x40,(char)0x80);

    __m256i count_sat  = _mm256_min_epu8(count, _mm256_set1_epi8(8));
    __m256i multiplier = _mm256_shuffle_epi8(multiplier_lut, count_sat);

    // Low bytes: multiply, then shift right by 7 to position result
    __m256i a_lo = _mm256_andnot_si256(mask_hi, a);
    __m256i multiplier_lo = _mm256_andnot_si256(mask_hi, multiplier);
    __m256i x_lo = _mm256_mullo_epi16(a_lo, multiplier_lo);
    x_lo = _mm256_srli_epi16(x_lo, 7);

    // High bytes: use mulhi to get the right-shifted result
    __m256i multiplier_hi = _mm256_and_si256(mask_hi, multiplier);
    __m256i x_hi = _mm256_mulhi_epu16(a, multiplier_hi);
    x_hi = _mm256_slli_epi16(x_hi, 1);

    return _mm256_blendv_epi8(x_lo, x_hi, mask_hi);
}

// Per-byte variable rotate left: rot by (amount & 7)
__attribute__((target("avx2")))
static inline __m256i mm256_rolv_epi8(__m256i x, __m256i y) {
    __m256i y_mod = _mm256_and_si256(y, _mm256_set1_epi8(7));
    __m256i left = mm256_sllv_epi8(x, y_mod);
    __m256i right_count = _mm256_sub_epi8(_mm256_set1_epi8(8), y_mod);
    __m256i right = mm256_srlv_epi8(x, right_count);
    return _mm256_or_si256(left, right);
}

// Fixed rotate left by constant N (byte-level)
// Splits even/odd bytes to avoid 16-bit cross-byte contamination
__attribute__((target("avx2")))
static inline __m256i mm256_rol_epi8(__m256i x, int r) {
    __m256i mask_lo = _mm256_set1_epi16(0x00FF);
    __m256i mask_hi = _mm256_set1_epi16((short)0xFF00);
    __m256i a = _mm256_and_si256(x, mask_lo);
    __m256i b = _mm256_and_si256(x, mask_hi);

    // Rotate low bytes
    __m256i rotA = _mm256_or_si256(
        _mm256_slli_epi16(a, r),
        _mm256_srli_epi16(a, 8 - r));
    rotA = _mm256_and_si256(rotA, mask_lo);

    // Rotate high bytes
    __m256i rotB = _mm256_or_si256(
        _mm256_slli_epi16(b, r),
        _mm256_srli_epi16(b, 8 - r));
    rotB = _mm256_and_si256(rotB, mask_hi);

    return _mm256_or_si256(rotA, rotB);
}

// Bit reverse per byte: swap nibbles, pairs, bits
__attribute__((target("avx2")))
static inline __m256i mm256_reverse_epi8(__m256i v) {
    __m256i mask_0f = _mm256_set1_epi8(0x0F);
    __m256i mask_33 = _mm256_set1_epi8(0x33);
    __m256i mask_55 = _mm256_set1_epi8(0x55);
    __m256i all_ff  = _mm256_set1_epi8((char)0xFF);

    // Swap nibbles: (b & 0x0F) << 4 | (b & 0xF0) >> 4
    __m256i temp = _mm256_slli_epi16(_mm256_and_si256(v, mask_0f), 4);
    v = _mm256_srli_epi16(_mm256_and_si256(v, _mm256_andnot_si256(mask_0f, all_ff)), 4);
    v = _mm256_or_si256(v, temp);

    // Swap pairs: (b & 0x33) << 2 | (b & 0xCC) >> 2
    temp = _mm256_slli_epi16(_mm256_and_si256(v, mask_33), 2);
    v = _mm256_srli_epi16(_mm256_and_si256(v, _mm256_andnot_si256(mask_33, all_ff)), 2);
    v = _mm256_or_si256(v, temp);

    // Swap bits: (b & 0x55) << 1 | (b & 0xAA) >> 1
    temp = _mm256_slli_epi16(_mm256_and_si256(v, mask_55), 1);
    v = _mm256_srli_epi16(_mm256_and_si256(v, _mm256_andnot_si256(mask_55, all_ff)), 1);
    v = _mm256_or_si256(v, temp);

    return v;
}

// Per-byte popcount via nibble lookup
__attribute__((target("avx2")))
static inline __m256i mm256_popcnt_epi8(__m256i v) {
    // Split into 128-bit lanes, use SSE shuffle for popcount, recombine
    __m128i lo = _mm256_castsi256_si128(v);
    __m128i hi = _mm256_extractf128_si256(v, 1);

    __m128i mask4 = _mm_set1_epi8(0x0F);
    __m128i lut = _mm_setr_epi8(0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4);

    __m128i lo_cnt = _mm_add_epi8(
        _mm_shuffle_epi8(lut, _mm_and_si128(mask4, lo)),
        _mm_shuffle_epi8(lut, _mm_and_si128(mask4, _mm_srli_epi16(lo, 4))));
    __m128i hi_cnt = _mm_add_epi8(
        _mm_shuffle_epi8(lut, _mm_and_si128(mask4, hi)),
        _mm_shuffle_epi8(lut, _mm_and_si128(mask4, _mm_srli_epi16(hi, 4))));

    return _mm256_set_m128i(hi_cnt, lo_cnt);
}

// Generate mask: bytes [0..len-1] = 0xFF, rest = 0x00
__attribute__((target("avx2")))
static inline __m256i genMask_avx2(int len) {
    const __m256i sequence = _mm256_setr_epi8(
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31);
    len = (len < 0) ? 0 : (len > 32) ? 32 : len;
    return _mm256_cmpgt_epi8(_mm256_set1_epi8((char)len), sequence);
}

// ---------------------------------------------------------------------------
// wolfPermute_avx2 — the main vectorized wolf permutation
// ---------------------------------------------------------------------------
__attribute__((target("avx2")))
static inline void wolfPermute_avx2(uint8_t* in, uint8_t* out,
                                     uint8_t op, uint8_t pos1, uint8_t pos2) {
    uint32_t opcode = CodeLUT_16[op];

    __m256i data = _mm256_loadu_si256((const __m256i*)&in[pos1]);
    __m256i old = data;

    __m256i pos2vec = _mm256_set1_epi8((char)in[pos2]);
    __m256i vec_3 = _mm256_set1_epi8(3);

    // Execute 4 sub-instructions (i=3 downto 0)
    for (int i = 3; i >= 0; --i) {
        uint8_t insn = (opcode >> (i << 2)) & 0xF;
        switch (insn) {
            case 0:  data = _mm256_add_epi8(data, data); break;
            case 1:  data = _mm256_sub_epi8(data, _mm256_xor_si256(data, _mm256_set1_epi8(97))); break;
            case 2:  data = mm256_mul_epi8(data, data); break;
            case 3:  data = _mm256_xor_si256(data, pos2vec); break;
            case 4:  data = _mm256_xor_si256(data, _mm256_set1_epi64x(-1LL)); break;
            case 5:  data = _mm256_and_si256(data, pos2vec); break;
            case 6:  data = mm256_sllv_epi8(data, _mm256_and_si256(data, vec_3)); break;
            case 7:  data = mm256_srlv_epi8(data, _mm256_and_si256(data, vec_3)); break;
            case 8:  data = mm256_reverse_epi8(data); break;
            case 9:  data = _mm256_xor_si256(data, mm256_popcnt_epi8(data)); break;
            case 10: data = mm256_rolv_epi8(data, data); break;
            case 11: data = mm256_rol_epi8(data, 1); break;
            case 12: data = _mm256_xor_si256(data, mm256_rol_epi8(data, 2)); break;
            case 13: data = mm256_rol_epi8(data, 3); break;
            case 14: data = _mm256_xor_si256(data, mm256_rol_epi8(data, 4)); break;
            case 15: data = mm256_rol_epi8(data, 5); break;
        }
    }

    // Blend: only write [0:pos2-pos1) bytes, keep the rest from old
    data = _mm256_blendv_epi8(old, data, genMask_avx2(pos2 - pos1));
    _mm256_storeu_si256((__m256i*)&out[pos1], data);
}

#endif // PIKE_HAS_AVX2_HEADER
