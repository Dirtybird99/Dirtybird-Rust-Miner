// AVX2 wolfPermute wrapper. Reuses the validated reference `wolfPermute_avx2` from
// vendor/v114/simd_wolf.h (32 bytes/op), exposed with a C ABI. The LUTs are filled
// from Rust's CODELUT (single source of truth) via wolf_init_lut so the SIMD path is
// byte-identical to the scalar wolf_branch (gated by a differential test on the Rust side).
#include <cstdint>
#include "simd_wolf.h"

// simd_wolf.h declares these extern; define them here (nothing else in the build does).
uint32_t CodeLUT[256];
uint16_t CodeLUT_16[256];
void init_code_lut_16() {}

extern "C" void wolf_init_lut(const uint32_t* codelut) {
    for (int op = 0; op < 256; ++op) {
        uint32_t c = codelut[op];
        CodeLUT[op] = c;
        // 16-bit nibble-pack: nibble i = byte i of the 32-bit word (each is 0..15).
        CodeLUT_16[op] = (uint16_t)((((c >> 24) & 0xF) << 12) | (((c >> 16) & 0xF) << 8) |
                                    (((c >> 8) & 0xF) << 4) | (c & 0xF));
    }
}

// out[p1..p2) = wolfBranch(in[i], in[p2], op) for i in [p1,p2), via 32-byte AVX2.
// Reads/writes 32 bytes from p1 (blended) — caller buffers must have >=32 bytes past p1.
extern "C" void wolf_permute_avx2(const uint8_t* in, uint8_t* out, uint8_t op, uint8_t p1, uint8_t p2) {
    wolfPermute_avx2((uint8_t*)in, out, op, p1, p2);
}
