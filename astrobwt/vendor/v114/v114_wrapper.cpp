// v114_wrapper.cpp -- expose the v1.14 descriptor suffix-array build to Zig.
//
// The descriptor SA exploits the repeat structure recorded by wolfCompute (the
// per-template group markers -> `flags`) to build the EXACT suffix array ~2x
// faster than libsais on the (period-256 self-similar) Wolf-permuted data. It is
// byte-identical to libsais (the dirtybird source verifies this via memcmp).
#include "dluna_v114.h"
#include <cstdint>
#include <cstddef>

// Returns 1 on success (out filled with logical_len*4 SA bytes), 0 on failure
// (caller falls back to libsais). `out_len` receives the bytes written.
extern "C" int v114_sa_build_fused(const uint8_t* data,
                                   uint32_t logical_len,
                                   uint32_t data_len_with_tail,
                                   const uint8_t* flags,
                                   uint32_t flag_len,
                                   uint8_t* out,
                                   size_t out_cap,
                                   size_t* out_len) {
    return deroluna::stages::v114::stage_v114_sa_build_compact_fused_raw(
               data, logical_len, data_len_with_tail,
               flags, flag_len, out, out_cap, out_len)
               ? 1
               : 0;
}

// Build the descriptor SA and stream its little-endian i32 bytes straight into
// SHA-256, writing the 32-byte digest to `out_hash` — never materializing the
// full ~280 KB suffix array. The streaming SHA sink inside the v114 stubs calls
// SHA256_Init/Update/Final, which the Rust crate supplies backed by hardware
// SHA-NI (see sha_ni_shim in sais32.rs). Returns 1 on success, 0 if the
// descriptor build refused the input (caller falls back to materialized SA).
extern "C" int v114_hash_fused(const uint8_t* data,
                               uint32_t logical_len,
                               uint32_t data_len_with_tail,
                               const uint8_t* flags,
                               uint32_t flag_len,
                               uint8_t* out_hash) {
    return deroluna::stages::v114::stage_v114_hash_compact_fused_raw(
               data, logical_len, data_len_with_tail,
               flags, flag_len, out_hash)
               ? 1
               : 0;
}
