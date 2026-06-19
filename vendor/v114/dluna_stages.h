// dluna_stages.h - Uniform stage entry function declarations for the
// v1.14 parity sweep replay harness.

#pragma once

#include <cstddef>
#include <cstdint>

namespace deroluna::stages {

using StageFn = bool (*)(const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len);

bool stage_salsa20_init(const uint8_t* in, size_t in_len,
                        uint8_t* out, size_t out_cap, size_t* out_len);

bool stage_rc4_ksa(const uint8_t* in, size_t in_len,
                   uint8_t* out, size_t out_cap, size_t* out_len);

bool stage_branch_dispatch(const uint8_t* in, size_t in_len,
                           uint8_t* out, size_t out_cap, size_t* out_len);

bool stage_sha256_of_sa(const uint8_t* in, size_t in_len,
                        uint8_t* out, size_t out_cap, size_t* out_len);

}  // namespace deroluna::stages
