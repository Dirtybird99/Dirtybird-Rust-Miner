// report.h - Per-stage stats accumulator and report emitter.

#pragma once

#include "cap_format.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace deroluna::replay {

struct StageObservation {
    uint64_t hash_seq = 0;
    uint32_t in_len = 0;
    uint32_t cap_out_len = 0;
    size_t clone_out_len = 0;
    bool fn_ok = false;
    bool match = false;
    bool out_len_mismatch = false;
    int first_diverge = -1;
};

struct StageStats {
    StageId id = StageId::Salsa20Init;
    bool is_stub = false;
    std::filesystem::path diffs_dir;
    int max_diffs = 16;

    uint64_t coverage = 0;
    uint64_t exact_matches = 0;
    uint64_t mismatches = 0;
    uint64_t fn_returned_false = 0;
    uint64_t out_len_mismatches = 0;
    uint64_t first_diverge_sum = 0;
    uint64_t first_diverge_n = 0;
    int diffs_written = 0;
    std::vector<StageObservation> observations;

    void record_one(uint64_t hash_seq, uint32_t in_len, uint32_t cap_out_len,
                    bool fn_ok, size_t clone_out_len,
                    const uint8_t* clone_out, const uint8_t* cap_out,
                    const uint8_t* cap_in);
};

void write_report(const std::string& out_dir,
                  const std::string& caps_dir,
                  const StageStats* stats,
                  int stage_count);

}  // namespace deroluna::replay
