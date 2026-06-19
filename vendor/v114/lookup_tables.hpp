/**
 * lookup_tables.hpp - Memory-bound lookup tables for AstroBWTv3 branch operations
 *
 * Replaces compute-intensive AVX2/AVX512 SIMD operations with memory lookups.
 * Total memory:
 *   - with USE_LOOKUP_3D_TABLE=1: ~6.6 MB
 *   - with USE_LOOKUP_3D_TABLE=0: ~38 KB (1D table only)
 *
 * Table Layout:
 *   - lookup1D: 152 regular ops x 256 = 38,912 entries (uint8_t) = ~38 KB (L1 cache!)
 *   - lookup3D: 104 branched ops x 256 x 256 = 6,815,744 entries (uint8_t) = ~6.5 MB
 *   - reg_idx[256]: Maps op -> index in lookup1D
 *   - branched_idx[256]: Maps op -> index in lookup3D
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <bit>
#include <bitset>
#include <algorithm>
#include <vector>
#include "lookup.h"  // bitTable for popcount

// Forward declarations
extern uint32_t CodeLUT[256];
extern const std::vector<unsigned char> branchedOps_global;

// Global lookup table pointers (allocated in miner.cpp with huge pages)
extern uint8_t *lookup1D_global;      // Regular ops: 152 x 256 = 38 KB (L1 cache)
extern unsigned char *lookup3D_global; // Branched ops: 104 x 256 x 256 = 6.5 MB (L3 cache)

// Index arrays: map opcode -> table index (extern - defined in lookupcompute.cpp)
constexpr size_t kLookupRegOpsSize = 152;
extern uint8_t g_reg_idx[256];      // Regular op index (0-151)
extern uint8_t g_branched_idx[256]; // Branched op index (0-103)
extern uint8_t g_is_branched[256];  // 1 if branched op, 0 if regular (replaces linear search)
extern std::bitset<256> g_unchanged_bytes[kLookupRegOpsSize];
extern std::bitset<256> g_clipped_bytes[kLookupRegOpsSize];
extern bool g_lookup_tables_initialized;
extern bool g_lookup_1d_initialized;
extern bool g_lookup_3d_initialized;

// Legacy compile-time default for precomputed 3D table.
// Runtime `--lookup-mode` now controls whether 3D table is used.
// This macro is retained as a fallback default selection.
#ifndef USE_LOOKUP_3D_TABLE
#define USE_LOOKUP_3D_TABLE 0
#endif

namespace lookup_tables {

// Scalar branch computation (from wolfbranching.cpp wolfBranch)
inline uint8_t computeBranch(uint8_t val, uint8_t pos2val, uint32_t opcode) {
    for (int i = 3; i >= 0; --i) {
        uint8_t insn = (opcode >> (i << 3)) & 0xFF;
        switch (insn) {
            case 0: val += val; break;
            case 1: val -= val ^ 97; break;
            case 2: val *= val; break;
            case 3: val ^= pos2val; break;
            case 4: val ^= 0xFF; break;
            case 5: val &= pos2val; break;
            case 6: val <<= (val & 3); break;
            case 7: val >>= (val & 3); break;
            case 8: val = static_cast<uint8_t>(std::rotl(val, 4) | std::rotr(val, 4)); break; // reverse bits approx
            case 9: val ^= bitTable[val]; break;
            case 10: val = std::rotl(val, val & 7); break;
            case 11: val = std::rotl(val, 1); break;
            case 12: val ^= std::rotl(val, 2); break;
            case 13: val = std::rotl(val, 3); break;
            case 14: val ^= std::rotl(val, 4); break;
            case 15: val = std::rotl(val, 5); break;
        }
    }
    return val;
}

// Proper bit reverse for case 8
inline uint8_t reverse8(uint8_t b) {
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1);
    return b;
}

// Proper scalar branch with correct bit reverse
inline uint8_t computeBranchCorrect(uint8_t val, uint8_t pos2val, uint32_t opcode) {
    for (int i = 3; i >= 0; --i) {
        uint8_t insn = (opcode >> (i << 3)) & 0xFF;
        switch (insn) {
            case 0: val += val; break;
            case 1: val -= val ^ 97; break;
            case 2: val *= val; break;
            case 3: val ^= pos2val; break;
            case 4: val ^= 0xFF; break;
            case 5: val &= pos2val; break;
            case 6: val <<= (val & 3); break;
            case 7: val >>= (val & 3); break;
            case 8: val = reverse8(val); break;
            case 9: val ^= bitTable[val]; break;
            case 10: val = std::rotl(val, val & 7); break;
            case 11: val = std::rotl(val, 1); break;
            case 12: val ^= std::rotl(val, 2); break;
            case 13: val = std::rotl(val, 3); break;
            case 14: val ^= std::rotl(val, 4); break;
            case 15: val = std::rotl(val, 5); break;
        }
    }
    return val;
}

// Check if opcode uses pos2val (is branched)
// After init: use g_is_branched[op] for O(1) lookup in hot paths
inline bool isBranchedOp(uint8_t op) {
    if (g_lookup_tables_initialized) return g_is_branched[op];
    for (size_t i = 0; i < branchedOps_global.size(); i++) {
        if (branchedOps_global[i] == op) return true;
    }
    return false;
}

// Initialize index arrays
inline void initIndexArrays() {
    memset(g_reg_idx, 0xFF, 256);
    memset(g_branched_idx, 0xFF, 256);
    memset(g_is_branched, 0, 256);

    uint8_t reg_count = 0;
    uint8_t branched_count = 0;

    for (int op = 0; op < 256; op++) {
        if (isBranchedOp(op)) {
            g_branched_idx[op] = branched_count++;
            g_is_branched[op] = 1;
        } else {
            g_reg_idx[op] = reg_count++;
        }
    }
}

// Generate the lookup tables at startup
inline void generateTables(uint8_t* lookup1D, uint8_t* lookup3D) {
    if (!g_lookup_tables_initialized) {
        initIndexArrays();
        for (auto& bits : g_unchanged_bytes) {
            bits.reset();
        }
        for (auto& bits : g_clipped_bytes) {
            bits.reset();
        }
        g_lookup_tables_initialized = true;
    }

    if (lookup1D != nullptr && !g_lookup_1d_initialized) {
        // Generate 1D table for regular ops (no pos2val dependency)
        // Layout: lookup1D[reg_idx * 256 + input] = output
        // Size: 152 * 256 = 38 KB (fits in L1 cache!)
        for (int op = 0; op < 256; op++) {
            if (isBranchedOp(op)) continue;

            uint8_t idx = g_reg_idx[op];
            uint32_t opcode = CodeLUT[op];
            size_t base = (size_t)idx * 256;

            for (int input = 0; input < 256; input++) {
                const uint8_t result = computeBranchCorrect((uint8_t)input, 0, opcode);
                lookup1D[base + input] = result;
                if (result == input) {
                    g_unchanged_bytes[idx].set(input);
                }
                if (result == 0) {
                    g_clipped_bytes[idx].set(input);
                }
            }
        }
        g_lookup_1d_initialized = true;
    }

    // Generate 3D table for branched ops (depends on pos2val) when available.
    if (lookup3D != nullptr && !g_lookup_3d_initialized) {
        // Layout: lookup3D[branched_idx * 256 * 256 + pos2val * 256 + input] = output
        // Size: 104 * 256 * 256 = 6.5 MB (fits in L3 cache)
        for (int op = 0; op < 256; op++) {
            if (!isBranchedOp(op)) continue;

            uint8_t idx = g_branched_idx[op];
            uint32_t opcode = CodeLUT[op];
            size_t base = (size_t)idx * 256 * 256;

            for (int pos2val = 0; pos2val < 256; pos2val++) {
                for (int input = 0; input < 256; input++) {
                    uint8_t result = computeBranchCorrect((uint8_t)input, (uint8_t)pos2val, opcode);
                    lookup3D[base + pos2val * 256 + input] = result;
                }
            }
        }
        g_lookup_3d_initialized = true;
    }
}

// Lookup function for regular ops (1D - L1 cache friendly)
inline uint8_t lookup1D_compute(uint8_t op, uint8_t input) {
    uint8_t idx = g_reg_idx[op];
    return lookup1D_global[(size_t)idx * 256 + input];
}

// Lookup function for branched ops (3D)
inline uint8_t lookup3D_compute(uint8_t op, uint8_t pos2val, uint8_t input) {
    if (lookup3D_global != nullptr) {
        uint8_t idx = g_branched_idx[op];
        size_t offset = (size_t)idx * 256 * 256 + (size_t)pos2val * 256 + input;
        return lookup3D_global[offset];
    }
    return computeBranchCorrect(input, pos2val, CodeLUT[op]);
}

} // namespace lookup_tables
