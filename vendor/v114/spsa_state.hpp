#pragma once
/**
 * SPSA (Stamp-based Predictive Suffix Array)
 *
 * Port of Tritonn's SPSA algorithm from Rust to C++.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <iostream>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE inline
#endif

struct workerData;

namespace spsa {

// Constants
constexpr size_t MAX_STAMPS = 277;
/* MAX_CHUNKS_PER_STAMP bumped 2026-04-25 from 32 to 128.
 * The wolfCompute templateMarker.posData encodes chunkCount in 7 bits
 * (max value 127), so any cap below 128 silently drops chunks. The
 * 32 cap was discarding 9 chunks worth of positions for pow("a")
 * (marker[3] count=41), which produced wrong hashes. bytes_pos1[] and
 * bytes_255[] are only written, never read — dead storage; the bump
 * costs 192 bytes/stamp = 53 KB extra per state. */
constexpr size_t MAX_CHUNKS_PER_STAMP = 128;
/* MAX_MODIFIED_BYTES bumped 2026-04-25 from 2048 to 16384.
 * Diagnostic showed pow("a") produces ~10836 "modified" positions per
 * hash (per-chunk bytes in stamp's [pos1, pos2] modified region).
 * The 2048 cap was silently dropping ~8800 positions per hash, leading
 * to a 12% short SHA256 input stream and wrong hash output. 16384 is
 * a comfortable headroom (worst-case 277 chunks * ~33 mod bytes each
 * = ~9100 typical, plus tail). Per-state cost: 16384 * 5 = 80 KB. */
constexpr size_t MAX_MODIFIED_BYTES = 16384;

struct Stamp {
    uint16_t start_chunk;
    uint16_t chunk_count;
    uint8_t pos1;
    uint8_t pos2;
    uint8_t bytes_pos1[MAX_CHUNKS_PER_STAMP];
    uint8_t bytes_255[MAX_CHUNKS_PER_STAMP];

    Stamp(uint16_t start, uint8_t p1, uint8_t p2) 
        : start_chunk(start), chunk_count(0), pos1(p1), pos2(p2) {}

    void add_chunk(uint8_t b_p1, uint8_t b_255) {
        if (chunk_count < MAX_CHUNKS_PER_STAMP) {
            bytes_pos1[chunk_count] = b_p1;
            bytes_255[chunk_count] = b_255;
            chunk_count++;
        }
    }
};

class SpsaState {
public:
    std::vector<Stamp> stamps;
    
    struct ModifiedByte {
        uint32_t global_pos;
        uint8_t byte_value;
    };
    ModifiedByte modified_bytes[MAX_MODIFIED_BYTES];
    size_t modified_bytes_count = 0;

    SpsaState() {
        stamps.reserve(MAX_STAMPS);
    }

    void reset() {
        stamps.clear();
        modified_bytes_count = 0;
        current_stamp_idx = -1;
        current_chunk = 0;
    }

    void start_stamp(uint8_t p1, uint8_t p2) {
        stamps.emplace_back(current_chunk, p1, p2);
        current_stamp_idx = static_cast<int>(stamps.size()) - 1;
    }

    void add_chunk(const uint8_t* chunk) {
        if (current_stamp_idx >= 0) {
            Stamp& stamp = stamps[current_stamp_idx];
            stamp.add_chunk(chunk[stamp.pos1], chunk[stamp.pos2]);
            
            for (int i = stamp.pos1; i <= stamp.pos2; i++) {
                if (modified_bytes_count < MAX_MODIFIED_BYTES) {
                    modified_bytes[modified_bytes_count++] = {static_cast<uint32_t>(current_chunk * 256 + i), chunk[i]};
                }
            }
            if (stamp.pos2 != 255 && modified_bytes_count < MAX_MODIFIED_BYTES) {
                modified_bytes[modified_bytes_count++] = {static_cast<uint32_t>(current_chunk * 256 + 255), chunk[255]};
            }
            current_chunk++;
        }
    }

    size_t get_total_suffix_count() const {
        size_t count = 0;
        for (const auto& s : stamps) count += static_cast<size_t>(s.chunk_count) * 256;
        return count + modified_bytes_count;
    }

    void merge_stamps(const uint8_t* data, size_t data_size);

    std::vector<uint32_t> all_entries;
    uint32_t bucket_counts[256];
    uint32_t bucket_offsets[256];

    // Buffers for sorting to avoid thread_local destructors which crash MinGW emutls
    struct SortEntry { uint64_t key; uint32_t pos; uint32_t encoded; };
    std::vector<SortEntry> sort_buffer;
    std::vector<SortEntry> radix_temp;

private:
    int current_stamp_idx = -1;
    uint16_t current_chunk = 0;
    void finalize_current_stamp();
};

// Global integrated path function
bool SPSA_Integrated(const uint8_t* data, int data_size, struct ::workerData &ctx, uint8_t* output);

#define MERGE_STAMP_MARKER 0x80000000
#define MERGE_POSITION_FLAG 0x40000000
/* Tiebreak fix 2026-04-29 (Agent 4 spec): widen pos field 16->17 bits to match
 * Tritonn's libastroSPSA encoding (& 0x1FFFF in spsa_main.asm at 419e/41af/
 * 42b6/4248/4395/4476). Stamp_id narrowed from 14 to 13 bits — still 8191
 * max, vs MAX_STAMPS=277. Functionally a no-op for clone (rel<256) but
 * encoding now matches Tritonn for AVX2-helper-compat. */
#define MERGE_STAMP_ID_SHIFT 17
#define MERGE_STAMP_ID_MASK 0x3FFE0000
#define MERGE_POS_MASK 0x0001FFFF

inline bool is_merge_stamp_ref(uint32_t entry) { return (entry & MERGE_STAMP_MARKER) != 0; }
inline bool is_position_level_entry(uint32_t entry) { return (entry & MERGE_POSITION_FLAG) != 0; }
inline uint16_t decode_merge_stamp_id(uint32_t entry) { return (entry & MERGE_STAMP_ID_MASK) >> MERGE_STAMP_ID_SHIFT; }
inline uint32_t decode_merge_relative_pos(uint32_t entry) { return entry & MERGE_POS_MASK; }

// Core decode logic
inline int32_t merge_entry_to_global_pos_fast(uint32_t entry, const Stamp* stamps) {
    if (is_position_level_entry(entry)) {
        uint16_t sid = decode_merge_stamp_id(entry), rp = decode_merge_relative_pos(entry);
        return (static_cast<int32_t>(stamps[sid].start_chunk) << 8) + rp;
    }
    return static_cast<int32_t>(entry & 0x7FFFFFFF);
}

// Backwards compatibility for sha256_spsa.cpp
inline void merge_entries_to_global_pos_batch4(const uint32_t* entries, const Stamp* stamps, int32_t* out) {
    for (int i = 0; i < 4; i++) out[i] = merge_entry_to_global_pos_fast(entries[i], stamps);
}

#if defined(__AVX2__)
static ALWAYS_INLINE void merge_entries_to_global_pos_avx2_bases(const uint32_t* entries, const int32_t* stamp_base_offsets, int32_t* out) {
    __m256i e = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(entries));
    __m256i sid = _mm256_and_si256(_mm256_srli_epi32(e, 17), _mm256_set1_epi32(0x1FFF));
    __m256i rp = _mm256_and_si256(e, _mm256_set1_epi32(0x1FFFF));
    __m256i sb = _mm256_i32gather_epi32(stamp_base_offsets, sid, 4);
    __m256i sr = _mm256_add_epi32(sb, rp);
    __m256i dr = _mm256_and_si256(e, _mm256_set1_epi32(0x7FFFFFFF));
    __m256i m = _mm256_srai_epi32(_mm256_slli_epi32(e, 1), 31);
    __m256i res = _mm256_blendv_epi8(dr, sr, m);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), res);
}

static ALWAYS_INLINE void merge_entries_to_global_pos_avx2_stamp_only_bases(const uint32_t* entries, const int32_t* stamp_base_offsets, int32_t* out) {
    __m256i e = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(entries));
    __m256i sid = _mm256_and_si256(_mm256_srli_epi32(e, 17), _mm256_set1_epi32(0x1FFF));
    __m256i rp = _mm256_and_si256(e, _mm256_set1_epi32(0x1FFFF));
    __m256i sb = _mm256_i32gather_epi32(stamp_base_offsets, sid, 4);
    __m256i res = _mm256_add_epi32(sb, rp);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), res);
}
#endif

// Compatibility placeholders
inline int32_t merge_entry_to_global_pos_fast_bases(uint32_t entry, const int32_t* base_offsets) {
    if (is_position_level_entry(entry)) {
        uint16_t sid = decode_merge_stamp_id(entry), rp = decode_merge_relative_pos(entry);
        return base_offsets[sid] + static_cast<int32_t>(rp);
    }
    return static_cast<int32_t>(entry & 0x7FFFFFFF);
}
inline int32_t merge_entry_to_global_pos_fast_starts(uint32_t entry, const uint16_t* start_chunks) {
    if (is_position_level_entry(entry)) {
        uint16_t sid = decode_merge_stamp_id(entry), rp = decode_merge_relative_pos(entry);
        return (static_cast<int32_t>(start_chunks[sid]) << 8) + rp;
    }
    return static_cast<int32_t>(entry & 0x7FFFFFFF);
}
inline void merge_entries_to_global_pos_batch4_bases(const uint32_t* e, const int32_t* b, int32_t* o) {
    for(int i=0; i<4; i++) o[i] = merge_entry_to_global_pos_fast_bases(e[i], b);
}
inline void merge_entries_to_global_pos_batch4_stamp_only_bases(const uint32_t* e, const int32_t* b, int32_t* o) {
    for(int i=0; i<4; i++) { uint16_t sid = decode_merge_stamp_id(e[i]), rp = decode_merge_relative_pos(e[i]); o[i] = b[sid] + rp; }
}
inline void merge_entries_to_global_pos_batch4_starts(const uint32_t* e, const uint16_t* s, int32_t* o) {
    for(int i=0; i<4; i++) o[i] = merge_entry_to_global_pos_fast_starts(e[i], s);
}
inline void merge_entries_to_global_pos_batch4_stamp_only_starts(const uint32_t* e, const uint16_t* s, int32_t* o) {
    for(int i=0; i<4; i++) { uint16_t sid = decode_merge_stamp_id(e[i]), rp = decode_merge_relative_pos(e[i]); o[i] = (static_cast<int32_t>(s[sid]) << 8) + rp; }
}

} // namespace spsa
