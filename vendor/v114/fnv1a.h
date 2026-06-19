#pragma once
#include <stdint.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

//fnv1a 32 and 64 bit hash functions
// key is the data to hash, len is the size of the data (or how much of it to hash against)
// code license: public domain or equivalent
// post: https://notes.underscorediscovery.com/constexpr-fnv1a/

inline uint32_t hash_32_fnv1a(const void* key, const uint32_t len) {

    const char* data = (char*)key;
    uint32_t hash = 0x811c9dc5;
    uint32_t prime = 0x1000193;

    for(int i = 0; i < len; ++i) {
        uint8_t value = data[i];
        hash = hash ^ value;
        hash *= prime;
    }

    return hash;

} //hash_32_fnv1a

inline uint64_t hash_64_fnv1a_256(const void* key) {
    const char* data = (char*)key;
    uint64_t hash = 0xcbf29ce484222325;
    uint64_t prime = 0x100000001b3;
    
    #pragma clang loop unroll_count(256)
    for(int i = 0; i < 256; ++i) {
        uint8_t value = data[i];
        hash = hash ^ value;
        hash *= prime;
    }
    
    return hash;

}

inline uint64_t hash_64_fnv1a(const void* key, const uint64_t len) {
    const char* data = (char*)key;
    uint64_t hash = 0xcbf29ce484222325;
    uint64_t prime = 0x100000001b3;

    for(int i = 0; i < len; ++i) {
        uint8_t value = data[i];
        hash = hash ^ value;
        hash *= prime;
    }

    return hash;

} //hash_64_fnv1a

// Variable-length FNV-1a with prefetching
// Processes in cache-line-friendly chunks when length >= 64
inline uint64_t hash_64_fnv1a_prefetch(const void* key, const uint64_t len) {
    const uint8_t* data = (const uint8_t*)key;
    uint64_t hash = 0xcbf29ce484222325;
    constexpr uint64_t FNV_PRIME = 0x100000001b3;

    uint64_t i = 0;

    // Process full cache lines (64 bytes) with prefetching
    while (i + 64 <= len) {
        // Prefetch next cache line
        if (i + 128 <= len) {
            __builtin_prefetch(data + i + 64, 0, 3);
        }

        // Process 64 bytes (one cache line)
        for (int j = 0; j < 64; ++j) {
            hash ^= data[i + j];
            hash *= FNV_PRIME;
        }
        i += 64;
    }

    // Process remaining bytes
    while (i < len) {
        hash ^= data[i++];
        hash *= FNV_PRIME;
    }

    return hash;
}

// Prefetch-optimized FNV-1a for 256 bytes
// Ported from Rust dero-miner simd.rs:73-101
// Processes in cache-line-friendly chunks with prefetching
// Uses __builtin_prefetch for portability (works on GCC/Clang/ICC)
inline uint64_t hash_64_fnv1a_256_prefetch(const void* key) {
    const uint8_t* data = (const uint8_t*)key;
    uint64_t hash = 0xcbf29ce484222325;
    constexpr uint64_t FNV_PRIME = 0x100000001b3;

    // Process in cache-line-friendly chunks (64 bytes = cache line)
    // Chunk 0: prefetch chunk 1
    __builtin_prefetch(data + 64, 0, 3);
    for (int i = 0; i < 64; ++i) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    // Chunk 1: prefetch chunk 2
    __builtin_prefetch(data + 128, 0, 3);
    for (int i = 64; i < 128; ++i) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    // Chunk 2: prefetch chunk 3
    __builtin_prefetch(data + 192, 0, 3);
    for (int i = 128; i < 192; ++i) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    // Chunk 3: final chunk, no prefetch needed
    for (int i = 192; i < 256; ++i) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    return hash;
}

// AVX2 version with explicit SIMD prefetch intrinsics
// Slightly more explicit control over prefetch hints
#if defined(__x86_64__) || defined(_M_X64)
__attribute__((target("avx2")))
inline uint64_t hash_64_fnv1a_256_avx2(const void* key) {
    const uint8_t* data = (const uint8_t*)key;
    uint64_t hash = 0xcbf29ce484222325;
    constexpr uint64_t FNV_PRIME = 0x100000001b3;

    // Process in cache-line-friendly chunks (64 bytes = cache line)
    for (int chunk = 0; chunk < 4; ++chunk) {
        int base = chunk * 64;

        // Prefetch next cache line into L1 cache
        if (chunk < 3) {
            _mm_prefetch((const char*)(data + base + 64), _MM_HINT_T0);
        }

        // Manually unrolled for better instruction-level parallelism
        hash ^= data[base + 0];  hash *= FNV_PRIME;
        hash ^= data[base + 1];  hash *= FNV_PRIME;
        hash ^= data[base + 2];  hash *= FNV_PRIME;
        hash ^= data[base + 3];  hash *= FNV_PRIME;
        hash ^= data[base + 4];  hash *= FNV_PRIME;
        hash ^= data[base + 5];  hash *= FNV_PRIME;
        hash ^= data[base + 6];  hash *= FNV_PRIME;
        hash ^= data[base + 7];  hash *= FNV_PRIME;
        hash ^= data[base + 8];  hash *= FNV_PRIME;
        hash ^= data[base + 9];  hash *= FNV_PRIME;
        hash ^= data[base + 10]; hash *= FNV_PRIME;
        hash ^= data[base + 11]; hash *= FNV_PRIME;
        hash ^= data[base + 12]; hash *= FNV_PRIME;
        hash ^= data[base + 13]; hash *= FNV_PRIME;
        hash ^= data[base + 14]; hash *= FNV_PRIME;
        hash ^= data[base + 15]; hash *= FNV_PRIME;
        hash ^= data[base + 16]; hash *= FNV_PRIME;
        hash ^= data[base + 17]; hash *= FNV_PRIME;
        hash ^= data[base + 18]; hash *= FNV_PRIME;
        hash ^= data[base + 19]; hash *= FNV_PRIME;
        hash ^= data[base + 20]; hash *= FNV_PRIME;
        hash ^= data[base + 21]; hash *= FNV_PRIME;
        hash ^= data[base + 22]; hash *= FNV_PRIME;
        hash ^= data[base + 23]; hash *= FNV_PRIME;
        hash ^= data[base + 24]; hash *= FNV_PRIME;
        hash ^= data[base + 25]; hash *= FNV_PRIME;
        hash ^= data[base + 26]; hash *= FNV_PRIME;
        hash ^= data[base + 27]; hash *= FNV_PRIME;
        hash ^= data[base + 28]; hash *= FNV_PRIME;
        hash ^= data[base + 29]; hash *= FNV_PRIME;
        hash ^= data[base + 30]; hash *= FNV_PRIME;
        hash ^= data[base + 31]; hash *= FNV_PRIME;
        hash ^= data[base + 32]; hash *= FNV_PRIME;
        hash ^= data[base + 33]; hash *= FNV_PRIME;
        hash ^= data[base + 34]; hash *= FNV_PRIME;
        hash ^= data[base + 35]; hash *= FNV_PRIME;
        hash ^= data[base + 36]; hash *= FNV_PRIME;
        hash ^= data[base + 37]; hash *= FNV_PRIME;
        hash ^= data[base + 38]; hash *= FNV_PRIME;
        hash ^= data[base + 39]; hash *= FNV_PRIME;
        hash ^= data[base + 40]; hash *= FNV_PRIME;
        hash ^= data[base + 41]; hash *= FNV_PRIME;
        hash ^= data[base + 42]; hash *= FNV_PRIME;
        hash ^= data[base + 43]; hash *= FNV_PRIME;
        hash ^= data[base + 44]; hash *= FNV_PRIME;
        hash ^= data[base + 45]; hash *= FNV_PRIME;
        hash ^= data[base + 46]; hash *= FNV_PRIME;
        hash ^= data[base + 47]; hash *= FNV_PRIME;
        hash ^= data[base + 48]; hash *= FNV_PRIME;
        hash ^= data[base + 49]; hash *= FNV_PRIME;
        hash ^= data[base + 50]; hash *= FNV_PRIME;
        hash ^= data[base + 51]; hash *= FNV_PRIME;
        hash ^= data[base + 52]; hash *= FNV_PRIME;
        hash ^= data[base + 53]; hash *= FNV_PRIME;
        hash ^= data[base + 54]; hash *= FNV_PRIME;
        hash ^= data[base + 55]; hash *= FNV_PRIME;
        hash ^= data[base + 56]; hash *= FNV_PRIME;
        hash ^= data[base + 57]; hash *= FNV_PRIME;
        hash ^= data[base + 58]; hash *= FNV_PRIME;
        hash ^= data[base + 59]; hash *= FNV_PRIME;
        hash ^= data[base + 60]; hash *= FNV_PRIME;
        hash ^= data[base + 61]; hash *= FNV_PRIME;
        hash ^= data[base + 62]; hash *= FNV_PRIME;
        hash ^= data[base + 63]; hash *= FNV_PRIME;
    }
    return hash;
}
#endif

// Runtime dispatch wrapper for FNV-1a 256-byte hash
// Uses AVX2 version with explicit prefetch on x86-64
inline uint64_t hash_64_fnv1a_256_optimized(const void* key) {
#if defined(__x86_64__) || defined(_M_X64)
    // Modern x86-64 systems all have AVX2 (required by this miner)
    return hash_64_fnv1a_256_avx2(key);
#else
    // Use portable prefetch version for other architectures
    return hash_64_fnv1a_256_prefetch(key);
#endif
}