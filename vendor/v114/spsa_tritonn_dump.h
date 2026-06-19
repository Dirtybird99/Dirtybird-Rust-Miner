// spsa_tritonn_dump.h — DLUNA_DUMP_GROUND_TRUTH dumper for clone-side checkpoints.
//
// Mirrors an offline ground-truth capture. Five
// checkpoints written to the dump directory with `clone_` prefix:
//
//   clone_input.bin                 — input blob at SPSA entry
//   clone_bd_post_phase4.bin        — buckets_d post-Phase 4
//   clone_bheads.bin                — bHeads post-setBuckets
//   clone_bheadidx.bin              — bHeadIdx post-setBuckets
//   clone_sa_prelim_post_phase12.bin — sa_prelim post-Phase 12
//   clone_decompress_stream.bin     — SHA256 input stream
//   clone_manifest.json             — sizes + checkpoint identities
//
// Activated by env DLUNA_DUMP_GROUND_TRUTH=1. Off-by-default (zero overhead).
//
// USAGE inside SPSA():
//   DLUNA_DUMP("input",        input,                  len);
//   DLUNA_DUMP("bd_post_phase4", &w.buckets_d[0][0],   sizeof(w.buckets_d));
//   ... etc.
//
// Checks env exactly once (thread_local cache). Writes synchronously.

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace deroluna_tritonn {

inline bool dluna_dump_enabled() {
    static thread_local int cached = -1;
    if (cached < 0) {
        const char* e = std::getenv("DLUNA_DUMP_GROUND_TRUTH");
        cached = (e && e[0] == '1') ? 1 : 0;
    }
    return cached == 1;
}

inline const char* dluna_dump_dir() {
    static thread_local std::string d = []{
        const char* e = std::getenv("DLUNA_DUMP_DIR");
        return std::string(e ? e
            : "spsa-ground-truth");
    }();
    return d.c_str();
}

inline void dluna_dump_blob(const char* tag, const void* data, size_t bytes) {
    if (!dluna_dump_enabled()) return;
    char path[1024];
    std::snprintf(path, sizeof(path), "%s/clone_%s.bin", dluna_dump_dir(), tag);
    FILE* f = std::fopen(path, "wb");
    if (!f) {
        std::fprintf(stderr, "[DUMP] failed to open %s\n", path);
        return;
    }
    std::fwrite(data, 1, bytes, f);
    std::fclose(f);
    std::fprintf(stderr, "[DUMP] %s -> %s (%zu B)\n", tag, path, bytes);
}

// Append-on-each-call sink for SHA256-feed bytes when capturing decompress().
// Dump it at the end via dluna_dump_flush_sha_stream().
inline void dluna_dump_sha_append(const void* data, size_t bytes) {
    if (!dluna_dump_enabled()) return;
    static thread_local FILE* f = nullptr;
    if (!f) {
        char path[1024];
        std::snprintf(path, sizeof(path), "%s/clone_decompress_stream.bin",
                      dluna_dump_dir());
        f = std::fopen(path, "wb");
        if (!f) {
            std::fprintf(stderr, "[DUMP] failed to open decompress_stream\n");
            return;
        }
    }
    std::fwrite(data, 1, bytes, f);
    std::fflush(f);
}

inline void dluna_dump_manifest(int input_len, int data_len, int templateIdx) {
    if (!dluna_dump_enabled()) return;
    char path[1024];
    std::snprintf(path, sizeof(path), "%s/clone_manifest.json", dluna_dump_dir());
    FILE* f = std::fopen(path, "w");
    if (!f) return;
    std::fprintf(f,
        "{\n"
        "  \"side\": \"clone\",\n"
        "  \"input_len\": %d,\n"
        "  \"data_len\": %d,\n"
        "  \"templateIdx\": %d,\n"
        "  \"captures\": [\n"
        "    {\"name\": \"clone_input.bin\",                  \"checkpoint\": \"SPSA entry\"},\n"
        "    {\"name\": \"clone_bd_post_phase4.bin\",         \"checkpoint\": \"post-Phase 4 (asm 0x3b5f)\"},\n"
        "    {\"name\": \"clone_bheads.bin\",                 \"checkpoint\": \"post-setBuckets (asm 0x3b6a)\"},\n"
        "    {\"name\": \"clone_bheadidx.bin\",               \"checkpoint\": \"post-setBuckets (asm 0x3b6a)\"},\n"
        "    {\"name\": \"clone_sa_prelim_post_phase12.bin\", \"checkpoint\": \"post-Phase 12 (asm 0x3f1a)\"},\n"
        "    {\"name\": \"clone_bheadidx_post_phase12.bin\",  \"checkpoint\": \"post-Phase 12 (asm 0x3f1a)\"},\n"
        "    {\"name\": \"clone_decompress_stream.bin\",      \"checkpoint\": \"SHA256 stream during decompress\"}\n"
        "  ]\n"
        "}\n",
        input_len, data_len, templateIdx);
    std::fclose(f);
}

}  // namespace deroluna_tritonn

// Compact macros to drop into SPSA().
#define DLUNA_DUMP(tag, ptr, sz) ::deroluna_tritonn::dluna_dump_blob(tag, ptr, sz)
