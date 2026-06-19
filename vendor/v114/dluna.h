/*
 * dluna.h -- DIRTYBIRD Miner master header
 *
 * The entire miner's public interface in one file.
 * No forward declarations scattered across 12 headers.
 * If you can't understand this file, you can't understand the miner.
 */
#pragma once

#include <atomic>
#include <mutex>
#include <condition_variable>
#include <string>
#include <cstdint>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/sha.h>

/* Platform sleep -- no nanosleep64 link errors on TDM-GCC. */
#ifdef _WIN32
#include <windows.h>
static inline void dluna_sleep_ms(int ms) { Sleep(ms); }
#else
#include <thread>
#include <chrono>
static inline void dluna_sleep_ms(int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}
#endif

/* Feature flags -- compile-time, not runtime knobs. */
#define USE_ASTRO_SPSA 1

#include "astroworker.h"

/*
 * DERO protocol constants.
 * These are defined by the network. Change them and your shares get rejected.
 */
enum {
    MINIBLOCK_SIZE    = 48,
    NONCE_OFFSET      = 43,  /* bytes 43-46, 4 bytes big-endian */
    THREAD_ID_OFFSET  = 47,
    HASH_SIZE         = 32,
};

/*
 * MinerState -- all shared mutable state lives here.
 *
 * One instance. Global. If you need a second one, you've made
 * a design mistake.
 */
struct MinerState {
    /* Job state (jobMutex protects blob/jobId/height on writes) */
    std::atomic<uint64_t> jobEpoch{0};
    std::atomic<uint64_t> difficulty{0};
    std::atomic<bool>     connected{false};
    std::atomic<bool>     quit{false};

    std::string blob;           /* hex, 96 chars */
    uint8_t     blobBin[48];    /* decoded binary */
    std::string jobId;
    int64_t     height{0};
    std::mutex  jobMutex;
    std::condition_variable newJob;

    /* Share submission -- single-slot mailbox */
    std::atomic<bool> submitReady{false};
    std::string submitJobId;
    std::string submitBlob;
    uint64_t    submitEpoch{0};
    std::mutex  submitMutex;

    /* Counters */
    std::atomic<int64_t> totalHashes{0};
    std::atomic<int64_t> accepted{0};
    std::atomic<int64_t> rejected{0};
    std::atomic<int64_t> blocks{0};
    std::atomic<int64_t> submitted{0};
    std::atomic<int64_t> sendFails{0};
    std::atomic<int64_t> staleDrops{0};

    /* Config -- set once at startup, read-only after.
     * Defaults let the binary run with no args; override via -d/-w. */
    std::string host{"dero.rabidmining.com"};
    uint16_t    port{10300};
    std::string wallet{""};
    int         nthreads{0};
};

extern MinerState G;
extern bool       g_has_avx2;

/* Console output coordination.
 *   g_console_mtx -- serializes every write to the console so timestamped
 *                    event lines never corrupt the in-place status line.
 *   g_verbose     -- -V / DLUNA_VERBOSE: restores per-job/share event logging.
 *   log_line()    -- timestamped, mutex-guarded log ("DD/MM HH:MM:SS.mmm  LEVEL  msg").
 *   dluna_console_init() -- enable VT processing + UTF-8, detect TTY (call once). */
extern std::mutex g_console_mtx;
extern bool       g_verbose;
void log_line(const char *level, const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 2, 3)))
#endif
	;
void dluna_console_init(void);
bool dluna_is_tty(void);       /* stdout is an interactive console */
const char *dluna_clr_eol(void); /* ANSI erase-to-EOL, or "" when unavailable */

/* Thread entry points */
void mine_thread(int tid);
void network_thread(void);

/* Difficulty: target = 2^256 / diff */
void compute_target(int64_t diff, uint8_t target[32]);
bool check_hash(const uint8_t hash[32], const uint8_t target[32]);

/* AstroBWT v3 hash */
void dluna_hash(uint8_t *input, int len, uint8_t *output, workerData &w);
void init_lut(void);

/* SHA-256 via SHA-NI (linked with --wrap) or EVP (OpenSSL 3.0) */
inline void hashSHA256(const uint8_t *in, uint8_t *out, int len) {
#if defined(__x86_64__) || defined(_M_X64)
    /* On x86, we use our hardware-accelerated SHA-NI implementation via linker wraps. */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, len);
    SHA256_Final(out, &ctx);
#else
    /* On other platforms (e.g. ARM), use the modern OpenSSL 3.0 EVP API. */
    unsigned int md_len;
    EVP_Digest(in, len, out, &md_len, EVP_sha256(), NULL);
#endif
}

/* Hex helpers */
std::string to_hex(const uint8_t *data, int len);
bool from_hex(const std::string &hex, uint8_t *out, int max);
