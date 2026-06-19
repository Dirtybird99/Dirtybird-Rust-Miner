#pragma once

#include <cstdint>

/* Priority profile for the mining process + worker threads.
 *
 *   NORMAL (default): make NO priority/power syscalls — mine at the OS default,
 *           exactly like DeroLuna v1.14. The scheduler can freely preempt the
 *           miner for the desktop UI, so the machine stays smooth/responsive
 *           while mining. On an idle machine this still gets ~all the cores.
 *   MAX:    aggressive — HIGH_PRIORITY_CLASS + THREAD_PRIORITY_HIGHEST + power
 *           throttling disabled. Maximum sustained hashrate, but the 20 workers
 *           preempt the UI and will freeze/stutter the desktop while in use.
 *           Intended for headless / dedicated mining.
 *
 * Selected via the -p/--priority CLI flag or the DLUNA_PRIORITY env var. */
enum DlunaPriorityLevel : uint32_t {
    DLUNA_PRIO_NORMAL = 0,
    DLUNA_PRIO_MAX = 1,
};

struct DlunaRuntimeTuneOptions {
    DlunaPriorityLevel level;          /* default NORMAL */
    bool disable_power_throttling;     /* true only for MAX */
};

enum DlunaRuntimeTuneFlags : uint32_t {
    DLUNA_RUNTIME_TUNE_NONE = 0,
    DLUNA_RUNTIME_TUNE_PROCESS_PRIORITY = 1u << 0,
    DLUNA_RUNTIME_TUNE_PROCESS_POWER = 1u << 1,
    DLUNA_RUNTIME_TUNE_THREAD_PRIORITY = 1u << 2,
    DLUNA_RUNTIME_TUNE_THREAD_POWER = 1u << 3,
};

/* "max" (case-insensitive) -> MAX; null / "normal" / anything else -> NORMAL. */
DlunaPriorityLevel dluna_priority_level_from_string(const char* s);

/* Pure resolver (testable): DLUNA_PRIORITY wins; else DLUNA_DISABLE_RUNTIME_TUNE=1
 * forces NORMAL; else NORMAL. MAX implies power-throttle disable. */
DlunaRuntimeTuneOptions dluna_runtime_tune_options_from_values(
    const char* priority,
    const char* disable_runtime_tune);

DlunaRuntimeTuneOptions dluna_runtime_tune_options_from_env();

const char* dluna_priority_level_name(DlunaPriorityLevel level);

uint32_t dluna_tune_process_runtime();
uint32_t dluna_tune_mining_thread();
