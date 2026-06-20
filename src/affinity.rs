//! Windows CPU-affinity helper for the Intel i7-13700HX (and a sane fallback
//! elsewhere). Dependency-free: raw `extern "system"` declarations against
//! kernel32 (already linked by `std`). Off Windows every public fn is a no-op.
//!
//! # Verified topology — i7-13700HX (Windows 11)
//!
//! Enumerated live with `GetLogicalProcessorInformationEx(RelationProcessorCore)`:
//!
//! ```text
//! physical core  efficiency-class  HT  logical ids
//!   0..7  (P)          1           yes  P-core k -> {2k, 2k+1}
//!   8..15 (E)          0           no   E-core (k-8) -> {16 + (k-8)}
//! ```
//!
//! So the 24 logical CPUs partition as:
//!   * **P primary** (one logical per physical P-core, no HT sibling):
//!     `0, 2, 4, 6, 8, 10, 12, 14`  (8 ids)
//!   * **P HT siblings**: `1, 3, 5, 7, 9, 11, 13, 15`  (8 ids)
//!   * **E-cores**: `16, 17, 18, 19, 20, 21, 22, 23`   (8 ids)
//!
//! AstroBWTv3 is memory-bandwidth bound, so the HT siblings share an L1/L2 and a
//! single memory port with their primary and tend to add little (or hurt). The
//! curated maps below let callers pin to exactly the cores they want.

/// Logical ids of the P-core primaries (one hardware thread per physical P-core).
pub const P_PRIMARY: [usize; 8] = [0, 2, 4, 6, 8, 10, 12, 14];

/// Logical ids of the P-core hyper-thread siblings.
pub const P_HT_SIBLING: [usize; 8] = [1, 3, 5, 7, 9, 11, 13, 15];

/// Logical ids of the E-cores (no hyper-threading).
pub const E_CORE: [usize; 8] = [16, 17, 18, 19, 20, 21, 22, 23];

/// All 16 P-core logicals (primaries + HT siblings), ascending.
pub const P_ALL: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// Build the recommended pin order for `n` worker threads on this CPU:
/// fill the P-core primaries first (best per-thread throughput), then the
/// E-cores, then finally the P-core HT siblings (lowest marginal value on a
/// bandwidth-bound load). Returns logical-core ids of length `n` (wrapping if
/// `n` exceeds 24). This is a sensible production default; the `--sustained`
/// harness can override it with an explicit `PIN_CORES` list.
pub fn recommended_order(n: usize) -> Vec<usize> {
    let mut order: Vec<usize> = Vec::with_capacity(24);
    order.extend_from_slice(&P_PRIMARY);
    order.extend_from_slice(&E_CORE);
    order.extend_from_slice(&P_HT_SIBLING);
    if order.is_empty() {
        return (0..n).collect();
    }
    (0..n).map(|i| order[i % order.len()]).collect()
}

/// Number of active logical processors visible to the process. Windows-accurate
/// (handles >64-CPU groups conceptually, though one affinity mask only reaches
/// the first 64); falls back to `available_parallelism` elsewhere.
#[cfg(windows)]
pub fn active_logical_cpus() -> usize {
    extern "system" {
        fn GetActiveProcessorCount(group: u16) -> u32;
    }
    const ALL_GROUPS: u16 = 0xffff;
    let n = unsafe { GetActiveProcessorCount(ALL_GROUPS) } as usize;
    if n == 0 {
        std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1)
    } else {
        n
    }
}

#[cfg(not(windows))]
pub fn active_logical_cpus() -> usize {
    std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1)
}

/// Raise the current PROCESS to HIGH scheduling priority. Measured worth on the
/// 13700HX: +~8% sustained aggregate hashrate at full occupancy vs NORMAL,
/// because the OS stops time-slicing the grind threads against background work.
/// Windows-only; best-effort no-op elsewhere. Does not affect mining semantics.
#[cfg(windows)]
pub fn set_high_priority() {
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn SetPriorityClass(h: isize, class: u32) -> i32;
    }
    const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
    unsafe {
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    }
}

#[cfg(not(windows))]
pub fn set_high_priority() {}

/// Pin the *current* OS thread to the single logical core `core`. Returns true
/// if the affinity was applied. A single affinity mask addresses only the first
/// 64 logical CPUs, which is ample here. No-op (false) off Windows or for an
/// out-of-range index.
#[cfg(windows)]
pub fn pin_current_thread(core: usize) -> bool {
    extern "system" {
        fn GetCurrentThread() -> isize;
        fn SetThreadAffinityMask(h_thread: isize, mask: usize) -> usize;
    }
    if core >= usize::BITS as usize {
        return false;
    }
    let mask = 1usize << core;
    let prev = unsafe { SetThreadAffinityMask(GetCurrentThread(), mask) };
    prev != 0
}

#[cfg(not(windows))]
pub fn pin_current_thread(_core: usize) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_map_partitions_24_logicals_without_overlap() {
        let mut all: Vec<usize> = Vec::new();
        all.extend_from_slice(&P_PRIMARY);
        all.extend_from_slice(&P_HT_SIBLING);
        all.extend_from_slice(&E_CORE);
        all.sort_unstable();
        assert_eq!(all, (0..24).collect::<Vec<_>>(), "maps must tile 0..24 exactly");
    }

    #[test]
    fn p_all_is_primaries_plus_siblings() {
        let mut combined: Vec<usize> = P_PRIMARY.iter().chain(P_HT_SIBLING.iter()).copied().collect();
        combined.sort_unstable();
        assert_eq!(combined, P_ALL.to_vec());
    }

    #[test]
    fn recommended_order_prefers_p_primaries_then_e_then_ht() {
        // First 8 should be the P primaries.
        assert_eq!(recommended_order(8), P_PRIMARY.to_vec());
        // Next 8 should add the E-cores (P-primary + E, the no-HT 16-thread set).
        let sixteen = recommended_order(16);
        assert_eq!(&sixteen[0..8], &P_PRIMARY);
        assert_eq!(&sixteen[8..16], &E_CORE);
        // The last 8 bring in the HT siblings.
        let twentyfour = recommended_order(24);
        assert_eq!(&twentyfour[16..24], &P_HT_SIBLING);
    }
}
