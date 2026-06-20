//! Sustained throughput harness — the honest scoreboard for "beat the C miner".
//!
//! The Dirtybird C miner reports "~20 KH/s **sustained** at 20 threads,
//! measure over >=10 minutes". The legacy [`crate::bench`] table measures a
//! fixed-work burst whose wall-clock is gated by the *slowest* thread — on a
//! hybrid CPU (P+E cores) the fast P-cores finish their 1000 hashes and sit
//! idle, structurally understating aggregate throughput and making the number
//! incomparable to the target.
//!
//! This harness instead measures real sustained throughput: spawn N worker
//! threads, each grinds AstroBWTv3 on its own 48-byte miniblock buffer
//! (mutating a BE nonce counter every iteration, exactly like the miner) for a
//! fixed wall-clock window, summing every completed hash into a shared atomic.
//! Throughput = total_hashes / elapsed_seconds. Threads can be pinned to
//! logical cores for stable, repeatable deltas.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dero_astrobwt::{astrobwtv3_with_scratch, AstroBwtScratch};

use crate::affinity;

const MINIBLOCK_SIZE: usize = 48;

/// Resolve the per-thread pin order from the environment, with a documented
/// fallback to round-robin over all logical CPUs (the original behaviour).
///
/// * `PIN_CORES` — explicit comma-separated logical-core list. Thread `t` is
///   pinned to `list[t % list.len()]`. This single knob expresses every pinning
///   strategy without a new CLI flag (main.rs is owned elsewhere):
///     - P-primary only (no HT):      `0,2,4,6,8,10,12,14`
///     - E-cores only:                `16,17,18,19,20,21,22,23`
///     - P-primary + E (16, no HT):   `0,2,4,6,8,10,12,14,16,17,18,19,20,21,22,23`
///     - P with HT + E (24, all):     `0,1,2,...,23`
///     - all P logicals incl. HT:     `0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15`
/// * `PIN_SMART=1` — use [`affinity::recommended_order`] (P-primary, then E,
///   then HT) sized to the thread count. A convenience for the production map.
///
/// When neither is set, falls back to `t % logical_cpus` (legacy round-robin).
fn resolve_pin_order(threads: usize, logical_cpus: usize) -> Vec<usize> {
    if let Ok(spec) = std::env::var("PIN_CORES") {
        let list: Vec<usize> = spec
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .collect();
        if !list.is_empty() {
            return (0..threads).map(|t| list[t % list.len()]).collect();
        }
    }
    if std::env::var("PIN_SMART").map(|v| v != "0").unwrap_or(false) {
        return affinity::recommended_order(threads);
    }
    let cpus = logical_cpus.max(1);
    (0..threads).map(|t| t % cpus).collect()
}

use affinity::set_high_priority;

/// One worker: grind for the lifetime of `stop`, returning hashes completed.
fn worker_loop(stop: &AtomicBool, global: &AtomicU64, tid: u8) -> u64 {
    let mut work = [0u8; MINIBLOCK_SIZE];
    // A plausible version-1 miniblock body; only the nonce region is mutated.
    rand::Rng::fill(&mut rand::thread_rng(), &mut work[..]);
    work[0] = (work[0] & 0xf0) | 0x01;
    work[MINIBLOCK_SIZE - 1] = tid;

    let mut scratch = AstroBwtScratch::new();
    let mut i: u32 = 0;
    let mut local: u64 = 0;
    // Flush to the shared counter in batches to avoid contention.
    const FLUSH: u64 = 64;
    loop {
        for _ in 0..FLUSH {
            i = i.wrapping_add(1);
            work[MINIBLOCK_SIZE - 5..MINIBLOCK_SIZE - 1].copy_from_slice(&i.to_be_bytes());
            std::hint::black_box(astrobwtv3_with_scratch(&work, &mut scratch));
            local += 1;
        }
        global.fetch_add(FLUSH, Ordering::Relaxed);
        if stop.load(Ordering::Relaxed) {
            break;
        }
    }
    local
}

/// Run the sustained benchmark and print an aggregate throughput line.
///
/// When `pin` is set, threads are pinned per [`resolve_pin_order`] (honouring
/// `PIN_CORES` / `PIN_SMART`). The harness also prints a per-window throughput
/// trace (default ~10s buckets, override with `PIN_INTERVAL=<secs>`) so the
/// boost→throttle decay curve and the honest steady-state tail are visible
/// without averaging them together.
pub fn run_sustained(threads: usize, secs: u64, pin: bool) {
    let threads = threads.max(1);
    let cores = affinity::active_logical_cpus();
    // Large pages (2 MB) for the bandwidth/TLB-bound SA buffers — the lever that
    // breaks the 24-thread saturation tie (the C miner runs 4 KB pages on
    // Windows). Enable the process privilege once before workers allocate scratch.
    let lp = dero_astrobwt::enable_large_pages();
    // HIGH priority by default; `SUSTAINED_NOPRIO=1` leaves NORMAL so the
    // priority experiment has a control arm.
    let high_prio = std::env::var("SUSTAINED_NOPRIO").map(|v| v == "0").unwrap_or(true);
    if high_prio {
        set_high_priority();
    }

    let pin_order = resolve_pin_order(threads, cores);
    let interval: u64 = std::env::var("PIN_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);

    let stop = Arc::new(AtomicBool::new(false));
    let global = Arc::new(AtomicU64::new(0));

    eprintln!(
        "sustained: {threads} threads, {secs}s window, pin={}, prio={}, largepages={}, logical_cpus={cores}",
        if pin { "on" } else { "off" },
        if high_prio { "HIGH" } else { "NORMAL" },
        if lp { "2MB" } else { "off(4KB)" }
    );
    if pin {
        eprintln!("pin map        : thread->core {pin_order:?}");
    }

    let start = Instant::now();
    let mut handles = Vec::with_capacity(threads);
    for t in 0..threads {
        let stop = Arc::clone(&stop);
        let global = Arc::clone(&global);
        let core = pin_order[t];
        handles.push(std::thread::spawn(move || {
            if pin {
                affinity::pin_current_thread(core);
            }
            worker_loop(&stop, &global, t as u8)
        }));
    }

    // Interval sampling: print aggregate H/s over each window so a long run
    // reveals the boost→sustained decay (laptop thermal throttling).
    let mut last_count = 0u64;
    let mut last_t = start;
    let mut elapsed_whole = 0u64;
    println!("---------------------------------------------");
    println!("interval trace (window H/s):");
    while elapsed_whole < secs {
        let chunk = interval.min(secs - elapsed_whole);
        std::thread::sleep(Duration::from_secs(chunk));
        let now = Instant::now();
        let count = global.load(Ordering::Relaxed);
        let dt = now.duration_since(last_t).as_secs_f64();
        let win_rate = (count - last_count) as f64 / dt.max(1e-9);
        elapsed_whole += chunk;
        println!(
            "  t={:>3}s  window={:>7.1} H/s  ({:.2} KH/s)",
            elapsed_whole,
            win_rate,
            win_rate / 1000.0
        );
        last_count = count;
        last_t = now;
    }

    stop.store(true, Ordering::Relaxed);

    let mut per_thread = Vec::with_capacity(threads);
    for h in handles {
        per_thread.push(h.join().expect("worker panicked"));
    }
    let elapsed = start.elapsed().as_secs_f64();
    let total: u64 = per_thread.iter().sum();
    let rate = total as f64 / elapsed;

    let min = per_thread.iter().copied().min().unwrap_or(0);
    let max = per_thread.iter().copied().max().unwrap_or(0);
    println!("---------------------------------------------");
    println!("threads        : {threads}");
    println!("elapsed        : {elapsed:.2}s");
    println!("total hashes   : {total}");
    println!("HASHRATE       : {rate:.1} H/s  ({:.2} KH/s)", rate / 1000.0);
    println!("per-thread H/s : {:.1}", rate / threads as f64);
    println!(
        "thread spread  : min={min} max={max} ({}% spread)",
        if max > 0 { (max - min) * 100 / max } else { 0 }
    );
}
