//! FROZEN throughput harness — the measuring instrument for arm64 optimization.
//!
//! Reports median ns/hash for a FIXED amount of work, as one JSON line, so an
//! automated keep/revert loop can compare candidates. Once that loop starts this
//! file is read-only: editing the instrument to move the number is how a loop
//! optimizes its own scoreboard instead of the miner.
//!
//! Why a new example instead of extending `sa_bench`:
//!   * `sa_bench` calls `astrobwtv3()`, which builds a fresh `AstroBwtScratch`
//!     PER HASH — roughly 358 KB of allocate-touch-free that the miner never
//!     pays, because every real path reuses a per-thread scratch. On a phone
//!     that dwarfs the effects being hunted.
//!   * it hashes a 255-byte buffer; the miner grinds a 48-byte miniblock.
//!   * its numbers are quoted in BENCHMARKS.md, so freezing it would sterilize
//!     it for ad-hoc use and mutating it would break historical comparability.
//!
//! Why fixed work rather than a wall-clock window (`throughput.rs`, `x2_mt.rs`):
//! on a shared CI runner a wall-clock window silently converts interference into
//! "fewer hashes at the same rate", which reads as no change. Fixed work turns
//! the same interference into a visibly slower number.
//!
//! Why this does NOT set `DERO_MATERIALIZE`: the fused/materialized choice is
//! read once into a `OnceLock` (`lib.rs`), so it cannot be flipped in-process —
//! the caller must launch this binary once per configuration. Note the polarity
//! trap: the flag is tested with `is_none()`, so `DERO_MATERIALIZE=0` selects
//! MATERIALIZED. The only way to ask for fused is to unset it entirely
//! (`env -u DERO_MATERIALIZE`). The JSON echoes which one was in effect so a
//! mislabelled run is visible after the fact.
//!
//! Run:
//!   cargo run -p dero-astrobwt --release --features "v114 shani2" \
//!     --example arm_bench -- --threads 4 --iters 400 --mode 1way --repeats 7

use std::hint::black_box;
use std::sync::Barrier;
use std::time::Instant;

use dero_astrobwt::{astrobwtv3_with_scratch, astrobwtv3_x2, AstroBwtScratch};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// One nonce per call — what the miner runs everywhere except x86 SHA-NI.
    One,
    /// Two nonces per call. Reaches `astrobwtv3_x2`, which `--sustained` and
    /// `--bench` structurally cannot (both call `astrobwtv3_with_scratch`
    /// directly, and both dispatch before the miner's config logic runs).
    Two,
}

fn arg(name: &str) -> Option<String> {
    let mut it = std::env::args().skip_while(|a| a != name);
    it.next()?;
    it.next()
}

/// Nearest-rank percentile over an ascending slice. No interpolation: with six
/// samples an interpolated median invents a value that was never measured.
fn pct(sorted: &[f64], p: f64) -> f64 {
    let n = sorted.len();
    let idx = ((p * n as f64).ceil() as usize).saturating_sub(1).min(n - 1);
    sorted[idx]
}

/// One measurement: `threads * iters` hashes, timed from a barrier so thread
/// spawn and scratch allocation stay outside the clock.
fn measure(threads: usize, iters: u64, mode: Mode) -> f64 {
    let barrier = Barrier::new(threads + 1);
    let total_hashes = (threads as u64) * iters;

    // The clock starts inside the scope, once every worker has reached the
    // barrier, and is read after `scope` has joined them all — so thread spawn
    // and scratch allocation stay outside the measured window.
    let start = std::thread::scope(|s| {
        for t in 0..threads {
            let barrier = &barrier;
            s.spawn(move || {
                // Miner-shaped input: 48-byte miniblock, per-thread seed, nonce
                // written big-endian at [43..47] exactly as the worker does.
                // Deterministic across candidates, so op-loop lengths are
                // identical run to run and a ns/hash delta is pure speed.
                let mut a = [0x5au8; 48];
                let mut b = [0xa5u8; 48];
                a[47] = t as u8;
                b[47] = t as u8;
                // 1-way allocates ONE scratch per thread, exactly like the
                // miner: a spare would add ~358 KB of resident working set per
                // thread and quietly change the memory pressure being measured.
                let mut sa = AstroBwtScratch::new();
                let mut sb = (mode == Mode::Two).then(AstroBwtScratch::new);

                barrier.wait();

                let mut i: u32 = 0;
                match mode {
                    Mode::One => {
                        for _ in 0..iters {
                            a[43..47].copy_from_slice(&i.to_be_bytes());
                            black_box(astrobwtv3_with_scratch(black_box(&a), &mut sa));
                            i = i.wrapping_add(1);
                        }
                    }
                    Mode::Two => {
                        // iters is forced even by main(), so both modes do
                        // exactly `iters` hashes per thread and the two numbers
                        // are directly comparable.
                        let sb = sb.as_mut().expect("2way allocates a second scratch");
                        for _ in 0..iters / 2 {
                            a[43..47].copy_from_slice(&i.to_be_bytes());
                            b[43..47].copy_from_slice(&i.wrapping_add(1).to_be_bytes());
                            black_box(astrobwtv3_x2(black_box(&a), black_box(&b), &mut sa, sb));
                            i = i.wrapping_add(2);
                        }
                    }
                }
            });
        }
        barrier.wait();
        Instant::now()
    });

    start.elapsed().as_nanos() as f64 / total_hashes as f64
}

fn main() {
    let threads: usize = arg("--threads")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
    let mut iters: u64 = arg("--iters").and_then(|s| s.parse().ok()).unwrap_or(300);
    let repeats: usize = arg("--repeats").and_then(|s| s.parse().ok()).unwrap_or(7);
    let mode = match arg("--mode").as_deref() {
        Some("2way") => Mode::Two,
        _ => Mode::One,
    };
    if mode == Mode::Two && iters % 2 == 1 {
        iters += 1;
    }
    assert!(repeats >= 2, "--repeats must be >= 2 (the first is warmup)");

    // Presence, not value — mirrors how the library reads it.
    let materialize = std::env::var_os("DERO_MATERIALIZE").is_some();
    let mode_str = if mode == Mode::Two { "2way" } else { "1way" };
    eprintln!(
        "arm_bench: {threads}T x {iters} iters, mode={mode_str}, materialize={materialize}, \
         repeats={repeats} (first discarded)"
    );

    let mut samples: Vec<f64> = Vec::with_capacity(repeats - 1);
    for r in 0..repeats {
        let ns = measure(threads, iters, mode);
        if r == 0 {
            eprintln!("  warmup      {ns:9.1} ns/hash (discarded)");
            continue;
        }
        eprintln!("  repeat {r:<2}   {ns:9.1} ns/hash");
        samples.push(ns);
    }

    let mut sorted = samples.clone();
    sorted.sort_by(|x, y| x.partial_cmp(y).expect("no NaN timings"));
    let median = pct(&sorted, 0.5);
    let p25 = pct(&sorted, 0.25);
    let p75 = pct(&sorted, 0.75);
    let min = sorted[0];
    // Interquartile spread relative to the median: the run-to-run instability
    // of THIS job. The between-job spread matters more for a keep/revert
    // decision and can only be had by dispatching repeatedly.
    let spread_pct = 100.0 * (p75 - p25) / median;

    eprintln!("  median {median:.1} ns/hash  =>  {:.1} H/s aggregate", 1e9 / median);

    // One JSON line on stdout; everything else goes to stderr so `tail -n1`
    // always yields parseable output.
    let samples_json: Vec<String> = samples.iter().map(|s| format!("{s:.1}")).collect();
    println!(
        "{{\"ns_per_hash_median\":{median:.1},\"ns_per_hash_min\":{min:.1},\"p25\":{p25:.1},\
         \"p75\":{p75:.1},\"spread_pct\":{spread_pct:.2},\"threads\":{threads},\"iters\":{iters},\
         \"mode\":\"{mode_str}\",\"materialize\":{materialize},\"samples\":[{}]}}",
        samples_json.join(",")
    );
}
