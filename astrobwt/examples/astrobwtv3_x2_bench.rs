//! Fixed-corpus latency benchmark for the production x2 path.
//!
//! Matches Zig `p95bench`: seed-12345/tid-0 blob, big-endian nonces at
//! `[43..47]`, one warmup sweep, then the per-pair minimum across timed sweeps.
//! Usage: astrobwtv3_x2_bench [pin] [repeats] [pairs]

use dero_astrobwt::{astrobwtv3_x2, AstroBwtScratch};
use std::hint::black_box;
use std::time::Instant;

const ZIG_SEED_12345_BLOB: [u8; 48] = [
    104, 165, 248, 222, 130, 138, 148, 141, 160, 2, 103, 121, 83, 249, 119, 52, 105, 141, 219, 230,
    252, 162, 202, 21, 208, 109, 12, 194, 83, 136, 239, 44, 217, 156, 3, 156, 255, 63, 255, 67,
    135, 50, 51, 114, 74, 139, 193, 0,
];

#[cfg(windows)]
fn tune_current_thread(pin: u32) {
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn GetCurrentThread() -> *mut core::ffi::c_void;
        fn SetPriorityClass(process: *mut core::ffi::c_void, class: u32) -> i32;
        fn SetThreadAffinityMask(thread: *mut core::ffi::c_void, mask: usize) -> usize;
        fn SetThreadPriority(thread: *mut core::ffi::c_void, priority: i32) -> i32;
    }

    const HIGH_PRIORITY_CLASS: u32 = 0x80;
    const THREAD_PRIORITY_HIGHEST: i32 = 2;
    unsafe {
        let _ = SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        let _ = SetThreadAffinityMask(GetCurrentThread(), 1usize << pin);
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    }
}

#[cfg(not(windows))]
fn tune_current_thread(_pin: u32) {}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pin = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2);
    let repeats = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5usize);
    let pairs = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_500usize);
    assert!(
        repeats > 0 && pairs > 0,
        "repeats and pairs must be nonzero"
    );
    tune_current_thread(pin);

    let mut blob0 = ZIG_SEED_12345_BLOB;
    let mut blob1 = blob0;
    let (mut worker0, mut worker1) = (AstroBwtScratch::new(), AstroBwtScratch::new());
    let mut checksum = 0xcbf2_9ce4_8422_2325u64;

    for i in 0..pairs {
        blob0[43..47].copy_from_slice(&(2 * i as u32).to_be_bytes());
        blob1[43..47].copy_from_slice(&(2 * i as u32 + 1).to_be_bytes());
        let (out0, out1) = astrobwtv3_x2(&blob0, &blob1, &mut worker0, &mut worker1);
        for byte in out0.into_iter().chain(out1) {
            checksum = (checksum ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
        }
    }

    let mut minima = vec![u64::MAX; pairs];
    let mut sweep_ns = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let sweep = Instant::now();
        for (i, minimum) in minima.iter_mut().enumerate() {
            blob0[43..47].copy_from_slice(&(2 * i as u32).to_be_bytes());
            blob1[43..47].copy_from_slice(&(2 * i as u32 + 1).to_be_bytes());
            let started = Instant::now();
            let outputs = astrobwtv3_x2(&blob0, &blob1, &mut worker0, &mut worker1);
            let elapsed = started.elapsed().as_nanos() as u64;
            black_box(outputs);
            *minimum = (*minimum).min(elapsed);
        }
        sweep_ns.push(sweep.elapsed().as_nanos() as u64);
    }

    minima.sort_unstable();
    let per_hash = |percent: usize| minima[pairs * percent / 100] / 2;
    let mean = minima.iter().sum::<u64>() / pairs as u64 / 2;
    let p95 = per_hash(95);

    eprintln!("p95bench-rust: pin={pin} hp=false pairs={pairs} repeats={repeats}");
    eprintln!(
        "  per-hash ns: p50={} p90={} p95={} p99={} max={} mean={mean}",
        per_hash(50),
        per_hash(90),
        p95,
        per_hash(99),
        minima[pairs - 1] / 2,
    );
    for (index, ns) in sweep_ns.into_iter().enumerate() {
        eprintln!("  sweep{index}: {:.1} ms", ns as f64 / 1e6);
    }
    eprintln!("  checksum={checksum:016x}");
    println!("p95_ns={p95}");
}
