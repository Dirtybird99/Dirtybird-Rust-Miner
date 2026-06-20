//! Single-thread sustained throughput of the active AstroBWTv3 backend.
//! Isolates the per-hash speed (independent of the miner crate / threading), so
//! per-hash optimizations (e.g. fused SA→SHA) can be A/B measured cleanly.
//!
//! Run: cargo run -p dero-astrobwt --example throughput --release --features v114

use std::time::{Duration, Instant};

use dero_astrobwt::{astrobwtv3_with_scratch, AstroBwtScratch};

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);

    let mut scratch = AstroBwtScratch::new();
    let mut work = [0u8; 48];
    for (j, b) in work.iter_mut().enumerate() {
        *b = (j as u8).wrapping_mul(73).wrapping_add(17);
    }
    work[0] = (work[0] & 0xf0) | 0x01;

    // Warm up.
    for i in 0..3_000u32 {
        work[43..47].copy_from_slice(&i.to_be_bytes());
        std::hint::black_box(astrobwtv3_with_scratch(&work, &mut scratch));
    }

    let dur = Duration::from_secs(secs);
    let start = Instant::now();
    let mut n: u64 = 0;
    let mut i: u32 = 0;
    while start.elapsed() < dur {
        for _ in 0..256 {
            i = i.wrapping_add(1);
            work[43..47].copy_from_slice(&i.to_be_bytes());
            std::hint::black_box(astrobwtv3_with_scratch(&work, &mut scratch));
            n += 1;
        }
    }
    let el = start.elapsed().as_secs_f64();
    let rate = n as f64 / el;
    println!(
        "single-thread: {n} hashes in {el:.2}s = {rate:.1} H/s  ({:.0} ns/hash)",
        1e9 / rate
    );
}
