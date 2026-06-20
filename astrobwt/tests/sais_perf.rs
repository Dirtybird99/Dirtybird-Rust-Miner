//! Perf sanity note for the SA-IS swap (run with `--release --ignored`).
//!
//! AstroBWTv3 spends almost all its time in the suffix-array stage. With the old
//! O(n log² n) prefix-doubling SA, a single hash took ~0.4 s; with SA-IS
//! (linear-time) it drops to single-digit milliseconds. This test times N hashes
//! and prints the per-hash cost; it asserts only a loose ceiling so it documents
//! (not over-constrains) the win.

use std::time::Instant;

use dero_astrobwt::astrobwtv3;

#[test]
#[ignore = "perf note — run with --release --ignored"]
fn perf_astrobwtv3_hashes_are_low_ms() {
    // Warm up (first hash pays for code/cache).
    let _ = astrobwtv3(b"warmup");

    let n = 50u32;
    let start = Instant::now();
    for i in 0..n {
        let input = i.to_le_bytes();
        let _ = astrobwtv3(&input);
    }
    let elapsed = start.elapsed();
    let per_hash_ms = elapsed.as_secs_f64() * 1000.0 / n as f64;
    println!(
        "AstroBWTv3 (SA-IS): {n} hashes in {:.3}s = {:.3} ms/hash",
        elapsed.as_secs_f64(),
        per_hash_ms
    );

    // The old prefix-doubling SA was ~400 ms/hash; SA-IS should be well under
    // 50 ms/hash even in CI. A generous ceiling keeps this a sanity note.
    assert!(
        per_hash_ms < 50.0,
        "expected low-ms/hash with SA-IS, got {per_hash_ms:.3} ms/hash"
    );
}
