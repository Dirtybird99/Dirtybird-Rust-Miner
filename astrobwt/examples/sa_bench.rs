//! Micro-benchmark for the AstroBWTv3 suffix-array lever (plan Step 0/4).
//!
//! End-to-end hash rate mirrors `dero-miner --bench` (255-byte input → the real
//! 65–98 KB op-loop → SA → hash), so the numbers are comparable. Run both backends:
//!
//!   cargo run -p dero-astrobwt --release --example sa_bench                    # pure Rust
//!   cargo run -p dero-astrobwt --release --features libsais --example sa_bench # C libsais
//!
//! Under `--features libsais` it additionally reports the raw SA speedup and the
//! SA's share of a full hash (both impls are callable in that build).

use std::time::Instant;

use dero_astrobwt::astrobwtv3;
#[cfg(feature = "libsais")]
use dero_astrobwt::sais32;

/// Tiny deterministic PRNG (same one the sais_vectors fuzz uses) — no rand dep.
struct SplitMix64 {
    s: u64,
}
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { s: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.s = self.s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next_u64() as u8;
        }
    }
}

/// Aggregate hashes/sec across `threads` workers, each grinding `iters`
/// AstroBWTv3 hashes over a 255-byte buffer (the miner's workload).
fn end_to_end_hps(threads: usize, iters: u32) -> f64 {
    let now = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            std::thread::spawn(move || {
                let mut rng = SplitMix64::new(0x1234_5678 ^ (t as u64).wrapping_mul(0x9E37_79B1));
                let mut work = [0u8; 255];
                rng.fill(&mut work);
                for i in 0..iters {
                    // perturb a couple of bytes per iter, like nonce grinding
                    work[0] = i as u8;
                    work[1] = (i >> 8) as u8;
                    std::hint::black_box(astrobwtv3(std::hint::black_box(&work)));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("bench thread panicked");
    }
    let secs = now.elapsed().as_secs_f64();
    (threads as u32 * iters) as f64 / secs
}

fn main() {
    let backend = if cfg!(feature = "libsais") {
        "libsais (C)"
    } else {
        "sais32 (pure Rust)"
    };
    println!("AstroBWTv3 SA backend: {backend}");

    let max = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let iters = 300u32;
    for &t in &[1usize, max] {
        let hps = end_to_end_hps(t, iters);
        println!("  end-to-end: {t:>3} thread(s) -> {hps:9.1} H/s  ({iters} iters/thread)");
    }

    #[cfg(feature = "libsais")]
    {
        // Representative high-entropy buffer in the v3 SA size range (~80 KB).
        let mut rng = SplitMix64::new(0xDEAD_BEEF_CAFE_F00D);
        let mut buf = vec![0u8; 80_000];
        rng.fill(&mut buf);

        // Byte-identity on the exact bench input before timing it.
        assert_eq!(
            sais32::suffix_array(&buf),
            sais32::suffix_array_libsais(&buf),
            "SA mismatch on the bench buffer"
        );

        let iters = 200u32;
        let t0 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(sais32::suffix_array(std::hint::black_box(&buf)));
        }
        let rust_ms = t0.elapsed().as_secs_f64() * 1e3 / iters as f64;

        let t1 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(sais32::suffix_array_libsais(std::hint::black_box(&buf)));
        }
        let lib_ms = t1.elapsed().as_secs_f64() * 1e3 / iters as f64;

        println!(
            "  SA on {} bytes: sais32 = {:.3} ms, libsais = {:.3} ms, speedup = {:.2}x",
            buf.len(),
            rust_ms,
            lib_ms,
            rust_ms / lib_ms
        );
    }
}
