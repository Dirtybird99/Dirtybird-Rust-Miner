//! Per-stage profiler for the AstroBWTv3 hot path. Reports the share of each
//! stage (prologue / op-loop / suffix-array / final-SHA256) so optimization
//! effort targets the real bottleneck of the *current* backend.
//!
//! Run: cargo run -p dero-astrobwt --example profile --release --features "v114 profiling"

#[cfg(feature = "profiling")]
fn main() {
    use dero_astrobwt::{astrobwtv3_stage_cycles, AstroBwtScratch};

    const WARMUP: usize = 2_000;
    const ITERS: usize = 50_000;
    let names = ["prologue(sha+salsa+rc4+fnv)", "op-loop(step5)", "suffix-array(step6)", "final-sha256(step7)"];

    let mut scratch = AstroBwtScratch::new();
    let mut work = [0u8; 48];
    // Deterministic but varied body; the per-iteration nonce counter varies the
    // input every hash, which is what drives the data-dependent op-loop length.
    for (j, b) in work.iter_mut().enumerate() {
        *b = (j as u8).wrapping_mul(73).wrapping_add(17);
    }
    work[0] = (work[0] & 0xf0) | 0x01;

    // Warm caches / branch predictors.
    for i in 0..WARMUP as u32 {
        work[43..47].copy_from_slice(&i.to_be_bytes());
        std::hint::black_box(astrobwtv3_stage_cycles(&work, &mut scratch));
    }

    let mut acc = [0u64; 4];
    let mut total: u64 = 0;
    for i in 0..ITERS as u32 {
        work[43..47].copy_from_slice(&i.to_be_bytes());
        let c = astrobwtv3_stage_cycles(&work, &mut scratch);
        for k in 0..4 {
            acc[k] += c[k];
        }
        total += c.iter().sum::<u64>();
    }

    println!("AstroBWTv3 per-stage profile ({ITERS} hashes)\n");
    let total_f = total as f64;
    let per_hash = total_f / ITERS as f64;
    for k in 0..4 {
        let pct = 100.0 * acc[k] as f64 / total_f;
        let cyc = acc[k] as f64 / ITERS as f64;
        println!("  {:<30} {:6.2}%   {:>10.0} cyc/hash", names[k], pct, cyc);
    }
    println!("\n  {:<30} {:>17.0} cyc/hash", "TOTAL", per_hash);
}

#[cfg(not(feature = "profiling"))]
fn main() {
    eprintln!("build with --features profiling (e.g. --features \"v114 profiling\")");
    std::process::exit(1);
}
