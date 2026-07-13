use dero_astrobwt::{astrobwtv3_with_scratch, astrobwtv3_x2, AstroBwtScratch};
use std::hint::black_box;
use std::time::{Duration, Instant};

fn main() {
    std::env::set_var("DERO_MATERIALIZE", "1");
    let duration = Duration::from_secs(8);
    let mut a = [0x5au8; 48];
    let mut b = [0xa5u8; 48];
    let (mut sa, mut sb) = (AstroBwtScratch::new(), AstroBwtScratch::new());

    for nonce in 0..2_000u64 {
        a[40..].copy_from_slice(&nonce.to_le_bytes());
        b[40..].copy_from_slice(&nonce.wrapping_add(1).to_le_bytes());
        black_box(astrobwtv3_x2(&a, &b, &mut sa, &mut sb));
    }

    let start = Instant::now();
    let mut pairs = 0u64;
    while start.elapsed() < duration {
        a[40..].copy_from_slice(&(pairs * 2).to_le_bytes());
        b[40..].copy_from_slice(&(pairs * 2 + 1).to_le_bytes());
        black_box(astrobwtv3_x2(&a, &b, &mut sa, &mut sb));
        pairs += 1;
    }
    let x2_secs = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let mut single_pairs = 0u64;
    while start.elapsed() < duration {
        a[40..].copy_from_slice(&(single_pairs * 2).to_le_bytes());
        b[40..].copy_from_slice(&(single_pairs * 2 + 1).to_le_bytes());
        black_box(astrobwtv3_with_scratch(&a, &mut sa));
        black_box(astrobwtv3_with_scratch(&b, &mut sb));
        single_pairs += 1;
    }
    let x1_secs = start.elapsed().as_secs_f64();
    let x2_ns = x2_secs * 1e9 / (pairs * 2) as f64;
    let x1_ns = x1_secs * 1e9 / (single_pairs * 2) as f64;

    println!(
        "x2:   {:.1} H/s ({x2_ns:.0} ns/hash)",
        (pairs * 2) as f64 / x2_secs
    );
    println!(
        "2x1:  {:.1} H/s ({x1_ns:.0} ns/hash)",
        (single_pairs * 2) as f64 / x1_secs
    );
    println!(
        "per-hash speedup: {:.4}x ({:+.2}%)",
        x1_ns / x2_ns,
        (x1_ns / x2_ns - 1.0) * 100.0
    );
}
