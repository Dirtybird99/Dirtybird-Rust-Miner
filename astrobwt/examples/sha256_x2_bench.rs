use dero_astrobwt::sha256_x2::sha256_x2;
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    const LEN: usize = 256 * 1024;
    const ITERS: usize = 400;
    let a: Vec<u8> = (0..LEN).map(|i| i.wrapping_mul(17) as u8).collect();
    let b: Vec<u8> = (0..LEN)
        .map(|i| i.wrapping_mul(29).wrapping_add(7) as u8)
        .collect();

    black_box(sha256_x2(&a, &b));
    let start = Instant::now();
    for _ in 0..ITERS {
        black_box(sha256_x2(black_box(&a), black_box(&b)));
    }
    let paired = start.elapsed();

    black_box((Sha256::digest(&a), Sha256::digest(&b)));
    let start = Instant::now();
    for _ in 0..ITERS {
        black_box((Sha256::digest(black_box(&a)), Sha256::digest(black_box(&b))));
    }
    let sequential = start.elapsed();

    println!("sha256_x2: {paired:?}");
    println!("2x sha2:    {sequential:?}");
    println!(
        "speedup:    {:.3}x",
        sequential.as_secs_f64() / paired.as_secs_f64()
    );
}
