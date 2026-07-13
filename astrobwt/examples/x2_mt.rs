//! 20-thread de-risk for the 2-way pipeline: does the single-thread +7.96% of
//! `astrobwtv3_x2` survive the DOUBLED per-thread SA working set at saturation?
//! Compares aggregate H/s of T threads running 2-way (2 nonces / 2 scratches per
//! thread) vs T threads running 1-way (both materialized, the current default).
//!
//! Run: cargo run -p dero-astrobwt --release --features "v114 shani2" --example x2_mt -- 20 20

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dero_astrobwt::{astrobwtv3_with_scratch, astrobwtv3_x2, AstroBwtScratch};

fn run(threads: usize, secs: u64, two_way: bool) -> f64 {
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut a = [0x5au8; 48];
                let mut b = [0xa5u8; 48];
                a[47] = t as u8;
                b[47] = t as u8;
                let mut sa = AstroBwtScratch::new();
                let mut sb = AstroBwtScratch::new();
                let mut i: u32 = 0;
                let mut count: u64 = 0;
                loop {
                    if two_way {
                        a[43..47].copy_from_slice(&i.to_be_bytes());
                        b[43..47].copy_from_slice(&i.wrapping_add(1).to_be_bytes());
                        black_box(astrobwtv3_x2(
                            black_box(&a),
                            black_box(&b),
                            &mut sa,
                            &mut sb,
                        ));
                        count += 2;
                        i = i.wrapping_add(2);
                    } else {
                        a[43..47].copy_from_slice(&i.to_be_bytes());
                        black_box(astrobwtv3_with_scratch(black_box(&a), &mut sa));
                        count += 1;
                        i = i.wrapping_add(1);
                    }
                    if count % 64 == 0 && stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
                count
            })
        })
        .collect();
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    total as f64 / start.elapsed().as_secs_f64()
}

fn main() {
    std::env::set_var("DERO_MATERIALIZE", "1");
    let threads: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    println!("x2_mt: {threads} threads, {secs}s per phase (materialized)\n");

    // Warm up briefly, then measure each arm. Order: 2-way first, then 1-way.
    let _ = run(threads, 3, true);
    let hps_x2 = run(threads, secs, true);
    let hps_x1 = run(threads, secs, false);

    println!("2-way : {hps_x2:9.1} H/s ({:.2} KH/s)", hps_x2 / 1000.0);
    println!("1-way : {hps_x1:9.1} H/s ({:.2} KH/s)", hps_x1 / 1000.0);
    println!(
        "\n2-way vs 1-way at {threads}T: {:.4}x ({:+.2}%)",
        hps_x2 / hps_x1,
        (hps_x2 / hps_x1 - 1.0) * 100.0
    );
}
