//! PGO training workload for the v114 descriptor SA. Runs AstroBWTv3 over many
//! varied nonces (exercising the descriptor's data-dependent branches) and
//! returns from `main` NORMALLY so the LLVM profile runtime's atexit hook writes
//! the .profraw (std::process::exit would skip it).
//!
//! Build instrumented:  DERO_CC_PGO=gen cargo build -p dero-astrobwt --example pgo_train --release --features v114
//! Collect:             LLVM_PROFILE_FILE=pgo.profraw ./pgo_train 60000
//! Merge:               llvm-profdata merge -o merged.profdata pgo.profraw
//! Use:                 DERO_CC_PGO=<abs merged.profdata> cargo build -p dero-miner --profile release-lto --features v114

#[cfg(feature = "v114")]
fn main() {
    use dero_astrobwt::{astrobwtv3_with_scratch, AstroBwtScratch};

    let iters: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60_000);

    // A few independent base blobs so the profile isn't tied to one input shape;
    // the per-iteration nonce drives the data-dependent op-loop / SA branches.
    let bases: [[u8; 48]; 3] = [
        {
            let mut w = [0u8; 48];
            for (j, b) in w.iter_mut().enumerate() {
                *b = (j as u8).wrapping_mul(73).wrapping_add(17);
            }
            w[0] = (w[0] & 0xf0) | 0x01;
            w
        },
        {
            let mut w = [0u8; 48];
            for (j, b) in w.iter_mut().enumerate() {
                *b = (j as u8).wrapping_mul(181).wrapping_add(3);
            }
            w[0] = (w[0] & 0xf0) | 0x01;
            w
        },
        {
            let mut w = [0u8; 48];
            for (j, b) in w.iter_mut().enumerate() {
                *b = (j as u8) ^ 0xA5;
            }
            w[0] = (w[0] & 0xf0) | 0x01;
            w
        },
    ];

    let mut scratch = AstroBwtScratch::new();
    let mut acc = 0u8;
    for i in 0..iters {
        let mut work = bases[(i as usize) % bases.len()];
        work[43..47].copy_from_slice(&i.to_be_bytes());
        let h = astrobwtv3_with_scratch(&work, &mut scratch);
        acc ^= h[0];
    }
    std::hint::black_box(acc);
    eprintln!("pgo_train: {iters} hashes done");
    // main returns normally -> C runtime exit -> LLVM profile atexit fires.
}

#[cfg(not(feature = "v114"))]
fn main() {
    eprintln!("build with --features v114");
    std::process::exit(1);
}
