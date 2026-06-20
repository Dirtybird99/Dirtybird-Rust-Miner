//! Dump real AstroBWT-shaped inputs on which the v114 descriptor SA diverges
//! from the canonical pure-Rust SA, so an external clang++ harness can decide
//! whether the divergence is a clang-cl miscompile (clang++ would be correct)
//! or a genuine algorithm bug (clang++ also wrong).
//!
//! Run: cargo run -p dero-astrobwt --example dump_failcase --release --features v114
//!
//! Output file: /tmp/v114_failcases.bin (override with arg 1)
//!   u32 LE  count
//!   per case:
//!     u32 LE  N   (logical_len)
//!     u32 LE  F   (flag_len)
//!     u8[N]       data            (the SA input)
//!     u8[F]       flags           (per-group template boundaries)
//!     i32[N] LE   libsais_sa      (ground-truth suffix array)

#[cfg(feature = "v114")]
fn main() {
    use std::io::Write;

    let out_path = std::env::args().nth(1).unwrap_or_else(|| "/tmp/v114_failcases.bin".to_string());
    const WANT: usize = 12;

    // Deterministic xorshift64* (same generator as the fuzz test).
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };

    let mut scratch = dero_astrobwt::AstroBwtScratch::new();
    let mut cases: Vec<(Vec<u8>, Vec<u8>, usize, Vec<i32>)> = Vec::new();
    let mut scanned = 0usize;

    while cases.len() < WANT && scanned < 2_000_000 {
        scanned += 1;
        let len = (next() % 80 + 1) as usize;
        let mut input = vec![0u8; len];
        for chunk in input.chunks_mut(8) {
            let r = next().to_le_bytes();
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
        // descriptor path vs canonical pure-Rust path
        let descriptor = dero_astrobwt::astrobwtv3_with_scratch(&input, &mut scratch);
        let (canonical, _) = dero_astrobwt::astrobwtv3_full(&input);
        if descriptor == canonical {
            continue;
        }
        // divergent — capture the exact descriptor inputs + ground truth SA
        let (data, flags, logical_len) = dero_astrobwt::dump_v114_case(&input);
        let sa = dero_astrobwt::sais32::suffix_array_libsais(&data);
        assert_eq!(sa.len(), logical_len);
        println!(
            "case {}: input_len={} logical_len={} flag_len={}",
            cases.len(),
            input.len(),
            logical_len,
            flags.len()
        );
        cases.push((data, flags, logical_len, sa));
    }

    println!("found {} divergent cases in {} scans", cases.len(), scanned);

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for (data, flags, logical_len, sa) in &cases {
        buf.extend_from_slice(&(*logical_len as u32).to_le_bytes());
        buf.extend_from_slice(&(flags.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
        buf.extend_from_slice(flags);
        for &v in sa {
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }
    let mut f = std::fs::File::create(&out_path).expect("create out file");
    f.write_all(&buf).expect("write");
    println!("wrote {} bytes to {}", buf.len(), out_path);
}

#[cfg(not(feature = "v114"))]
fn main() {
    eprintln!("build with --features v114");
    std::process::exit(1);
}
