//! Golden-freeze of the v114 descriptor SA backend (pure-Rust port, Phase 0).
//!
//! `capture_v114_golden` snapshots the CURRENT backend's exact observable
//! behavior — the pipeline PoW hash, the fused SA→SHA hash (or refusal), and a
//! SHA-256 digest of the materialized descriptor SA (or refusal) — for a fixed
//! deterministic corpus, into `tests/fixtures/v114_golden.json`.
//!
//! `v114_matches_golden_fixture` asserts the backend still reproduces that
//! snapshot byte-for-byte. Captured against the vendored C++ backend, it lets
//! the C++→Rust swap be verified even after the C++ is deleted. Refusal parity
//! is part of the contract: a port that refuses on *different* inputs silently
//! shifts work to the libsais fallback and changes the perf profile.

use crate::{astrobwtv3_full, astrobwtv3_with_scratch, sais32, AstroBwtScratch};
use sha2::{Digest, Sha256};

#[derive(serde::Serialize, serde::Deserialize)]
struct Case {
    input_hex: String,
    data_len: u32,
    pow_hash_hex: String,
    /// `None` = the fused (SA→SHA streaming) build refused this input.
    fused_hash_hex: Option<String>,
    /// `None` = the materialized descriptor SA build refused this input.
    sa_sha256_hex: Option<String>,
}

fn fixture_path() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/v114_golden.json");
    p
}

/// The frozen corpus: the fixed edge cases from
/// `v114_descriptor_sa_matches_libsais_on_astrobwt_data`, fuzz-style short
/// inputs (same xorshift64* generator/seed as `fused_v114_matches_reference_fuzz`),
/// and miner-shaped 255-byte inputs (same SplitMix64 recipe as `sa_bench`).
fn corpus() -> Vec<Vec<u8>> {
    let mut inputs: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"DERO AstroBWTv3".to_vec(),
        b"v114 descriptor suffix array regression".to_vec(),
        b"\x00\x01\x02\x03\xfd\xfe\xff".to_vec(),
    ];

    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    for _ in 0..512 {
        let len = (next() % 80 + 1) as usize;
        let mut input = vec![0u8; len];
        for chunk in input.chunks_mut(8) {
            let r = next().to_le_bytes();
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
        inputs.push(input);
    }

    for i in 0..16u64 {
        let mut input = vec![0u8; 255];
        let mut s = 0x1234_5678u64 ^ i.wrapping_mul(0x9E37_79B1);
        for b in input.iter_mut() {
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *b = (z ^ (z >> 31)) as u8;
        }
        inputs.push(input);
    }

    inputs
}

fn evaluate(input: &[u8], scratch: &mut AstroBwtScratch) -> Case {
    let (_, dbg) = astrobwtv3_full(input);
    let pow = astrobwtv3_with_scratch(input, scratch);
    let data_len = dbg.data_len as usize;

    // Re-drive both descriptor entry points on the op-loop output the pipeline
    // just produced (same pattern as the diagnostic tests in lib.rs).
    let mut flags: Vec<u8> = Vec::new();
    let fused = sais32::hash_v114_fused_into(
        &scratch.data,
        data_len,
        &scratch.v114_markers,
        &mut flags,
    );
    let mut sa = crate::lpbuf::LpVec::<i32>::with_capacity(data_len);
    let sa_used = sais32::suffix_array_v114_into(
        &scratch.data,
        data_len,
        &scratch.v114_markers,
        &mut flags,
        &mut sa,
    );
    let sa_digest = sa_used.then(|| {
        let mut h = Sha256::new();
        for &v in &sa[..] {
            h.update(v.to_le_bytes());
        }
        hex::encode(h.finalize())
    });

    Case {
        input_hex: hex::encode(input),
        data_len: dbg.data_len,
        pow_hash_hex: hex::encode(pow),
        fused_hash_hex: fused.map(hex::encode),
        sa_sha256_hex: sa_digest,
    }
}

/// Regenerate `tests/fixtures/v114_golden.json` from the current backend.
/// Run: `cargo test -p dero-astrobwt --features v114 --release -- --ignored capture_v114_golden`
#[test]
#[ignore = "writes the golden fixture; run explicitly to (re)capture"]
fn capture_v114_golden() {
    let mut scratch = AstroBwtScratch::new();
    let cases: Vec<Case> = corpus().iter().map(|i| evaluate(i, &mut scratch)).collect();
    let fused_refusals = cases.iter().filter(|c| c.fused_hash_hex.is_none()).count();
    let sa_refusals = cases.iter().filter(|c| c.sa_sha256_hex.is_none()).count();
    let path = fixture_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_string_pretty(&cases).unwrap()).unwrap();
    println!(
        "captured {} cases (fused refusals: {fused_refusals}, sa refusals: {sa_refusals}) to {}",
        cases.len(),
        path.display()
    );
}

/// The backend must reproduce the frozen snapshot byte-for-byte — including
/// WHICH inputs it refuses.
#[test]
fn v114_matches_golden_fixture() {
    let json = std::fs::read_to_string(fixture_path())
        .expect("tests/fixtures/v114_golden.json missing; run capture_v114_golden first");
    let want: Vec<Case> = serde_json::from_str(&json).unwrap();
    assert!(!want.is_empty());
    let mut scratch = AstroBwtScratch::new();
    for (i, w) in want.iter().enumerate() {
        let input = hex::decode(&w.input_hex).unwrap();
        let got = evaluate(&input, &mut scratch);
        assert_eq!(got.data_len, w.data_len, "case {i}: op-loop data_len");
        assert_eq!(got.pow_hash_hex, w.pow_hash_hex, "case {i}: pipeline PoW hash");
        assert_eq!(
            got.fused_hash_hex, w.fused_hash_hex,
            "case {i}: fused hash / refusal parity"
        );
        assert_eq!(
            got.sa_sha256_hex, w.sa_sha256_hex,
            "case {i}: SA digest / refusal parity"
        );
    }
}
