//! Differential tests: the pure-Rust descriptor SA ([`crate::v114`]) against
//! the vendored C++ it was ported from, over real AstroBWT-shaped inputs.
//!
//! Both backends are driven from the SAME op-loop output — the exact `(data,
//! logical_len, flags)` triple the production hot path feeds them. Three things
//! must agree byte-for-byte:
//!   1. the materialized suffix array,
//!   2. the fused SA→SHA-256 hash,
//!   3. *which inputs each backend refuses* (refusal drift silently changes
//!      how often the libsais fallback runs).
//!
//! libsais is the independent third opinion: on every accepted input, both
//! descriptor backends must equal it.

use crate::{astrobwtv3_full, astrobwtv3_with_scratch, sais32, AstroBwtScratch};

/// Deterministic xorshift64*, the generator the existing fuzz tests use.
struct Rng(u64);
impl Rng {
    fn new() -> Self {
        Self(0x9E37_79B9_7F4A_7C15)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn input(&mut self, max_len: u64) -> Vec<u8> {
        let len = (self.next() % max_len + 1) as usize;
        let mut input = vec![0u8; len];
        for chunk in input.chunks_mut(8) {
            let r = self.next().to_le_bytes();
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
        input
    }
}

/// Drive the op loop, then hand the identical `(data, logical_len, flags)` to
/// both descriptor backends plus libsais.
struct Both {
    logical_len: usize,
    cpp_sa: Option<Vec<i32>>,
    rust_sa: Option<Vec<i32>>,
    cpp_hash: Option<[u8; 32]>,
    rust_hash: Option<[u8; 32]>,
    libsais_sa: Vec<i32>,
}

fn run_both(input: &[u8], scratch: &mut AstroBwtScratch) -> Option<Both> {
    let (_, dbg) = astrobwtv3_full(input);
    let _ = astrobwtv3_with_scratch(input, scratch);
    let logical_len = dbg.data_len as usize;
    if logical_len == 0 {
        return None;
    }

    let mut flags: Vec<u8> = Vec::new();
    let flag_len =
        sais32::build_v114_stage5_flags(&scratch.v114_markers, logical_len, &mut flags)? as usize;
    let flags = &flags[..flag_len];

    // C++ path, pinned: call the FFI directly rather than through the
    // `DERO_V114_CPP` dispatcher, which now defaults to the Rust backend and
    // would otherwise make this test compare Rust against itself.
    let mut cpp_buf = crate::lpbuf::LpVec::<i32>::with_capacity(logical_len);
    cpp_buf.resize(logical_len, 0);
    let cpp_ok = sais32::suffix_array_v114_cpp_into(
        &scratch.data,
        logical_len,
        flags,
        flag_len as u32,
        &mut cpp_buf,
    );
    let cpp_sa = cpp_ok.then(|| cpp_buf[..].to_vec());
    let cpp_hash =
        sais32::hash_v114_cpp_fused_into(&scratch.data, logical_len, flags, flag_len as u32);

    // Pure-Rust path (same inputs, direct call).
    let mut rust_buf = vec![0i32; logical_len + crate::v114::MATERIALIZED_SA_TAIL_WORDS];
    let rust_ok =
        crate::v114::sa_build_compact_fused(&scratch.data, logical_len, flags, &mut rust_buf);
    rust_buf.truncate(logical_len);
    let rust_sa = rust_ok.then_some(rust_buf);
    let rust_hash = crate::v114::hash_compact_fused(&scratch.data, logical_len, flags);

    let libsais_sa = sais32::suffix_array_libsais(&scratch.data[..logical_len]);

    Some(Both {
        logical_len,
        cpp_sa,
        rust_sa,
        cpp_hash,
        rust_hash,
        libsais_sa,
    })
}

fn check(b: &Both, label: &str) {
    assert_eq!(
        b.cpp_sa.is_some(),
        b.rust_sa.is_some(),
        "{label}: SA refusal drift (cpp={}, rust={})",
        b.cpp_sa.is_some(),
        b.rust_sa.is_some()
    );
    assert_eq!(
        b.cpp_hash.is_some(),
        b.rust_hash.is_some(),
        "{label}: fused-hash refusal drift"
    );

    if let (Some(cpp), Some(rust)) = (&b.cpp_sa, &b.rust_sa) {
        assert_eq!(cpp, rust, "{label}: descriptor SA mismatch (cpp vs rust)");
        assert_eq!(
            rust, &b.libsais_sa,
            "{label}: rust descriptor SA != libsais ground truth"
        );
        assert_eq!(rust.len(), b.logical_len);
    }
    if let (Some(cpp), Some(rust)) = (&b.cpp_hash, &b.rust_hash) {
        assert_eq!(cpp, rust, "{label}: fused hash mismatch (cpp vs rust)");
    }
    // The fused hash must equal sha256 over the materialized SA's LE bytes.
    if let (Some(rust_hash), Some(rust_sa)) = (&b.rust_hash, &b.rust_sa) {
        assert_eq!(
            rust_hash,
            &crate::sha256_sa_i32_le(rust_sa),
            "{label}: fused hash != sha256(materialized SA)"
        );
    }
}

#[test]
fn rust_v114_matches_cpp_on_fixed_cases() {
    let cases: [&[u8]; 4] = [
        b"",
        b"DERO AstroBWTv3",
        b"v114 descriptor suffix array regression",
        b"\x00\x01\x02\x03\xfd\xfe\xff",
    ];
    let mut scratch = AstroBwtScratch::new();
    for (i, input) in cases.iter().enumerate() {
        if let Some(b) = run_both(input, &mut scratch) {
            check(&b, &format!("fixed case {i}"));
            assert!(b.rust_sa.is_some(), "case {i}: rust should accept");
        }
    }
}

#[test]
fn rust_v114_matches_cpp_fuzz() {
    let mut scratch = AstroBwtScratch::new();
    let mut rng = Rng::new();
    let n: usize = std::env::var("DERO_DIFF_FUZZ_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);
    let mut accepted = 0usize;
    for i in 0..n {
        let input = rng.input(80);
        if let Some(b) = run_both(&input, &mut scratch) {
            check(&b, &format!("fuzz {i} input={input:02x?}"));
            accepted += b.rust_sa.is_some() as usize;
        }
    }
    // Guard against a port that vacuously passes by refusing everything.
    assert!(
        accepted * 100 >= n * 95,
        "rust backend accepted only {accepted}/{n} inputs — refusal rate too high"
    );
}

/// Miner-shaped work: 255-byte inputs, the real nonce-grinding size.
#[test]
fn rust_v114_matches_cpp_on_miner_sized_inputs() {
    let mut scratch = AstroBwtScratch::new();
    let mut rng = Rng::new();
    for i in 0..64 {
        let mut input = vec![0u8; 255];
        for chunk in input.chunks_mut(8) {
            let r = rng.next().to_le_bytes();
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
        if let Some(b) = run_both(&input, &mut scratch) {
            check(&b, &format!("miner-sized {i}"));
        }
    }
}
