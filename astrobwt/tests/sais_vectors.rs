//! Verifies the SA-IS suffix-array engines ([`dero_astrobwt::sais32`] /
//! [`dero_astrobwt::sais16`]) reproduce the REAL Go SA-IS index-for-index.
//!
//! Two gates:
//!
//! 1. **Vector gate** — `vectors/sais.json` (from `go-harness/run.sh sais`) holds
//!    the FULL suffix array Go's `sais_8_32` and `sais_8_16` produce for a set of
//!    edge inputs (trivial lengths, all-equal, monotone, SLSL alternation,
//!    periodic/recursion-forcing, forcealloc-trigger, and the boundary lengths
//!    255/256/257/512/9973/98303). Rust must match every array exactly.
//!
//! 2. **Differential fuzz** — 1000+ random inputs of varied lengths and
//!    alphabets (including the full 98303 range) are run through both SA-IS
//!    modules and the retained slow prefix-doubling reference
//!    ([`dero_astrobwt::suffix_array_reference`]); all three must agree
//!    index-for-index. This catches any divergence the fixed vectors miss.

use dero_astrobwt::{sais16, sais32, suffix_array_reference};

fn load() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/sais.json");
    let raw = std::fs::read_to_string(path).expect("run go-harness/run.sh sais first");
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn sais32_full_arrays_match_go() {
    let v = load();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 20, "expected the full edge-input set");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let input = hex::decode(case["input_hex"].as_str().unwrap()).unwrap();
        let want: Vec<i32> = case["sa32"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_i64().unwrap() as i32)
            .collect();
        let got = sais32::suffix_array(&input);
        assert_eq!(got.len(), input.len(), "case {name}: SA length");
        assert_eq!(got, want, "case {name}: sais_8_32 SA mismatch");
        // Gate: libsais must reproduce the REAL Go sais_8_32 vector byte-for-byte.
        #[cfg(feature = "libsais")]
        assert_eq!(
            sais32::suffix_array_libsais(&input),
            want,
            "case {name}: libsais SA mismatch vs Go sais_8_32"
        );
    }
}

#[test]
fn sais16_full_arrays_match_go() {
    let v = load();
    let cases = v["cases"].as_array().unwrap();

    let mut checked = 0;
    for case in cases {
        if !case["has_sa16"].as_bool().unwrap_or(false) {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let input = hex::decode(case["input_hex"].as_str().unwrap()).unwrap();
        let want: Vec<i16> = case["sa16"]
            .as_array()
            .map(|a| a.iter().map(|x| x.as_i64().unwrap() as i16).collect())
            .unwrap_or_default();
        let got = sais16::suffix_array(&input);
        assert_eq!(got.len(), input.len(), "case {name}: SA16 length");
        assert_eq!(got, want, "case {name}: sais_8_16 SA mismatch");
        checked += 1;
    }
    assert!(checked >= 20, "expected most cases to carry an sais_8_16 vector");
}

// --- self-contained deterministic PRNG for the differential fuzz (no crates) ---

struct SplitMix64 {
    state: u64,
}
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn byte_in(&mut self, alphabet: u32) -> u8 {
        (self.next_u64() % alphabet as u64) as u8
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize) % (hi - lo + 1)
    }
}

/// 1000+ random inputs, varied lengths and alphabets, cross-checked between both
/// SA-IS engines and the slow prefix-doubling reference. Reference returns
/// `Vec<i32>`; sais16 returns `Vec<i16>` (compared widened).
#[test]
fn differential_fuzz_sais_vs_reference() {
    let mut rng = SplitMix64::new(0xDE40_C0FF_EE12_3456);
    let mut total = 0usize;

    // A spread of length buckets, including a few large ones up to MAX_LENGTH.
    // (alphabet, [length buckets...])
    let alphabets: [u32; 6] = [2, 3, 4, 16, 64, 256];

    for &alphabet in &alphabets {
        // many small/medium inputs
        for _ in 0..175 {
            let n = rng.range(0, 600);
            let input: Vec<u8> = (0..n).map(|_| rng.byte_in(alphabet)).collect();
            check_one(&input, alphabet);
            total += 1;
        }
        // a handful around the POW16 / boundary sizes
        for _ in 0..10 {
            let n = rng.range(9900, 10050);
            let input: Vec<u8> = (0..n).map(|_| rng.byte_in(alphabet)).collect();
            check_one(&input, alphabet);
            total += 1;
        }
    }

    // A few large inputs across the full AstroBWTv3 range (sais32 only — > i16).
    for &n in &[20000usize, 50000, 98303] {
        for &alphabet in &[2u32, 256] {
            let input: Vec<u8> = (0..n).map(|_| rng.byte_in(alphabet)).collect();
            let got = sais32::suffix_array(&input);
            let want = suffix_array_reference(&input);
            assert_eq!(got, want, "large fuzz: alphabet {alphabet} len {n}");
            // Gate: libsais on the large (real AstroBWTv3-sized) inputs.
            #[cfg(feature = "libsais")]
            assert_eq!(
                sais32::suffix_array_libsais(&input),
                want,
                "large fuzz libsais: alphabet {alphabet} len {n}"
            );
            total += 1;
        }
    }

    assert!(total >= 1000, "expected 1000+ fuzz inputs, ran {total}");
}

fn check_one(input: &[u8], alphabet: u32) {
    let reference = suffix_array_reference(input);

    let got32 = sais32::suffix_array(input);
    assert_eq!(
        got32,
        reference,
        "sais32 vs reference: alphabet {alphabet} len {} input {:?}",
        input.len(),
        &input[..input.len().min(64)]
    );

    // Gate: the libsais-backed SA must agree with the prefix-doubling oracle on
    // every fuzz input (covers n=0/1, small alphabets, and the 9900..10050 band).
    #[cfg(feature = "libsais")]
    assert_eq!(
        sais32::suffix_array_libsais(input),
        reference,
        "libsais vs reference: alphabet {alphabet} len {} input {:?}",
        input.len(),
        &input[..input.len().min(64)]
    );

    // sais16 valid for lengths < i16::MAX (these fuzz inputs are all < 11000).
    if input.len() < 32768 {
        let got16 = sais16::suffix_array(input);
        let want16: Vec<i16> = reference.iter().map(|&v| v as i16).collect();
        assert_eq!(
            got16,
            want16,
            "sais16 vs reference: alphabet {alphabet} len {}",
            input.len()
        );
    }
}
