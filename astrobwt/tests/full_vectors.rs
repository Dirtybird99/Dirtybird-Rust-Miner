//! Byte-exact verification of the full AstroBWTv3 pipeline against the Go
//! reference. Vector from `go-harness/astrobwt` (./go-harness/run.sh astrobwt),
//! which dumps both the final hash and the op-loop intermediates (from the
//! clone's debug instrumentation), so the op loop is verified separately from
//! the suffix-array + final-sha256 stages.

use std::path::PathBuf;

use dero_astrobwt::{astrobwtv3, astrobwtv3_full};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    input_hex: String,
    final_hash_hex: String,
    tries: u64,
    data_len: u32,
    lhash_final: u64,
    prev_lhash_final: u64,
    step3_final_hex: String,
    data_hash_hex: String,
}

fn load() -> Vec<Case> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../vectors/astrobwt.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

#[test]
fn op_loop_intermediates_match_go() {
    for (i, c) in load().iter().enumerate() {
        let input = hex::decode(&c.input_hex).unwrap();
        let (_out, dbg) = astrobwtv3_full(&input);

        assert_eq!(dbg.tries, c.tries, "case {i}: tries");
        assert_eq!(dbg.data_len, c.data_len, "case {i}: data_len");
        assert_eq!(dbg.lhash, c.lhash_final, "case {i}: lhash");
        assert_eq!(dbg.prev_lhash, c.prev_lhash_final, "case {i}: prev_lhash");
        assert_eq!(hex::encode(dbg.step3), c.step3_final_hex, "case {i}: final step_3");
        assert_eq!(
            hex::encode(dbg.data_hash),
            c.data_hash_hex,
            "case {i}: op-loop stream hash (data[:data_len])"
        );
    }
}

#[test]
fn final_hash_matches_go() {
    for (i, c) in load().iter().enumerate() {
        let input = hex::decode(&c.input_hex).unwrap();
        assert_eq!(
            hex::encode(astrobwtv3(&input)),
            c.final_hash_hex,
            "case {i}: AstroBWTv3 final hash"
        );
    }
}
