//! Byte-exact verification of the AstroBWTv3 prologue (sha256 → salsa20 → rc4 →
//! fnv1a) against the Go reference. Vector from `go-harness/astrobwt`
//! (./go-harness/run.sh astrobwt). The `final_hash_hex` field is the end-to-end
//! target recorded for the full port (steps 5–7), and is not asserted yet.

use std::path::PathBuf;

use dero_astrobwt::{fnv1a_64, prologue};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    input_hex: String,
    sha_key_hex: String,
    post_salsa_hex: String,
    post_rc4_hex: String,
    lhash: u64,
    #[allow(dead_code)]
    final_hash_hex: String,
}

fn load() -> Vec<Case> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../vectors/astrobwt.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

#[test]
fn prologue_matches_go_reference() {
    let cases = load();
    assert!(!cases.is_empty(), "no vectors");
    for (i, c) in cases.iter().enumerate() {
        let input = hex::decode(&c.input_hex).unwrap();
        let p = prologue(&input);

        assert_eq!(hex::encode(p.sha_key), c.sha_key_hex, "case {i}: sha_key");
        assert_eq!(
            hex::encode(p.post_salsa),
            c.post_salsa_hex,
            "case {i}: post-salsa (salsa20 keystream)"
        );
        assert_eq!(
            hex::encode(p.post_rc4),
            c.post_rc4_hex,
            "case {i}: post-rc4 (modified RC4)"
        );
        assert_eq!(p.lhash, c.lhash, "case {i}: lhash (fnv1a-64)");
    }
}

#[test]
fn fnv1a_known_vector() {
    // FNV-1a-64 of the empty string is the offset basis.
    assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
}
