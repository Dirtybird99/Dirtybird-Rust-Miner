//! Verifies the legacy `pow16` PoW byte-exact against Go's `astrobwt.POW16`.
//!
//! `vectors/pow16.json` (from `go-harness/run.sh pow16`) holds, per input, the
//! sha3 key, the 9973-byte salsa20 stage1, and the final POW16 hash. We check
//! the final hash for every input (including the 48-byte miniblock size), and
//! also re-derive stage1 to localize any divergence.

use dero_astrobwt::pow16::{pow16, STAGE1_LENGTH};

fn load() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/pow16.json");
    let raw = std::fs::read_to_string(path).expect("run go-harness/run.sh pow16 first");
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn pow16_final_hash_matches_go() {
    let v = load();
    assert_eq!(v["stage1_length"].as_u64().unwrap() as usize, STAGE1_LENGTH);
    let cases = v["cases"].as_array().unwrap();
    assert!(!cases.is_empty());

    for case in cases {
        let input = hex::decode(case["input_hex"].as_str().unwrap()).unwrap();
        let want = case["final_hex"].as_str().unwrap();
        let got = hex::encode(pow16(&input));
        assert_eq!(got, want, "POW16({} bytes) mismatch", input.len());
    }
}

#[test]
fn pow16_stage1_keystream_matches_go() {
    // localizes a divergence to before/after the salsa20 stage: re-derive
    // sha3 key + salsa20 keystream and compare to the dumped stage1.
    use sha3::{Digest, Sha3_256};
    let v = load();
    for case in v["cases"].as_array().unwrap() {
        let input = hex::decode(case["input_hex"].as_str().unwrap()).unwrap();
        let key: [u8; 32] = Sha3_256::digest(&input).into();
        assert_eq!(hex::encode(key), case["key_hex"].as_str().unwrap(), "sha3 key");

        use salsa20::cipher::{KeyIvInit, StreamCipher};
        use salsa20::Salsa20;
        let nonce = [0u8; 8];
        let mut cipher = Salsa20::new((&key).into(), (&nonce).into());
        let mut stage1 = vec![0u8; STAGE1_LENGTH];
        cipher.apply_keystream(&mut stage1);
        assert_eq!(hex::encode(&stage1), case["stage1_hex"].as_str().unwrap(), "stage1");
    }
}
