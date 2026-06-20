//! Byte-exact verification against vectors dumped from the Go bn256 reference
//! (`go-harness/bn256`). Run `./go-harness/run.sh bn256` to regenerate.

use dero_bn256::G1;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../vectors/bn256.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("valid json")
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}

#[test]
fn scalar_base_mul_matches_go() {
    let v = load();
    for entry in v["scalar_base_mul"].as_array().unwrap() {
        let k = hx(entry, "k");
        let g = G1::scalar_base_mult(&k);

        let marshal = hex::encode(g.marshal());
        assert_eq!(
            marshal,
            entry["marshal"].as_str().unwrap(),
            "marshal mismatch for k={}",
            entry["k"]
        );

        let compressed = hex::encode(g.compress());
        assert_eq!(
            compressed,
            entry["compressed"].as_str().unwrap(),
            "compress mismatch for k={}",
            entry["k"]
        );

        // decompress round-trips back to the same uncompressed point
        let back = G1::decompress(&g.compress()).expect("decompress");
        assert_eq!(
            hex::encode(back.marshal()),
            entry["marshal"].as_str().unwrap(),
            "decompress round-trip mismatch for k={}",
            entry["k"]
        );
    }
}

#[test]
fn add_matches_go() {
    let v = load();
    for entry in v["add"].as_array().unwrap() {
        let a = hx(entry, "a");
        let b = hx(entry, "b");
        let ag = G1::scalar_base_mult(&a);
        let bg = G1::scalar_base_mult(&b);
        let sum = G1::add(&ag, &bg);
        assert_eq!(
            hex::encode(sum.marshal()),
            entry["marshal"].as_str().unwrap(),
            "add mismatch for a={} b={}",
            entry["a"],
            entry["b"]
        );
    }
}

#[test]
fn neg_matches_go() {
    let v = load();
    for entry in v["neg"].as_array().unwrap() {
        let k = hx(entry, "k");
        let g = G1::scalar_base_mult(&k);
        let ng = G1::neg(&g);
        assert_eq!(
            hex::encode(ng.marshal()),
            entry["marshal"].as_str().unwrap(),
            "neg mismatch for k={}",
            entry["k"]
        );
    }
}
