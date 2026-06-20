//! Byte-exact verification of the crypto layer vs the Go reference.
//! Regenerate with `./go-harness/run.sh crypto`.

use dero_crypto::{
    base_g, base_h, derive_public_key, gs, hash_to_number, hash_to_point, hs, keccak256,
};
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../vectors/crypto.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("valid json")
}

fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}

#[test]
fn keccak256_matches_go() {
    let v = load();
    for e in v["keccak256"].as_array().unwrap() {
        let input = e["input"].as_str().unwrap();
        let got = hex::encode(keccak256(&[input.as_bytes()]));
        assert_eq!(got, e["hex"].as_str().unwrap(), "keccak256({input:?})");
    }
}

#[test]
fn hash_to_number_matches_go() {
    let v = load();
    for e in v["hash_to_number"].as_array().unwrap() {
        let input = e["input"].as_str().unwrap();
        let got = hash_to_number(input.as_bytes());
        assert_eq!(got, dec(e["dec"].as_str().unwrap()), "htn({input:?})");
    }
}

#[test]
fn generators_match_go() {
    let v = load();
    for e in v["points"].as_array().unwrap() {
        let label = e["label"].as_str().unwrap();
        let point = match label {
            "G" => base_g(),
            "H" => base_h(),
            l if l.starts_with("Gs[") => gs(parse_idx(l)),
            l if l.starts_with("Hs[") => hs(parse_idx(l)),
            other => panic!("unknown label {other}"),
        };
        assert_eq!(
            hex::encode(point.marshal()),
            e["marshal"].as_str().unwrap(),
            "{label} marshal"
        );
        assert_eq!(
            hex::encode(point.compress()),
            e["compressed"].as_str().unwrap(),
            "{label} compressed"
        );
    }
}

#[test]
fn hash_to_point_matches_go() {
    let v = load();
    for e in v["hash_to_point"].as_array().unwrap() {
        let seed = dec(e["seed_dec"].as_str().unwrap());
        let p = hash_to_point(&seed);
        assert_eq!(
            hex::encode(p.marshal()),
            e["marshal"].as_str().unwrap(),
            "hash_to_point(seed={})",
            e["seed_dec"]
        );
    }
}

#[test]
fn pubkey_derivation_matches_go() {
    let v = load();
    for e in v["pubkeys"].as_array().unwrap() {
        let secret = dec(e["secret"].as_str().unwrap());
        let pub_key = derive_public_key(&secret);
        assert_eq!(
            hex::encode(pub_key.compress()),
            e["compressed"].as_str().unwrap(),
            "pubkey(secret={})",
            e["secret"]
        );
    }
}

fn parse_idx(label: &str) -> usize {
    // "Gs[63]" -> 63
    let start = label.find('[').unwrap() + 1;
    let end = label.find(']').unwrap();
    label[start..end].parse().unwrap()
}
