//! Verify Statement serialization + graviton.Sum (blake2s) vs Go.
//! Regenerate: `./go-harness/run.sh statement`.

use dero_crypto::{base_g, graviton_sum, Statement, G1};
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors/statement.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn g_mul(n: i64) -> G1 {
    base_g().scalar_mult(&BigUint::from(n as u64).to_bytes_be())
}

#[test]
fn graviton_sum_is_blake2s() {
    let v = load();
    let got = hex::encode(graviton_sum(v["graviton_sum_input"].as_str().unwrap().as_bytes()));
    assert_eq!(got, v["graviton_sum_hex"].as_str().unwrap());
}

#[test]
fn statement_serialize_matches_go() {
    let v = load();
    let pub_scalars: Vec<i64> = v["pub_scalars"].as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect();
    let c_scalars: Vec<i64> = v["c_scalars"].as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect();
    let d_scalar = v["d_scalar"].as_i64().unwrap();

    let mut roothash = [0u8; 32];
    let rh = hex::decode(v["roothash_hex"].as_str().unwrap()).unwrap();
    roothash.copy_from_slice(&rh);

    let mut s = Statement {
        publickeylist: pub_scalars.iter().map(|&n| g_mul(n)).collect(),
        c: c_scalars.iter().map(|&n| g_mul(n)).collect(),
        d: g_mul(d_scalar),
        fees: v["fees"].as_u64().unwrap(),
        bytes_per_publickey: v["bytes_per_publickey"].as_u64().unwrap() as u8,
        roothash,
        ..Default::default()
    };

    let serialized = hex::encode(s.serialize());
    assert_eq!(serialized, v["serialized_hex"].as_str().unwrap());
}
