//! THE transfer-proof gate: with the deterministic RNG, the Rust-built Zether/
//! Bulletproof transfer proof must serialize byte-for-byte identically to the Go
//! reference's, on a synthetic N=2 statement that Go's `Proof.Verify` accepts.
//! Regenerate: `./go-harness/run.sh proof`.

use dero_crypto::{generate_proof, DeterministicRng, Statement, Witness, G1};
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors/proof.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}
fn pt(s: &str) -> G1 {
    G1::decompress(&hex::decode(s).unwrap()).unwrap()
}
fn pts(v: &Value, k: &str) -> Vec<G1> {
    v[k].as_array().unwrap().iter().map(|x| pt(x.as_str().unwrap())).collect()
}
fn arr32(s: &str) -> [u8; 32] {
    let b = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}

#[test]
fn transfer_proof_matches_go() {
    let v = load();
    assert!(v["verify_go"].as_bool().unwrap(), "Go reference must accept its own proof");

    let publickeylist = pts(&v, "publickeylist");
    let statement = Statement {
        ring_size: publickeylist.len() as u64,
        cln: pts(&v, "cln"),
        crn: pts(&v, "crn"),
        c: pts(&v, "c"),
        d: pt(v["d"].as_str().unwrap()),
        fees: v["fees"].as_u64().unwrap(),
        publickeylist,
        roothash: arr32(v["roothash"].as_str().unwrap()),
        ..Default::default()
    };
    let witness = Witness {
        secret_key: dec(v["sender_secret"].as_str().unwrap()),
        r: dec(v["r"].as_str().unwrap()),
        transfer_amount: v["transfer"].as_u64().unwrap(),
        balance: v["balance"].as_u64().unwrap(),
        index: v["index"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as usize).collect(),
    };
    let u = pt(v["u"].as_str().unwrap());
    let scid = arr32(v["scid"].as_str().unwrap());
    let scid_index = v["scid_index"].as_u64().unwrap() as usize;
    let txid = arr32(v["txid"].as_str().unwrap());

    let mut rng = DeterministicRng::new();
    let proof = generate_proof(&scid, scid_index, &statement, &witness, u, &txid, 0, &mut rng);

    assert_eq!(
        hex::encode(proof.serialize()),
        v["proof_hex"].as_str().unwrap(),
        "Rust transfer proof must equal Go byte-for-byte"
    );
}
