//! Generalization gate: the Rust transfer prover must byte-match Go for ring
//! sizes 2, 4, 8 (m = 1, 2, 3) — exercising the m>1 paths (RecursivePolynomials,
//! P/Q transpose, C_XG aggregation over N members). Regenerate:
//! `./go-harness/run.sh proofrings`.

use dero_crypto::{generate_proof, DeterministicRng, Statement, Witness, G1};
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors/proofrings.json");
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
fn transfer_proof_rings_match_go() {
    let cases = load();
    for c in cases.as_array().unwrap() {
        let n = c["n"].as_u64().unwrap();
        assert!(c["verify_go"].as_bool().unwrap(), "Go must accept its N={n} proof");

        let publickeylist = pts(c, "publickeylist");
        let statement = Statement {
            ring_size: publickeylist.len() as u64,
            cln: pts(c, "cln"),
            crn: pts(c, "crn"),
            c: pts(c, "c"),
            d: pt(c["d"].as_str().unwrap()),
            fees: c["fees"].as_u64().unwrap(),
            publickeylist,
            roothash: arr32(c["roothash"].as_str().unwrap()),
            ..Default::default()
        };
        let witness = Witness {
            secret_key: dec(c["sender_secret"].as_str().unwrap()),
            r: dec(c["r"].as_str().unwrap()),
            transfer_amount: c["transfer"].as_u64().unwrap(),
            balance: c["balance"].as_u64().unwrap(),
            index: c["index"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as usize).collect(),
        };
        let u = pt(c["u"].as_str().unwrap());
        let scid = arr32(c["scid"].as_str().unwrap());
        let scid_index = c["scid_index"].as_u64().unwrap() as usize;
        let txid = arr32(c["txid"].as_str().unwrap());

        let mut rng = DeterministicRng::new();
        let proof = generate_proof(&scid, scid_index, &statement, &witness, u, &txid, 0, &mut rng);
        assert_eq!(
            hex::encode(proof.serialize()),
            c["proof_hex"].as_str().unwrap(),
            "ring N={n} proof must byte-match Go"
        );
    }
}
