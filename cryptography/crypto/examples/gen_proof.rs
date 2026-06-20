//! Generate a transfer proof in Rust with a DIFFERENT (offset) deterministic
//! nonce sequence than the canonical one, then print its hex. Fed to the Go
//! `verifyproof` harness to prove the Go verifier accepts a Rust proof built
//! with arbitrary randomness (not just the byte-compare sequence).
//!
//! cargo run -p dero-crypto --example gen_proof   (reads ../../vectors/proof.json)

use dero_crypto::hashtopoint::reduced_hash;
use dero_crypto::scalar::to_32_be;
use dero_crypto::{generate_proof, ScalarRng, Statement, Witness, G1};
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

struct OffsetRng {
    counter: u64,
}
impl ScalarRng for OffsetRng {
    fn next_scalar(&mut self) -> BigUint {
        self.counter += 1;
        // offset by 500_000 so the sequence differs from Go's canonical one
        reduced_hash(&to_32_be(&BigUint::from(self.counter + 500_000)))
    }
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

fn main() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors/proof.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();

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

    let mut rng = OffsetRng { counter: 0 };
    let proof = generate_proof(&scid, scid_index, &statement, &witness, u, &txid, 0, &mut rng);
    println!("{}", hex::encode(proof.serialize()));
}
