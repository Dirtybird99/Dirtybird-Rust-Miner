//! Verifier gate for the Zether/Bulletproof transfer proof (`Proof::verify`,
//! port of proof_verify.go). Uses the `proofrings.json` vectors (full statements
//! incl. CLn/CRn/Publickeylist, ring sizes 2/4/8, each marked `verify_go: true`).
//!
//! The Rust verifier must (1) ACCEPT each proof Go accepts, and (2) REJECT every
//! tamper mutation — which, since Go accepts the same inputs, demonstrates the
//! port matches Go's accept/reject behavior. No chain state required (the full
//! statement is supplied by the vector).

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

// Heavyweight (generates real proofs for rings 2/4/8 + ~20 verifications).
// Run explicitly: `cargo test -p dero-crypto --test proof_verify --release -- --ignored`
#[test]
#[ignore = "slow crypto gate; run with --release --ignored"]
fn verifier_accepts_real_and_rejects_tampered() {
    let order = dero_crypto::group_order();
    let cases = load();
    for c in cases.as_array().unwrap() {
        let n = c["n"].as_u64().unwrap();
        assert!(c["verify_go"].as_bool().unwrap(), "Go accepts its N={n} proof");

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

        // (1) accept the genuine proof
        assert!(
            proof.verify(&scid, scid_index, &statement, &txid, 0),
            "ring N={n}: verifier must accept the genuine proof"
        );

        // (2) reject tamper mutations across distinct proof regions
        let bump = |x: &BigUint| (x + BigUint::from(1u32)) % &order;

        let mut t1 = proof.clone();
        t1.that = bump(&t1.that);
        assert!(!t1.verify(&scid, scid_index, &statement, &txid, 0), "N={n}: tampered `that` must fail");

        let mut t2 = proof.clone();
        t2.c = bump(&t2.c);
        assert!(!t2.verify(&scid, scid_index, &statement, &txid, 0), "N={n}: tampered `c` must fail");

        let mut t3 = proof.clone();
        t3.mu = bump(&t3.mu);
        assert!(!t3.verify(&scid, scid_index, &statement, &txid, 0), "N={n}: tampered `mu` must fail");

        let mut t4 = proof.clone();
        t4.ip.a = bump(&t4.ip.a);
        assert!(!t4.verify(&scid, scid_index, &statement, &txid, 0), "N={n}: tampered ip.a must fail");

        let mut t5 = proof.clone();
        t5.ba = G1::add(&t5.ba, &dero_crypto::base_g()); // perturb a commitment point
        assert!(!t5.verify(&scid, scid_index, &statement, &txid, 0), "N={n}: tampered BA must fail");

        // a different valid txid must also fail (binds the proof to its txid)
        let mut other_txid = txid;
        other_txid[0] ^= 0xff;
        assert!(
            !proof.verify(&scid, scid_index, &statement, &other_txid, 0),
            "N={n}: proof must not verify against a different txid"
        );
    }
}
