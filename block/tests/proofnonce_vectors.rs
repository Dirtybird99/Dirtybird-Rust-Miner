//! Byte-exact verification of `Proof.Nonce()` extraction — the per-payload
//! double-spend nonce (`Keccak256(u.EncodeCompressed())`,
//! proof_generate.go:72-74) plus `Transaction.Fees()` and the serialized Size
//! the mempool records — against the Go reference on a real mainnet 3-payload
//! tx. Vector produced by `go-harness/proofnonce`
//! (./go-harness/run.sh proofnonce).

use std::path::PathBuf;

use dero_protocol::Transaction;
use serde::Deserialize;

#[derive(Deserialize)]
struct PayloadOut {
    scid_hex: String,
    nonce_hex: String,
    statement_fees: u64,
}

#[derive(Deserialize)]
struct Vector {
    tx_hex: String,
    txid_hex: String,
    size_bytes: usize,
    fees: u64,
    payloads: Vec<PayloadOut>,
}

fn load() -> Vector {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../vectors/proofnonce.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

#[test]
fn payload_nonces_fees_and_size_match_go() {
    let v = load();
    let raw = hex::decode(&v.tx_hex).unwrap();
    let (tx, consumed) = Transaction::deserialize(&raw).expect("tx deserialize");
    assert_eq!(consumed, raw.len());
    assert_eq!(hex::encode(tx.get_hash()), v.txid_hex, "txid");

    // mempool bookkeeping inputs: Size = len(Serialize()), Fees()
    assert_eq!(tx.serialize().len(), v.size_bytes, "Size");
    assert_eq!(tx.fees(), v.fees, "Fees()");

    // per-payload Proof.Nonce()
    let nonces = tx.payload_nonces();
    assert_eq!(nonces.len(), v.payloads.len());
    for (i, (nonce, want)) in nonces.iter().zip(&v.payloads).enumerate() {
        assert_eq!(hex::encode(tx.payloads[i].scid), want.scid_hex, "payload {i} scid");
        assert_eq!(hex::encode(nonce), want.nonce_hex, "payload {i} Proof.Nonce()");
        assert_eq!(tx.payloads[i].statement.fees, want.statement_fees, "payload {i} fees");
        assert_eq!(tx.payloads[i].proof_nonce(), Some(*nonce));
    }
}
