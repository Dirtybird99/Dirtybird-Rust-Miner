//! Byte-exact verification of Block / MiniBlock / coinbase-tx serialization and
//! the BLID (SHA3-256) against the Go reference. Vector produced by
//! `go-harness/block` (./go-harness/run.sh block).

use std::path::PathBuf;

use dero_protocol::block::Block;
use dero_protocol::miniblock::MiniBlock;
use dero_protocol::transaction::Transaction;
use serde::Deserialize;

#[derive(Deserialize)]
struct MBOut {
    version: u8,
    high_diff: bool,
    #[serde(rename = "final")]
    final_field: bool, // `final` is a Rust keyword
    past_count: u8,
    timestamp: u16,
    height: u64,
    past: [u32; 2],
    key_hash16_hex: String,
    flags: u32,
    nonce: [u32; 3],
    ser_hex: String,
    hash_hex: String,
}

#[derive(Deserialize)]
struct Vector {
    coinbase_addr_hex: String,
    coinbase_ser_hex: String,
    coinbase_txid_hex: String,
    major_version: u64,
    minor_version: u64,
    timestamp: u64,
    height: u64,
    proof_hex: String,
    tips_hex: Vec<String>,
    tx_hashes_hex: Vec<String>,
    miniblocks: Vec<MBOut>,
    block_ser_hex: String,
    blid_hex: String,
    tips_hash_hex: String,
    txs_hash_hex: String,
    nonminimal_tips_hex: String,
    nonminimal_tips_reject: bool,
    nonminimal_miniblocks_hex: String,
    nonminimal_miniblocks_reject: bool,
}

fn load() -> Vector {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../vectors/block.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn h33(s: &str) -> [u8; 33] {
    let v = hex::decode(s).unwrap();
    let mut a = [0u8; 33];
    a.copy_from_slice(&v);
    a
}

fn build_mb(m: &MBOut) -> MiniBlock {
    let kh = hex::decode(&m.key_hash16_hex).unwrap();
    let mut key_hash = [0u8; 16];
    key_hash.copy_from_slice(&kh);
    MiniBlock {
        version: m.version,
        high_diff: m.high_diff,
        final_: m.final_field,
        past_count: m.past_count,
        timestamp: m.timestamp,
        height: m.height,
        past: m.past,
        key_hash,
        flags: m.flags,
        nonce: m.nonce,
    }
}

#[test]
fn coinbase_tx_serialize_and_txid() {
    let v = load();
    let tx = Transaction::new_coinbase(h33(&v.coinbase_addr_hex));
    assert_eq!(hex::encode(tx.serialize()), v.coinbase_ser_hex, "coinbase serialize");
    assert_eq!(hex::encode(tx.get_hash()), v.coinbase_txid_hex, "coinbase txid (keccak)");

    // round-trip via the generic deserializer
    let raw = hex::decode(&v.coinbase_ser_hex).unwrap();
    let (tx2, consumed) = Transaction::deserialize(&raw).unwrap();
    assert_eq!(consumed, raw.len(), "coinbase consumed all bytes");
    assert_eq!(hex::encode(tx2.serialize()), v.coinbase_ser_hex, "coinbase re-serialize");
}

#[test]
fn miniblock_serialize_hash_and_roundtrip() {
    let v = load();
    for m in &v.miniblocks {
        let mb = build_mb(m);
        let ser = mb.serialize();
        assert_eq!(hex::encode(ser), m.ser_hex, "miniblock serialize");
        assert_eq!(hex::encode(mb.get_hash()), m.hash_hex, "miniblock GetHash (sha3-256)");

        let back = MiniBlock::deserialize(&ser).unwrap();
        assert_eq!(back, mb, "miniblock deserialize round-trip");
    }
}

#[test]
fn block_serialize_blid_and_subtree_hashes() {
    let v = load();
    let bl = Block {
        major_version: v.major_version,
        minor_version: v.minor_version,
        timestamp: v.timestamp,
        height: v.height,
        miner_tx: Transaction::new_coinbase(h33(&v.coinbase_addr_hex)),
        proof: h32(&v.proof_hex),
        tips: v.tips_hex.iter().map(|s| h32(s)).collect(),
        miniblocks: v.miniblocks.iter().map(build_mb).collect(),
        tx_hashes: v.tx_hashes_hex.iter().map(|s| h32(s)).collect(),
    };

    assert_eq!(hex::encode(bl.serialize()), v.block_ser_hex, "block serialize");
    assert_eq!(hex::encode(bl.get_hash()), v.blid_hex, "BLID (sha3-256)");
    assert_eq!(hex::encode(bl.get_tips_hash()), v.tips_hash_hex, "tips hash");
    assert_eq!(hex::encode(bl.get_txs_hash()), v.txs_hash_hex, "txs hash");
}

#[test]
fn block_deserialize_roundtrip() {
    let v = load();
    let raw = hex::decode(&v.block_ser_hex).unwrap();
    let bl = Block::deserialize(&raw).expect("deserialize mainnet-shaped block");

    // structural spot-checks
    assert_eq!(bl.major_version, v.major_version);
    assert_eq!(bl.minor_version, v.minor_version);
    assert_eq!(bl.timestamp, v.timestamp);
    assert_eq!(bl.height, v.height);
    assert_eq!(bl.tips.len(), v.tips_hex.len());
    assert_eq!(bl.miniblocks.len(), v.miniblocks.len());
    assert_eq!(bl.tx_hashes.len(), v.tx_hashes_hex.len());

    // exact byte round-trip and BLID match
    assert_eq!(hex::encode(bl.serialize()), v.block_ser_hex, "block re-serialize");
    assert_eq!(hex::encode(bl.get_hash()), v.blid_hex, "BLID after round-trip");
}

/// A1: non-minimal varint encodings of the tips/miniblock COUNT must be rejected
/// exactly like Go (`block.go:256` done>1 tips / `:274` done>2 miniblocks).
#[test]
fn block_rejects_nonminimal_count_varints() {
    let v = load();
    assert!(v.nonminimal_tips_reject, "Go must reject non-minimal tips count");
    assert!(v.nonminimal_miniblocks_reject, "Go must reject non-minimal miniblock count");

    let nm_tips = hex::decode(&v.nonminimal_tips_hex).unwrap();
    assert!(
        Block::deserialize(&nm_tips).is_err(),
        "Rust must reject a 2-byte (non-minimal) tips count, like Go"
    );
    let nm_mbl = hex::decode(&v.nonminimal_miniblocks_hex).unwrap();
    assert!(
        Block::deserialize(&nm_mbl).is_err(),
        "Rust must reject a 3-byte (non-minimal) miniblock count, like Go"
    );
}
