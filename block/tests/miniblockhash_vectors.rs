//! Byte-exact verification of `Verify_MiniBlocks_HashCheck` — the final
//! miniblock's keyhash binding (`KeyHash[0..16] ==
//! sha3-256(SerializeWithoutLastMiniBlock())[0..16]`) — against the Go
//! reference. Vector produced by `go-harness/miniblockhash`
//! (./go-harness/run.sh miniblockhash).

use std::path::PathBuf;

use dero_protocol::block::Block;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    template_ser_hex: String,
    final_mbl_ser_hex: String,
    block_ser_hex: String,
    ser_without_last_hex: String,
    block_header_hash_hex: String,
    final_key_hash16_hex: String,
    convert_keyhash_match: bool,
    template_equals_ser_without_last: bool,
    hashcheck_ok: bool,
    tampered_err: String,
    non_highdiff_err: String,
    non_final_err: String,
}

fn load() -> Vector {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../vectors/miniblockhash.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

#[test]
fn serialize_without_last_miniblock_matches_go() {
    let v = load();
    let bl = Block::deserialize(&hex::decode(&v.block_ser_hex).unwrap()).expect("block");
    assert_eq!(hex::encode(bl.serialize()), v.block_ser_hex, "block round-trip");

    // SerializeWithoutLastMiniBlock + its sha3 (the binding source)
    assert_eq!(
        hex::encode(bl.serialize_without_last_miniblock()),
        v.ser_without_last_hex,
        "SerializeWithoutLastMiniBlock"
    );
    assert_eq!(
        hex::encode(bl.get_hash_skip_last_miniblock()),
        v.block_header_hash_hex,
        "sha3-256 of it (GetHashSkipLastMiniBlock)"
    );

    // the final miniblock the Go side bound (ConvertBlockToMiniblock branch)
    let final_mbl = bl.miniblocks.last().unwrap();
    assert!(final_mbl.final_ && final_mbl.high_diff);
    assert_eq!(hex::encode(final_mbl.serialize()), v.final_mbl_ser_hex, "final miniblock bytes");
    assert_eq!(hex::encode(final_mbl.key_hash), v.final_key_hash16_hex, "bound keyhash16");

    // Go's ConvertBlockToMiniblock hashes the TEMPLATE's full Serialize()
    // (final miniblock not yet appended) — byte-identical to the completed
    // block's SerializeWithoutLastMiniBlock(). Both asserted by Go too.
    assert!(v.convert_keyhash_match && v.template_equals_ser_without_last);
    let template = Block::deserialize(&hex::decode(&v.template_ser_hex).unwrap()).expect("template");
    assert_eq!(
        template.serialize(),
        bl.serialize_without_last_miniblock(),
        "template Serialize() == completed SerializeWithoutLastMiniBlock()"
    );
}

#[test]
fn hashcheck_verdicts_match_go() {
    let v = load();
    let bl = Block::deserialize(&hex::decode(&v.block_ser_hex).unwrap()).expect("block");

    // bound block passes, exactly like Go
    assert!(v.hashcheck_ok);
    bl.verify_miniblocks_hashcheck().expect("hashcheck must pass");

    // tampered tx set under the same final miniblock -> rejected (Go err:
    // "MiniBlock has corrupted header expected ... actual ...")
    let mut tampered = bl.clone();
    tampered.tx_hashes[0][0] ^= 0xff;
    let err = tampered.verify_miniblocks_hashcheck().unwrap_err();
    assert!(v.tampered_err.starts_with("MiniBlock has corrupted header"), "go: {}", v.tampered_err);
    assert!(err.starts_with("MiniBlock has corrupted header"), "rust: {err}");

    // last miniblock not HighDiff / not Final -> Go's exact error
    let mut nh = bl.clone();
    nh.miniblocks.last_mut().unwrap().high_diff = false;
    assert_eq!(nh.verify_miniblocks_hashcheck().unwrap_err(), v.non_highdiff_err);

    let mut nf = bl.clone();
    nf.miniblocks.last_mut().unwrap().final_ = false;
    assert_eq!(nf.verify_miniblocks_hashcheck().unwrap_err(), v.non_final_err);
}
