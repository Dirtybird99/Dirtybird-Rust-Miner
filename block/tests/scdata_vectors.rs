//! Byte-exact verification of rpc.Arguments (SCDATA) canonical-CBOR marshaling
//! against the Go reference. Vector from `go-harness/scdata`.

use std::path::PathBuf;

use dero_protocol::arguments::{ArgValue, Argument, Arguments, SC_ACTION, SC_CODE, SC_ID};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    scid_hex: String,
    code: String,
    amount: u64,
    label: String,
    delta: i64,
    action: u64,
    marshal_hex: String,
}

fn load() -> Vector {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../vectors/scdata.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

#[test]
fn arguments_marshal_matches_go() {
    let v = load();
    let mut scid = [0u8; 32];
    scid.copy_from_slice(&hex::decode(&v.scid_hex).unwrap());

    // build in a deliberately different order than Go — marshal must re-sort
    let args = Arguments(vec![
        Argument { name: "amount".into(), value: ArgValue::Uint64(v.amount) },
        Argument { name: SC_ACTION.into(), value: ArgValue::Uint64(v.action) },
        Argument { name: "delta".into(), value: ArgValue::Int64(v.delta) },
        Argument { name: SC_CODE.into(), value: ArgValue::Str(v.code.clone()) },
        Argument { name: "label".into(), value: ArgValue::Str(v.label.clone()) },
        Argument { name: SC_ID.into(), value: ArgValue::Hash(scid) },
    ]);

    assert_eq!(hex::encode(args.marshal_binary()), v.marshal_hex, "canonical CBOR marshal");

    // round-trip: unmarshal Go bytes, re-marshal, must reproduce the bytes
    let raw = hex::decode(&v.marshal_hex).unwrap();
    let parsed = Arguments::unmarshal_binary(&raw).expect("unmarshal");
    assert_eq!(hex::encode(parsed.marshal_binary()), v.marshal_hex, "round-trip");

    // field access
    assert_eq!(parsed.get(SC_ACTION), Some(&ArgValue::Uint64(v.action)));
    assert_eq!(parsed.get(SC_CODE), Some(&ArgValue::Str(v.code)));
    assert_eq!(parsed.get(SC_ID), Some(&ArgValue::Hash(scid)));
    assert_eq!(parsed.get("delta"), Some(&ArgValue::Int64(v.delta)));
}
