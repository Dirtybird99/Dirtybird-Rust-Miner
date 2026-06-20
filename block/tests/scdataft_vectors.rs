//! Byte-exact verification of rpc.Arguments float 'F' (DataFloat64) and time
//! 'T' (DataTime) canonical-CBOR marshaling + decode behavior against the Go
//! reference, including the RPC_EXPIRY 'E' argument. Vectors from
//! `go-harness/scdataft`.

use std::path::PathBuf;

use dero_protocol::arguments::{
    ArgValue, Argument, Arguments, GO_ZERO_TIME_UNIX, RPC_EXPIRY,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct ArgDesc {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    u: u64,
    #[serde(default)]
    i: i64,
    #[serde(default)]
    s: String,
    #[serde(default)]
    hash_hex: String,
    #[serde(default)]
    f64_bits: String,
    #[serde(default)]
    unix: i64,
}

#[derive(Deserialize)]
struct BuildCase {
    name: String,
    args: Vec<ArgDesc>,
    marshal_hex: String,
    marshal_err: String,
    roundtrip_hex: String,
    unmarshal_err: String,
}

#[derive(Deserialize)]
struct RawDecoded {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    unix: Option<i64>,
    #[serde(default)]
    f64_bits: String,
}

#[derive(Deserialize)]
struct RawCase {
    name: String,
    raw_hex: String,
    unmarshal_err: String,
    remarshal_hex: String,
    #[serde(default)]
    decoded: Vec<RawDecoded>,
}

#[derive(Deserialize)]
struct Vectors {
    go_zero_time_unix: i64,
    build: Vec<BuildCase>,
    raw: Vec<RawCase>,
}

fn load() -> Vectors {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../vectors/scdataft.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn build_arg(d: &ArgDesc) -> Argument {
    let value = match d.ty.as_str() {
        "U" => ArgValue::Uint64(d.u),
        "I" => ArgValue::Int64(d.i),
        "S" => ArgValue::Str(d.s.clone()),
        "H" => {
            let mut h = [0u8; 32];
            h.copy_from_slice(&hex::decode(&d.hash_hex).unwrap());
            ArgValue::Hash(h)
        }
        "F" => ArgValue::Float64(f64::from_bits(
            u64::from_str_radix(&d.f64_bits, 16).unwrap(),
        )),
        "T" => ArgValue::Time(d.unix),
        other => panic!("unhandled vector arg type {other}"),
    };
    Argument { name: d.name.clone(), value }
}

#[test]
fn go_zero_time_constant_matches() {
    assert_eq!(load().go_zero_time_unix, GO_ZERO_TIME_UNIX);
}

/// Build the same Arguments as Go, marshal, and compare bytes; then unmarshal
/// the Go bytes and verify error parity + re-marshal bytes.
#[test]
fn build_cases_match_go() {
    let v = load();
    assert!(!v.build.is_empty());
    for c in &v.build {
        assert!(c.marshal_err.is_empty(), "{}: no Go marshal errors expected", c.name);
        let args = Arguments(c.args.iter().map(build_arg).collect());
        assert_eq!(
            hex::encode(args.marshal_binary()),
            c.marshal_hex,
            "{}: canonical CBOR marshal",
            c.name
        );
        let raw = hex::decode(&c.marshal_hex).unwrap();
        match Arguments::unmarshal_binary(&raw) {
            Ok(parsed) => {
                assert!(
                    c.unmarshal_err.is_empty(),
                    "{}: Go failed to unmarshal but Rust accepted",
                    c.name
                );
                assert_eq!(
                    hex::encode(parsed.marshal_binary()),
                    c.roundtrip_hex,
                    "{}: round-trip re-marshal",
                    c.name
                );
            }
            Err(e) => {
                assert!(
                    !c.unmarshal_err.is_empty(),
                    "{}: Go unmarshaled fine but Rust errored: {e}",
                    c.name
                );
            }
        }
    }
}

/// Crafted (often non-canonical / adversarial) CBOR: decode success/error
/// parity, decoded values, and canonical re-marshal bytes.
#[test]
fn raw_cases_match_go() {
    let v = load();
    assert!(!v.raw.is_empty());
    for c in &v.raw {
        let raw = hex::decode(&c.raw_hex).unwrap();
        match Arguments::unmarshal_binary(&raw) {
            Ok(parsed) => {
                assert!(
                    c.unmarshal_err.is_empty(),
                    "{}: Go errored ({}) but Rust accepted",
                    c.name,
                    c.unmarshal_err
                );
                assert_eq!(
                    hex::encode(parsed.marshal_binary()),
                    c.remarshal_hex,
                    "{}: canonical re-marshal",
                    c.name
                );
                for d in &c.decoded {
                    let got = parsed
                        .get(&d.name)
                        .unwrap_or_else(|| panic!("{}: missing arg {}", c.name, d.name));
                    match d.ty.as_str() {
                        "T" => {
                            let want = d.unix.unwrap();
                            assert_eq!(
                                got,
                                &ArgValue::Time(want),
                                "{}: decoded time",
                                c.name
                            );
                        }
                        "F" => {
                            let want = u64::from_str_radix(&d.f64_bits, 16).unwrap();
                            // compare bits (NaN payloads must survive exactly)
                            match got {
                                ArgValue::Float64(f) => assert_eq!(
                                    f.to_bits(),
                                    want,
                                    "{}: decoded float bits",
                                    c.name
                                ),
                                other => panic!("{}: expected Float64, got {other:?}", c.name),
                            }
                        }
                        _ => {} // covered by remarshal byte-equality
                    }
                }
            }
            Err(e) => {
                assert!(
                    !c.unmarshal_err.is_empty(),
                    "{}: Go accepted but Rust errored: {e}",
                    c.name
                );
            }
        }
    }
}

/// Item 3: RPC_EXPIRY ('E', DataTime) round-trips through the codec as a plain
/// 'T' argument, alongside D/C — and decoded arguments come back name-sorted
/// (Go sorts after UnmarshalBinary, rpc.go:305).
#[test]
fn rpc_expiry_roundtrip() {
    let v = load();
    let c = v.build.iter().find(|c| c.name == "e_expiry").expect("e_expiry vector");
    let raw = hex::decode(&c.marshal_hex).unwrap();
    let parsed = Arguments::unmarshal_binary(&raw).expect("unmarshal");
    assert_eq!(parsed.get(RPC_EXPIRY), Some(&ArgValue::Time(1893456000)));
    assert_eq!(parsed.get("D"), Some(&ArgValue::Uint64(0x1234)));
    assert_eq!(parsed.get("C"), Some(&ArgValue::Str("dero".into())));
    let names: Vec<&str> = parsed.0.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["C", "D", "E"], "decoded args sorted by name");
    assert_eq!(hex::encode(parsed.marshal_binary()), c.marshal_hex, "byte round-trip");
}

/// The zero time marshals (to CBOR null) but, exactly like Go, fails to
/// unmarshal — and the same instant arriving as an RFC3339 tag-0 string
/// re-marshals back to null.
#[test]
fn zero_time_error_parity() {
    let v = load();
    let c = v.build.iter().find(|c| c.name == "t_zero").expect("t_zero vector");
    assert!(!c.unmarshal_err.is_empty(), "Go rejects its own zero-time encoding");
    let args = Arguments(vec![Argument {
        name: "t".into(),
        value: ArgValue::Time(GO_ZERO_TIME_UNIX),
    }]);
    assert_eq!(hex::encode(args.marshal_binary()), c.marshal_hex);
    let raw = hex::decode(&c.marshal_hex).unwrap();
    assert!(Arguments::unmarshal_binary(&raw).is_err());
}
