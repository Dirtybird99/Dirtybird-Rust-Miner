//! Byte-exact verification of the FULL `Arguments` decode surface against the
//! REAL Go `rpc.Arguments.UnmarshalBinary` (`go-harness/argdecode` →
//! `vectors/argdecode.json`): adversarial CBOR inputs — any-length H/A byte
//! strings, indefinite-length items, duplicate keys, time tag forms, the
//! bn256 decompress corners — with Go's exact error strings and the canonical
//! re-marshal bytes on success.
//!
//! Vector args are sorted by (name, type) — Go's post-decode `Sort` is
//! non-stable over random map iteration, so same-name relative order has no
//! canonical Go form; we sort identically before comparing.

use dero_protocol::arguments::{ArgValue, Arguments};
use serde::Deserialize;

#[derive(Deserialize)]
struct VArg {
    name: String,
    #[serde(rename = "type")]
    typechar: String,
    u: Option<u64>,
    i: Option<i64>,
    s: Option<String>,
    #[serde(default)]
    hex: String,
    #[serde(default)]
    f64_bits: String,
    unix: Option<i64>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    input_hex: String,
    ok: bool,
    #[serde(default)]
    error: String,
    #[serde(default)]
    remarshal_hex: String,
    #[serde(default)]
    args: Vec<VArg>,
}

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

fn vectors() -> Vectors {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/argdecode.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("run go-harness/run.sh argdecode"))
        .unwrap()
}

/// The portable (name, typechar, value-fields) form of a decoded argument,
/// mirroring the harness's `Arg` dump.
fn dump(args: &Arguments) -> Vec<(String, char, String)> {
    let mut out: Vec<(String, char, String)> = args
        .0
        .iter()
        .map(|a| {
            let (t, v) = match &a.value {
                ArgValue::Uint64(u) => ('U', format!("u={u}")),
                ArgValue::Int64(i) => ('I', format!("i={i}")),
                ArgValue::Str(s) => ('S', format!("s={s}")),
                ArgValue::Hash(h) => ('H', format!("hex={}", hex::encode(h))),
                ArgValue::Address(c) => ('A', format!("hex={}", hex::encode(c))),
                ArgValue::Float64(f) => ('F', format!("f64_bits={:016x}", f.to_bits())),
                ArgValue::Time(secs) => ('T', format!("unix={secs}")),
            };
            (a.name.clone(), t, v)
        })
        .collect();
    out.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    out
}

fn dump_vector(args: &[VArg]) -> Vec<(String, char, String)> {
    let mut out: Vec<(String, char, String)> = args
        .iter()
        .map(|a| {
            let t = a.typechar.chars().next().expect("typechar");
            let v = match t {
                'U' => format!("u={}", a.u.expect("u")),
                'I' => format!("i={}", a.i.expect("i")),
                'S' => format!("s={}", a.s.clone().expect("s")),
                'H' | 'A' => format!("hex={}", a.hex),
                'F' => format!("f64_bits={}", a.f64_bits),
                'T' => format!("unix={}", a.unix.expect("unix")),
                other => panic!("unknown vector typechar {other}"),
            };
            (a.name.clone(), t, v)
        })
        .collect();
    out.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    out
}

/// Every vector case must reproduce: ok/err parity, Go's exact error string,
/// the canonical re-marshal bytes, and every decoded argument value.
#[test]
fn argdecode_vectors_match_go() {
    let v = vectors();
    assert!(v.cases.len() >= 100, "expected the full adversarial set");
    for c in &v.cases {
        let input = hex::decode(&c.input_hex).expect(&c.name);
        match Arguments::unmarshal_binary_exact(&input) {
            Ok(args) => {
                assert!(c.ok, "{}: Rust decoded but Go errored with {:?}", c.name, c.error);
                assert_eq!(
                    hex::encode(args.marshal_binary()),
                    c.remarshal_hex,
                    "{}: canonical re-marshal bytes",
                    c.name
                );
                assert_eq!(dump(&args), dump_vector(&c.args), "{}: decoded args", c.name);
            }
            Err(e) => {
                assert!(!c.ok, "{}: Go decoded but Rust errored with {e:?}", c.name);
                assert_eq!(e, c.error, "{}: exact Go error string", c.name);
            }
        }
    }
}

/// The legacy `&'static str` wrapper keeps its stable error and accepts
/// exactly what the exact decoder accepts.
#[test]
fn argdecode_wrapper_parity() {
    let v = vectors();
    for c in &v.cases {
        let input = hex::decode(&c.input_hex).unwrap();
        assert_eq!(
            Arguments::unmarshal_binary(&input).is_ok(),
            c.ok,
            "{}: wrapper accept/reject parity",
            c.name
        );
    }
}
