//! Byte-exact verification of INTEGRATED / PROOF address encoding vs the Go
//! reference (`rpc/address.go` + `rpc.Arguments` CBOR tail).
//! Regenerate with `bash go-harness/run.sh iaddress`.

use dero_crypto::derive_public_key;
use dero_protocol::arguments::{ArgValue, Argument, Arguments};
use dero_protocol::Address;
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../vectors/iaddress.json");
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("valid json")
}

fn addr_from_secret(secret_dec: &str, mainnet: bool) -> Address {
    let secret = BigUint::parse_bytes(secret_dec.as_bytes(), 10).unwrap();
    let mut a = Address::from_public_key(derive_public_key(&secret));
    a.mainnet = mainnet;
    a
}

/// pong_server.go:34-42 — D, C, N, V (V LAST: `[..len-1]` is the no-amount set)
fn pong_args() -> Arguments {
    Arguments(vec![
        Argument { name: "D".into(), value: ArgValue::Uint64(0x1234567812345678) },
        Argument { name: "C".into(), value: ArgValue::Str("Purchase PONG".into()) },
        Argument { name: "N".into(), value: ArgValue::Uint64(0) },
        Argument { name: "V".into(), value: ArgValue::Uint64(12345) },
    ])
}

fn check_roundtrip(s: &str, want_mainnet: bool, want_integrated: bool) {
    let d = Address::from_string(s).unwrap();
    assert_eq!(d.mainnet, want_mainnet, "mainnet flag of {s}");
    assert_eq!(d.is_integrated(), want_integrated, "integrated flag of {s}");
    assert_eq!(d.to_string().unwrap(), s, "decode->re-encode of {s}");
}

#[test]
fn pong_integrated_addresses_match_go() {
    let v = load();
    for e in v["pong"].as_array().unwrap() {
        let secret = e["secret_dec"].as_str().unwrap();
        let full = pong_args();
        let noamount = Arguments(full.0[..full.0.len() - 1].to_vec());

        // CBOR tail is byte-exact
        assert_eq!(
            hex::encode(full.marshal_binary()),
            e["args_cbor_hex"].as_str().unwrap(),
            "full args cbor"
        );
        assert_eq!(
            hex::encode(noamount.marshal_binary()),
            e["args_noamount_cbor_hex"].as_str().unwrap(),
            "noamount args cbor"
        );

        for (mainnet, base_key, int_key, na_key) in [
            (true, "base_main", "integrated_main", "integrated_main_noamount"),
            (false, "base_test", "integrated_test", "integrated_test_noamount"),
        ] {
            let mut a = addr_from_secret(secret, mainnet);
            assert_eq!(
                a.to_string().unwrap(),
                e[base_key].as_str().unwrap(),
                "base ({base_key}) for secret={secret}"
            );

            a.arguments = full.clone();
            let int_str = e[int_key].as_str().unwrap();
            assert_eq!(
                a.to_string().unwrap(),
                int_str,
                "integrated ({int_key}) for secret={secret}"
            );

            a.arguments = noamount.clone();
            assert_eq!(
                a.to_string().unwrap(),
                e[na_key].as_str().unwrap(),
                "noamount ({na_key}) for secret={secret}"
            );

            // decode -> re-encode idempotence + base_address()
            check_roundtrip(int_str, mainnet, true);
            let d = Address::from_string(int_str).unwrap();
            assert_eq!(
                d.base_address().to_string().unwrap(),
                e[base_key].as_str().unwrap(),
                "base_address() of {int_key} for secret={secret}"
            );
            assert_eq!(
                d.arguments.marshal_binary(),
                full.marshal_binary(),
                "decoded args of {int_key} re-marshal canonically"
            );
            check_roundtrip(e[na_key].as_str().unwrap(), mainnet, true);
        }
    }
}

#[test]
fn proof_addresses_match_go() {
    let v = load();
    for e in v["proof"].as_array().unwrap() {
        let secret = e["secret_dec"].as_str().unwrap();
        let value = e["value"].as_u64().unwrap();
        let shared: [u8; 32] = hex::decode(e["shared_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        // walletapi/daemon_communication.go:979 — H(Hash)=shared, V(U)=amount
        let mut a = addr_from_secret(secret, true);
        a.proof = true;
        a.arguments = Arguments(vec![
            Argument { name: "H".into(), value: ArgValue::Hash(shared) },
            Argument { name: "V".into(), value: ArgValue::Uint64(value) },
        ]);
        let want = e["proof_addr"].as_str().unwrap();
        assert_eq!(a.to_string().unwrap(), want, "proof addr for secret={secret}");

        let d = Address::from_string(want).unwrap();
        assert!(d.proof && d.mainnet && d.is_integrated());
        assert_eq!(d.arguments.get("V"), Some(&ArgValue::Uint64(value)));
        assert_eq!(d.arguments.get("H"), Some(&ArgValue::Hash(shared)));
        assert_eq!(d.to_string().unwrap(), want, "proof re-encode");
    }
}

#[test]
fn mixed_argument_types_match_go() {
    let v = load();
    for e in v["mixed"].as_array().unwrap() {
        let reply = addr_from_secret(e["reply_secret_dec"].as_str().unwrap(), true);
        let args = Arguments(vec![
            Argument { name: "R".into(), value: ArgValue::Address(reply.compressed()) },
            Argument { name: "X".into(), value: ArgValue::Int64(-123456789) },
            Argument { name: "C".into(), value: ArgValue::Str("mixed types".into()) },
        ]);
        assert_eq!(
            hex::encode(args.marshal_binary()),
            e["args_cbor_hex"].as_str().unwrap(),
            "mixed args cbor"
        );

        let mut a = addr_from_secret(e["secret_dec"].as_str().unwrap(), true);
        a.arguments = args;
        let want = e["integrated_main"].as_str().unwrap();
        assert_eq!(a.to_string().unwrap(), want, "mixed integrated addr");
        check_roundtrip(want, true, true);
    }
}

#[test]
fn fixed_real_world_proof_decodes() {
    let v = load();
    for e in v["fixed"].as_array().unwrap() {
        let s = e["addr"].as_str().unwrap();
        let d = Address::from_string(s).unwrap();
        assert_eq!(d.mainnet, e["mainnet"].as_bool().unwrap());
        assert_eq!(d.proof, e["proof"].as_bool().unwrap());
        assert_eq!(
            hex::encode(d.compressed()),
            e["pubkey_hex"].as_str().unwrap()
        );
        assert_eq!(
            d.to_string().unwrap(),
            e["reencoded"].as_str().unwrap(),
            "re-encode of fixed proof"
        );
        for arg in e["args"].as_array().unwrap() {
            let name = arg["name"].as_str().unwrap();
            let got = d.arguments.get(name).unwrap_or_else(|| panic!("arg {name} missing"));
            match arg["datatype"].as_str().unwrap() {
                "U" => assert_eq!(
                    got,
                    &ArgValue::Uint64(arg["value"].as_str().unwrap().parse().unwrap())
                ),
                "H" => {
                    let h: [u8; 32] = hex::decode(arg["value"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap();
                    assert_eq!(got, &ArgValue::Hash(h));
                }
                other => panic!("unexpected datatype {other} in fixed vector"),
            }
        }
        assert_eq!(
            d.arguments.0.len(),
            e["args"].as_array().unwrap().len(),
            "arg count of fixed proof"
        );
    }
}
