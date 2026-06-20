//! Byte-exact verification of address encoding vs the Go reference.
//! Regenerate with `./go-harness/run.sh address`.

use dero_crypto::derive_public_key;
use dero_protocol::Address;
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../vectors/address.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("valid json")
}

#[test]
fn address_encoding_matches_go() {
    let v = load();
    for e in v.as_array().unwrap() {
        let secret = BigUint::parse_bytes(e["secret_dec"].as_str().unwrap().as_bytes(), 10).unwrap();
        let pubkey = derive_public_key(&secret);

        let mainnet = Address {
            mainnet: true,
            proof: false,
            public_key: pubkey,
            arguments: Default::default(),
        };
        let testnet = Address {
            mainnet: false,
            proof: false,
            public_key: pubkey,
            arguments: Default::default(),
        };

        assert_eq!(
            mainnet.to_string().unwrap(),
            e["mainnet"].as_str().unwrap(),
            "mainnet address for secret={}",
            e["secret_dec"]
        );
        assert_eq!(
            testnet.to_string().unwrap(),
            e["testnet"].as_str().unwrap(),
            "testnet address for secret={}",
            e["secret_dec"]
        );

        // decode round-trips back to the same compressed pubkey
        let decoded = Address::from_string(e["mainnet"].as_str().unwrap()).unwrap();
        assert!(decoded.mainnet);
        assert_eq!(decoded.compressed(), pubkey.compress());

        let decoded_t = Address::from_string(e["testnet"].as_str().unwrap()).unwrap();
        assert!(!decoded_t.mainnet);
        assert_eq!(decoded_t.compressed(), pubkey.compress());
    }
}
