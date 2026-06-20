//! Byte-exact verification of the account-state codec (NonceBalance) and the
//! homomorphic ElGamal.Add used to apply a transfer to a stored balance.
//! Vector from `go-harness/nonbalance`.

use std::path::PathBuf;

use dero_crypto::{base_g, ElGamal, NonceBalance};
use num_bigint::BigUint;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    nonce: u64,
    nl: i64,
    nr: i64,
    nc: i64,
    nd: i64,
    ser_hex: String,
    added_ser_hex: String,
    reg_secret: i64,
    reg_amount: u64,
    reg_ser_hex: String,
}

fn load() -> Vector {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors/nonbalance.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn gmul(n: i64) -> dero_crypto::G1 {
    base_g().scalar_mult(&BigUint::from(n as u64).to_bytes_be())
}

#[test]
fn nonce_balance_codec_and_add_match_go() {
    let v = load();
    let balance = ElGamal { left: gmul(v.nl), right: gmul(v.nr) };
    let nb = NonceBalance { nonce_height: v.nonce, balance };

    assert_eq!(hex::encode(nb.serialize()), v.ser_hex, "NonceBalance serialize");

    // round-trip deserialize
    let back = NonceBalance::deserialize(&hex::decode(&v.ser_hex).unwrap()).unwrap();
    assert_eq!(back.nonce_height, v.nonce);
    assert_eq!(hex::encode(back.serialize()), v.ser_hex, "NonceBalance round-trip");

    // homomorphic add: balance + (C, D)
    let echanges = ElGamal { left: gmul(v.nc), right: gmul(v.nd) };
    let added = NonceBalance { nonce_height: v.nonce, balance: balance.add(&echanges) };
    assert_eq!(hex::encode(added.serialize()), v.added_ser_hex, "ElGamal.Add then serialize");

    // registration zero-balance: ConstructElGamal(pubkey, BASE_G).Plus(amount)
    let pubkey = gmul(v.reg_secret);
    let regbal = ElGamal::registration_zero(&pubkey).plus(v.reg_amount);
    let regnb = NonceBalance { nonce_height: 0, balance: regbal };
    assert_eq!(hex::encode(regnb.serialize()), v.reg_ser_hex, "registration NonceBalance serialize");
}
