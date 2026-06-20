//! Byte/value-exact verification of RecursivePolynomials (and Polynomial.Mul,
//! exercised within it) vs Go. Regenerate: `./go-harness/run.sh polynomial`.

use dero_crypto::recursive_polynomials;
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors/polynomial.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}

#[test]
fn recursive_polynomials_match_go() {
    let v = load();
    let a: Vec<BigUint> = v["a"].as_array().unwrap().iter().map(|x| dec(x.as_str().unwrap())).collect();
    let b: Vec<BigUint> = v["b"].as_array().unwrap().iter().map(|x| dec(x.as_str().unwrap())).collect();

    let rows = recursive_polynomials(&a, &b);

    let want: Vec<Vec<BigUint>> = v["rec_rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row.as_array().unwrap().iter().map(|x| dec(x.as_str().unwrap())).collect())
        .collect();

    assert_eq!(rows, want, "RecursivePolynomials rows mismatch");
}
