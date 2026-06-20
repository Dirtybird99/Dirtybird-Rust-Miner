//! Byte-exact verification of the inner-product argument vs Go.
//! Regenerate: `./go-harness/run.sh innerproduct`.

use dero_crypto::{base_h, gs, hs, FieldVector, InnerProduct, PointVector};
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors/innerproduct.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn fv_from(v: &Value, k: &str) -> FieldVector {
    FieldVector::new(
        v[k].as_array()
            .unwrap()
            .iter()
            .map(|x| BigUint::from(x.as_u64().unwrap()))
            .collect(),
    )
}

#[test]
fn inner_product_matches_go() {
    let v = load();
    let n = v["n"].as_u64().unwrap() as usize;
    let salt = BigUint::parse_bytes(v["salt"].as_str().unwrap().as_bytes(), 10).unwrap();
    let a = fv_from(&v, "as");
    let b = fv_from(&v, "bs");

    let gs_vec = PointVector::new((0..n).map(gs).collect());
    let hs_vec = PointVector::new((0..n).map(hs).collect());
    let u = base_h();

    let ip = InnerProduct::generate(&gs_vec, &hs_vec, &u, &a, &b, &salt);
    assert_eq!(
        hex::encode(ip.serialize()),
        v["serialized_hex"].as_str().unwrap(),
        "inner-product proof serialization mismatch"
    );
}
