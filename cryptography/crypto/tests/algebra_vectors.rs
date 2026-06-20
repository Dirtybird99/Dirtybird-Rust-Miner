//! Byte-exact verification of the FieldVector / PointVector / FFT-convolution /
//! Pedersen algebra vs the Go reference. Regenerate: `./go-harness/run.sh algebra`.

use dero_crypto::{
    base_g, convolution, pedersen_commit, FieldVector, FieldVectorPolynomial, PointVector, G1,
};
use num_bigint::BigUint;
use serde_json::Value;
use std::path::PathBuf;

fn load() -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../vectors/algebra.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}
fn fv(xs: &[u64]) -> FieldVector {
    FieldVector::new(xs.iter().map(|&x| BigUint::from(x)).collect())
}
fn decs(v: &Value, k: &str) -> Vec<BigUint> {
    v[k].as_array().unwrap().iter().map(|x| dec(x.as_str().unwrap())).collect()
}
fn assert_scalars(label: &str, got: &[BigUint], want: &[BigUint]) {
    assert_eq!(got, want, "{label}");
}
fn g_mul(n: u64) -> G1 {
    base_g().scalar_mult(&BigUint::from(n).to_bytes_be())
}

#[test]
fn field_vector_ops_match_go() {
    let v = load();
    let a = fv(&[1, 2, 3, 4]);
    let b = fv(&[5, 6, 7, 8]);

    assert_eq!(a.inner_product(&b), dec(v["inner_product"].as_str().unwrap()));
    assert_scalars("hadamard", &a.hadamard(&b).vector, &decs(&v, "hadamard"));
    assert_scalars("times_a_9", &a.times(&BigUint::from(9u32)).vector, &decs(&v, "times_a_9"));
    assert_scalars("negate_a", &a.negate().vector, &decs(&v, "negate_a"));
    assert_eq!(a.sum(), dec(v["sum_a"].as_str().unwrap()), "sum_a");
    assert_scalars("flip_a", &a.flip().vector, &decs(&v, "flip_a"));
    assert_scalars("add_ab", &a.add(&b).vector, &decs(&v, "add_ab"));
    assert_scalars("concat_ab", &a.concat(&b).vector, &decs(&v, "concat_ab"));
    assert_scalars("invert_a", &a.invert().vector, &decs(&v, "invert_a"));
}

#[test]
fn field_vector_polynomial_matches_go() {
    let v = load();
    let a = fv(&[1, 2, 3, 4]);
    let b = fv(&[5, 6, 7, 8]);
    let poly = FieldVectorPolynomial::new(vec![a.clone(), b.clone()]);
    let poly2 = FieldVectorPolynomial::new(vec![b.clone(), a.clone()]);

    assert_scalars("poly_eval_x3", &poly.evaluate(&BigUint::from(3u32)).vector, &decs(&v, "poly_eval_x3"));
    assert_scalars("poly_inner_product", &poly.inner_product(&poly2), &decs(&v, "poly_inner_product"));
}

#[test]
fn point_vector_and_convolution_match_go() {
    let v = load();
    let a = fv(&[1, 2, 3, 4]);
    let base: Vec<G1> = (1..=4).map(g_mul).collect();
    let bv = PointVector::new(base.clone());

    // base points
    let want_base: Vec<&str> = v["base_points"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    for (i, p) in base.iter().enumerate() {
        assert_eq!(hex::encode(p.compress()), want_base[i], "base_points[{i}]");
    }

    let exps = [1u64, 2, 3, 4].map(BigUint::from);
    assert_eq!(hex::encode(bv.commit(&exps).compress()), v["commit_1234"].as_str().unwrap(), "commit_1234");
    assert_eq!(hex::encode(bv.multi_exponentiate(&a).compress()), v["multi_exp"].as_str().unwrap(), "multi_exp");
    assert_eq!(hex::encode(bv.sum().compress()), v["pv_sum"].as_str().unwrap(), "pv_sum");

    let conv = convolution(&a, &bv);
    let want_conv: Vec<&str> = v["convolution"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert_eq!(conv.length(), want_conv.len(), "convolution length");
    for (i, p) in conv.vector.iter().enumerate() {
        assert_eq!(hex::encode(p.compress()), want_conv[i], "convolution[{i}]");
    }
}

#[test]
fn pedersen_commit_matches_go() {
    let v = load();
    let gexps = fv(&[2, 4, 6, 8]);
    let hexps = fv(&[1, 3, 5, 7]);
    let pc = pedersen_commit(&BigUint::from(99u32), &gexps, Some(&hexps));
    assert_eq!(hex::encode(pc.compress()), v["pedersen_commit"].as_str().unwrap(), "pedersen_commit");
}
