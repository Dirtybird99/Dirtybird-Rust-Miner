//! Scalar polynomials and the recursive polynomial expansion used to build the
//! anonymity-set aggregation (C_XG/y_XG). Port of `cryptography/crypto/polynomial.go`.

use crate::scalar;
use num_bigint::BigUint;
use num_traits::One;

/// Go: `Polynomial.Mul` — multiply `p` by `m = [c0, c1]`. Only the `c1 == 1`
/// case is exercised by the prover (and is the only correct branch); the result
/// is `p · (c0 + c1·x)` with `product[i] = p[i]·c0` then (if c1==1) `+= p[i-1]`.
pub fn polynomial_mul(p: &[BigUint], m: &[BigUint]) -> Vec<BigUint> {
    let mut product: Vec<BigUint> = p.iter().map(|pi| scalar::mul(pi, &m[0])).collect();
    product.push(BigUint::from(0u32)); // append 0 element
    if m[1] == BigUint::one() {
        for i in 1..product.len() {
            product[i] = scalar::add(&product[i], &p[i - 1]);
        }
    }
    product
}

/// Go: `RecursivePolynomials` — expands `(a, b)` (each length m) into `2^m` rows
/// of length `m+1`, starting from `accum = [1]`. At each level: left branch
/// `[-atop, 1-btop]`, right branch `[atop, btop]`, popping from the END of a,b.
pub fn recursive_polynomials(a: &[BigUint], b: &[BigUint]) -> Vec<Vec<BigUint>> {
    let mut list = Vec::new();
    recurse(&[BigUint::one()], a, b, &mut list);
    list
}

fn recurse(accum: &[BigUint], a: &[BigUint], b: &[BigUint], list: &mut Vec<Vec<BigUint>>) {
    if a.is_empty() {
        list.push(accum.to_vec());
        return;
    }
    let atop = &a[a.len() - 1];
    let btop = &b[b.len() - 1];
    let left = [scalar::neg(atop), scalar::sub(&BigUint::one(), btop)];
    let right = [atop.clone(), btop.clone()];
    recurse(&polynomial_mul(accum, &left), &a[..a.len() - 1], &b[..b.len() - 1], list);
    recurse(&polynomial_mul(accum, &right), &a[..a.len() - 1], &b[..b.len() - 1], list);
}

/// Build the transposed P matrix used by the prover: `P[i][j] = Pi[j][i]`,
/// `i in 0..m`, `j in 0..2^m`. (Go: `proof_generate.go:582-589`.)
pub fn transpose_polynomials(pi: &[Vec<BigUint>], m: usize) -> Vec<Vec<BigUint>> {
    let mut p = vec![Vec::with_capacity(pi.len()); m];
    for row in pi {
        for (i, item) in p.iter_mut().enumerate() {
            item.push(row[i].clone());
        }
    }
    p
}
