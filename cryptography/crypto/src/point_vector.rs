//! `PointVector` — vectors of G1 points, the generator-side FFT, and the
//! Bulletproof `Convolution`. Port of `algebra_pointvector.go` and the
//! `fft_GeneratorVector` / `Convolution` in `fieldvector.go`.

use crate::field_vector::{fft_field_vector, unity, FieldVector};
use crate::scalar;
use dero_bn256::G1;
use num_bigint::BigUint;
use num_traits::One;

#[derive(Clone, Debug)]
pub struct PointVector {
    pub vector: Vec<G1>,
}

fn smul(p: &G1, s: &BigUint) -> G1 {
    p.scalar_mult(&scalar::reduce(s).to_bytes_be())
}

impl PointVector {
    pub fn new(vector: Vec<G1>) -> PointVector {
        PointVector { vector }
    }

    pub fn length(&self) -> usize {
        self.vector.len()
    }

    pub fn slice(&self, start: usize, end: usize) -> PointVector {
        PointVector::new(self.vector[start..end].to_vec())
    }

    pub fn element(&self, i: usize) -> &G1 {
        &self.vector[i]
    }

    /// Go: `Commit` — Σ vector[i]·exponent[i] (starting from identity).
    pub fn commit(&self, exponent: &[BigUint]) -> G1 {
        assert_eq!(self.vector.len(), exponent.len(), "mismatched lengths");
        let mut acc = G1::infinity();
        for (p, e) in self.vector.iter().zip(exponent) {
            acc = G1::add(&acc, &smul(p, e));
        }
        acc
    }

    pub fn sum(&self) -> G1 {
        let mut acc = G1::infinity();
        for p in &self.vector {
            acc = G1::add(&acc, p);
        }
        acc
    }

    pub fn add(&self, other: &PointVector) -> PointVector {
        assert_eq!(self.vector.len(), other.vector.len(), "mismatched lengths");
        PointVector::new(
            self.vector
                .iter()
                .zip(&other.vector)
                .map(|(a, b)| G1::add(a, b))
                .collect(),
        )
    }

    pub fn hadamard(&self, exponent: &[BigUint]) -> PointVector {
        assert_eq!(self.vector.len(), exponent.len(), "mismatched lengths");
        PointVector::new(
            self.vector
                .iter()
                .zip(exponent)
                .map(|(p, e)| smul(p, e))
                .collect(),
        )
    }

    pub fn negate(&self) -> PointVector {
        PointVector::new(self.vector.iter().map(G1::neg).collect())
    }

    pub fn times(&self, m: &BigUint) -> PointVector {
        PointVector::new(self.vector.iter().map(|p| smul(p, m)).collect())
    }

    pub fn extract(&self, parity: bool) -> PointVector {
        let remainder = if parity { 1 } else { 0 };
        PointVector::new(
            self.vector
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == remainder)
                .map(|(_, p)| *p)
                .collect(),
        )
    }

    pub fn concat(&self, other: &PointVector) -> PointVector {
        let mut out = self.vector.clone();
        out.extend(other.vector.iter().copied());
        PointVector::new(out)
    }

    /// Go: `MultiExponentiate` — Σ vector[i]·fv[i].
    pub fn multi_exponentiate(&self, fv: &FieldVector) -> G1 {
        let mut acc = G1::infinity();
        for (p, e) in self.vector.iter().zip(&fv.vector) {
            acc = G1::add(&acc, &smul(p, e));
        }
        acc
    }
}

/// Go: `fft_GeneratorVector`.
pub fn fft_generator_vector(input: &PointVector, inverse: bool) -> PointVector {
    let length = input.length();
    if length == 1 {
        return input.clone();
    }
    assert!(length % 2 == 0, "length must be a multiple of 2");

    let exp = BigUint::from((1u64 << 28) / length as u64);
    let mut omega = unity().modpow(&exp, &scalar::order());
    if inverse {
        omega = scalar::inv(&omega);
    }

    let even = fft_generator_vector(&input.extract(false), inverse);
    let odd = fft_generator_vector(&input.extract(true), inverse);

    let mut omegas = vec![BigUint::one()];
    for i in 1..length / 2 {
        omegas.push(scalar::mul(&omegas[i - 1], &omega));
    }

    let odd_had = odd.hadamard(&omegas);
    let mut result = even.add(&odd_had).concat(&even.add(&odd_had.negate()));
    if inverse {
        result = result.times(&scalar::half());
    }
    result
}

/// Go: `Convolution` — FFT-based, using the optimization in fieldvector.go.
pub fn convolution(exponent: &FieldVector, base: &PointVector) -> PointVector {
    let size = base.length();
    let exponent_fft = fft_field_vector(&exponent.flip(), false);
    let temp = fft_generator_vector(base, false).hadamard(&exponent_fft.vector);
    let combined = temp
        .slice(0, size / 2)
        .add(&temp.slice(size / 2, size))
        .times(&scalar::half());
    fft_generator_vector(&combined, true)
}
