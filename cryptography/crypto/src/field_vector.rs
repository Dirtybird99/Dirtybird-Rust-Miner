//! `FieldVector` and `FieldVectorPolynomial` — vectors of scalars mod Order,
//! plus the radix-2 FFT used by the Bulletproof convolution. Port of
//! `cryptography/crypto/algebra_fieldvector.go` and `fieldvector.go`.

use crate::scalar;
use num_bigint::BigUint;
use num_traits::One;

/// 2^28-th root of unity mod Order (Go: `unity` in fieldvector.go).
pub fn unity() -> BigUint {
    BigUint::parse_bytes(
        b"14a3074b02521e3b1ed9852e5028452693e87be4e910500c7ba9bbddb2f46edd",
        16,
    )
    .unwrap()
}

#[derive(Clone, Debug)]
pub struct FieldVector {
    pub vector: Vec<BigUint>,
}

impl FieldVector {
    pub fn new(vector: Vec<BigUint>) -> FieldVector {
        FieldVector { vector }
    }

    pub fn length(&self) -> usize {
        self.vector.len()
    }

    pub fn slice(&self, start: usize, end: usize) -> FieldVector {
        FieldVector::new(self.vector[start..end].to_vec())
    }

    pub fn clone_vec(&self) -> FieldVector {
        self.clone()
    }

    pub fn element(&self, i: usize) -> &BigUint {
        &self.vector[i]
    }

    /// Go: `Flip` — result[i] = vector[(len-i) % len].
    pub fn flip(&self) -> FieldVector {
        let n = self.vector.len();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(self.vector[(n - i) % n].clone());
        }
        FieldVector::new(out)
    }

    pub fn sum(&self) -> BigUint {
        let mut acc = BigUint::from(0u32);
        for v in &self.vector {
            acc = scalar::add(&acc, v);
        }
        acc
    }

    pub fn add(&self, other: &FieldVector) -> FieldVector {
        assert_eq!(self.vector.len(), other.vector.len(), "mismatched lengths");
        FieldVector::new(
            self.vector
                .iter()
                .zip(&other.vector)
                .map(|(a, b)| scalar::add(a, b))
                .collect(),
        )
    }

    pub fn add_constant(&self, c: &BigUint) -> FieldVector {
        FieldVector::new(self.vector.iter().map(|a| scalar::add(a, c)).collect())
    }

    pub fn hadamard(&self, other: &FieldVector) -> FieldVector {
        assert_eq!(self.vector.len(), other.vector.len(), "mismatched lengths");
        FieldVector::new(
            self.vector
                .iter()
                .zip(&other.vector)
                .map(|(a, b)| scalar::mul(a, b))
                .collect(),
        )
    }

    pub fn inner_product(&self, other: &FieldVector) -> BigUint {
        assert_eq!(self.vector.len(), other.vector.len(), "mismatched lengths");
        let mut acc = BigUint::from(0u32);
        for (a, b) in self.vector.iter().zip(&other.vector) {
            acc = scalar::add(&acc, &scalar::mul(a, b));
        }
        acc
    }

    pub fn negate(&self) -> FieldVector {
        FieldVector::new(self.vector.iter().map(scalar::neg).collect())
    }

    pub fn times(&self, m: &BigUint) -> FieldVector {
        FieldVector::new(self.vector.iter().map(|a| scalar::mul(a, m)).collect())
    }

    pub fn invert(&self) -> FieldVector {
        FieldVector::new(self.vector.iter().map(scalar::inv).collect())
    }

    pub fn concat(&self, other: &FieldVector) -> FieldVector {
        let mut out = self.vector.clone();
        out.extend(other.vector.iter().cloned());
        FieldVector::new(out)
    }

    /// Go: `Extract(parity)` — parity=false → even indices, true → odd indices.
    pub fn extract(&self, parity: bool) -> FieldVector {
        let remainder = if parity { 1 } else { 0 };
        FieldVector::new(
            self.vector
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == remainder)
                .map(|(_, v)| v.clone())
                .collect(),
        )
    }
}

/// Go: `fft_FieldVector`.
pub fn fft_field_vector(input: &FieldVector, inverse: bool) -> FieldVector {
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

    let even = fft_field_vector(&input.extract(false), inverse);
    let odd = fft_field_vector(&input.extract(true), inverse);

    let mut omegas = vec![BigUint::one()];
    for i in 1..length / 2 {
        omegas.push(scalar::mul(&omegas[i - 1], &omega));
    }
    let omegasv = FieldVector::new(omegas);

    let odd_had = odd.hadamard(&omegasv);
    let mut result = even.add(&odd_had).concat(&even.add(&odd_had.negate()));
    if inverse {
        result = result.times(&scalar::half());
    }
    result
}

/// Go: `FieldVectorPolynomial`.
#[derive(Clone, Debug)]
pub struct FieldVectorPolynomial {
    pub coefficients: Vec<FieldVector>,
}

impl FieldVectorPolynomial {
    pub fn new(inputs: Vec<FieldVector>) -> FieldVectorPolynomial {
        FieldVectorPolynomial {
            coefficients: inputs,
        }
    }

    pub fn length(&self) -> usize {
        self.coefficients.len()
    }

    /// Go: `Evaluate`.
    pub fn evaluate(&self, x: &BigUint) -> FieldVector {
        let mut result = self.coefficients[0].clone();
        let mut accumulator = scalar::reduce(x);
        for i in 1..self.coefficients.len() {
            result = result.add(&self.coefficients[i].times(&accumulator));
            accumulator = scalar::mul(&accumulator, x);
        }
        result
    }

    /// Go: `InnerProduct` — polynomial (convolution) inner product.
    pub fn inner_product(&self, other: &FieldVectorPolynomial) -> Vec<BigUint> {
        let result_length = self.length() + other.length() - 1;
        let mut result = vec![BigUint::from(0u32); result_length];
        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                let ip = self.coefficients[i].inner_product(&other.coefficients[j]);
                result[i + j] = scalar::add(&result[i + j], &ip);
            }
        }
        result
    }
}
