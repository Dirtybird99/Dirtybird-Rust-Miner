//! Hash-to-number and hash-to-point. Port of `cryptography/crypto/hashtopoint.go`.

use crate::keccak::keccak256;
use dero_bn256::{field_prime, group_order, G1};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;

/// PROTOCOL_CONSTANT (Go: `const.go`).
pub const PROTOCOL_CONSTANT: &str = "DERO";

/// Go: `HashtoNumber` — Keccak-256 of input as an unreduced big-endian integer.
pub fn hash_to_number(input: &[u8]) -> BigUint {
    BigUint::from_bytes_be(&keccak256(&[input]))
}

/// Go: `ReducedHash` — `HashtoNumber(input) mod Order`.
pub fn reduced_hash(input: &[u8]) -> BigUint {
    hash_to_number(input) % group_order()
}

/// Left-pad a field/scalar value to 32 big-endian bytes (Go: `big.Int.FillBytes`).
pub(crate) fn to_32_be(x: &BigUint) -> [u8; 32] {
    let b = x.to_bytes_be();
    debug_assert!(b.len() <= 32, "value exceeds 32 bytes");
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

/// Go: `HashToPoint` — try-and-increment onto y² = x³ + 3.
///
/// Starts at `seed mod Order`, then for each candidate computes
/// `beta = x³ + 3 mod p` and `y = beta^((p+1)/4) mod p`; if `y² == beta`
/// (i.e. beta is a QR), the point `(x, y)` is returned. Otherwise
/// `x = (x + 1) mod p`. The chosen `y` is the principal root `beta^((p+1)/4)`,
/// used as-is (not normalized) — matching the Go reference exactly.
pub fn hash_to_point(seed: &BigUint) -> G1 {
    let p = field_prime();
    let order = group_order();
    let three = BigUint::from(3u32);
    let exp = (&p + BigUint::one()) / BigUint::from(4u32); // (p+1)/4 == CURVE_A

    let mut x = seed % &order;
    loop {
        // beta = (x^3 + 3) mod p
        let x3 = x.modpow(&three, &p);
        let beta = (&x3 + &three) % &p;
        // y = beta^((p+1)/4) mod p
        let y = beta.modpow(&exp, &p);
        let y2 = (&y * &y) % &p;
        if y2 == beta {
            let xb = to_32_be(&x);
            let yb = to_32_be(&y);
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&xb);
            buf[32..].copy_from_slice(&yb);
            return G1::unmarshal(&buf).expect("hash-to-point produced on-curve point");
        }
        x = (&x + BigUint::one()).mod_floor(&p);
    }
}
