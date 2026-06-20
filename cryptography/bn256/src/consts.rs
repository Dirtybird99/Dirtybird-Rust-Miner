//! Curve constants (Go: `bn256/constants.go`).

use num_bigint::BigUint;

/// P — the base field prime: 36u⁴+36u³+24u²+6u+1.
pub const P_DECIMAL: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

/// Order — number of elements in G₁: 36u⁴+36u³+18u²+6u+1.
pub const ORDER_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// The base field prime P as a `BigUint`.
pub fn field_prime() -> BigUint {
    BigUint::parse_bytes(P_DECIMAL.as_bytes(), 10).expect("valid P")
}

/// The group order as a `BigUint`.
pub fn group_order() -> BigUint {
    BigUint::parse_bytes(ORDER_DECIMAL.as_bytes(), 10).expect("valid Order")
}
