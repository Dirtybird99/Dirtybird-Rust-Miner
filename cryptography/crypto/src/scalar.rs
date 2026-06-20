//! Scalar arithmetic modulo the group order (the Zether/Bulletproof field).
//! All field-vector and proof math reduces mod `Order`. `Order` is prime, so
//! inversion uses Fermat (`a^(Order-2)`), matching Go's `big.Int.ModInverse`.

use dero_bn256::group_order;
use num_bigint::BigUint;
use num_traits::Zero;

/// The group order N.
pub fn order() -> BigUint {
    group_order()
}

/// `x mod N`.
pub fn reduce(x: &BigUint) -> BigUint {
    x % order()
}

pub fn add(a: &BigUint, b: &BigUint) -> BigUint {
    (a + b) % order()
}

/// `a - b mod N` (non-negative result, matching Go's `Mod`).
pub fn sub(a: &BigUint, b: &BigUint) -> BigUint {
    let n = order();
    let a = a % &n;
    let b = b % &n;
    (a + &n - b) % &n
}

pub fn mul(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) % order()
}

/// `-a mod N`.
pub fn neg(a: &BigUint) -> BigUint {
    let n = order();
    let a = a % &n;
    if a.is_zero() {
        BigUint::zero()
    } else {
        &n - a
    }
}

/// `a^-1 mod N` via Fermat (N prime). Matches `big.Int.ModInverse` for nonzero a.
pub fn inv(a: &BigUint) -> BigUint {
    let n = order();
    let exp = &n - BigUint::from(2u32);
    a.modpow(&exp, &n)
}

/// `1/2 mod N`, used repeatedly by the FFT.
pub fn half() -> BigUint {
    inv(&BigUint::from(2u32))
}

/// Go: `ConvertBigIntToByte` — left-pad the big-endian bytes of `x` to 32 bytes.
/// (Does not reduce; callers pass values already < 2^256.)
pub fn to_32_be(x: &BigUint) -> [u8; 32] {
    let b = x.to_bytes_be();
    let mut out = [0u8; 32];
    let n = b.len().min(32);
    out[32 - n..].copy_from_slice(&b[b.len() - n..]);
    out
}
