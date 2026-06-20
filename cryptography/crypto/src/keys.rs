//! Key derivation. Port of `Generate_Keys_From_Seed` (walletapi/wallet.go):
//! `Secret = seed`, `Public = G · Secret`.

use crate::generators::base_g;
use dero_bn256::{group_order, G1};
use num_bigint::BigUint;

/// Replicates Go's `bn256.G1.String()`:
/// `"bn256.G1(" + hex(X) + ", " + hex(Y) + ")"`, where X/Y are the affine,
/// Montgomery-decoded coordinates as 64-char lowercase hex (== `hex(marshal())`).
/// Used verbatim as input to the registration/SignData Schnorr challenge hash.
pub fn point_to_string(p: &G1) -> String {
    let m = p.marshal();
    format!(
        "bn256.G1({}, {})",
        hex::encode(&m[..32]),
        hex::encode(&m[32..])
    )
}

/// Derive the public-key point from a secret scalar: `Public = G · secret`.
/// (Scalar multiplication is implicitly mod the group order, so an unreduced
/// `secret` yields the same point as `secret mod Order` — matching Go.)
pub fn derive_public_key(secret: &BigUint) -> G1 {
    base_g().scalar_mult(&secret.to_bytes_be())
}

/// Reduce a scalar mod the group order.
pub fn reduce_scalar(s: &BigUint) -> BigUint {
    s % group_order()
}
