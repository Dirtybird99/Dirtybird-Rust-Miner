//! # dero-bn256
//!
//! Faithful Rust port of the **G1 subset** of DERO HE's `cryptography/bn256`
//! package (the Barreto–Naehrig 256-bit curve). The DERO wallet path uses only
//! G1 point arithmetic plus the group order and field prime — pairings, G2 and
//! GT are intentionally omitted (verified unused by grep of the wallet path).
//!
//! Byte-for-byte compatible with the Go reference for:
//! - field `marshal`/`unmarshal` (32-byte big-endian, Montgomery-decoded),
//! - G1 `marshal`/`unmarshal` (64-byte X‖Y),
//! - G1 `compress`/`decompress` (DERO's 33-byte X‖parity-flag scheme),
//! - scalar multiplication results.

mod consts;
mod curve;
mod g1;
mod gfp;

pub use consts::{field_prime, group_order, ORDER_DECIMAL, P_DECIMAL};
pub use g1::G1;

/// Size in bytes of a compressed point.
pub const COMPRESSED_SIZE: usize = 33;
/// Size in bytes of an uncompressed point.
pub const UNCOMPRESSED_SIZE: usize = 64;
