//! Non-cryptographic hashes used inside the AstroBWTv3 op loop, matched to the
//! exact Go libraries the reference imports:
//!
//! - `xxh64` → `github.com/cespare/xxhash` `Sum64` (XXH64, seed 0)
//! - `siphash24` → `github.com/dchest/siphash` `Hash(k0, k1, b)` (SipHash-2-4)
//!
//! (FNV-1a-64 lives in `lib.rs` as it is also used in the prologue.)

/// XXH64 with seed 0 — Go: `xxhash.Sum64(b)`.
pub fn xxh64(data: &[u8]) -> u64 {
    xxhash_rust::xxh64::xxh64(data, 0)
}

/// SipHash-2-4 keyed by (k0, k1) — Go: `siphash.Hash(k0, k1, b)`.
pub fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    use core::hash::Hasher;
    let mut h = siphasher::sip::SipHasher24::new_with_keys(k0, k1);
    h.write(data);
    h.finish()
}
