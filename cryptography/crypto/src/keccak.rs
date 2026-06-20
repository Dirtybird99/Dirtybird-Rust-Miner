//! Keccak hashing. DERO uses **legacy Keccak-256** (`sha3.NewLegacyKeccak256`,
//! 0x01 padding) — NOT NIST SHA3-256. The `sha3::Keccak256` type is the legacy
//! variant and matches byte-for-byte. Port of `cryptography/crypto/keccak.go`.

use sha3::{Digest, Keccak256, Keccak512, Sha3_256};

/// Go: `Keccak256(data ...[]byte)` — concatenated write, 32-byte digest.
pub fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Go: `Keccak512`.
pub fn keccak512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Keccak512::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

/// NIST **SHA3-256** (0x06 padding) — *distinct* from the legacy Keccak above.
/// DERO's block layer uses this for the block identifier (BLID):
/// `block.go` imports `golang.org/x/crypto/sha3` and calls `sha3.Sum256`, which
/// is the FIPS-202 SHA3-256, not the legacy Keccak the wallet/crypto layer uses.
pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Go: `Keccak256_64` — first 8 bytes of the digest as a big-endian u64.
pub fn keccak256_64(parts: &[&[u8]]) -> u64 {
    let r = keccak256(parts);
    u64::from_be_bytes(r[..8].try_into().unwrap())
}
