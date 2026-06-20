//! Legacy AstroBWT PoW (`astrobwt.POW16`) — the proof-of-work used by miniblocks
//! **below** `MAJOR_HF2_HEIGHT` (mainnet 481600). Port of `astrobwt/astrobwt.go`.
//!
//! Far simpler than AstroBWTv3 (no RC4/op-loop): a single fixed-size BWT stage.
//!
//! Pipeline:
//! 1. `key = SHA3-256(input)` (NIST SHA3, golang.org/x/crypto/sha3.Sum256 —
//!    *not* the SHA-256 that v3 uses for its key, and not legacy Keccak).
//! 2. `stage1[9973] = Salsa20(key, zero-counter)` keystream (XOR over zeros).
//! 3. `sa = suffixArray(stage1)` — `sais_8_16`, an int16 SA (positions < 9973
//!    fit in int16). The SA is unique under the sentinel-smallest convention, so
//!    prefix-doubling reproduces it byte-for-byte (same argument as v3).
//! 4. `out = SHA3-256(sa serialized as little-endian uint16)` — 9973·2 = 19946
//!    bytes in → the 32-byte PoW hash.

use crate::sais16::suffix_array;
use sha3::{Digest, Sha3_256};

/// Go: `astrobwt.stage1_length` — a prime; the fixed BWT stage size.
pub const STAGE1_LENGTH: usize = 9973;

/// Salsa20 keystream of `len` bytes with the given 32-byte key and an all-zero
/// 16-byte counter. Same counter/nonce convention as [`crate`]'s v3 prologue
/// (RustCrypto's 8-byte nonce + zero block counter == Go's 16-byte zero
/// counter); here the length is arbitrary rather than fixed at 256.
fn salsa20_keystream(key: &[u8; 32], len: usize) -> Vec<u8> {
    use salsa20::cipher::{KeyIvInit, StreamCipher};
    use salsa20::Salsa20;

    let nonce = [0u8; 8];
    let mut cipher = Salsa20::new(key.into(), (&nonce).into());
    let mut buf = vec![0u8; len];
    cipher.apply_keystream(&mut buf);
    buf
}

/// Legacy AstroBWT PoW hash. Go: `astrobwt.POW16(input)`.
///
/// (Go wraps the body in a recover() that returns a random — i.e. failing —
/// hash on panic, as a miner-robustness hack; that path never produces a valid
/// PoW, so it is intentionally not reproduced. A deterministic verifier only
/// needs the success path.)
pub fn pow16(input: &[u8]) -> [u8; 32] {
    // 1. key = SHA3-256(input)
    let key: [u8; 32] = Sha3_256::digest(input).into();

    // 2. stage1 = Salsa20 keystream over 9973 zero bytes
    let stage1 = salsa20_keystream(&key, STAGE1_LENGTH);

    // 3. suffix array of stage1 (positions 0..9972, serialized as uint16 LE).
    //    SA-IS (sais_8_16), byte-identical to the retained prefix-doubling
    //    reference. Go: text_16_0alloc → sais_8_16 (astrobwt.go).
    let sa = suffix_array(&stage1);
    let mut sa_bytes = Vec::with_capacity(STAGE1_LENGTH * 2);
    for &v in &sa {
        sa_bytes.extend_from_slice(&(v as u16).to_le_bytes());
    }

    // 4. out = SHA3-256(sa bytes)
    Sha3_256::digest(&sa_bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_sized() {
        let a = pow16(b"hello dero");
        let b = pow16(b"hello dero");
        assert_eq!(a, b, "pow16 must be deterministic");
        let c = pow16(b"hello derp");
        assert_ne!(a, c, "different input → different hash");
        assert_eq!(a.len(), 32);
    }
}
