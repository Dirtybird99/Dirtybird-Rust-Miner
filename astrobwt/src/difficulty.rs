//! PoW difficulty check. Port of the relevant parts of `blockchain/difficulty.go`.
//!
//! The verification (`CheckPowHashBig` / `VerifyMiniblockPoW`) does NOT require
//! the difficulty-adjustment algorithm — for an existing block the target is
//! derived from the block's own stored difficulty (`block_header.difficulty`).

use crate::pow16::pow16;
use crate::{astrobwtv3, astrobwtv3_with_scratch, AstroBwtScratch};
use num_bigint::BigUint;
use num_traits::One;

/// Go: `config.MINIBLOCK_HIGHDIFF` — a HighDiff miniblock must meet 9× difficulty.
pub const MINIBLOCK_HIGHDIFF: u64 = 9;

/// Go: `config.Mainnet.MAJOR_HF2_HEIGHT` — the height at and above which the PoW
/// switches from the legacy `POW16` to `AstroBWTv3`.
pub const MAJOR_HF2_HEIGHT_MAINNET: u64 = 481_600;

/// Go: `MiniBlock.GetPoWHash` — below `hf2_height` use the legacy `POW16`, at or
/// above it use `AstroBWTv3`. (Mainnet `hf2_height` = [`MAJOR_HF2_HEIGHT_MAINNET`].)
pub fn pow_hash_at_height(serialized: &[u8], height: u64, hf2_height: u64) -> [u8; 32] {
    if height < hf2_height {
        pow16(serialized)
    } else {
        astrobwtv3(serialized)
    }
}

/// Height-aware PoW selection with caller-owned AstroBWT scratch for mining.
pub fn pow_hash_at_height_with_scratch(
    serialized: &[u8],
    height: u64,
    hf2_height: u64,
    scratch: &mut AstroBwtScratch,
) -> [u8; 32] {
    if height < hf2_height {
        pow16(serialized)
    } else {
        astrobwtv3_with_scratch(serialized, scratch)
    }
}

/// Go: `HashToBig` — the 32-byte PoW hash is interpreted **little-endian**
/// (Go reverses the bytes, then `SetBytes` reads big-endian). This is the
/// classic endianness subtlety: the hash is *not* read big-endian directly.
pub fn hash_to_big(hash: &[u8; 32]) -> BigUint {
    let mut b = *hash;
    b.reverse();
    BigUint::from_bytes_be(&b)
}

/// Go: `ConvertIntegerDifficultyToBig` — the target is `2^256 / difficulty`.
pub fn pow_target(difficulty: &BigUint) -> BigUint {
    let one: BigUint = One::one();
    (one << 256u32) / difficulty
}

/// Precomputed target for repeated PoW hash checks at one difficulty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowTarget {
    target_le: [u8; 32],
    accepts_all: bool,
}

/// Precompute `2^256 / difficulty` once for repeated hash comparisons.
pub fn precompute_pow_target(difficulty: &BigUint) -> PowTarget {
    let target = pow_target(difficulty);
    let target_bytes = target.to_bytes_le();
    if target_bytes.len() > 32 {
        return PowTarget {
            target_le: [0xff; 32],
            accepts_all: true,
        };
    }

    let mut target_le = [0u8; 32];
    target_le[..target_bytes.len()].copy_from_slice(&target_bytes);
    PowTarget {
        target_le,
        accepts_all: false,
    }
}

/// True iff the little-endian PoW hash is at or below the precomputed target.
pub fn check_pow_hash_precomputed(pow_hash: &[u8; 32], target: &PowTarget) -> bool {
    if target.accepts_all {
        return true;
    }

    for i in (0..32).rev() {
        if pow_hash[i] < target.target_le[i] {
            return true;
        }
        if pow_hash[i] > target.target_le[i] {
            return false;
        }
    }
    true
}

/// Go: `CheckPowHashBig` — true iff `HashToBig(pow) <= 2^256 / difficulty`.
pub fn check_pow_hash_big(pow_hash: &[u8; 32], difficulty: &BigUint) -> bool {
    hash_to_big(pow_hash) <= pow_target(difficulty)
}

/// Go: `VerifyMiniblockPoW` (v3 path). Computes the AstroBWTv3 PoW of the
/// 48-byte serialized miniblock and checks it against the block difficulty,
/// scaled by `MINIBLOCK_HIGHDIFF` when the miniblock is HighDiff.
///
/// `block_difficulty` is the block's own difficulty (RPC `block_header.difficulty`).
pub fn verify_miniblock_pow_v3(
    serialized_miniblock: &[u8],
    high_diff: bool,
    block_difficulty: &BigUint,
) -> bool {
    let diff = if high_diff {
        block_difficulty * MINIBLOCK_HIGHDIFF
    } else {
        block_difficulty.clone()
    };
    let pow = astrobwtv3(serialized_miniblock);
    check_pow_hash_big(&pow, &diff)
}

/// Go: `VerifyMiniblockPoW` with the height-aware PoW selection — uses `POW16`
/// below `hf2_height` and `AstroBWTv3` at or above it, then checks the hash
/// against the block difficulty (×MINIBLOCK_HIGHDIFF for HighDiff miniblocks).
pub fn verify_miniblock_pow(
    serialized_miniblock: &[u8],
    high_diff: bool,
    block_difficulty: &BigUint,
    height: u64,
    hf2_height: u64,
) -> bool {
    let diff = if high_diff {
        block_difficulty * MINIBLOCK_HIGHDIFF
    } else {
        block_difficulty.clone()
    };
    let pow = pow_hash_at_height(serialized_miniblock, height, hf2_height);
    check_pow_hash_big(&pow, &diff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_discriminates() {
        // difficulty 1 → target = 2^256/1 = 2^256-... → everything below 2^256
        // passes (a 32-byte hash is always < 2^256).
        let one: BigUint = One::one();
        assert!(
            check_pow_hash_big(&[0xff; 32], &one),
            "difficulty 1 accepts any hash"
        );

        // A large difficulty makes the target tiny; an all-ones hash (the
        // maximum 256-bit value) must FAIL — proving the check is directional,
        // not always-true.
        let big = BigUint::parse_bytes(b"1000000000000", 10).unwrap();
        assert!(
            !check_pow_hash_big(&[0xff; 32], &big),
            "max hash must fail high difficulty"
        );
        // The all-zero hash is the minimum and must always pass.
        assert!(check_pow_hash_big(&[0x00; 32], &big), "zero hash must pass");
    }

    #[test]
    fn hash_to_big_is_little_endian() {
        // Little-endian: the FIRST byte is least significant.
        let mut h = [0u8; 32];
        h[0] = 1;
        assert_eq!(hash_to_big(&h), BigUint::from(1u8), "first byte is LSB");

        // The LAST byte is most significant → 1 << 248.
        let mut h2 = [0u8; 32];
        h2[31] = 1;
        assert_eq!(
            hash_to_big(&h2),
            BigUint::from(1u8) << (31u32 * 8),
            "last byte is MSB"
        );
    }

    fn big_to_hash_le(value: &BigUint) -> Option<[u8; 32]> {
        let bytes = value.to_bytes_le();
        if bytes.len() > 32 {
            return None;
        }

        let mut hash = [0u8; 32];
        hash[..bytes.len()].copy_from_slice(&bytes);
        Some(hash)
    }

    #[test]
    fn precomputed_target_matches_biguint_check_for_representative_values() {
        let difficulties = [
            BigUint::from(1u8),
            BigUint::from(2u8),
            BigUint::from(MINIBLOCK_HIGHDIFF),
            BigUint::from(u64::MAX),
            BigUint::parse_bytes(b"1000000000000000000000000000000", 10).unwrap(),
        ];
        let mut hashes = vec![
            [0x00; 32],
            [0xff; 32],
            {
                let mut h = [0u8; 32];
                h[0] = 1;
                h
            },
            {
                let mut h = [0u8; 32];
                h[31] = 1;
                h
            },
            [
                0x00, 0x01, 0x10, 0x7f, 0x80, 0xfe, 0xff, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee,
                0x13, 0x37, 0x42, 0x24, 0x99, 0x55, 0x33, 0x11, 0xde, 0xad, 0xbe, 0xef, 0x08, 0x15,
                0x16, 0x23, 0x2a, 0x5a,
            ],
        ];

        for difficulty in &difficulties {
            let target = precompute_pow_target(difficulty);
            let target_big = pow_target(difficulty);
            if let Some(exact_target_hash) = big_to_hash_le(&target_big) {
                hashes.push(exact_target_hash);
                hashes
                    .push(big_to_hash_le(&(target_big + BigUint::from(1u8))).unwrap_or([0xff; 32]));
            }

            for hash in &hashes {
                assert_eq!(
                    check_pow_hash_precomputed(hash, &target),
                    check_pow_hash_big(hash, difficulty),
                    "difficulty={difficulty} hash={}",
                    hex::encode(hash)
                );
            }
        }
    }

    #[test]
    fn scratch_height_selector_matches_regular_selector() {
        let input = b"height selector scratch regression";
        let mut scratch = AstroBwtScratch::new();

        assert_eq!(
            pow_hash_at_height_with_scratch(input, 481_599, MAJOR_HF2_HEIGHT_MAINNET, &mut scratch),
            pow_hash_at_height(input, 481_599, MAJOR_HF2_HEIGHT_MAINNET)
        );
        assert_eq!(
            pow_hash_at_height_with_scratch(input, 481_600, MAJOR_HF2_HEIGHT_MAINNET, &mut scratch),
            pow_hash_at_height(input, 481_600, MAJOR_HF2_HEIGHT_MAINNET)
        );
    }
}
