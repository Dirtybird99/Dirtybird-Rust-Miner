//! Difficulty → target, and the share-validity check (port of difficulty.zig).

/// `target = floor(2^256 / difficulty)` as 32 big-endian bytes. `difficulty == 0`
/// yields all-0xFF (accept every hash). Long division of 2^256 (a 33-byte
/// `[1,0,…,0]`) by the u64 difficulty, one byte at a time.
pub fn target_from_difficulty(difficulty: u64) -> [u8; 32] {
    if difficulty == 0 {
        return [0xFF; 32];
    }
    let d = difficulty as u128;
    let mut dividend = [0u8; 33];
    dividend[0] = 1; // 2^256
    let mut q = [0u8; 33];
    let mut rem: u128 = 0;
    for i in 0..33 {
        let cur = (rem << 8) | dividend[i] as u128;
        q[i] = (cur / d) as u8;
        rem = cur % d;
    }
    let mut target = [0u8; 32];
    target.copy_from_slice(&q[1..33]);
    target
}

/// True if the hash (interpreted as a little-endian 256-bit integer) is `<=` the
/// target (big-endian). Compares MSB→LSB: `hash[31-i]` vs `target[i]`.
#[inline]
pub fn check_hash(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        let h = hash[31 - i];
        let t = target[i];
        if h < t {
            return true;
        }
        if h > t {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_powers_of_two() {
        // 2^256 / 2 = 2^255 => 0x80 00 ... 00
        let t = target_from_difficulty(2);
        assert_eq!(t[0], 0x80);
        assert!(t[1..].iter().all(|&b| b == 0));
        // 2^256 / 256 = 2^248 => 0x01 00 ... 00
        let t = target_from_difficulty(256);
        assert_eq!(t[0], 0x01);
        assert!(t[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn diff_zero_accepts_all() {
        assert_eq!(target_from_difficulty(0), [0xFF; 32]);
    }

    #[test]
    fn check_basic() {
        let target = target_from_difficulty(256); // 0x01,0,...
        // hash LE = 0 => accept
        assert!(check_hash(&[0u8; 32], &target));
        // hash whose MSB (byte 31) is large => reject
        let mut h = [0u8; 32];
        h[31] = 0xFF;
        assert!(!check_hash(&h, &target));
    }
}
