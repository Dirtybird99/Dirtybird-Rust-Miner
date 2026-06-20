//! The "modified" RC4 cipher used by AstroBWTv3. Port of
//! `astrobwt/astrobwtv3/rc4.go`.
//!
//! It is stock RC4 (Schneier KSA + PRGA); the only modification vs Go's stdlib
//! `crypto/rc4` is that Go stores the S-box as `[uint32; 256]`; values never
//! exceed one byte, so the miner keeps the state byte-sized.

/// RC4 cipher state.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Go: `NewCipher(key)`. Key must be 1..=256 bytes. Runs the KSA.
    pub fn new(key: &[u8]) -> Rc4 {
        let k = key.len();
        assert!((1..=256).contains(&k), "invalid rc4 key size");
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256usize {
            // j += s[i] + key[i % k]   (all mod 256)
            j = j.wrapping_add(s[i]).wrapping_add(key[i % k]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// Go: `XORKeyStream(dst, src)`. Here `buf` is XORed in place (DERO always
    /// calls it with `dst == src == step_3`).
    pub fn xor_key_stream(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let mut i = self.i;
        let mut j = self.j;
        for b in buf.iter_mut() {
            i = i.wrapping_add(1);
            let x = self.s[i as usize];
            j = j.wrapping_add(x);
            let y = self.s[j as usize];
            self.s[i as usize] = y;
            self.s[j as usize] = x;
            let idx = x.wrapping_add(y);
            *b ^= self.s[idx as usize];
        }
        self.i = i;
        self.j = j;
    }
}
