//! Full AstroBWTv3 hash: SHA256 → Salsa20/20 → RC4 → FNV1a → wolfCompute → SA → SHA256.
use crate::codelut::Reglut;
use crate::primitives::{fnv1a, salsa20_expand};
use crate::sa;
use crate::sha_hw::sha256;
use crate::wolf::Worker;

/// Stages 1–6 (SHA → Salsa20 → RC4 → FNV1a → wolfCompute → suffix array). Leaves the
/// SA in `w.sa[0..data_len]`; returns `data_len`. The final SHA is applied by the caller
/// (single via [`hash`] or batched 2-way via [`hash2`]).
#[inline]
fn build_through_sa(input: &[u8], w: &mut Worker, reglut: &Reglut) -> usize {
    let key = sha256(input); // Stage 1
    let mut block = [0u8; 256];
    salsa20_expand(&key, &mut block); // Stage 2
    w.key.set_key(&block); // Stage 3
    w.key.process(&mut block);
    w.lhash = fnv1a(&block); // Stage 4
    w.prev_lhash = w.lhash;
    w.s_data[0..256].copy_from_slice(&block);
    w.wolf_compute(reglut); // Stage 5
    let n = w.data_len as usize;
    for b in &mut w.s_data[n..n + 16] {
        *b = 0;
    }
    sa::build_sa(&w.s_data, w.data_len, &w.template_markers, w.n_templates, &mut w.sa); // Stage 6
    n
}

#[inline]
fn sa_bytes(w: &Worker, n: usize) -> &[u8] {
    // SA i32 array reinterpreted as little-endian bytes (x86-64 LE matches the oracle).
    unsafe { std::slice::from_raw_parts(w.sa.as_ptr() as *const u8, n * 4) }
}

/// Compute the AstroBWTv3 hash of `input`, reusing `w` (per-thread scratch) and the
/// shared `reglut`. Returns the 32-byte final hash.
pub fn hash(input: &[u8], w: &mut Worker, reglut: &Reglut) -> [u8; 32] {
    let n = build_through_sa(input, w, reglut);
    sha256(sa_bytes(w, n)) // Stage 7
}

/// Hash two inputs, batching the final SHA-256 via 2-way SHA-NI (~1.3× on that stage —
/// the Zig miner's signature edge). Uses two per-thread workers. Each output is
/// byte-identical to [`hash`] of its input.
pub fn hash2(
    in0: &[u8],
    in1: &[u8],
    w0: &mut Worker,
    w1: &mut Worker,
    reglut: &Reglut,
) -> ([u8; 32], [u8; 32]) {
    let n0 = build_through_sa(in0, w0, reglut);
    let n1 = build_through_sa(in1, w1, reglut);
    crate::sha_hw::sha256_2x(sa_bytes(w0, n0), sa_bytes(w1, n1))
}

/// Convenience for single-shot / tests: allocate scratch + LUT and hash once.
pub fn hash_once(input: &[u8]) -> [u8; 32] {
    let reglut = Reglut::new();
    let mut w = Worker::new();
    hash(input, &mut w, &reglut)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn kat_a_with_intermediates() {
        let reglut = Reglut::new();
        let mut w = Worker::new();
        let out = hash(b"a", &mut w, &reglut);
        // Intermediates localize any divergence before the final hash.
        assert_eq!(w.data_len, 70318, "DATALEN");
        assert_eq!(w.lhash, 0x7721d69022d68c55, "LHASH");
        assert_eq!(w.prev_lhash, 0xd0a0d3748d3d4c89, "PREVLHASH");
        assert_eq!(
            hex(&out),
            "54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea",
            "KAT pow(\"a\")"
        );
    }

    #[test]
    fn golden_zero48() {
        let out = hash_once(&[0u8; 48]);
        assert_eq!(hex(&out), "e511c6a69ffcc8a28cf410ad47b2d9d032d436f9280b887ac20044c3f040314e");
    }

    #[test]
    fn golden_pat48() {
        let pat: [u8; 48] = std::array::from_fn(|i| i as u8);
        let out = hash_once(&pat);
        assert_eq!(hex(&out), "4474513fdacd0dd4840e923ecf0c4a14861849dcde87e2935bf4f9ef2233ad10");
    }

    #[test]
    fn hash2_matches_two_singles() {
        let reglut = Reglut::new();
        let mut w0 = Worker::new();
        let mut w1 = Worker::new();
        // Different-length inputs exercise the variable-length 2-way SHA path.
        let a = b"a";
        let b: [u8; 48] = std::array::from_fn(|i| (i as u8).wrapping_add(5));
        let (h0, h1) = hash2(a, &b, &mut w0, &mut w1, &reglut);
        assert_eq!(h0, hash_once(a));
        assert_eq!(h1, hash_once(&b));
    }
}
