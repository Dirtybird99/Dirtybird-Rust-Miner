//! Suffix array construction for AstroBWTv3 step 6.
//!
//! The Go reference (`text_32_0alloc` → `sais_8_32`) computes the **lexicographic
//! suffix array** of the text with an implicit sentinel `$` (smaller than every
//! byte) at position `n`. Because every suffix then has a unique order, the
//! suffix array is *unique* — so any correct construction reproduces Go's output
//! byte-for-byte. We use prefix-doubling (O(n log n)); SA-IS could be slotted in
//! later for speed without changing the result.
//!
//! Returns `sa` of length `n`, a permutation of `0..n`, sorted so that
//! `text[sa[0]..] < text[sa[1]..] < ...` under the sentinel convention.

/// Build the suffix array of `text` (sentinel-smallest convention).
pub fn suffix_array(text: &[u8]) -> Vec<i32> {
    let n = text.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![0];
    }

    // rank[i] = current rank of suffix starting at i; positions >= n use the
    // sentinel rank -1 (smaller than any real rank, which start at 0).
    let mut sa: Vec<i32> = (0..n as i32).collect();
    let mut rank: Vec<i64> = text.iter().map(|&b| b as i64).collect();
    let mut tmp: Vec<i64> = vec![0; n];

    let mut k = 1usize;
    while k < n {
        // sort by (rank[i], rank[i+k]) with sentinel = -1 beyond the end.
        let key = |i: i32| -> (i64, i64) {
            let i = i as usize;
            let second = if i + k < n { rank[i + k] } else { -1 };
            (rank[i], second)
        };
        sa.sort_by(|&a, &b| key(a).cmp(&key(b)));

        // re-rank
        tmp[sa[0] as usize] = 0;
        for w in 1..n {
            let prev = sa[w - 1];
            let cur = sa[w];
            let inc = if key(prev) == key(cur) { 0 } else { 1 };
            tmp[cur as usize] = tmp[prev as usize] + inc;
        }
        std::mem::swap(&mut rank, &mut tmp);

        if rank[sa[n - 1] as usize] == (n as i64 - 1) {
            break; // all ranks distinct → fully sorted
        }
        k <<= 1;
    }

    sa
}
