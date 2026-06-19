//! SHA-256. On x86_64 with SHA-NI this FFIs the hardware path in vendor/sha_ni/sha_ni.c
//! (the `sha2` crate's backend doesn't engage SHA-NI on the MSVC target, and the final
//! hash over the ~280 KB SA buffer is ~10% of per-hash cost). On every other target — and
//! on x86 CPUs that lack SHA-NI — it falls back to the `sha2` crate's portable soft SHA,
//! which is byte-identical. SHA-NI is runtime-detected so a generic x86 build never faults.
#[cfg(target_arch = "x86_64")]
extern "C" {
    fn sha256_ni(data: *const u8, len: usize, out: *mut u8);
    fn sha256_ni_2x(
        d0: *const u8,
        len0: usize,
        d1: *const u8,
        len1: usize,
        out0: *mut u8,
        out1: *mut u8,
    );
}

#[inline]
fn soft_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("sha") {
            let mut out = [0u8; 32];
            unsafe { sha256_ni(data.as_ptr(), data.len(), out.as_mut_ptr()) };
            return out;
        }
    }
    soft_sha256(data)
}

/// 2-way multi-buffer SHA-256: on x86 SHA-NI, hashes two independent messages with
/// interleaved chains (~1.3× throughput on Raptor Cove); otherwise two soft hashes. Each
/// output is byte-identical to the standard SHA-256 of its input. Lengths may differ.
#[inline]
pub fn sha256_2x(d0: &[u8], d1: &[u8]) -> ([u8; 32], [u8; 32]) {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("sha") {
            let mut o0 = [0u8; 32];
            let mut o1 = [0u8; 32];
            unsafe {
                sha256_ni_2x(d0.as_ptr(), d0.len(), d1.as_ptr(), d1.len(), o0.as_mut_ptr(), o1.as_mut_ptr())
            };
            return (o0, o1);
        }
    }
    (soft_sha256(d0), soft_sha256(d1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn soft(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    #[test]
    fn matches_sha2_across_lengths() {
        // Cover all padding boundaries (rem <56, ==55/56/63, multi-block) + a big buffer.
        for &len in &[0usize, 1, 31, 55, 56, 57, 63, 64, 65, 127, 128, 129, 1000, 283008] {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(11)).collect();
            assert_eq!(sha256(&data), soft(&data), "mismatch at len {len}");
        }
    }

    #[test]
    fn kat_a() {
        assert_eq!(
            sha256(b"a").iter().map(|x| format!("{x:02x}")).collect::<String>(),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
    }

    #[test]
    fn sha256_2x_matches_sha2_over_length_pairs() {
        let lens = [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 1000, 282000, 283008];
        let mk = |len: usize, seed: u8| -> Vec<u8> {
            (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
        };
        for &l0 in &lens {
            for &l1 in &lens {
                let a = mk(l0, 7);
                let b = mk(l1, 200);
                let (g0, g1) = sha256_2x(&a, &b);
                assert_eq!(g0, soft(&a), "lane0 mismatch l0={l0} l1={l1}");
                assert_eq!(g1, soft(&b), "lane1 mismatch l0={l0} l1={l1}");
            }
        }
    }
}
