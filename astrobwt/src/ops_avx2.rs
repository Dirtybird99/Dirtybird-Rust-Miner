use core::arch::x86_64::*;

// Four 4-bit primitive IDs per op. Ops 0 and 253 use the scalar fallback.
const OPS: [u16; 256] = [
    0x0000, 0x7654, 0x0480, 0x5a93, 0xd3cb, 0xc4a0, 0xdb94, 0xb037, 0x411b, 0xfcea, 0x292b, 0x3615,
    0xbf2f, 0x1ca5, 0x424c, 0xd64f, 0xb52e, 0xb12a, 0x159e, 0x741d, 0xf8a6, 0x67a5, 0x5284, 0x6059,
    0x1ec7, 0xd390, 0x8702, 0x1e61, 0x1774, 0x7ca2, 0x41e6, 0x24fb, 0xf98f, 0x28e3, 0xd44d, 0xa5b7,
    0x5f50, 0x2cc3, 0x309c, 0x6caf, 0xa0a3, 0xe9d1, 0x3f95, 0xd676, 0x3900, 0x0611, 0xe170, 0x4161,
    0x1bb3, 0xe870, 0x5798, 0x1eea, 0x0bc3, 0xee07, 0xbba8, 0x5ee8, 0x5b2f, 0x8913, 0x76f8, 0xb325,
    0x92ba, 0x1941, 0x7fb6, 0x7d01, 0x2e8a, 0x2f91, 0x5e8f, 0x1f05, 0xaeb6, 0xc827, 0xec2a, 0x42b1,
    0x4a08, 0xd180, 0x6892, 0xe602, 0xc1f3, 0x0479, 0xd283, 0x27fe, 0x6743, 0x034e, 0xcbba, 0x8984,
    0x745d, 0x43ac, 0xbe3e, 0x7e97, 0xb25f, 0xfb27, 0xc518, 0x8e60, 0x60b0, 0x762f, 0x4635, 0x11b5,
    0x50ff, 0xc045, 0xec4e, 0xc8de, 0x0843, 0xbc0c, 0x97d9, 0x3a85, 0x7108, 0xf394, 0x25e8, 0x51fc,
    0xf6ba, 0xfa32, 0xcff7, 0xc282, 0xd1b9, 0xb051, 0xb385, 0x9613, 0x40a6, 0x6494, 0x147c, 0xabf8,
    0x8a2f, 0x207c, 0xf13e, 0x99b6, 0xbaff, 0xc7f8, 0x8159, 0xa624, 0x1ff3, 0xc00b, 0xe53c, 0x205d,
    0xf186, 0x4f1a, 0x65eb, 0x87fc, 0x1adc, 0x38c1, 0xd7aa, 0x9f91, 0x1af5, 0x70d5, 0xf816, 0x4c96,
    0x3b43, 0xefe8, 0x0646, 0x2e4b, 0xd416, 0x7d8a, 0x6444, 0x4247, 0xf4bc, 0xbb95, 0x0ab1, 0xa0ad,
    0x59cc, 0x534c, 0x5790, 0xa3ad, 0x958c, 0x31aa, 0xdf82, 0x5ed4, 0xbd02, 0x74ae, 0xbf79, 0xc2bb,
    0x5363, 0x6e45, 0x2d8d, 0x80d9, 0x54de, 0x724b, 0x003b, 0x12d9, 0x1a2a, 0x6ff0, 0x5b76, 0x8c7f,
    0xdaec, 0x1f4b, 0xe15a, 0x2dd7, 0xa124, 0xc1eb, 0xcdef, 0x97ba, 0xee0e, 0xdae1, 0xf6c1, 0xc397,
    0x2747, 0x5346, 0x6436, 0xeaf0, 0x5489, 0x223e, 0x58cc, 0xa27b, 0x880c, 0xbef9, 0x13ba, 0x356a,
    0xa3f1, 0x74e0, 0x088e, 0x0091, 0x9c77, 0xd081, 0xb13f, 0x3d7e, 0xaaf3, 0xd947, 0xbcda, 0x246a,
    0x6db3, 0xe571, 0xd2b8, 0x869e, 0x4845, 0x8ba1, 0x2a4c, 0xd3a9, 0x495f, 0x98cb, 0xa2d8, 0x6d4b,
    0x07c7, 0x0f39, 0x3362, 0x8ac9, 0x1e22, 0x0905, 0xac26, 0xb92f, 0xd67a, 0x9f41, 0xd977, 0x6251,
    0x467b, 0x5a0e, 0xad77, 0x50f1, 0x18fb, 0xcf1d, 0x7c57, 0xb1f1, 0x10db, 0x3ee8, 0xe036, 0xf807,
    0x4fe8, 0x0000, 0x9f90, 0x9f90,
];

#[inline]
pub(crate) fn apply_op_avx2(
    op: u8,
    s: &mut [u8; 256],
    pos1: u8,
    pos2: u8,
    lhash: &mut u64,
    prev_lhash: &mut u64,
    rc4: &mut crate::rc4::Rc4,
) {
    if matches!(op, 0 | 253) || !is_x86_feature_detected!("avx2") {
        crate::ops_generated::apply_op(op, s, pos1, pos2, lhash, prev_lhash, rc4);
        return;
    }
    // SAFETY: guarded by runtime detection; all memory accesses stay in s.
    unsafe { apply(op, s, pos1, pos2, rc4) }
}

#[target_feature(enable = "avx2")]
unsafe fn apply(op: u8, s: &mut [u8; 256], pos1: u8, pos2: u8, rc4: &mut crate::rc4::Rc4) {
    if op >= 254 {
        *rc4 = crate::rc4::Rc4::new(s);
    }
    if pos1 == pos2 {
        return;
    }

    let p1 = pos1 as usize;
    let p2 = pos2 as usize;
    let start = p1.min(224);
    let lanes = _mm256_setr_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    );
    let low = _mm256_set1_epi8((p1 - start) as i8 - 1);
    let high = _mm256_set1_epi8((p2 - start) as i8);
    let mask = _mm256_and_si256(
        _mm256_cmpgt_epi8(lanes, low),
        _mm256_cmpgt_epi8(high, lanes),
    );
    let ptr = s.as_mut_ptr().add(start).cast::<__m256i>();
    let old = _mm256_loadu_si256(ptr);
    let mut x = old;
    let p2 = _mm256_set1_epi8(s[p2] as i8);
    let mut code = OPS[op as usize];
    for _ in 0..4 {
        x = primitive(code & 15, x, p2);
        code >>= 4;
    }
    _mm256_storeu_si256(ptr, _mm256_blendv_epi8(old, x, mask));
}

#[inline]
unsafe fn shl<const N: i32>(x: __m256i) -> __m256i {
    _mm256_and_si256(
        _mm256_slli_epi16::<N>(x),
        _mm256_set1_epi8((0xffu8 << N) as i8),
    )
}

#[inline]
unsafe fn shr<const N: i32>(x: __m256i) -> __m256i {
    _mm256_and_si256(
        _mm256_srli_epi16::<N>(x),
        _mm256_set1_epi8((0xffu8 >> N) as i8),
    )
}

#[inline]
unsafe fn rot<const N: i32>(x: __m256i) -> __m256i {
    match N {
        1 => _mm256_or_si256(shl::<1>(x), shr::<7>(x)),
        2 => _mm256_or_si256(shl::<2>(x), shr::<6>(x)),
        3 => _mm256_or_si256(shl::<3>(x), shr::<5>(x)),
        4 => _mm256_or_si256(shl::<4>(x), shr::<4>(x)),
        5 => _mm256_or_si256(shl::<5>(x), shr::<3>(x)),
        _ => unreachable!(),
    }
}

#[inline]
unsafe fn select(mask: __m256i, no: __m256i, yes: __m256i) -> __m256i {
    _mm256_blendv_epi8(no, yes, mask)
}

#[inline]
unsafe fn variable_shift(x: __m256i, right: bool) -> __m256i {
    let count = _mm256_and_si256(x, _mm256_set1_epi8(3));
    let mut out = x;
    for n in 1..=3 {
        let shifted = match (right, n) {
            (false, 1) => shl::<1>(x),
            (false, 2) => shl::<2>(x),
            (false, _) => shl::<3>(x),
            (true, 1) => shr::<1>(x),
            (true, 2) => shr::<2>(x),
            (true, _) => shr::<3>(x),
        };
        out = select(_mm256_cmpeq_epi8(count, _mm256_set1_epi8(n)), out, shifted);
    }
    out
}

#[inline]
unsafe fn rotate_self(x: __m256i) -> __m256i {
    let mut out = x;
    out = select(
        _mm256_cmpeq_epi8(
            _mm256_and_si256(x, _mm256_set1_epi8(1)),
            _mm256_set1_epi8(1),
        ),
        out,
        rot::<1>(out),
    );
    out = select(
        _mm256_cmpeq_epi8(
            _mm256_and_si256(x, _mm256_set1_epi8(2)),
            _mm256_set1_epi8(2),
        ),
        out,
        rot::<2>(out),
    );
    select(
        _mm256_cmpeq_epi8(
            _mm256_and_si256(x, _mm256_set1_epi8(4)),
            _mm256_set1_epi8(4),
        ),
        out,
        rot::<4>(out),
    )
}

#[inline]
unsafe fn popcount(x: __m256i) -> __m256i {
    let a = _mm256_sub_epi8(x, _mm256_and_si256(shr::<1>(x), _mm256_set1_epi8(0x55)));
    let b = _mm256_add_epi8(
        _mm256_and_si256(a, _mm256_set1_epi8(0x33)),
        _mm256_and_si256(shr::<2>(a), _mm256_set1_epi8(0x33)),
    );
    _mm256_and_si256(_mm256_add_epi8(b, shr::<4>(b)), _mm256_set1_epi8(0x0f))
}

#[inline]
unsafe fn reverse_bits(x: __m256i) -> __m256i {
    let a = _mm256_or_si256(
        _mm256_and_si256(shr::<1>(x), _mm256_set1_epi8(0x55)),
        shl::<1>(_mm256_and_si256(x, _mm256_set1_epi8(0x55))),
    );
    let b = _mm256_or_si256(
        _mm256_and_si256(shr::<2>(a), _mm256_set1_epi8(0x33)),
        shl::<2>(_mm256_and_si256(a, _mm256_set1_epi8(0x33))),
    );
    rot::<4>(b)
}

#[inline]
unsafe fn square(x: __m256i) -> __m256i {
    let lo = _mm256_and_si256(x, _mm256_set1_epi16(0xff));
    let hi = _mm256_srli_epi16::<8>(x);
    _mm256_or_si256(
        _mm256_and_si256(_mm256_mullo_epi16(lo, lo), _mm256_set1_epi16(0xff)),
        _mm256_slli_epi16::<8>(_mm256_and_si256(
            _mm256_mullo_epi16(hi, hi),
            _mm256_set1_epi16(0xff),
        )),
    )
}

#[inline]
unsafe fn primitive(op: u16, x: __m256i, p2: __m256i) -> __m256i {
    match op {
        0 => _mm256_xor_si256(x, popcount(x)),
        1 => rot::<5>(x),
        2 => square(x),
        3 => rotate_self(x),
        4 => variable_shift(x, false),
        5 => rot::<1>(x),
        6 => _mm256_and_si256(x, p2),
        7 => _mm256_add_epi8(x, x),
        8 => reverse_bits(x),
        9 => rot::<3>(x),
        10 => _mm256_xor_si256(x, p2),
        11 => _mm256_xor_si256(x, _mm256_set1_epi8(-1)),
        12 => variable_shift(x, true),
        13 => _mm256_sub_epi8(x, _mm256_xor_si256(x, _mm256_set1_epi8(97))),
        14 => _mm256_xor_si256(x, rot::<4>(x)),
        15 => _mm256_xor_si256(x, rot::<2>(x)),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ops_match_scalar() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        for op in 0..=255u8 {
            for case in 0..64 {
                let mut scalar = [0u8; 256];
                for b in &mut scalar {
                    *b = next() as u8;
                }
                let mut avx2 = scalar;
                let pos1 = if case == 0 { 0 } else { next() as u8 };
                let len = if case == 0 { 32 } else { (next() % 33) as u8 };
                let pos2 = pos1.saturating_add(len.min(255 - pos1));
                let mut lh1 = next();
                let mut lh2 = lh1;
                let mut ph1 = next();
                let mut ph2 = ph1;
                let mut rc1 = crate::rc4::Rc4::new(&scalar);
                let mut rc2 = crate::rc4::Rc4::new(&scalar);
                crate::ops_generated::apply_op(
                    op,
                    &mut scalar,
                    pos1,
                    pos2,
                    &mut lh1,
                    &mut ph1,
                    &mut rc1,
                );
                apply_op_avx2(op, &mut avx2, pos1, pos2, &mut lh2, &mut ph2, &mut rc2);
                assert_eq!(
                    (avx2, lh2, ph2),
                    (scalar, lh1, ph1),
                    "op={op} pos={pos1}..{pos2}"
                );
                let mut stream1 = [0u8; 64];
                let mut stream2 = [0u8; 64];
                rc1.xor_key_stream(&mut stream1);
                rc2.xor_key_stream(&mut stream2);
                assert_eq!(stream2, stream1, "rc4 op={op} pos={pos1}..{pos2}");
            }
        }
    }
}
