//! Base field GF(p) for the bn256 curve, in Montgomery form.
//!
//! Faithful port of `cryptography/bn256/gfp.go`, `gfp_generic.go`, and the
//! relevant constants from `constants.go`. Field elements are `[u64; 4]`
//! little-endian 64-bit words held in Montgomery representation (`a * R mod p`,
//! `R = 2^256`), exactly as in the Go reference. All u64 arithmetic uses
//! wrapping semantics to mirror Go's unsigned integer overflow behavior.

/// p, represented as little-endian 64-bit words (Go: `p2`).
pub(crate) const P2: [u64; 4] = [
    0x3c208c16d87cfd47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// negative inverse of p, mod 2^256 (Go: `np`).
const NP: [u64; 4] = [
    0x87d20782e4866389,
    0x9ede7d651eca6ac9,
    0xd8afcbd01833da80,
    0xf57a22b791888c6b,
];

/// R^-1 where R = 2^256 mod p (Go: `rN1`).
const RN1: GfP = GfP([
    0xed84884a014afa37,
    0xeb2022850278edf8,
    0xcf63e9cfb74492d9,
    0x2e67157159e5c639,
]);

/// R^2 where R = 2^256 mod p (Go: `r2`).
const R2: GfP = GfP([
    0xf32cfc5b538afa89,
    0xb5e71911d44501fb,
    0x47ab1eff0a417ff6,
    0x06d89f71cab8351f,
]);

/// R^3 where R = 2^256 mod p (Go: `r3`).
const R3: GfP = GfP([
    0xb1cd6dafda1530df,
    0x62f210e6a7283db6,
    0xef7f0b0c0ada0afb,
    0x20fd6e902d592544,
]);

/// A base field element, Montgomery-encoded `[u64; 4]` little-endian words.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GfP(pub [u64; 4]);

impl GfP {
    pub const ZERO: GfP = GfP([0, 0, 0, 0]);

    /// Go: `newGFp(x)` — small integer into Montgomery form.
    pub fn new(x: i64) -> GfP {
        let mut out = if x >= 0 {
            GfP([x as u64, 0, 0, 0])
        } else {
            let mut t = GfP([(-x) as u64, 0, 0, 0]);
            let neg = gfp_neg(&t);
            t = neg;
            t
        };
        out = mont_encode(&out);
        out
    }

    /// Go: `gfP.Marshal` — 32 big-endian bytes (most significant word first).
    /// Operates on the raw (Montgomery-form) words; callers `mont_decode` first
    /// when they want the true coordinate, exactly as the Go G1.Marshal does.
    pub fn marshal(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for w in 0..4usize {
            for b in 0..8usize {
                out[8 * w + b] = (self.0[3 - w] >> (56 - 8 * b)) as u8;
            }
        }
        out
    }

    /// Go: `gfP.Unmarshal` — load 32 big-endian bytes into words and verify the
    /// value is strictly less than p. Does NOT Montgomery-encode (matches Go).
    pub fn unmarshal(input: &[u8]) -> Result<GfP, &'static str> {
        if input.len() < 32 {
            return Err("bn256: not enough data");
        }
        let mut e = [0u64; 4];
        for w in 0..4usize {
            let mut v = 0u64;
            for b in 0..8usize {
                v += (input[8 * w + b] as u64) << (56 - 8 * b);
            }
            e[3 - w] = v;
        }
        // Ensure the value respects the curve modulus.
        for i in (0..4usize).rev() {
            if e[i] < P2[i] {
                return Ok(GfP(e));
            }
            if e[i] > P2[i] {
                return Err("bn256: coordinate exceeds modulus");
            }
        }
        Err("bn256: coordinate equals modulus")
    }

    /// Go: `gfP.Invert` — modular inverse via exponentiation by (p-2).
    pub fn invert(&self) -> GfP {
        // bits = p - 2, little-endian words.
        const BITS: [u64; 4] = [
            0x3c208c16d87cfd45,
            0x97816a916871ca8d,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ];
        let mut sum = RN1;
        let mut power = *self;
        for word in 0..4usize {
            for bit in 0..64u32 {
                if (BITS[word] >> bit) & 1 == 1 {
                    sum = gfp_mul(&sum, &power);
                }
                power = gfp_mul(&power, &power);
            }
        }
        gfp_mul(&sum, &R3)
    }
}

#[inline]
pub(crate) fn mont_encode(a: &GfP) -> GfP {
    gfp_mul(a, &R2)
}

#[inline]
pub(crate) fn mont_decode(a: &GfP) -> GfP {
    gfp_mul(a, &GfP([1, 0, 0, 0]))
}

/// Go: `gfpCarry` — conditional subtraction of p if `a + head*2^256 >= p`.
fn gfp_carry(a: &mut GfP, head: u64) {
    let mut b = [0u64; 4];
    let mut carry: u64 = 0;
    for i in 0..4usize {
        let pi = P2[i];
        let ai = a.0[i];
        let bi = ai.wrapping_sub(pi).wrapping_sub(carry);
        b[i] = bi;
        carry = (pi & !ai | (pi | !ai) & bi) >> 63;
    }
    carry &= !head;
    // If b is negative (borrow), keep a; else keep b.
    let carry = carry.wrapping_neg();
    let ncarry = !carry;
    for i in 0..4usize {
        a.0[i] = (a.0[i] & carry) | (b[i] & ncarry);
    }
}

/// Go: `gfpNeg`.
pub(crate) fn gfp_neg(a: &GfP) -> GfP {
    let mut c = GfP::ZERO;
    let mut carry: u64 = 0;
    for i in 0..4usize {
        let pi = P2[i];
        let ai = a.0[i];
        let ci = pi.wrapping_sub(ai).wrapping_sub(carry);
        c.0[i] = ci;
        carry = (ai & !pi | (ai | !pi) & ci) >> 63;
    }
    gfp_carry(&mut c, 0);
    c
}

/// Go: `gfpAdd`.
pub(crate) fn gfp_add(a: &GfP, b: &GfP) -> GfP {
    let mut c = GfP::ZERO;
    let mut carry: u64 = 0;
    for i in 0..4usize {
        let ai = a.0[i];
        let bi = b.0[i];
        let ci = ai.wrapping_add(bi).wrapping_add(carry);
        c.0[i] = ci;
        carry = (ai & bi | (ai | bi) & !ci) >> 63;
    }
    gfp_carry(&mut c, carry);
    c
}

/// Go: `gfpSub`.
pub(crate) fn gfp_sub(a: &GfP, b: &GfP) -> GfP {
    let mut t = [0u64; 4];
    let mut carry: u64 = 0;
    for i in 0..4usize {
        let pi = P2[i];
        let bi = b.0[i];
        let ti = pi.wrapping_sub(bi).wrapping_sub(carry);
        t[i] = ti;
        carry = (bi & !pi | (bi | !pi) & ti) >> 63;
    }
    let mut c = GfP::ZERO;
    carry = 0;
    for i in 0..4usize {
        let ai = a.0[i];
        let ti = t[i];
        let ci = ai.wrapping_add(ti).wrapping_add(carry);
        c.0[i] = ci;
        carry = (ai & ti | (ai | ti) & !ci) >> 63;
    }
    gfp_carry(&mut c, carry);
    c
}

/// Go: `mul` — schoolbook 4x4 -> 8 word product.
fn mul(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    const MASK16: u64 = 0x0000ffff;
    const MASK32: u64 = 0xffffffff;

    let mut buff = [0u64; 32];
    for i in 0..4usize {
        let ai = a[i];
        let a0 = ai & MASK16;
        let a1 = (ai >> 16) & MASK16;
        let a2 = (ai >> 32) & MASK16;
        let a3 = ai >> 48;
        for j in 0..4usize {
            let bj = b[j];
            let b0 = bj & MASK32;
            let b2 = bj >> 32;
            let off = 4 * (i + j);
            buff[off] = buff[off].wrapping_add(a0.wrapping_mul(b0));
            buff[off + 1] = buff[off + 1].wrapping_add(a1.wrapping_mul(b0));
            buff[off + 2] = buff[off + 2]
                .wrapping_add(a2.wrapping_mul(b0).wrapping_add(a0.wrapping_mul(b2)));
            buff[off + 3] = buff[off + 3]
                .wrapping_add(a3.wrapping_mul(b0).wrapping_add(a1.wrapping_mul(b2)));
            buff[off + 4] = buff[off + 4].wrapping_add(a2.wrapping_mul(b2));
            buff[off + 5] = buff[off + 5].wrapping_add(a3.wrapping_mul(b2));
        }
    }

    for i in 1..4u32 {
        let shift = 16 * i;
        let mut head: u64 = 0;
        let mut carry: u64 = 0;
        for j in 0..8usize {
            let block = 4 * j;
            let xi = buff[block];
            let yi = (buff[block + i as usize] << shift).wrapping_add(head);
            let zi = xi.wrapping_add(yi).wrapping_add(carry);
            buff[block] = zi;
            carry = (xi & yi | (xi | yi) & !zi) >> 63;
            head = buff[block + i as usize] >> (64 - shift);
        }
    }

    [
        buff[0], buff[4], buff[8], buff[12], buff[16], buff[20], buff[24], buff[28],
    ]
}

/// Go: `halfMul` — low half of the product.
fn half_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    const MASK16: u64 = 0x0000ffff;
    const MASK32: u64 = 0xffffffff;

    let mut buff = [0u64; 18];
    for i in 0..4usize {
        let ai = a[i];
        let a0 = ai & MASK16;
        let a1 = (ai >> 16) & MASK16;
        let a2 = (ai >> 32) & MASK16;
        let a3 = ai >> 48;
        for j in 0..4usize {
            if i + j > 3 {
                break;
            }
            let bj = b[j];
            let b0 = bj & MASK32;
            let b2 = bj >> 32;
            let off = 4 * (i + j);
            buff[off] = buff[off].wrapping_add(a0.wrapping_mul(b0));
            buff[off + 1] = buff[off + 1].wrapping_add(a1.wrapping_mul(b0));
            buff[off + 2] = buff[off + 2]
                .wrapping_add(a2.wrapping_mul(b0).wrapping_add(a0.wrapping_mul(b2)));
            buff[off + 3] = buff[off + 3]
                .wrapping_add(a3.wrapping_mul(b0).wrapping_add(a1.wrapping_mul(b2)));
            buff[off + 4] = buff[off + 4].wrapping_add(a2.wrapping_mul(b2));
            buff[off + 5] = buff[off + 5].wrapping_add(a3.wrapping_mul(b2));
        }
    }

    for i in 1..4u32 {
        let shift = 16 * i;
        let mut head: u64 = 0;
        let mut carry: u64 = 0;
        for j in 0..4usize {
            let block = 4 * j;
            let xi = buff[block];
            let yi = (buff[block + i as usize] << shift).wrapping_add(head);
            let zi = xi.wrapping_add(yi).wrapping_add(carry);
            buff[block] = zi;
            carry = (xi & yi | (xi | yi) & !zi) >> 63;
            head = buff[block + i as usize] >> (64 - shift);
        }
    }

    [buff[0], buff[4], buff[8], buff[12]]
}

/// Go: `gfpMul` — Montgomery multiplication.
pub(crate) fn gfp_mul(a: &GfP, b: &GfP) -> GfP {
    let mut t = mul(a.0, b.0);
    let m = half_mul([t[0], t[1], t[2], t[3]], NP);
    let tp = mul([m[0], m[1], m[2], m[3]], P2);

    let mut carry: u64 = 0;
    for i in 0..8usize {
        let ti = t[i];
        let tpi = tp[i];
        let zi = ti.wrapping_add(tpi).wrapping_add(carry);
        t[i] = zi;
        carry = (ti & tpi | (ti | tpi) & !zi) >> 63;
    }

    let mut c = GfP([t[4], t[5], t[6], t[7]]);
    gfp_carry(&mut c, carry);
    c
}
