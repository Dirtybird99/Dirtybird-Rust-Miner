//! G1 group element — wraps a `CurvePoint`, provides (un)marshal and the
//! DERO-specific 33-byte point compression.
//!
//! Faithful port of the G1 parts of `cryptography/bn256/bn256.go` and the
//! compression in `changes.go`.

use crate::consts::field_prime;
use crate::curve::CurvePoint;
use crate::gfp::{mont_decode, mont_encode, GfP};
use num_bigint::BigUint;
use num_traits::Zero;

const NUM_BYTES: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct G1 {
    pub(crate) p: CurvePoint,
}

impl Default for G1 {
    fn default() -> Self {
        G1::infinity()
    }
}

impl G1 {
    pub fn infinity() -> G1 {
        G1 {
            p: CurvePoint::infinity(),
        }
    }

    /// g·k where g is the group generator. `k` big-endian bytes.
    pub fn scalar_base_mult(k: &[u8]) -> G1 {
        G1 {
            p: CurvePoint::mul(&CurvePoint::generator(), k),
        }
    }

    /// self·k. `k` big-endian bytes.
    pub fn scalar_mult(&self, k: &[u8]) -> G1 {
        G1 {
            p: CurvePoint::mul(&self.p, k),
        }
    }

    pub fn add(a: &G1, b: &G1) -> G1 {
        G1 {
            p: CurvePoint::add(&a.p, &b.p),
        }
    }

    pub fn neg(a: &G1) -> G1 {
        G1 {
            p: CurvePoint::neg(&a.p),
        }
    }

    pub fn is_infinity(&self) -> bool {
        let mut c = self.p;
        c.make_affine();
        c.is_infinity()
    }

    /// Go: `G1.Marshal` — 64 bytes, X‖Y big-endian, Montgomery-decoded.
    pub fn marshal(&self) -> [u8; 64] {
        let mut p = self.p;
        p.make_affine();
        let mut ret = [0u8; 64];
        if p.is_infinity() {
            return ret;
        }
        let x = mont_decode(&p.x);
        let y = mont_decode(&p.y);
        ret[..NUM_BYTES].copy_from_slice(&x.marshal());
        ret[NUM_BYTES..].copy_from_slice(&y.marshal());
        ret
    }

    /// Go: `G1.Unmarshal` — parse 64 bytes; validate on curve.
    pub fn unmarshal(m: &[u8]) -> Result<G1, &'static str> {
        if m.len() < 2 * NUM_BYTES {
            return Err("bn256: not enough data");
        }
        let mut x = GfP::unmarshal(&m[..NUM_BYTES])?;
        let mut y = GfP::unmarshal(&m[NUM_BYTES..2 * NUM_BYTES])?;
        x = mont_encode(&x);
        y = mont_encode(&y);

        let mut p = CurvePoint {
            x,
            y,
            z: GfP::ZERO,
            t: GfP::ZERO,
        };
        if x == GfP::ZERO && y == GfP::ZERO {
            // point at infinity
            p.y = GfP::new(1);
            p.z = GfP::ZERO;
            p.t = GfP::ZERO;
        } else {
            p.z = GfP::new(1);
            p.t = GfP::new(1);
            if !p.is_on_curve() {
                return Err("bn256: malformed point");
            }
        }
        Ok(G1 { p })
    }

    /// Go: `G1.Compress` / `EncodeCompressed` — 33-byte X‖flag form.
    /// flag = 0x00 if y < p−y else 0x01.
    pub fn compress(&self) -> [u8; 33] {
        let eb = self.marshal();
        let p = field_prime();
        let y = BigUint::from_bytes_be(&eb[32..64]);
        let y2 = &p - &y;
        let mut out = [0u8; 33];
        out[..32].copy_from_slice(&eb[..32]);
        out[32] = if y < y2 { 0x00 } else { 0x01 };
        out
    }

    /// Go: `Decompress` / `DecodeCompressed` — recover Y from the 33-byte form.
    pub fn decompress(encoding: &[u8]) -> Result<G1, &'static str> {
        if encoding.len() != 33 {
            return Err("bn256: not enough data on compressed point");
        }
        let (y1, y2) = x_to_y(&encoding[..32]).ok_or("bn256: Cannot decompress")?;
        let smaller = y1 < y2;
        let flag = encoding[32];
        let chosen = if flag == 0x00 && smaller {
            y1
        } else if flag == 0x01 && smaller {
            y2
        } else if flag == 0x00 {
            y2
        } else {
            y1
        };
        marshal_xy(&encoding[..32], &chosen)
    }

    pub fn encode_uncompressed(&self) -> [u8; 64] {
        self.marshal()
    }

    pub fn decode_uncompressed(input: &[u8]) -> Result<G1, &'static str> {
        G1::unmarshal(input)
    }
}

/// Go: `xToY` — y = sqrt(x³ + 3) mod p, returning (y1, y2 = p−y1).
/// `None` if x³+3 is not a quadratic residue (mirrors ModSqrt returning nil).
fn x_to_y(xb: &[u8]) -> Option<(BigUint, BigUint)> {
    let p = field_prime();
    let xi = BigUint::from_bytes_be(&xb[..32]);
    // beta = (x³ + 3) mod p
    let x3 = (&xi * &xi * &xi) % &p;
    let beta = (&x3 + BigUint::from(3u32)) % &p;
    // y1 = beta^((p+1)/4) mod p  (p ≡ 3 mod 4)
    let exp = (&p + BigUint::from(1u32)) / BigUint::from(4u32);
    let y1 = beta.modpow(&exp, &p);
    // Replicate ModSqrt's QR check: a genuine root squares back to beta.
    let check = (&y1 * &y1) % &p;
    if check != beta {
        return None;
    }
    let y2 = if y1.is_zero() {
        BigUint::zero()
    } else {
        &p - &y1
    };
    Some((y1, y2))
}

/// Go: `marshal(xb, yi)` — assemble X‖Y (Y left-padded to 32 bytes big-endian)
/// then validate via Unmarshal.
fn marshal_xy(xb: &[u8], y: &BigUint) -> Result<G1, &'static str> {
    let mut g = [0u8; 64];
    g[..32].copy_from_slice(&xb[..32]);
    let yb = y.to_bytes_be();
    if yb.len() > 32 {
        return Err("bn256: y coordinate too large");
    }
    g[64 - yb.len()..].copy_from_slice(&yb);
    G1::unmarshal(&g)
}
