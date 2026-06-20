//! G1 curve points y² = x³ + 3 over GF(p), in Jacobian coordinates.
//!
//! Faithful port of `cryptography/bn256/curve.go`. The one deliberate change:
//! `mul` is implemented as standard MSB-first double-and-add instead of Go's
//! GLV lattice decomposition. Both compute the identical group element `k·P`,
//! and `Marshal` normalizes via `MakeAffine`, so serialized output is
//! byte-identical — this lets us skip porting `lattice.go` and the GFp²
//! endomorphism with zero compatibility risk.

use crate::gfp::{gfp_add, gfp_mul, gfp_neg, gfp_sub, GfP};

#[derive(Clone, Copy, Debug)]
pub struct CurvePoint {
    pub x: GfP,
    pub y: GfP,
    pub z: GfP,
    pub t: GfP,
}

#[inline]
fn curve_b() -> GfP {
    GfP::new(3)
}

#[inline]
fn one() -> GfP {
    GfP::new(1)
}

#[inline]
fn zero() -> GfP {
    GfP::ZERO
}

impl CurvePoint {
    /// Generator of G₁: (1, 2) in affine, Montgomery-encoded.
    pub fn generator() -> CurvePoint {
        CurvePoint {
            x: GfP::new(1),
            y: GfP::new(2),
            z: GfP::new(1),
            t: GfP::new(1),
        }
    }

    pub fn infinity() -> CurvePoint {
        CurvePoint {
            x: zero(),
            y: one(),
            z: zero(),
            t: zero(),
        }
    }

    #[allow(dead_code)]
    pub fn set_infinity(&mut self) {
        self.x = zero();
        self.y = one();
        self.z = zero();
        self.t = zero();
    }

    pub fn is_infinity(&self) -> bool {
        self.z == GfP::ZERO
    }

    pub fn is_on_curve(&self) -> bool {
        let mut c = *self;
        c.make_affine();
        if c.is_infinity() {
            return true;
        }
        let y2 = gfp_mul(&c.y, &c.y);
        let mut x3 = gfp_mul(&c.x, &c.x);
        x3 = gfp_mul(&x3, &c.x);
        x3 = gfp_add(&x3, &curve_b());
        y2 == x3
    }

    /// Go: `curvePoint.Add`.
    pub fn add(a: &CurvePoint, b: &CurvePoint) -> CurvePoint {
        if a.is_infinity() {
            return *b;
        }
        if b.is_infinity() {
            return *a;
        }

        let z12 = gfp_mul(&a.z, &a.z);
        let z22 = gfp_mul(&b.z, &b.z);

        let u1 = gfp_mul(&a.x, &z22);
        let u2 = gfp_mul(&b.x, &z12);

        let mut t = gfp_mul(&b.z, &z22);
        let s1 = gfp_mul(&a.y, &t);

        t = gfp_mul(&a.z, &z12);
        let s2 = gfp_mul(&b.y, &t);

        let h = gfp_sub(&u2, &u1);
        let x_equal = h == GfP::ZERO;

        t = gfp_add(&h, &h);
        let i = gfp_mul(&t, &t);
        let j = gfp_mul(&h, &i);

        t = gfp_sub(&s2, &s1);
        let y_equal = t == GfP::ZERO;
        if x_equal && y_equal {
            return CurvePoint::double(a);
        }
        let r = gfp_add(&t, &t);

        let v = gfp_mul(&u1, &i);

        let mut t4 = gfp_mul(&r, &r);
        t = gfp_add(&v, &v);
        let t6 = gfp_sub(&t4, &j);

        let mut c = CurvePoint {
            x: zero(),
            y: zero(),
            z: zero(),
            t: zero(),
        };
        c.x = gfp_sub(&t6, &t);

        t = gfp_sub(&v, &c.x);
        t4 = gfp_mul(&s1, &j);
        let t6 = gfp_add(&t4, &t4);
        t4 = gfp_mul(&r, &t);
        c.y = gfp_sub(&t4, &t6);

        t = gfp_add(&a.z, &b.z);
        t4 = gfp_mul(&t, &t);
        t = gfp_sub(&t4, &z12);
        t4 = gfp_sub(&t, &z22);
        c.z = gfp_mul(&t4, &h);

        c
    }

    /// Go: `curvePoint.Double`.
    pub fn double(a: &CurvePoint) -> CurvePoint {
        let aa = gfp_mul(&a.x, &a.x);
        let bb = gfp_mul(&a.y, &a.y);
        let cc = gfp_mul(&bb, &bb);

        let mut t = gfp_add(&a.x, &bb);
        let mut t2 = gfp_mul(&t, &t);
        t = gfp_sub(&t2, &aa);
        t2 = gfp_sub(&t, &cc);

        let d = gfp_add(&t2, &t2);
        t = gfp_add(&aa, &aa);
        let e = gfp_add(&t, &aa);
        let f = gfp_mul(&e, &e);

        t = gfp_add(&d, &d);

        let mut c = CurvePoint {
            x: zero(),
            y: zero(),
            z: zero(),
            t: zero(),
        };
        c.x = gfp_sub(&f, &t);

        c.z = gfp_mul(&a.y, &a.z);
        c.z = gfp_add(&c.z, &c.z);

        t = gfp_add(&cc, &cc);
        t2 = gfp_add(&t, &t);
        t = gfp_add(&t2, &t2);
        c.y = gfp_sub(&d, &c.x);
        t2 = gfp_mul(&e, &c.y);
        c.y = gfp_sub(&t2, &t);

        c
    }

    /// `k·a` via MSB-first double-and-add. `scalar_be` is big-endian bytes.
    /// Produces the identical group element as Go's GLV-based `Mul`.
    pub fn mul(a: &CurvePoint, scalar_be: &[u8]) -> CurvePoint {
        let mut sum = CurvePoint::infinity();
        for &byte in scalar_be.iter() {
            for bit in (0..8).rev() {
                sum = CurvePoint::double(&sum);
                if (byte >> bit) & 1 == 1 {
                    sum = CurvePoint::add(&sum, a);
                }
            }
        }
        sum
    }

    /// Go: `curvePoint.MakeAffine`.
    pub fn make_affine(&mut self) {
        if self.z == one() {
            return;
        } else if self.z == GfP::ZERO {
            self.x = zero();
            self.y = one();
            self.t = zero();
            return;
        }

        let z_inv = self.z.invert();
        let t = gfp_mul(&self.y, &z_inv);
        let z_inv2 = gfp_mul(&z_inv, &z_inv);

        self.x = gfp_mul(&self.x, &z_inv2);
        self.y = gfp_mul(&t, &z_inv2);

        self.z = one();
        self.t = one();
    }

    /// Go: `curvePoint.Neg`.
    pub fn neg(a: &CurvePoint) -> CurvePoint {
        CurvePoint {
            x: a.x,
            y: gfp_neg(&a.y),
            z: a.z,
            t: GfP::ZERO,
        }
    }
}
