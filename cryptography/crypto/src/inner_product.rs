//! Inner-product argument (the Σ-protocol inside the Bulletproof). Port of
//! `cryptography/crypto/proof_innerproduct.go`.
//!
//! Deterministic given (generators Gs/Hs, u=H, vectors a/b, salt). Per-round
//! challenge `x = ReducedHash( to32(prev) ‖ L.marshal() ‖ R.marshal() )` — note
//! the FS hash uses the **uncompressed 64-byte marshal**, while serialization
//! uses the **compressed 33-byte** form.

use crate::field_vector::FieldVector;
use crate::hashtopoint::reduced_hash;
use crate::point_vector::PointVector;
use crate::scalar;
use dero_bn256::G1;
use num_bigint::BigUint;

/// Go: `InnerProduct` — the proof output.
#[derive(Clone, Debug)]
pub struct InnerProduct {
    pub a: BigUint,
    pub b: BigUint,
    pub ls: Vec<G1>,
    pub rs: Vec<G1>,
}

fn smul(p: &G1, s: &BigUint) -> G1 {
    p.scalar_mult(&scalar::reduce(s).to_bytes_be())
}

impl InnerProduct {
    /// Go: `NewInnerProductProof` / `generateInnerProductProof`.
    /// `gs`,`hs` are the generator vectors (length n, a power of 2); `u` is H.
    pub fn generate(
        gs: &PointVector,
        hs: &PointVector,
        u: &G1,
        a: &FieldVector,
        b: &FieldVector,
        salt: &BigUint,
    ) -> InnerProduct {
        let mut ls = Vec::new();
        let mut rs = Vec::new();
        let (a_fin, b_fin) = Self::recurse(gs, hs, u, a, b, salt, &mut ls, &mut rs);
        InnerProduct {
            a: a_fin,
            b: b_fin,
            ls,
            rs,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recurse(
        gs: &PointVector,
        hs: &PointVector,
        u: &G1,
        a: &FieldVector,
        b: &FieldVector,
        prev: &BigUint,
        ls: &mut Vec<G1>,
        rs: &mut Vec<G1>,
    ) -> (BigUint, BigUint) {
        let n = a.length();
        if n == 1 {
            return (a.vector[0].clone(), b.vector[0].clone());
        }
        let np = n / 2;
        let a_l = a.slice(0, np);
        let a_r = a.slice(np, n);
        let b_l = b.slice(0, np);
        let b_r = b.slice(np, n);
        let g_l = gs.slice(0, np);
        let g_r = gs.slice(np, n);
        let h_l = hs.slice(0, np);
        let h_r = hs.slice(np, n);

        let cl = a_l.inner_product(&b_r);
        let cr = a_r.inner_product(&b_l);

        let l = G1::add(
            &G1::add(&g_r.commit(&a_l.vector), &h_l.commit(&b_r.vector)),
            &smul(u, &cl),
        );
        let r = G1::add(
            &G1::add(&g_l.commit(&a_r.vector), &h_r.commit(&b_l.vector)),
            &smul(u, &cr),
        );
        ls.push(l);
        rs.push(r);

        let mut input = scalar::to_32_be(prev).to_vec();
        input.extend_from_slice(&l.marshal());
        input.extend_from_slice(&r.marshal());
        let x = reduced_hash(&input);
        let xinv = scalar::inv(&x);

        let g_prime = g_l.times(&xinv).add(&g_r.times(&x));
        let h_prime = h_l.times(&x).add(&h_r.times(&xinv));
        let a_prime = a_l.times(&x).add(&a_r.times(&xinv));
        let b_prime = b_l.times(&xinv).add(&b_r.times(&x));

        Self::recurse(&g_prime, &h_prime, u, &a_prime, &b_prime, &x, ls, rs)
    }

    /// Go: `InnerProduct.Serialize` — a(32) ‖ b(32) ‖ for each round
    /// L.compressed(33) ‖ R.compressed(33).
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&scalar::to_32_be(&self.a));
        w.extend_from_slice(&scalar::to_32_be(&self.b));
        for i in 0..self.ls.len() {
            w.extend_from_slice(&self.ls[i].compress());
            w.extend_from_slice(&self.rs[i].compress());
        }
        w
    }

    /// Go: `InnerProduct.Verify(hs, u, P, salt, gp)`. `hs` are the `hPrimes`
    /// (rescaled H generators), `u` the inner-product base, `P` the committed
    /// point, `salt` the seed challenge. Returns true iff the recomputed point
    /// equals `P`. (Go panics on mismatch; we return false.)
    pub fn verify(&self, hs: &[G1], u: &G1, p_in: &G1, salt: &BigUint) -> bool {
        use crate::generators::gs_all;
        use num_traits::{One, Zero};

        let order = scalar::order();
        let log_n = self.ls.len();
        if self.ls.len() != self.rs.len() {
            return false;
        }
        let n = 1usize << log_n;

        let mut o = salt.clone();
        let mut challenges: Vec<BigUint> = Vec::with_capacity(log_n);
        let mut p = p_in.clone();
        for i in 0..log_n {
            let mut input = scalar::to_32_be(&o).to_vec();
            input.extend_from_slice(&self.ls[i].marshal());
            input.extend_from_slice(&self.rs[i].marshal());
            o = reduced_hash(&input);
            challenges.push(o.clone());

            let o_inv = scalar::inv(&o);
            let osq = (&o * &o) % &order;
            let oinvsq = (&o_inv * &o_inv) % &order;
            let pl = self.ls[i].scalar_mult(&osq.to_bytes_be());
            let pr = self.rs[i].scalar_mult(&oinvsq.to_bytes_be());
            p = G1::add(&G1::add(&pl, &pr), &p);
        }

        let mut exp = BigUint::one();
        for c in &challenges {
            exp = (&exp * c) % &order;
        }
        let exp_inv = scalar::inv(&exp);

        let mut exponents = vec![BigUint::zero(); n];
        exponents[0] = exp_inv;
        let mut bits = vec![false; n];
        for i in 0..(n / 2) {
            let mut j = 0usize;
            while (1usize << j) + i < n {
                let i1 = (1usize << j) + i;
                if !bits[i1] {
                    let ch = &challenges[log_n - 1 - j];
                    let temp = (ch * ch) % &order;
                    exponents[i1] = (&exponents[i] * &temp) % &order;
                    bits[i1] = true;
                }
                j += 1;
            }
        }

        let gs = gs_all();
        let mut gtemp = G1::infinity();
        let mut htemp = G1::infinity();
        for i in 0..n {
            gtemp = G1::add(&gtemp, &gs[i].scalar_mult(&exponents[i].to_bytes_be()));
            htemp = G1::add(&htemp, &hs[i].scalar_mult(&exponents[n - 1 - i].to_bytes_be()));
        }
        let gtemp = gtemp.scalar_mult(&(&self.a % &order).to_bytes_be());
        let htemp = htemp.scalar_mult(&(&self.b % &order).to_bytes_be());
        let ab = (&self.a * &self.b) % &order;
        let utemp = u.scalar_mult(&ab.to_bytes_be());

        let p_calc = G1::add(&G1::add(&gtemp, &htemp), &utemp);
        p_calc.compress() == p.compress()
    }

    /// Go: `InnerProduct.Deserialize` — inverse of [`InnerProduct::serialize`].
    /// The round count is fixed at 7 (the 128-bit range proof → log2(128) = 7).
    pub fn deserialize(r: &mut &[u8]) -> Result<InnerProduct, &'static str> {
        use crate::read::{take_g1, take_scalar};
        const ROUNDS: usize = 7;
        let a = take_scalar(r)?;
        let b = take_scalar(r)?;
        let mut ls = Vec::with_capacity(ROUNDS);
        let mut rs = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            ls.push(take_g1(r)?);
            rs.push(take_g1(r)?);
        }
        Ok(InnerProduct { a, b, ls, rs })
    }
}
