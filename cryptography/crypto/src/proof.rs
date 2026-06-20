//! Zether + Bulletproof transfer proof generation. Port of `GenerateProof`,
//! the `Proof` struct and `Proof.Serialize` from `proof_generate.go`.
//!
//! Verified via the deterministic-RNG byte-compare against the Go reference
//! (patched `random.go`): with the same nonce sequence, the serialized Rust
//! proof must equal the Go proof byte-for-byte. The real (random-nonce) proof
//! is then accepted by the Go `Proof.Verify` (= mainnet consensus crypto).

use crate::field_vector::{FieldVector, FieldVectorPolynomial};
use crate::generators::{base_g, base_h, gs, gs_all, gsum, hs, hs_all};
use crate::hashtopoint::{hash_to_number, hash_to_point, reduced_hash, PROTOCOL_CONSTANT};
use crate::inner_product::InnerProduct;
use crate::point_vector::{convolution, PointVector};
use crate::polynomial::{recursive_polynomials, transpose_polynomials};
use crate::scalar::{self, to_32_be};
use crate::statement::{Statement, Witness};
use dero_bn256::G1;
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// A pluggable scalar source so the prover can run with real randomness or a
/// deterministic sequence for byte-exact cross-checking.
pub trait ScalarRng {
    fn next_scalar(&mut self) -> BigUint;
}

/// Deterministic RNG matching the patched Go `random.go`:
/// `nonce_k = reducedhash(ConvertBigIntToByte(k))`, k = 1,2,3,...
pub struct DeterministicRng {
    counter: u64,
}
impl DeterministicRng {
    pub fn new() -> Self {
        DeterministicRng { counter: 0 }
    }
}
impl Default for DeterministicRng {
    fn default() -> Self {
        Self::new()
    }
}
impl ScalarRng for DeterministicRng {
    fn next_scalar(&mut self) -> BigUint {
        self.counter += 1;
        reduced_hash(&to_32_be(&BigUint::from(self.counter)))
    }
}

// ---- ElGamal with optional left side (proof-internal) ----
#[derive(Clone)]
struct Eg {
    left: Option<G1>,
    right: G1,
}
impl Eg {
    fn new(left: Option<G1>, right: G1) -> Eg {
        Eg { left, right }
    }
    fn add(&self, o: &Eg) -> Eg {
        let right = G1::add(&self.right, &o.right);
        match (&self.left, &o.left) {
            (Some(a), Some(b)) => Eg::new(Some(G1::add(a, b)), right),
            (None, Some(b)) => Eg::new(Some(*b), right),
            (Some(a), None) => Eg::new(Some(*a), right),
            (None, None) => Eg::new(None, right),
        }
    }
    fn mul(&self, s: &BigUint) -> Eg {
        let sb = scalar::reduce(s);
        Eg::new(
            self.left.map(|l| l.scalar_mult(&sb.to_bytes_be())),
            self.right.scalar_mult(&sb.to_bytes_be()),
        )
    }
    fn plus(&self, value: &BigUint) -> Eg {
        // Left + G*value (right unchanged)
        let gv = base_g().scalar_mult(&scalar::reduce(value).to_bytes_be());
        let left = match &self.left {
            Some(l) => G1::add(l, &gv),
            None => gv,
        };
        Eg::new(Some(left), self.right)
    }
    fn neg(&self) -> Eg {
        Eg::new(self.left.map(|l| G1::neg(&l)), G1::neg(&self.right))
    }
}

fn smul(p: &G1, s: &BigUint) -> G1 {
    p.scalar_mult(&scalar::reduce(s).to_bytes_be())
}

/// `commit_elgamal(key, value)`: Left = G·value + key·r, Right = G·r.
fn commit_elgamal(key: &G1, value: &BigUint, rng: &mut dyn ScalarRng) -> (Eg, BigUint) {
    let r = rng.next_scalar();
    let left = G1::add(&smul(&base_g(), value), &smul(key, &r));
    let right = smul(&base_g(), &r);
    (Eg::new(Some(left), right), r)
}

/// PedersenVectorCommitment.Commit(gexps, hexps) = r·H + Σ Gs[i]·g[i] + Σ Hs[i]·h[i].
fn pvc_commit(gexps: &FieldVector, hexps: &FieldVector, rng: &mut dyn ScalarRng) -> (G1, BigUint) {
    let r = rng.next_scalar();
    let mut result = smul(&base_h(), &r);
    for (i, g) in gexps.vector.iter().enumerate() {
        result = G1::add(&result, &smul(&gs(i), g));
    }
    for (i, h) in hexps.vector.iter().enumerate() {
        result = G1::add(&result, &smul(&hs(i), h));
    }
    (result, r)
}

/// PedersenCommitmentNew.Commit(v) = v·G + r·H.
fn pc_commit(v: &BigUint, rng: &mut dyn ScalarRng) -> (G1, BigUint) {
    let r = rng.next_scalar();
    let result = G1::add(&smul(&base_g(), v), &smul(&base_h(), &r));
    (result, r)
}

/// The transfer proof (Go: `Proof`).
#[derive(Clone, Debug)]
pub struct Proof {
    pub ba: G1,
    pub bs: G1,
    pub a: G1,
    pub b: G1,
    pub cln_g: Vec<G1>,
    pub crn_g: Vec<G1>,
    pub c_0g: Vec<G1>,
    pub dg: Vec<G1>,
    pub y_0g: Vec<G1>,
    pub g_g: Vec<G1>,
    pub c_xg: Vec<G1>,
    pub y_xg: Vec<G1>,
    pub u: G1,
    pub f: FieldVector,
    pub z_a: BigUint,
    pub t_1: G1,
    pub t_2: G1,
    pub that: BigUint,
    pub mu: BigUint,
    pub c: BigUint,
    pub s_sk: BigUint,
    pub s_r: BigUint,
    pub s_b: BigUint,
    pub s_tau: BigUint,
    pub ip: InnerProduct,
}

impl Proof {
    /// Go: `Proof.Serialize`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&self.ba.compress());
        w.extend_from_slice(&self.bs.compress());
        w.extend_from_slice(&self.a.compress());
        w.extend_from_slice(&self.b.compress());
        for i in 0..self.cln_g.len() {
            w.extend_from_slice(&self.cln_g[i].compress());
            w.extend_from_slice(&self.crn_g[i].compress());
            w.extend_from_slice(&self.c_0g[i].compress());
            w.extend_from_slice(&self.dg[i].compress());
            w.extend_from_slice(&self.y_0g[i].compress());
            w.extend_from_slice(&self.g_g[i].compress());
            w.extend_from_slice(&self.c_xg[i].compress());
            w.extend_from_slice(&self.y_xg[i].compress());
        }
        w.extend_from_slice(&self.u.compress());
        for fi in &self.f.vector {
            w.extend_from_slice(&to_32_be(fi));
        }
        w.extend_from_slice(&to_32_be(&self.z_a));
        w.extend_from_slice(&self.t_1.compress());
        w.extend_from_slice(&self.t_2.compress());
        w.extend_from_slice(&to_32_be(&self.that));
        w.extend_from_slice(&to_32_be(&self.mu));
        w.extend_from_slice(&to_32_be(&self.c));
        w.extend_from_slice(&to_32_be(&self.s_sk));
        w.extend_from_slice(&to_32_be(&self.s_r));
        w.extend_from_slice(&to_32_be(&self.s_b));
        w.extend_from_slice(&to_32_be(&self.s_tau));
        w.extend_from_slice(&self.ip.serialize());
        w
    }

    /// Go: `Proof.Verify(scid, scid_index, s, txid, extra_value)` — full
    /// consensus verification of the transfer proof. Requires the *complete*
    /// statement (`cln`/`crn`/`publickeylist`/`c`/`d`/`fees`/`roothash`), which
    /// the chain reconstructs from on-chain encrypted balances.
    pub fn verify(
        &self,
        scid: &[u8; 32],
        scid_index: usize,
        s: &Statement,
        txid: &[u8; 32],
        extra_value: u64,
    ) -> bool {
        let order = scalar::order();
        let g = base_g();
        let h = base_h();
        let gs_v = gs_all();
        let hs_v = hs_all();

        // p * s  (scalar reduced mod order)
        let smul = |p: &G1, sc: &BigUint| -> G1 { p.scalar_mult(&(sc % &order).to_bytes_be()) };
        let neg = |sc: &BigUint| -> BigUint { (&order - (sc % &order)) % &order };

        if s.c.len() != s.publickeylist.len() {
            return false;
        }
        let total_open_value = s.fees.wrapping_add(extra_value);
        if total_open_value < s.fees || total_open_value < extra_value {
            return false;
        }

        // --- v, w (Fiat-Shamir, identical to the prover) ---
        let statementhash = reduced_hash(txid);
        let v = {
            let mut input = to_32_be(&statementhash).to_vec();
            input.extend_from_slice(&self.ba.marshal());
            input.extend_from_slice(&self.bs.marshal());
            input.extend_from_slice(&self.a.marshal());
            input.extend_from_slice(&self.b.marshal());
            reduced_hash(&input)
        };
        // Go: `hashmash1` — grouped by type (all CLnG, then all CRnG, ...), NOT
        // interleaved. Matters for ring size > 2.
        let w = {
            let mut input = to_32_be(&v).to_vec();
            for p in &self.cln_g { input.extend_from_slice(&p.marshal()); }
            for p in &self.crn_g { input.extend_from_slice(&p.marshal()); }
            for p in &self.c_0g { input.extend_from_slice(&p.marshal()); }
            for p in &self.dg { input.extend_from_slice(&p.marshal()); }
            for p in &self.y_0g { input.extend_from_slice(&p.marshal()); }
            for p in &self.g_g { input.extend_from_slice(&p.marshal()); }
            for p in &self.c_xg { input.extend_from_slice(&p.marshal()); }
            for p in &self.y_xg { input.extend_from_slice(&p.marshal()); }
            reduced_hash(&input)
        };

        let m = self.f.vector.len() / 2;
        let n = 1usize << m;

        // f matrix: [w - f_k, f_k]
        let mut f: Vec<[BigUint; 2]> = Vec::with_capacity(2 * m);
        for k in 0..(2 * m) {
            let f1 = self.f.vector[k].clone();
            let f0 = (&order + &w - (&f1 % &order)) % &order;
            f.push([f0, f1]);
        }

        // parity: w must equal f[0] or f[m]
        if !(w == self.f.vector[0] || w == self.f.vector[m]) {
            return false;
        }

        // temp recovery
        let mut temp = G1::infinity();
        for k in 0..(2 * m) {
            temp = G1::add(&temp, &smul(&gs_v[k], &f[k][1]));
            let t = (&f[k][1] * &f[k][0]) % &order;
            temp = G1::add(&temp, &smul(&hs_v[k], &t));
        }
        let t0v = (&f[0][1] * &f[m][1]) % &order;
        let t1v = (&f[0][0] * &f[m][0]) % &order;
        temp = G1::add(&temp, &smul(&hs_v[2 * m], &t0v));
        temp = G1::add(&temp, &smul(&hs_v[1 + 2 * m], &t1v));

        let stored = G1::add(&smul(&self.b, &w), &self.a);
        let computed = G1::add(&temp, &smul(&h, &self.z_a));
        if stored.compress() != computed.compress() {
            return false;
        }

        // r = assemblepolynomials(f); p,q vectors
        let r = assemble_polynomials(&f, &order);
        let p_vec: Vec<BigUint> = r.iter().map(|x| x[0].clone()).collect();
        let q_vec: Vec<BigUint> = r.iter().map(|x| x[1].clone()).collect();

        let mut cln_r = G1::infinity();
        let mut crn_r = G1::infinity();
        for i in 0..n {
            cln_r = G1::add(&cln_r, &smul(&s.cln[i], &r[i][0]));
            crn_r = G1::add(&crn_r, &smul(&s.crn[i], &r[i][0]));
        }

        let c_pv = PointVector::new(s.c.clone());
        let pk_pv = PointVector::new(s.publickeylist.clone());
        let c_p = convolution(&FieldVector::new(p_vec.clone()), &c_pv);
        let c_q = convolution(&FieldVector::new(q_vec.clone()), &c_pv);
        let y_p = convolution(&FieldVector::new(p_vec), &pk_pv);
        let y_q = convolution(&FieldVector::new(q_vec), &pk_pv);

        // CR[i] = [c_p[i], c_q[i]], yR[i] = [y_p[i], y_q[i]]  (len n/2)
        let mut cr: Vec<[G1; 2]> = Vec::with_capacity(n / 2);
        let mut yr: Vec<[G1; 2]> = Vec::with_capacity(n / 2);
        for i in 0..c_p.vector.len() {
            cr.push([c_p.vector[i], c_q.vector[i]]);
            yr.push([y_p.vector[i], y_q.vector[i]]);
        }

        let mut v_pow = BigUint::one();
        let mut c_xr = G1::infinity();
        let mut y_xr = G1::infinity();
        for i in 0..n {
            c_xr = G1::add(&c_xr, &smul(&cr[i / 2][i % 2], &v_pow));
            y_xr = G1::add(&y_xr, &smul(&yr[i / 2][i % 2], &v_pow));
            if i > 0 {
                v_pow = (&v_pow * &v) % &order;
            }
        }

        let mut w_pow = BigUint::one();
        let mut g_r = G1::infinity();
        let mut d_r = G1::infinity();
        for i in 0..m {
            let wpn = neg(&w_pow);
            cln_r = G1::add(&cln_r, &smul(&self.cln_g[i], &wpn));
            crn_r = G1::add(&crn_r, &smul(&self.crn_g[i], &wpn));
            cr[0][0] = G1::add(&cr[0][0], &smul(&self.c_0g[i], &wpn));
            d_r = G1::add(&d_r, &smul(&self.dg[i], &wpn));
            yr[0][0] = G1::add(&yr[0][0], &smul(&self.y_0g[i], &wpn));
            g_r = G1::add(&g_r, &smul(&self.g_g[i], &wpn));
            c_xr = G1::add(&c_xr, &smul(&self.c_xg[i], &wpn));
            y_xr = G1::add(&y_xr, &smul(&self.y_xg[i], &wpn));
            w_pow = (&w_pow * &w) % &order;
        }
        d_r = G1::add(&d_r, &smul(&s.d, &w_pow));
        g_r = G1::add(&g_r, &smul(&g, &w_pow));
        let tov_wpow = (BigUint::from(total_open_value) * &w_pow) % &order;
        c_xr = G1::add(&c_xr, &smul(&g, &tov_wpow));

        // --- range-proof challenges (y, z, k, t, twoTimesZSquared) ---
        let y = reduced_hash(&to_32_be(&w));
        let mut ys: Vec<BigUint> = vec![BigUint::one()];
        let mut k = BigUint::one();
        for i in 1..128 {
            ys.push((&ys[i - 1] * &y) % &order);
            k = (&k + &ys[i]) % &order;
        }
        let z = reduced_hash(&to_32_be(&y));
        let zs = [
            z.modpow(&BigUint::from(2u32), &order),
            z.modpow(&BigUint::from(3u32), &order),
        ];
        let mut z_sum = (&zs[0] + &zs[1]) % &order;
        z_sum = (&z_sum * &z) % &order;
        let z_z0 = (&order + &z - &zs[0]) % &order;
        k = (&k * &z_z0) % &order;
        let two_64 = BigUint::from(1u128 << 64);
        let mut zsum_pow = (&z_sum * &two_64) % &order;
        zsum_pow = (&order + &zsum_pow - &z_sum) % &order;
        k = (&order + &k - &zsum_pow) % &order;
        let t = (&order + &self.that - (&k % &order)) % &order;

        let mut two_times_z_squared = vec![BigUint::zero(); 128];
        for i in 0..64 {
            let p2 = BigUint::from(1u128 << i);
            two_times_z_squared[i] = (&zs[0] * &p2) % &order;
            two_times_z_squared[64 + i] = (&zs[1] * &p2) % &order;
        }

        // x challenge
        let x = {
            let mut input = to_32_be(&z).to_vec();
            input.extend_from_slice(&self.t_1.marshal());
            input.extend_from_slice(&self.t_2.marshal());
            reduced_hash(&input)
        };
        let xsq = (&x * &x) % &order;
        let t_eval = G1::add(&smul(&self.t_1, &x), &smul(&self.t_2, &xsq));

        // --- sigma protocol A-values ---
        let c_neg = neg(&self.c);

        let a_y = G1::add(&smul(&g_r, &self.s_sk), &smul(&yr[0][0], &c_neg));
        let a_d = G1::add(&smul(&g, &self.s_r), &smul(&s.d, &c_neg));

        let zs0_neg = neg(&zs[0]);
        let mut left = smul(&d_r, &zs0_neg);
        left = G1::add(&left, &smul(&crn_r, &zs[1]));
        left = smul(&left, &self.s_sk);

        let mid_scalar = (BigUint::from(total_open_value) * &w_pow) % &order;
        let mid = G1::add(&smul(&g, &mid_scalar), &cr[0][0]);
        let mut right = smul(&mid, &zs0_neg);
        right = G1::add(&right, &smul(&cln_r, &zs[1]));
        right = smul(&right, &c_neg);

        let a_b = G1::add(&smul(&g, &self.s_b), &G1::add(&left, &right));
        let a_x = G1::add(&smul(&y_xr, &self.s_r), &smul(&c_xr, &c_neg));

        let s_b_neg = neg(&self.s_b);
        let cw = (&self.c * &w_pow) % &order;
        let mut a_t = smul(&g, &t);
        a_t = G1::add(&a_t, &G1::neg(&t_eval));
        a_t = smul(&a_t, &cw);
        a_t = G1::add(&a_t, &smul(&h, &self.s_tau));
        a_t = G1::add(&a_t, &smul(&g, &s_b_neg));

        let a_u = {
            let mut input = PROTOCOL_CONSTANT.as_bytes().to_vec();
            input.extend_from_slice(&s.roothash);
            input.extend_from_slice(scid);
            input.extend_from_slice(scid_index.to_string().as_bytes());
            let point = hash_to_point(&hash_to_number(&input));
            G1::add(&smul(&point, &self.s_sk), &smul(&self.u, &c_neg))
        };

        // recompute c and compare
        let c_check = {
            let mut input = to_32_be(&x).to_vec();
            input.extend_from_slice(&a_y.marshal());
            input.extend_from_slice(&a_d.marshal());
            input.extend_from_slice(&a_b.marshal());
            input.extend_from_slice(&a_x.marshal());
            input.extend_from_slice(&a_t.marshal());
            input.extend_from_slice(&a_u.marshal());
            reduced_hash(&input)
        };
        if c_check != self.c {
            return false;
        }

        // --- inner product verification ---
        let o = reduced_hash(&to_32_be(&self.c));
        let u_x = smul(&h, &o);

        let mut h_primes: Vec<G1> = Vec::with_capacity(128);
        let mut h_prime_sum = G1::infinity();
        for i in 0..128 {
            let hp = hs_v[i].scalar_mult(&scalar::inv(&ys[i]).to_bytes_be());
            h_primes.push(hp);
            let tmp = ((&ys[i] * &z) % &order + &two_times_z_squared[i]) % &order;
            h_prime_sum = G1::add(&h_prime_sum, &smul(&h_primes[i], &tmp));
        }

        let mut p_pt = G1::add(&self.ba, &smul(&self.bs, &x));
        p_pt = G1::add(&p_pt, &smul(&gsum(), &neg(&z)));
        p_pt = G1::add(&p_pt, &h_prime_sum);
        p_pt = G1::add(&p_pt, &smul(&h, &neg(&self.mu)));
        p_pt = G1::add(&p_pt, &smul(&u_x, &(&self.that % &order)));

        self.ip.verify(&h_primes, &u_x, &p_pt, &o)
    }

    /// Go: `Proof.Deserialize(r, length)` — inverse of [`Proof::serialize`].
    /// `length` is the ring-size power `m = log2(ring_size)`; the anonymity
    /// vectors are `m` long and `f` is `2m` long.
    pub fn deserialize(r: &mut &[u8], length: usize) -> Result<Proof, &'static str> {
        use crate::read::{take_g1, take_scalar};

        let ba = take_g1(r)?;
        let bs = take_g1(r)?;
        let a = take_g1(r)?;
        let b = take_g1(r)?;

        let mut cln_g = Vec::with_capacity(length);
        let mut crn_g = Vec::with_capacity(length);
        let mut c_0g = Vec::with_capacity(length);
        let mut dg = Vec::with_capacity(length);
        let mut y_0g = Vec::with_capacity(length);
        let mut g_g = Vec::with_capacity(length);
        let mut c_xg = Vec::with_capacity(length);
        let mut y_xg = Vec::with_capacity(length);
        for _ in 0..length {
            cln_g.push(take_g1(r)?);
            crn_g.push(take_g1(r)?);
            c_0g.push(take_g1(r)?);
            dg.push(take_g1(r)?);
            y_0g.push(take_g1(r)?);
            g_g.push(take_g1(r)?);
            c_xg.push(take_g1(r)?);
            y_xg.push(take_g1(r)?);
        }

        let u = take_g1(r)?;

        let mut f_vec = Vec::with_capacity(length * 2);
        for _ in 0..(length * 2) {
            f_vec.push(take_scalar(r)?);
        }
        let f = FieldVector::new(f_vec);

        let z_a = take_scalar(r)?;
        let t_1 = take_g1(r)?;
        let t_2 = take_g1(r)?;
        let that = take_scalar(r)?;
        let mu = take_scalar(r)?;
        let c = take_scalar(r)?;
        let s_sk = take_scalar(r)?;
        let s_r = take_scalar(r)?;
        let s_b = take_scalar(r)?;
        let s_tau = take_scalar(r)?;
        let ip = InnerProduct::deserialize(r)?;

        Ok(Proof {
            ba,
            bs,
            a,
            b,
            cln_g,
            crn_g,
            c_0g,
            dg,
            y_0g,
            g_g,
            c_xg,
            y_xg,
            u,
            f,
            z_a,
            t_1,
            t_2,
            that,
            mu,
            c,
            s_sk,
            s_r,
            s_b,
            s_tau,
            ip,
        })
    }
}

fn marshal_into(input: &mut Vec<u8>, p: &G1) {
    input.extend_from_slice(&p.marshal());
}

/// Go: `assemblepolynomials` — N×2 coefficient matrix from the parity matrix `f`.
fn assemble_polynomials(f: &[[BigUint; 2]], order: &BigUint) -> Vec<[BigUint; 2]> {
    let m = f.len() / 2;
    let n = 1usize << m;
    let mut result = vec![[BigUint::zero(), BigUint::zero()]; n];
    for i in 0..2 {
        let half = recursive_polys(i * m, (i + 1) * m, BigUint::one(), f, order);
        for j in 0..n {
            result[j][i] = half[j].clone();
        }
    }
    result
}

/// Go: `recursivepolynomials` — product polynomial over the `m` parity factors.
fn recursive_polys(
    baseline: usize,
    current: usize,
    accum: BigUint,
    f: &[[BigUint; 2]],
    order: &BigUint,
) -> Vec<BigUint> {
    let size = 1usize << (current - baseline);
    if current == baseline {
        return vec![accum];
    }
    let cur = current - 1;
    let left = recursive_polys(baseline, cur, (&accum * &f[cur][0]) % order, f, order);
    let right = recursive_polys(baseline, cur, (&accum * &f[cur][1]) % order, f, order);
    let mut result = vec![BigUint::zero(); size];
    for i in 0..(size / 2) {
        result[i] = left[i].clone();
        result[i + size / 2] = right[i].clone();
    }
    result
}

/// Go: `GenerateProof`. `rng` supplies the proof nonces in call order.
pub fn generate_proof(
    scid: &[u8; 32],
    scid_index: usize,
    s: &Statement,
    witness: &Witness,
    u: G1,
    txid: &[u8; 32],
    burn_value: u64,
    rng: &mut dyn ScalarRng,
) -> Proof {
    let order = scalar::order();
    let statementhash = reduced_hash(txid);

    // C, Cn ElGamal vectors
    let mut c_eg: Vec<Eg> = Vec::new();
    let mut cn: Vec<Eg> = Vec::new();
    for i in 0..s.c.len() {
        c_eg.push(Eg::new(Some(s.c[i]), s.d));
        cn.push(Eg::new(Some(s.cln[i]), s.crn[i]));
    }

    // number = transfer + balance<<64 ; 128-bit range
    let number =
        BigUint::from(witness.transfer_amount) + (BigUint::from(witness.balance) << 64u32);
    let mut al_v = Vec::with_capacity(128);
    let mut ar_v = Vec::with_capacity(128);
    for i in 0..128u32 {
        let bit = (&number >> i) & BigUint::one();
        if bit.is_one() {
            al_v.push(BigUint::one());
            ar_v.push(BigUint::zero());
        } else {
            al_v.push(BigUint::zero());
            ar_v.push(&order - BigUint::one());
        }
    }
    let al = FieldVector::new(al_v);
    let ar = FieldVector::new(ar_v);

    let (ba, r_ba) = pvc_commit(&al, &ar, rng);
    let sl = fill_random(128, rng);
    let sr = fill_random(128, rng);
    let (bs, r_bs) = pvc_commit(&sl, &sr, rng);

    let n = s.publickeylist.len();
    let m = (n as f64).log2() as usize;

    // aa vector (length 2m), aa[0]=aa[m]=0, else random
    let mut aa_v = Vec::with_capacity(2 * m);
    for i in 0..2 * m {
        if i == 0 || i == m {
            aa_v.push(BigUint::zero());
        } else {
            aa_v.push(rng.next_scalar());
        }
    }

    // witness_index bit string: reverse( bin_m(Index[1]) ‖ bin_m(Index[0]) )
    let wi = witness_index_bits(witness.index[1], witness.index[0], m);
    let mut ba_v = Vec::with_capacity(2 * m);
    let mut bspecial_v = Vec::with_capacity(2 * m);
    for ch in wi.chars() {
        if ch == '1' {
            ba_v.push(BigUint::one());
            bspecial_v.push(&order - BigUint::one());
        } else {
            ba_v.push(BigUint::zero());
            bspecial_v.push(BigUint::one());
        }
    }
    let a = FieldVector::new(aa_v);
    let b = FieldVector::new(ba_v);
    let bspecial = FieldVector::new(bspecial_v);

    let c_vec = a.hadamard(&bspecial);
    let d_vec = a.hadamard(&a).negate();
    let e_vec = FieldVector::new(vec![
        scalar::mul(&a.vector[0], &a.vector[m]),
        scalar::mul(&a.vector[0], &a.vector[m]),
    ]);
    let bit = |x: &BigUint| -> usize { if x.is_one() { 1 } else { 0 } };
    let second = scalar::neg(&a.vector[bit(&b.vector[m]) * m]);
    let f_vec = FieldVector::new(vec![a.vector[bit(&b.vector[0]) * m].clone(), second]);

    let (a_pt, r_a) = pvc_commit(&a, &d_vec.concat(&e_vec), rng);
    let (b_pt, r_b) = pvc_commit(&b, &c_vec.concat(&f_vec), rng);

    // challenge v
    let v = {
        let mut input = to_32_be(&statementhash).to_vec();
        marshal_into(&mut input, &ba);
        marshal_into(&mut input, &bs);
        marshal_into(&mut input, &a_pt);
        marshal_into(&mut input, &b_pt);
        reduced_hash(&input)
    };

    // P, Q matrices via RecursivePolynomials then transpose
    let pi = recursive_polynomials(&a.vector[0..m], &b.vector[0..m]);
    let qi = recursive_polynomials(&a.vector[m..2 * m], &b.vector[m..2 * m]);
    let p_mat = transpose_polynomials(&pi, m);
    let q_mat = transpose_polynomials(&qi, m);

    // phi, chi, psi ElGamal vectors (m each) under sender pubkey
    let sender_pk = &s.publickeylist[witness.index[0]];
    let mut phi = Vec::with_capacity(m);
    let mut chi = Vec::with_capacity(m);
    let mut psi = Vec::with_capacity(m);
    let mut chi_r = Vec::with_capacity(m);
    let mut psi_r = Vec::with_capacity(m);
    for _ in 0..m {
        let (e, _) = commit_elgamal(sender_pk, &BigUint::zero(), rng);
        phi.push(e);
        let (e, rr) = commit_elgamal(sender_pk, &BigUint::zero(), rng);
        chi.push(e);
        chi_r.push(rr);
        let (e, rr) = commit_elgamal(sender_pk, &BigUint::zero(), rng);
        psi.push(e);
        psi_r.push(rr);
    }

    // CnG, C_0G, y_0G
    let mut cn_g: Vec<Eg> = Vec::new();
    let mut c_0g: Vec<Eg> = Vec::new();
    let mut y_0g: Vec<Eg> = Vec::new();
    for i in 0..m {
        // Cn.MultiExponentiate(P[i]).Add(phi[i])
        let mut acc = Eg::new(Some(G1::infinity()), G1::infinity());
        for (j, item) in cn.iter().enumerate() {
            acc = acc.add(&item.mul(&p_mat[i][j]));
        }
        cn_g.push(acc.add(&phi[i]));

        // C_0G: left = (Σ C[j].Left·P[i][j]) + chi[i].Left ; right = chi[i].Right
        let mut left = G1::infinity();
        for (j, item) in c_eg.iter().enumerate() {
            left = G1::add(&left, &smul(&item.left.unwrap(), &p_mat[i][j]));
        }
        left = G1::add(&left, &chi[i].left.unwrap());
        c_0g.push(Eg::new(Some(left), chi[i].right));

        // y_0G: left = (Σ pubkey[j]·P[i][j]) + psi[i].Left ; right = psi[i].Right
        let mut left = G1::infinity();
        for (j, pk) in s.publickeylist.iter().enumerate() {
            left = G1::add(&left, &smul(pk, &p_mat[i][j]));
        }
        left = G1::add(&left, &psi[i].left.unwrap());
        y_0g.push(Eg::new(Some(left), psi[i].right));
    }

    // C_XG accumulation across the ring
    let mut c_xg: Vec<Eg> = Vec::new();
    for _ in 0..m {
        let (e, _) = commit_elgamal(&c_eg[0].right, &BigUint::zero(), rng);
        c_xg.push(e);
    }
    let mut v_pow = BigUint::one();
    for i in 0..n {
        let poly = if i % 2 == 0 { &p_mat } else { &q_mat };
        for j in 0..c_xg.len() {
            let amount = BigUint::from(witness.transfer_amount);
            let amount_neg = scalar::neg(&amount);
            let amount_fees = BigUint::from(s.fees + burn_value);
            let left_s = scalar::sub(&amount_neg, &amount_fees);
            let idx_s = (witness.index[0] + n - (i - i % 2)) % n;
            let idx_r = (witness.index[1] + n - (i - i % 2)) % n;
            let left = scalar::mul(&left_s, &poly[j][idx_s]);
            let right = scalar::mul(&amount, &poly[j][idx_r]);
            let joined = scalar::add(&left, &right);
            let mul = scalar::mul(&v_pow, &joined);
            c_xg[j] = c_xg[j].plus(&mul);
        }
        if i != 0 {
            v_pow = scalar::mul(&v_pow, &v);
        }
    }

    // assemble proof arrays
    let mut p_cln = Vec::new();
    let mut p_crn = Vec::new();
    let mut p_c0 = Vec::new();
    let mut p_dg = Vec::new();
    let mut p_y0 = Vec::new();
    let mut p_gg = Vec::new();
    let mut p_cx = Vec::new();
    let mut p_yx = Vec::new();
    for i in 0..m {
        p_cx.push(c_xg[i].left.unwrap());
        p_yx.push(c_xg[i].right);
        p_cln.push(cn_g[i].left.unwrap());
        p_crn.push(cn_g[i].right);
        p_c0.push(c_0g[i].left.unwrap());
        p_dg.push(c_0g[i].right);
        p_y0.push(y_0g[i].left.unwrap());
        p_gg.push(y_0g[i].right);
    }

    // challenge w (hashmash1): sequential loops
    let w = {
        let mut input = to_32_be(&v).to_vec();
        for p in &p_cln { marshal_into(&mut input, p); }
        for p in &p_crn { marshal_into(&mut input, p); }
        for p in &p_c0 { marshal_into(&mut input, p); }
        for p in &p_dg { marshal_into(&mut input, p); }
        for p in &p_y0 { marshal_into(&mut input, p); }
        for p in &p_gg { marshal_into(&mut input, p); }
        for p in &p_cx { marshal_into(&mut input, p); }
        for p in &p_yx { marshal_into(&mut input, p); }
        reduced_hash(&input)
    };

    let f_proof = b.times(&w).add(&a);
    let z_a = scalar::add(&scalar::mul(&r_b, &w), &r_a);

    // y, ys
    let y = reduced_hash(&to_32_be(&w));
    let mut ys_v = vec![BigUint::one()];
    for i in 1..128 {
        ys_v.push(scalar::mul(&ys_v[i - 1], &y));
    }
    let ys = FieldVector::new(ys_v);

    // z, zs, twoTimesZs
    let z = reduced_hash(&to_32_be(&y));
    let zs = [
        z.modpow(&BigUint::from(2u32), &order),
        z.modpow(&BigUint::from(3u32), &order),
    ];
    let mut twos = vec![BigUint::one()];
    for i in 1..64 {
        twos.push(scalar::mul(&twos[i - 1], &BigUint::from(2u32)));
    }
    let mut two_times_zs = Vec::with_capacity(128);
    for zi in &zs {
        for tj in &twos {
            two_times_zs.push(scalar::mul(zi, tj));
        }
    }

    // l(X), r(X) polynomials
    let l_tmp = al.add_constant(&scalar::neg(&z));
    let l_poly = FieldVectorPolynomial::new(vec![l_tmp, sl.clone()]);
    let r0 = ys
        .hadamard(&ar.add_constant(&z))
        .add(&FieldVector::new(two_times_zs.clone()));
    let r1 = sr.hadamard(&ys);
    let r_poly = FieldVectorPolynomial::new(vec![r0, r1]);

    let t_poly = l_poly.inner_product(&r_poly); // length 3

    let (t_1, r_t1) = pc_commit(&t_poly[1], rng);
    let (t_2, r_t2) = pc_commit(&t_poly[2], rng);

    // challenge x
    let x = {
        let mut input = to_32_be(&z).to_vec();
        marshal_into(&mut input, &t_1);
        marshal_into(&mut input, &t_2);
        reduced_hash(&input)
    };
    let xsquare = scalar::mul(&x, &x);

    let that = scalar::add(
        &scalar::add(&t_poly[0], &scalar::mul(&t_poly[1], &x)),
        &scalar::mul(&t_poly[2], &xsquare),
    );

    let tau_x = scalar::add(&scalar::mul(&r_t1, &x), &scalar::mul(&r_t2, &xsquare));
    let mu = scalar::add(&scalar::mul(&r_bs, &x), &r_ba);

    // anonymity-aggregation: CnR, chi_bigint, psi_bigint, C_XR, p, q
    let mut cn_r = Eg::new(None, G1::infinity());
    let mut chi_bigint = BigUint::zero();
    let mut psi_bigint = BigUint::zero();
    let mut c_xr = Eg::new(None, G1::infinity());
    let mut p_vec = FieldVector::new(vec![BigUint::zero(); n]);
    let mut q_vec = FieldVector::new(vec![BigUint::zero(); n]);
    let mut w_pow = BigUint::one();
    for i in 0..m {
        cn_r = cn_r.add(&phi[i].neg().mul(&w_pow));
        chi_bigint = scalar::add(&chi_bigint, &scalar::mul(&chi_r[i], &w_pow));
        psi_bigint = scalar::add(&psi_bigint, &scalar::mul(&psi_r[i], &w_pow));
        c_xr = c_xr.add(&c_xg[i].neg().mul(&w_pow));
        p_vec = p_vec.add(&FieldVector::new(p_mat[i].clone()).times(&w_pow));
        q_vec = q_vec.add(&FieldVector::new(q_mat[i].clone()).times(&w_pow));
        w_pow = scalar::mul(&w_pow, &w);
    }
    cn_r = cn_r.add(&cn[witness.index[0]].mul(&w_pow));

    let dr = {
        let a1 = smul(&c_eg[0].right, &w_pow);
        G1::add(&a1, &smul(&base_g(), &scalar::neg(&chi_bigint)))
    };
    let g_r = smul(&base_g(), &scalar::sub(&w_pow, &psi_bigint));

    // p__, q__: wPow at sender/receiver index
    let mut p2 = vec![BigUint::zero(); n];
    let mut q2 = vec![BigUint::zero(); n];
    p2[witness.index[0]] = w_pow.clone();
    q2[witness.index[1]] = w_pow.clone();
    p_vec = p_vec.add(&FieldVector::new(p2));
    q_vec = q_vec.add(&FieldVector::new(q2));

    let pubkey_pv = crate::point_vector::PointVector::new(s.publickeylist.clone());
    let y_p = crate::point_vector::convolution(&p_vec, &pubkey_pv);
    let y_q = crate::point_vector::convolution(&q_vec, &pubkey_pv);

    let mut y_xr = G1::infinity();
    let mut v_pow2 = BigUint::one();
    for i in 0..n {
        let ypoly = if i % 2 == 1 { &y_q } else { &y_p };
        y_xr = G1::add(&y_xr, &smul(ypoly.element(i / 2), &v_pow2));
        c_xr = c_xr.add(&Eg::new(None, smul(ypoly.element(i / 2), &v_pow2)));
        if i > 0 {
            v_pow2 = scalar::mul(&v_pow2, &v);
        }
    }

    // sigma protocol
    let k_sk = rng.next_scalar();
    let k_r = rng.next_scalar();
    let k_b = rng.next_scalar();
    let k_tau = rng.next_scalar();

    let a_y = smul(&g_r, &k_sk);
    let a_d = smul(&base_g(), &k_r);
    let mut a_b = smul(&base_g(), &k_b);
    let t1p = smul(&cn_r.right, &zs[1]);
    let mut d1 = smul(&dr, &scalar::neg(&zs[0]));
    d1 = G1::add(&d1, &t1p);
    d1 = smul(&d1, &k_sk);
    a_b = G1::add(&a_b, &d1);

    let a_x = smul(&c_xr.right, &k_r);

    let mut a_t = smul(&base_g(), &scalar::neg(&k_b));
    a_t = G1::add(&a_t, &smul(&base_h(), &k_tau));

    let a_u = {
        let mut input = PROTOCOL_CONSTANT.as_bytes().to_vec();
        input.extend_from_slice(&s.roothash);
        input.extend_from_slice(scid);
        input.extend_from_slice(scid_index.to_string().as_bytes());
        let point = hash_to_point(&hash_to_number(&input));
        smul(&point, &k_sk)
    };

    let c = {
        let mut input = to_32_be(&x).to_vec();
        marshal_into(&mut input, &a_y);
        marshal_into(&mut input, &a_d);
        marshal_into(&mut input, &a_b);
        marshal_into(&mut input, &a_x);
        marshal_into(&mut input, &a_t);
        marshal_into(&mut input, &a_u);
        reduced_hash(&input)
    };

    let s_sk = scalar::add(&scalar::mul(&c, &witness.secret_key), &k_sk);
    let s_r = scalar::add(&scalar::mul(&c, &witness.r), &k_r);

    let w_transfer = scalar::mul(&BigUint::from(witness.transfer_amount), &zs[0]);
    let w_balance = scalar::mul(&BigUint::from(witness.balance), &zs[1]);
    let mut w_tmp = scalar::add(&w_transfer, &w_balance);
    w_tmp = scalar::mul(&w_tmp, &w_pow);
    w_tmp = scalar::mul(&w_tmp, &c);
    let s_b = scalar::add(&w_tmp, &k_b);

    let mut s_tau = scalar::mul(&tau_x, &w_pow);
    s_tau = scalar::mul(&s_tau, &c);
    s_tau = scalar::add(&s_tau, &k_tau);

    // inner product (the "New" variant == our IPA::generate)
    let o = reduced_hash(&to_32_be(&c));
    let u_h = smul(&base_h(), &o);
    let ys_inv = ys.invert();
    let hs_prime: Vec<G1> = (0..ys.vector.len())
        .map(|i| smul(&hs(i), &ys_inv.vector[i]))
        .collect();
    let gs_full: Vec<G1> = (0..ys.vector.len()).map(gs).collect();
    let gvalues = l_poly.evaluate(&x);
    let hvalues = r_poly.evaluate(&x);
    let ip = InnerProduct::generate(
        &crate::point_vector::PointVector::new(gs_full),
        &crate::point_vector::PointVector::new(hs_prime),
        &u_h,
        &gvalues,
        &hvalues,
        &o,
    );

    Proof {
        ba,
        bs,
        a: a_pt,
        b: b_pt,
        cln_g: p_cln,
        crn_g: p_crn,
        c_0g: p_c0,
        dg: p_dg,
        y_0g: p_y0,
        g_g: p_gg,
        c_xg: p_cx,
        y_xg: p_yx,
        u,
        f: f_proof,
        z_a,
        t_1,
        t_2,
        that,
        mu,
        c,
        s_sk,
        s_r,
        s_b,
        s_tau,
        ip,
    }
}

fn fill_random(n: usize, rng: &mut dyn ScalarRng) -> FieldVector {
    FieldVector::new((0..n).map(|_| rng.next_scalar()).collect())
}

/// witness_index = reverse( bin_m(idx1) ‖ bin_m(idx0) ), each zero-padded to m bits.
fn witness_index_bits(idx1: usize, idx0: usize, m: usize) -> String {
    let s = format!("{:0width$b}{:0width$b}", idx1, idx0, width = m);
    s.chars().rev().collect()
}
