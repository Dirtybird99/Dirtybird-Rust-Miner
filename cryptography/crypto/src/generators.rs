//! Deterministic generators. Port of the `init()` in `algebra_pedersen.go` and
//! `NewGeneratorParams` in `generatorparams.go`.
//!
//! - `G = H2P(HtN("DERO"+"G"))`, the base point for public keys.
//! - `H = H2P(HtN("DERO"+"H"))`.
//! - `Gs[i] = H2P(HtN("DERO"+"G" ‖ be32(i)))`, `Hs[i]` similarly, for i in 0..N.
//!
//! Computed once and cached. The default vector commitment uses 128 generators.

use crate::hashtopoint::{hash_to_number, hash_to_point, to_32_be, PROTOCOL_CONSTANT};
use dero_bn256::G1;
use num_bigint::BigUint;
use std::sync::OnceLock;

/// Number of generators in the default Pedersen vector commitment.
pub const GENERATOR_COUNT: usize = 128;

struct Generators {
    g: G1,
    h: G1,
    gs: Vec<G1>,
    hs: Vec<G1>,
    gsum: G1,
}

static GENERATORS: OnceLock<Generators> = OnceLock::new();

fn indexed_seed(label: &str, i: usize) -> BigUint {
    // Go: append("DERO"+label, hextobytes(makestring64(fmt.Sprintf("%x", i)))...)
    // == ascii("DERO"+label) ‖ be32(i)
    let mut input = format!("{PROTOCOL_CONSTANT}{label}").into_bytes();
    input.extend_from_slice(&to_32_be(&BigUint::from(i)));
    hash_to_number(&input)
}

fn compute() -> Generators {
    let g = hash_to_point(&hash_to_number(format!("{PROTOCOL_CONSTANT}G").as_bytes()));
    let h = hash_to_point(&hash_to_number(format!("{PROTOCOL_CONSTANT}H").as_bytes()));

    let mut gs = Vec::with_capacity(GENERATOR_COUNT);
    let mut hs = Vec::with_capacity(GENERATOR_COUNT);
    let mut gsum = G1::infinity();
    for i in 0..GENERATOR_COUNT {
        let gi = hash_to_point(&indexed_seed("G", i));
        let hi = hash_to_point(&indexed_seed("H", i));
        gsum = G1::add(&gsum, &gi);
        gs.push(gi);
        hs.push(hi);
    }
    Generators { g, h, gs, hs, gsum }
}

fn generators() -> &'static Generators {
    GENERATORS.get_or_init(compute)
}

/// The base point `G` (used for public-key derivation).
pub fn base_g() -> G1 {
    generators().g
}

/// The secondary generator `H`.
pub fn base_h() -> G1 {
    generators().h
}

/// `Gs[i]` (panics if i >= GENERATOR_COUNT).
pub fn gs(i: usize) -> G1 {
    generators().gs[i]
}

/// `Hs[i]` (panics if i >= GENERATOR_COUNT).
pub fn hs(i: usize) -> G1 {
    generators().hs[i]
}

/// All `Gs`.
pub fn gs_all() -> &'static [G1] {
    &generators().gs
}

/// All `Hs`.
pub fn hs_all() -> &'static [G1] {
    &generators().hs
}

/// Sum of all `Gs` (Go: `GSUM`).
pub fn gsum() -> G1 {
    generators().gsum
}

/// Go: `GeneratorParams.Commit(blind, gexps, hexps)` —
/// `H·blind + Σ Gs[i]·gexps[i] + Σ Hs[i]·hexps[i]`.
pub fn pedersen_commit(
    blind: &num_bigint::BigUint,
    gexps: &crate::field_vector::FieldVector,
    hexps: Option<&crate::field_vector::FieldVector>,
) -> G1 {
    let g = generators();
    let mut result = g.h.scalar_mult(&(blind % crate::scalar::order()).to_bytes_be());
    for i in 0..gexps.vector.len() {
        let e = &gexps.vector[i] % crate::scalar::order();
        result = G1::add(&result, &g.gs[i].scalar_mult(&e.to_bytes_be()));
    }
    if let Some(hexps) = hexps {
        for i in 0..hexps.vector.len() {
            let e = &hexps.vector[i] % crate::scalar::order();
            result = G1::add(&result, &g.hs[i].scalar_mult(&e.to_bytes_be()));
        }
    }
    result
}
