//! Per-stage profiler: localizes where per-hash time goes (full vs wolf vs SA vs final SHA).
use std::time::Instant;

use dero_miner::primitives::{fnv1a, salsa20_expand};
use dero_miner::sha_hw::{sha256, sha256_2x};
use dero_miner::{hash, sa, Reglut, Worker};

fn main() {
    // Pin to a P-core so the absolute stage times match the single-thread bench.
    if let Some(id) = core_affinity::get_core_ids().unwrap_or_default().iter().find(|c| c.id == 0).copied() {
        core_affinity::set_for_current(id);
    }
    let iters = 1000u32;
    let reglut = Reglut::new();
    let mut w = Worker::new();
    let mut input = [0u8; 48];

    // Full pipeline.
    let t = Instant::now();
    for i in 0..iters {
        input[8..16].copy_from_slice(&(i as u64).to_le_bytes());
        std::hint::black_box(hash(&input, &mut w, &reglut));
    }
    let full = t.elapsed().as_secs_f64() / iters as f64;

    // Stages 1–5 (through wolfCompute), no SA / final SHA.
    let t = Instant::now();
    for i in 0..iters {
        input[8..16].copy_from_slice(&(i as u64).to_le_bytes());
        let key = sha256(&input);
        let mut block = [0u8; 256];
        salsa20_expand(&key, &mut block);
        w.key.set_key(&block);
        w.key.process(&mut block);
        w.lhash = fnv1a(&block);
        w.prev_lhash = w.lhash;
        w.s_data[0..256].copy_from_slice(&block);
        w.wolf_compute(&reglut);
        std::hint::black_box(w.data_len);
    }
    let wolf = t.elapsed().as_secs_f64() / iters as f64;

    // SA alone (reuse the last wolf output repeatedly).
    let n = w.data_len as usize;
    for b in &mut w.s_data[n..n + 16] {
        *b = 0;
    }
    let markers = w.template_markers;
    let nt = w.n_templates;
    let t = Instant::now();
    for _ in 0..iters {
        sa::build_sa(&w.s_data, w.data_len, &markers, nt, &mut w.sa);
    }
    let sa_t = t.elapsed().as_secs_f64() / iters as f64;

    // Final SHA alone (1-way SHA-NI, over the SA bytes).
    let t = Instant::now();
    for _ in 0..iters {
        let sb = unsafe { std::slice::from_raw_parts(w.sa.as_ptr() as *const u8, n * 4) };
        std::hint::black_box(sha256(sb));
    }
    let fsha = t.elapsed().as_secs_f64() / iters as f64;

    // 2-way SHA-NI, per message.
    let t = Instant::now();
    for _ in 0..iters {
        let sb = unsafe { std::slice::from_raw_parts(w.sa.as_ptr() as *const u8, n * 4) };
        std::hint::black_box(sha256_2x(sb, sb));
    }
    let fsha2 = t.elapsed().as_secs_f64() / iters as f64 / 2.0;

    let ms = |s: f64| s * 1e3;
    println!("data_len={n}");
    println!("full(1way)= {:.3} ms  ({:.0} H/s/thread)", ms(full), 1.0 / full);
    println!("wolf(1-5) = {:.3} ms  ({:.1}%)", ms(wolf), 100.0 * wolf / full);
    println!("SA        = {:.3} ms  ({:.1}%)", ms(sa_t), 100.0 * sa_t / full);
    println!("finalSHA  = {:.3} ms  (1-way)", ms(fsha));
    println!("finalSHA2 = {:.3} ms/msg  (2-way, saves {:.3} ms)", ms(fsha2), ms(fsha - fsha2));
}
