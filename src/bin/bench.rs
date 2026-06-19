//! Synthetic hashrate benchmark (no network), mirroring the Zig `bench` harness so
//! baselines are measured under matching conditions.
//!   bench [threads] [seconds] [affinity 0|1]
//! Each thread hashes a 48-byte blob with a rolling nonce (mining-realistic), counts
//! hashes, and the harness reports aggregate H/s.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dero_miner::{hash, hash2, Reglut, Worker};

// Match the Zig reference's sustained-clock setup: HIGH process priority + per-thread
// highest priority + power-throttling disabled (stops the OS downclocking mining threads).
// Windows-only; on other platforms the affinity/priority calls below are no-ops.
#[cfg(windows)]
mod win {
    use std::os::raw::c_void;
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetCurrentThread() -> isize;
        fn SetPriorityClass(h: isize, class: u32) -> i32;
        fn SetThreadPriority(h: isize, prio: i32) -> i32;
        fn SetThreadInformation(h: isize, class: i32, info: *const c_void, size: u32) -> i32;
    }
    const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
    const THREAD_PRIORITY_HIGHEST: i32 = 2;
    const THREAD_POWER_THROTTLING: i32 = 4;

    #[repr(C)]
    struct PowerThrottlingState {
        version: u32,
        control_mask: u32,
        state_mask: u32,
    }

    pub fn process_high_priority() {
        unsafe {
            SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        }
    }

    pub fn thread_max_perf() {
        unsafe {
            let t = GetCurrentThread();
            SetThreadPriority(t, THREAD_PRIORITY_HIGHEST);
            // version=1, control_mask=EXECUTION_SPEED(1), state_mask=0 => throttling OFF.
            let st = PowerThrottlingState { version: 1, control_mask: 1, state_mask: 0 };
            SetThreadInformation(
                t,
                THREAD_POWER_THROTTLING,
                &st as *const _ as *const c_void,
                std::mem::size_of::<PowerThrottlingState>() as u32,
            );
        }
    }
}

/// P-core-first, E-cores next, HT-siblings last — i7-13700HX logical-id order
/// (per the Zig optimization log: +12% over the OS scheduler; HT packing is ~25% worse).
fn affinity_order(n: usize) -> Vec<usize> {
    let pcores = [0usize, 2, 4, 6, 8, 10, 12, 14];
    let ecores = [16usize, 17, 18, 19, 20, 21, 22, 23];
    let ht = [1usize, 3, 5, 7, 9, 11, 13, 15];
    let mut order = Vec::new();
    order.extend_from_slice(&pcores);
    order.extend_from_slice(&ecores);
    order.extend_from_slice(&ht);
    let mut i = 0;
    while order.len() < n {
        order.push(order[i % order.len().max(1)]);
        i += 1;
    }
    order.truncate(n.max(1));
    order
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let threads: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let seconds: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
    let affinity: bool = args.get(3).map(|s| s == "1").unwrap_or(true);
    // SHA mode: 2 = 2-way batched (default, the miner's path); 1 = 1-way (matches the
    // Zig bench's pow.hash, for apples-to-apples per-hash compute comparison).
    let two_way: bool = args.get(4).map(|s| s != "1").unwrap_or(true);

    let reglut = Arc::new(Reglut::new());
    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let order = affinity_order(threads);

    if affinity {
        #[cfg(windows)]
        win::process_high_priority();
    }
    println!("dero-miner bench: threads={threads} seconds={seconds} affinity={affinity}");

    let start = Instant::now();
    let mut handles = Vec::new();
    for t in 0..threads {
        let reglut = reglut.clone();
        let stop = stop.clone();
        let total = total.clone();
        let core = order[t];
        handles.push(std::thread::spawn(move || {
            if affinity {
                let ids = core_affinity::get_core_ids().unwrap_or_default();
                if let Some(id) = ids.iter().find(|c| c.id == core).copied() {
                    core_affinity::set_for_current(id);
                }
                #[cfg(windows)]
                win::thread_max_perf();
            }
            let mut w0 = Worker::new();
            let mut w1 = Worker::new();
            // Match the Zig bench: per-thread RANDOM 48-byte blobs (input content drives
            // wolf output length → SA work, so a fair comparison needs the same distribution).
            let mut in0 = [0u8; 48];
            let mut in1 = [0u8; 48];
            let mut s = 12345u64.wrapping_add(t as u64).wrapping_mul(0x2545f4914f6cdd1d) | 1;
            for b in in0.iter_mut().chain(in1.iter_mut()) {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *b = s as u8;
            }
            let mut nonce: u64 = 0;
            let mut count: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                in0[8..16].copy_from_slice(&nonce.to_le_bytes());
                if two_way {
                    in1[8..16].copy_from_slice(&nonce.wrapping_add(0x9e3779b97f4a7c15).to_le_bytes());
                    let _ = hash2(&in0, &in1, &mut w0, &mut w1, &reglut);
                    count += 2;
                } else {
                    let _ = hash(&in0, &mut w0, &reglut);
                    count += 1;
                }
                nonce = nonce.wrapping_add(1);
            }
            total.fetch_add(count, Ordering::Relaxed);
        }));
    }

    std::thread::sleep(Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    let elapsed = start.elapsed().as_secs_f64();
    let hashes = total.load(Ordering::Relaxed);
    let hs = hashes as f64 / elapsed;
    println!("hashes={hashes} elapsed={elapsed:.2}s");
    println!("HASHRATE {:.0} H/s  ({:.3} KH/s)", hs, hs / 1000.0);
}
