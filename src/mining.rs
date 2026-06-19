//! Mining coordinator: worker threads hash nonces (2-way batched) and stage valid shares.
use crate::difficulty::check_hash;
use crate::state::{MinerState, BLOB_LEN, NONCE_OFFSET, THREAD_ID_OFFSET};
use crate::{hash2, sys, Reglut, Worker};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

#[inline]
fn write_nonce(blob: &mut [u8; BLOB_LEN], nonce: u32) {
    blob[NONCE_OFFSET] = (nonce >> 24) as u8;
    blob[NONCE_OFFSET + 1] = (nonce >> 16) as u8;
    blob[NONCE_OFFSET + 2] = (nonce >> 8) as u8;
    blob[NONCE_OFFSET + 3] = nonce as u8;
}

fn worker(state: Arc<MinerState>, reglut: Arc<Reglut>, tid: usize, core: Option<usize>) {
    if let Some(c) = core {
        sys::pin_and_boost(c);
    }
    let mut w0 = Worker::new();
    let mut w1 = Worker::new();
    let mut local: u64 = 0;

    while !state.quit.load(Ordering::Relaxed) {
        let (job, epoch) = match state.snapshot() {
            Some(s) => s,
            None => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let mut blob0 = job.blob;
        let mut blob1 = job.blob;
        blob0[THREAD_ID_OFFSET] = tid as u8;
        blob1[THREAD_ID_OFFSET] = tid as u8;
        let mut nonce: u32 = (tid as u32) << 24;

        loop {
            if nonce & 127 == 0
                && (state.quit.load(Ordering::Relaxed)
                    || !state.connected.load(Ordering::Relaxed)
                    || state.epoch.load(Ordering::Acquire) != epoch)
            {
                break;
            }
            let n1 = nonce.wrapping_add(1);
            let n2 = nonce.wrapping_add(2);
            nonce = nonce.wrapping_add(2);
            write_nonce(&mut blob0, n1);
            write_nonce(&mut blob1, n2);

            let (h0, h1) = hash2(&blob0, &blob1, &mut w0, &mut w1, &reglut);
            if check_hash(&h0, &job.target) {
                state.stage_share(job.jobid.clone(), blob0, epoch);
            }
            if check_hash(&h1, &job.target) {
                state.stage_share(job.jobid.clone(), blob1, epoch);
            }

            local += 2;
            if local & 63 == 0 {
                state.total_hashes.fetch_add(64, Ordering::Relaxed);
            }
        }
    }
}

/// Spawn `threads` worker threads. Returns their join handles.
pub fn spawn_workers(state: Arc<MinerState>, threads: usize, affinity: bool) -> Vec<JoinHandle<()>> {
    let reglut = Arc::new(Reglut::new());
    if affinity {
        sys::process_high_priority();
    }
    let order = sys::affinity_order(threads);
    (0..threads)
        .map(|tid| {
            let state = state.clone();
            let reglut = reglut.clone();
            let core = if affinity { Some(order[tid]) } else { None };
            std::thread::spawn(move || worker(state, reglut, tid, core))
        })
        .collect()
}
