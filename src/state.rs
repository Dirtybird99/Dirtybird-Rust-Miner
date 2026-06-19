//! Shared miner state: the job mailbox (network thread → workers), the share channel
//! (workers → network thread), and the live counters (port of state.zig).
use crossbeam::channel::{unbounded, Receiver, Sender};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

pub const BLOB_LEN: usize = 48;
pub const NONCE_OFFSET: usize = 43; // big-endian u32 at [43..47)
pub const THREAD_ID_OFFSET: usize = 47;

#[derive(Clone)]
pub struct Job {
    pub blob: [u8; BLOB_LEN],
    pub jobid: String,
    pub target: [u8; 32],
    pub difficulty: u64,
    pub height: i64,
}

pub struct Share {
    pub jobid: String,
    pub blob: [u8; BLOB_LEN],
    pub epoch: u64,
}

pub struct MinerState {
    job: Mutex<Option<Job>>,
    pub epoch: AtomicU64,
    pub connected: AtomicBool,
    pub quit: AtomicBool,
    pub total_hashes: AtomicU64,
    pub miniblocks: AtomicI64,
    pub blocks: AtomicI64,
    pub rejected: AtomicI64,
    pub submitted: AtomicU64,
    pub stale_drops: AtomicU64,
    tx: Sender<Share>,
    rx: Receiver<Share>,
}

impl MinerState {
    pub fn new() -> Self {
        let (tx, rx) = unbounded();
        MinerState {
            job: Mutex::new(None),
            epoch: AtomicU64::new(0),
            connected: AtomicBool::new(false),
            quit: AtomicBool::new(false),
            total_hashes: AtomicU64::new(0),
            miniblocks: AtomicI64::new(0),
            blocks: AtomicI64::new(0),
            rejected: AtomicI64::new(0),
            submitted: AtomicU64::new(0),
            stale_drops: AtomicU64::new(0),
            tx,
            rx,
        }
    }

    /// Install a new job; bumps the epoch only if it actually changed. Returns true if changed.
    pub fn set_job(&self, job: Job) -> bool {
        let mut g = self.job.lock();
        let changed = match &*g {
            Some(j) => {
                j.jobid != job.jobid
                    || j.blob != job.blob
                    || j.height != job.height
                    || j.difficulty != job.difficulty
            }
            None => true,
        };
        *g = Some(job);
        drop(g);
        if changed {
            self.epoch.fetch_add(1, Ordering::Release);
        }
        changed
    }

    /// Snapshot the current job + its epoch (workers call this at the top of each outer loop).
    pub fn snapshot(&self) -> Option<(Job, u64)> {
        let g = self.job.lock();
        g.clone().map(|j| (j, self.epoch.load(Ordering::Acquire)))
    }

    pub fn stage_share(&self, jobid: String, blob: [u8; BLOB_LEN], epoch: u64) {
        let _ = self.tx.send(Share { jobid, blob, epoch });
    }

    /// Drain one staged share, dropping it if its epoch is stale.
    pub fn take_share(&self) -> Option<Share> {
        while let Ok(s) = self.rx.try_recv() {
            if s.epoch == self.epoch.load(Ordering::Acquire) {
                return Some(s);
            }
            self.stale_drops.fetch_add(1, Ordering::Relaxed);
        }
        None
    }
}

impl Default for MinerState {
    fn default() -> Self {
        Self::new()
    }
}
