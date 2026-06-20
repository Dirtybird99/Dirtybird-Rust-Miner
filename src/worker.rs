//! The mining loop — port of `mineblock()` (cmd/dero-miner/miner.go:453-541)
//! with byte-exact nonce-mutation semantics (verified vs Go in
//! vectors/minerwork.json, go-harness/minerwork).
//!
//! Per worker thread `tid` (0..threads, threads capped at 255 because the tid
//! lives in one byte):
//!  - once at startup: 12 random bytes (`random_buf`, miner.go:457-459);
//!  - per job snapshot: hex-decode the 96-char blob into the 48-byte `work`
//!    (must decode to exactly 48 bytes, miner.go:479-484); height =
//!    `BE u64(work[0..8]) & 0xffffffffff` (miner.go:486); copy random_buf into
//!    `work[36..48]` (miner.go:488); `work[47] = tid` (miner.go:489); parse
//!    the DECIMAL difficulty string (miner.go:491); version gate
//!    `work[0]&0xf == 1` (miner.go:493-497);
//!  - per iteration while the job is unchanged: `i += 1` (the counter PERSISTS
//!    across jobs, miner.go:471), BE u32 into `work[43..47]` (nonce_buf =
//!    work[48-5..], miner.go:465/502/522 — byte 47 stays tid), PoW (AstroBWTv3
//!    at heights >= MAJOR_HF2_HEIGHT, POW16 below — dead code on today's
//!    mainnet but the branch is kept, miner.go:499-539), and submit on
//!    `CheckPowHashBig(pow, diff)` semantics WITHOUT leaving the loop.
//!
//! Timestamp bytes [1..3] and Flags [32..36] are NEVER touched by the miner.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, RwLock};
use std::time::Duration;

use num_bigint::BigUint;
use num_traits::Zero;

use dero_astrobwt::difficulty::{
    check_pow_hash_precomputed, pow_hash_at_height_with_scratch, precompute_pow_target,
};
use dero_astrobwt::AstroBwtScratch;
use dero_protocol::MINIBLOCK_SIZE;

use crate::job::{GetBlockTemplateResult, SubmitBlockParams};

const HASH_COUNTER_FLUSH_INTERVAL: u64 = 64;

/// Shared miner state — the Go file-scope globals of miner.go:54-72.
pub struct Shared {
    /// Latest job push (miner.go `job`, guarded by `mutex`).
    pub job: RwLock<GetBlockTemplateResult>,
    /// Incremented per received job; workers re-snapshot when it changes
    /// (miner.go `job_counter`).
    pub job_counter: AtomicU64,
    /// Total hashes computed (miner.go `counter`) — feeds the 1 Hz rate line.
    pub counter: AtomicU64,
    /// Session counters mirrored from the last job push (miner.go:438-445).
    pub block_counter: AtomicU64,
    pub mini_block_counter: AtomicU64,
    pub rejected: AtomicU64,
    /// `difficultyuint64` of the last job — displayed as the network hashrate.
    pub hash_rate: AtomicU64,
    pub our_height: AtomicU64,
    /// Set on exit/quit/bye (Go `Exit_In_Progress` channel close).
    pub exit: AtomicBool,
}

impl Shared {
    pub fn new() -> Shared {
        Shared {
            job: RwLock::new(GetBlockTemplateResult::default()),
            job_counter: AtomicU64::new(0),
            counter: AtomicU64::new(0),
            block_counter: AtomicU64::new(0),
            mini_block_counter: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            hash_rate: AtomicU64::new(0),
            our_height: AtomicU64::new(0),
            exit: AtomicBool::new(false),
        }
    }
}

/// Optionally pin worker `tid` to a logical core and/or raise process priority
/// (opt-in; default no-op so the production miner behaves exactly like the Go
/// reference unless asked).
///
/// Activated by environment, mirroring the `--sustained` harness so the winning
/// config can be wired in without changing call sites:
///   * `MINER_HIGHPRIO=1`   — raise the process to HIGH priority (applied once,
///     by worker 0). Measured +~8% sustained on the 13700HX — the single best
///     lever for this latency-bound load. Recommended ON in production.
///   * `MINER_PIN=1`        — pin using [`crate::affinity::recommended_order`]
///     (P-core primaries first, then E-cores, then P HT siblings). On this CPU
///     pinning ties the Windows scheduler within noise at full (24-thread)
///     occupancy, so it is optional; the knob exists for completeness / for
///     under-subscribed runs.
///   * `MINER_PIN_CORES=..` — explicit comma-separated logical-core list; worker
///     `tid` pins to `list[tid % list.len()]`. Overrides `MINER_PIN`.
///
/// None of these change which hashes are computed; they only place threads and
/// set scheduling priority.
fn pin_worker(tid: u8) {
    let tid = tid as usize;

    // Process-wide priority: apply exactly once (worker 0) to avoid redundant
    // syscalls. Off by default; flip on in production for the +~8% win.
    if tid == 0 && std::env::var("MINER_HIGHPRIO").map(|v| v != "0").unwrap_or(false) {
        crate::affinity::set_high_priority();
    }

    if let Ok(spec) = std::env::var("MINER_PIN_CORES") {
        let list: Vec<usize> = spec
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .collect();
        if !list.is_empty() {
            crate::affinity::pin_current_thread(list[tid % list.len()]);
        }
        return;
    }
    if std::env::var("MINER_PIN").map(|v| v != "0").unwrap_or(false) {
        // Size the recommended order to the active CPU count and index by tid.
        let order = crate::affinity::recommended_order(crate::affinity::active_logical_cpus());
        if !order.is_empty() {
            crate::affinity::pin_current_thread(order[tid % order.len()]);
        }
    }
}

fn record_hash(shared: &Shared, pending_hashes: &mut u64) {
    *pending_hashes += 1;
    if *pending_hashes >= HASH_COUNTER_FLUSH_INTERVAL {
        flush_hashes(shared, pending_hashes);
    }
}

fn flush_hashes(shared: &Shared, pending_hashes: &mut u64) {
    if *pending_hashes != 0 {
        shared.counter.fetch_add(*pending_hashes, Ordering::Relaxed);
        *pending_hashes = 0;
    }
}

/// miner.go:486 — `binary.BigEndian.Uint64(work[0:]) & 0x000000ffffffffff`.
pub fn work_height(work: &[u8; MINIBLOCK_SIZE]) -> u64 {
    u64::from_be_bytes(work[0..8].try_into().unwrap()) & 0x0000_00ff_ffff_ffff
}

/// Per-job-snapshot stamp, miner.go:488-489: 12 random bytes into [36..48],
/// then tid into byte 47.
pub fn stamp_job(work: &mut [u8; MINIBLOCK_SIZE], random12: &[u8; 12], tid: u8) {
    work[MINIBLOCK_SIZE - 12..].copy_from_slice(random12);
    work[MINIBLOCK_SIZE - 1] = tid;
}

/// Per-iteration counter, miner.go:465/502: BE u32 into the first 4 bytes of
/// `work[43..48]` — i.e. bytes [43..47]; byte 47 (the tid) is untouched.
pub fn put_counter(work: &mut [u8; MINIBLOCK_SIZE], i: u32) {
    work[MINIBLOCK_SIZE - 5..MINIBLOCK_SIZE - 1].copy_from_slice(&i.to_be_bytes());
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)] // the Bad* prefix mirrors the three Go error logs
pub enum GrindError {
    /// hex decode failed or blob is not exactly 48 bytes (miner.go:479-484).
    BadBlob,
    /// `work[0]&0xf != 1` — Go logs the 0x1f-masked value (miner.go:493-497).
    BadVersion(u8),
    /// Difficulty string did not parse as a decimal big-int, or was zero.
    BadDifficulty,
}

/// One outer-loop pass of `mineblock`: prepare `work` from `job`, then grind
/// until `shared.job_counter` moves away from `local_job_counter` (or exit is
/// flagged). Found shares are handed to `on_share` (the full mutated 48-byte
/// buffer) WITHOUT stopping the grind — exactly Go, which keeps spinning the
/// counter after a submit.
///
/// `i` is the per-thread persistent counter (miner.go:471). `hf2_height`
/// selects the PoW: 481600 mainnet, 4 testnet (config/config.go:108,129).
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub fn grind_job(
    job: &GetBlockTemplateResult,
    local_job_counter: u64,
    shared: &Shared,
    random12: &[u8; 12],
    tid: u8,
    i: &mut u32,
    hf2_height: u64,
    on_share: &mut dyn FnMut(&[u8; MINIBLOCK_SIZE]),
) -> Result<(), GrindError> {
    let mut pow_scratch = AstroBwtScratch::new();
    grind_job_with_scratch(
        job,
        local_job_counter,
        shared,
        random12,
        tid,
        i,
        hf2_height,
        &mut pow_scratch,
        on_share,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn grind_job_with_scratch(
    job: &GetBlockTemplateResult,
    local_job_counter: u64,
    shared: &Shared,
    random12: &[u8; 12],
    tid: u8,
    i: &mut u32,
    hf2_height: u64,
    pow_scratch: &mut AstroBwtScratch,
    on_share: &mut dyn FnMut(&[u8; MINIBLOCK_SIZE]),
) -> Result<(), GrindError> {
    let mut work = [0u8; MINIBLOCK_SIZE];
    let blob = job.blockhashing_blob.as_bytes();
    if blob.len() != MINIBLOCK_SIZE * 2 {
        return Err(GrindError::BadBlob); // Go: n != block.MINIBLOCK_SIZE
    }
    hex::decode_to_slice(blob, &mut work).map_err(|_| GrindError::BadBlob)?;

    let height = work_height(&work);
    stamp_job(&mut work, random12, tid);

    // Go parses the difficulty before the version check (miner.go:491).
    let diff =
        BigUint::parse_bytes(job.difficulty.as_bytes(), 10).ok_or(GrindError::BadDifficulty)?;
    if diff.is_zero() {
        return Err(GrindError::BadDifficulty); // Go would div-by-zero panic; never sent by the server
    }
    let target = precompute_pow_target(&diff);

    if work[0] & 0xf != 1 {
        return Err(GrindError::BadVersion(work[0] & 0x1f));
    }

    let mut pending_hashes = 0u64;
    while local_job_counter == shared.job_counter.load(Ordering::Acquire)
        && !shared.exit.load(Ordering::Relaxed)
    {
        for _ in 0..HASH_COUNTER_FLUSH_INTERVAL {
            *i = i.wrapping_add(1); // i++ BEFORE the nonce write — first nonce is 1
            put_counter(&mut work, *i);

            let pow = pow_hash_at_height_with_scratch(&work, height, hf2_height, pow_scratch);
            record_hash(shared, &mut pending_hashes);

            if check_pow_hash_precomputed(&pow, &target) {
                // verify-on-submit: the v114 descriptor SA is ~1.4% non-canonical,
                // so a hash that clears the target here MIGHT be wrong. Recompute
                // the CANONICAL PoW (libsais/pure-Rust SA, byte-exact vs the Go
                // reference) and only submit if THAT clears the target — we never
                // submit a share the network would reject. This costs a full
                // canonical hash, but only on a target-clearing nonce (vanishingly
                // rare at real difficulty), so steady-state hashrate is unaffected.
                let canonical_ok = if height >= hf2_height {
                    let canon = dero_astrobwt::astrobwtv3_full(&work).0;
                    check_pow_hash_precomputed(&canon, &target)
                } else {
                    true // POW16 path does not use the descriptor SA
                };
                if canonical_ok {
                    on_share(&work);
                }
                if shared.exit.load(Ordering::Relaxed) {
                    break;
                }
            }
        }
    }
    flush_hashes(shared, &mut pending_hashes);
    Ok(())
}

/// The worker thread body — Go `mineblock(tid)`. Snapshots the job, grinds it
/// via [`grind_job`], pushes found shares as [`SubmitBlockParams`] onto the
/// submit channel (the connection thread writes them to the websocket; Go
/// writes inline under `connection_mutex`, miner.go:509-514).
pub fn mine_thread(
    tid: u8,
    shared: Arc<Shared>,
    submit: mpsc::Sender<SubmitBlockParams>,
    hf2_height: u64,
    debug: bool,
) {
    // Optional CPU pinning (opt-in, mining semantics unchanged). Off by default
    // so behaviour matches the Go reference unless the operator asks for it.
    // See [`pin_worker`] for the env knobs and the winning 13700HX map.
    pin_worker(tid);

    let mut random12 = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut random12[..]); // miner.go:459

    // miner.go:463 — let the first job arrive before spinning.
    std::thread::sleep(Duration::from_secs(5));

    let mut i: u32 = 0; // persists across jobs (miner.go:471)
    let mut pow_scratch = AstroBwtScratch::new();

    while !shared.exit.load(Ordering::Relaxed) {
        // snapshot counter FIRST: if a job lands between the two loads we
        // simply exit the inner loop immediately and re-snapshot (Go takes
        // both under one RWMutex, miner.go:474-477).
        let local_job_counter = shared.job_counter.load(Ordering::Acquire);
        let myjob = shared.job.read().unwrap().clone();
        let jobid = myjob.jobid.clone();

        let mut on_share = |work: &[u8; MINIBLOCK_SIZE]| {
            if debug {
                eprintln!(
                    "[worker {tid}] found miniblock (submitting) difficulty={} height={}",
                    myjob.difficulty, myjob.height
                );
            }
            // fmt.Sprintf("%x", work[:]) == lowercase hex
            let _ = submit.send(SubmitBlockParams {
                jobid: jobid.clone(),
                mbl_blob: hex::encode(work),
            });
        };

        match grind_job_with_scratch(
            &myjob,
            local_job_counter,
            &shared,
            &random12,
            tid,
            &mut i,
            hf2_height,
            &mut pow_scratch,
            &mut on_share,
        ) {
            Ok(()) => {} // job changed — re-snapshot at once
            Err(GrindError::BadBlob) => {
                // Go logs "Blockwork could not be decoded successfully" + 1s
                // (this is also the idle path before the first job arrives).
                if debug && !myjob.blockhashing_blob.is_empty() {
                    eprintln!(
                        "[worker {tid}] blockwork could not be decoded: {:?}",
                        myjob.blockhashing_blob
                    );
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(GrindError::BadVersion(v)) => {
                eprintln!("[worker {tid}] Unknown version {v}, please check for updates");
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(GrindError::BadDifficulty) => {
                if debug {
                    eprintln!("[worker {tid}] bad difficulty {:?}", myjob.difficulty);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dero_astrobwt::verify_miniblock_pow_v3;
    use dero_protocol::MiniBlock;

    fn vectors() -> serde_json::Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/minerwork.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// The full mutation pipeline must be byte-exact vs the Go reference lines
    /// (go-harness/minerwork replicates miner.go:479-522 verbatim).
    #[test]
    fn hash_counter_batches_and_flushes() {
        let shared = Shared::new();
        let mut pending = 0u64;

        for _ in 0..HASH_COUNTER_FLUSH_INTERVAL - 1 {
            record_hash(&shared, &mut pending);
        }
        assert_eq!(pending, HASH_COUNTER_FLUSH_INTERVAL - 1);
        assert_eq!(shared.counter.load(Ordering::SeqCst), 0);

        record_hash(&shared, &mut pending);
        assert_eq!(pending, 0);
        assert_eq!(
            shared.counter.load(Ordering::SeqCst),
            HASH_COUNTER_FLUSH_INTERVAL
        );

        record_hash(&shared, &mut pending);
        flush_hashes(&shared, &mut pending);
        assert_eq!(pending, 0);
        assert_eq!(
            shared.counter.load(Ordering::SeqCst),
            HASH_COUNTER_FLUSH_INTERVAL + 1
        );
    }

    #[test]
    fn mutation_byte_exact_vs_go() {
        let v = vectors();
        let cases = v["mutations"].as_array().unwrap();
        assert!(cases.len() >= 4);
        for c in cases {
            let mut work = [0u8; MINIBLOCK_SIZE];
            hex::decode_to_slice(c["blob_hex"].as_str().unwrap(), &mut work).unwrap();
            let mut random12 = [0u8; 12];
            hex::decode_to_slice(c["random_hex"].as_str().unwrap(), &mut random12).unwrap();
            let tid = c["tid"].as_u64().unwrap() as u8;
            let i = c["i"].as_u64().unwrap() as u32;

            assert_eq!(
                work_height(&work),
                c["height"].as_u64().unwrap(),
                "height mask"
            );
            stamp_job(&mut work, &random12, tid);
            put_counter(&mut work, i);
            assert_eq!(
                hex::encode(work),
                c["mutated_hex"].as_str().unwrap(),
                "tid={tid} i={i}"
            );
        }
    }

    /// Layout assertions via the verified MiniBlock decoder: the mutation only
    /// lands in the nonce region; version/timestamp/height/keyhash/flags are
    /// untouched, the counter occupies bytes [43..47] and the tid byte 47.
    #[test]
    fn mutated_blob_layout_via_miniblock_roundtrip() {
        let mbl = MiniBlock {
            version: 1,
            high_diff: false,
            final_: false,
            past_count: 1,
            timestamp: 0x1234,
            height: 3_528_900,
            past: [0xAABBCCDD, 0],
            key_hash: *b"0123456789abcdef",
            flags: 0x0F0E0D0C,
            nonce: [0x11111111, 0x22222222, 0x33333333],
        };
        let mut work = mbl.serialize();
        let random12 = [
            0x40u8, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
        ];
        let tid = 0xEEu8;
        let i = 0x01020304u32;

        stamp_job(&mut work, &random12, tid);
        put_counter(&mut work, i);

        let got = MiniBlock::deserialize(&work).expect("mutated blob is still a valid miniblock");
        assert_eq!(got.version, 1);
        assert_eq!(
            got.timestamp, 0x1234,
            "timestamp bytes [1..3] never touched"
        );
        assert_eq!(got.height, 3_528_900);
        assert_eq!(got.past, [0xAABBCCDD, 0]);
        assert_eq!(got.key_hash, *b"0123456789abcdef", "keyhash untouched");
        assert_eq!(got.flags, 0x0F0E0D0C, "flags [32..36] never touched");
        // nonce[0] = random12[0..4]
        assert_eq!(got.nonce[0], u32::from_be_bytes([0x40, 0x41, 0x42, 0x43]));
        // nonce[1] = random12[4..7] + counter byte 0 (offset 43)
        assert_eq!(got.nonce[1], u32::from_be_bytes([0x44, 0x45, 0x46, 0x01]));
        // nonce[2] = counter bytes 1..3 (offsets 44..47) + tid (offset 47)
        assert_eq!(got.nonce[2], u32::from_be_bytes([0x02, 0x03, 0x04, tid]));
    }

    /// End-to-end grind at a low difficulty: the share that `grind_job` emits
    /// must pass the byte-verified `verify_miniblock_pow_v3` at that same
    /// difficulty, and still deserialize as a version-1 miniblock with the
    /// job's untouched fields.
    #[test]
    fn low_difficulty_grind_finds_verifiable_share() {
        let mbl = MiniBlock {
            version: 1,
            past_count: 1,
            timestamp: 7,
            height: 600_000, // >= MAJOR_HF2_HEIGHT_MAINNET => AstroBWTv3
            past: [42, 0],
            key_hash: [0x5A; 16],
            flags: 0,
            nonce: [0, 0, 0],
            high_diff: false,
            final_: false,
        };
        let job = GetBlockTemplateResult {
            jobid: "1748090000123.0.notified".into(),
            blockhashing_blob: hex::encode(mbl.serialize()),
            difficulty: "2".into(), // ~1/2 of hashes pass — exercises the check both ways fast
            height: mbl.height,
            ..Default::default()
        };

        let shared = Shared::new();
        shared.job_counter.store(1, Ordering::SeqCst);
        let random12 = [9u8; 12];
        let mut i = 0u32;
        let mut found: Option<[u8; MINIBLOCK_SIZE]> = None;

        let mut on_share = |work: &[u8; MINIBLOCK_SIZE]| {
            if found.is_none() {
                found = Some(*work);
            }
            shared.exit.store(true, Ordering::SeqCst); // stop after the first share
        };
        grind_job(
            &job,
            1,
            &shared,
            &random12,
            3,
            &mut i,
            dero_astrobwt::MAJOR_HF2_HEIGHT_MAINNET,
            &mut on_share,
        )
        .expect("grind must accept a valid job");

        let work = found.expect("difficulty-2 share must be found");
        assert!(i >= 1, "counter advanced");
        assert!(
            shared.counter.load(Ordering::SeqCst) >= 1,
            "hash counter advanced"
        );

        // the submit blob passes the independent verifier at the job difficulty
        let diff = BigUint::parse_bytes(job.difficulty.as_bytes(), 10).unwrap();
        assert!(
            verify_miniblock_pow_v3(&work, false, &diff),
            "share must verify"
        );

        // and it is still a well-formed miniblock carrying our identity bytes
        let got = MiniBlock::deserialize(&work).unwrap();
        assert_eq!(got.version, 1);
        assert_eq!(got.height, 600_000);
        assert_eq!(got.key_hash, [0x5A; 16]);
        assert_eq!(work[MINIBLOCK_SIZE - 1], 3, "tid in the last byte");
    }

    /// Version gate: a blob whose low nibble isn't 1 must be rejected before
    /// any hashing (miner.go:493-497). MiniBlock::serialize can't produce one,
    /// so patch the byte directly.
    #[test]
    fn version_gate_rejects_unknown_version() {
        let mbl = MiniBlock {
            version: 1,
            past_count: 1,
            height: 600_000,
            ..Default::default()
        };
        let mut raw = mbl.serialize();
        raw[0] = (raw[0] & 0xf0) | 0x02; // version 2
        let job = GetBlockTemplateResult {
            blockhashing_blob: hex::encode(raw),
            difficulty: "1".into(),
            ..Default::default()
        };
        let shared = Shared::new();
        let mut i = 0u32;
        let err = grind_job(&job, 0, &shared, &[0; 12], 0, &mut i, 481_600, &mut |_| {
            panic!("no share")
        })
        .unwrap_err();
        match err {
            // byte 0 = (1<<6)|2 = 0x42; Go logs work[0]&0x1f = 2 (miner.go:494)
            GrindError::BadVersion(v) => assert_eq!(v, 0x42 & 0x1f),
            other => panic!("expected BadVersion, got {other:?}"),
        }
        assert_eq!(
            shared.counter.load(Ordering::SeqCst),
            0,
            "no hashing before the gate"
        );
    }

    #[test]
    fn bad_blob_and_bad_difficulty_rejected() {
        let shared = Shared::new();
        let mut i = 0u32;
        // empty blob (the pre-first-job state) => BadBlob, like Go's n != 48
        let job = GetBlockTemplateResult::default();
        assert!(matches!(
            grind_job(&job, 0, &shared, &[0; 12], 0, &mut i, 481_600, &mut |_| {}),
            Err(GrindError::BadBlob)
        ));
        // valid blob, unparseable difficulty
        let mbl = MiniBlock {
            version: 1,
            past_count: 1,
            height: 600_000,
            ..Default::default()
        };
        let job = GetBlockTemplateResult {
            blockhashing_blob: hex::encode(mbl.serialize()),
            difficulty: "not-a-number".into(),
            ..Default::default()
        };
        assert!(matches!(
            grind_job(&job, 0, &shared, &[0; 12], 0, &mut i, 481_600, &mut |_| {}),
            Err(GrindError::BadDifficulty)
        ));
        // zero difficulty guarded (Go would panic on the big.Int division)
        let job = GetBlockTemplateResult {
            difficulty: "0".into(),
            ..job
        };
        assert!(matches!(
            grind_job(&job, 0, &shared, &[0; 12], 0, &mut i, 481_600, &mut |_| {}),
            Err(GrindError::BadDifficulty)
        ));
    }

    /// Full worker-thread wiring: a preloaded difficulty-1 job makes
    /// `mine_thread` emit a [`SubmitBlockParams`] on the channel carrying the
    /// VERBATIM jobid (the server Sscanf's the block timestamp out of it) and
    /// a 96-char lowercase-hex blob that passes the independent verifier.
    /// Takes ~5s: mine_thread replicates Go's startup sleep (miner.go:463).
    #[test]
    fn mine_thread_submits_share_end_to_end() {
        let mbl = MiniBlock {
            version: 1,
            past_count: 1,
            height: 600_000,
            key_hash: [0x11; 16],
            ..Default::default()
        };
        let shared = Arc::new(Shared::new());
        *shared.job.write().unwrap() = GetBlockTemplateResult {
            jobid: "1748090000123.0.notified".into(),
            blockhashing_blob: hex::encode(mbl.serialize()),
            difficulty: "1".into(),
            height: 600_000,
            ..Default::default()
        };
        shared.job_counter.store(1, Ordering::SeqCst);

        let (tx, rx) = mpsc::channel();
        let handle = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                mine_thread(
                    9,
                    shared,
                    tx,
                    dero_astrobwt::MAJOR_HF2_HEIGHT_MAINNET,
                    false,
                )
            })
        };
        let share = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("share within 60s");
        shared.exit.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            share.jobid, "1748090000123.0.notified",
            "jobid echoed verbatim"
        );
        assert_eq!(share.mbl_blob.len(), 96, "96 hex chars = 48 bytes");
        assert_eq!(
            share.mbl_blob,
            share.mbl_blob.to_lowercase(),
            "Go %x = lowercase hex"
        );
        let mut work = [0u8; MINIBLOCK_SIZE];
        hex::decode_to_slice(&share.mbl_blob, &mut work).unwrap();
        assert_eq!(work[MINIBLOCK_SIZE - 1], 9, "tid in the last byte");
        assert_eq!(MiniBlock::deserialize(&work).unwrap().key_hash, [0x11; 16]);
        assert!(verify_miniblock_pow_v3(&work, false, &BigUint::from(1u32)));
    }

    /// difficulty 1 accepts every hash (target = 2^256/1 > any 32-byte hash) —
    /// the share fires on the very first nonce, i = 1.
    #[test]
    fn difficulty_one_first_nonce_wins() {
        let mbl = MiniBlock {
            version: 1,
            past_count: 1,
            height: 600_000,
            ..Default::default()
        };
        let job = GetBlockTemplateResult {
            blockhashing_blob: hex::encode(mbl.serialize()),
            difficulty: "1".into(),
            ..Default::default()
        };
        let shared = Shared::new();
        let mut i = 0u32;
        let mut hits = 0u32;
        let mut on_share = |_: &[u8; MINIBLOCK_SIZE]| {
            hits += 1;
            shared.exit.store(true, Ordering::SeqCst);
        };
        grind_job(
            &job,
            0,
            &shared,
            &[7; 12],
            0,
            &mut i,
            481_600,
            &mut on_share,
        )
        .unwrap();
        assert_eq!(hits, 1);
        assert_eq!(
            i, 1,
            "i++ happens before the first nonce write — first nonce is 1"
        );
    }
}
