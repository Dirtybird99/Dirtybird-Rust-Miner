//! dero-miner — port of `cmd/dero-miner` (derohe-reference/cmd/dero-miner/
//! miner.go + difficulty.go). The standalone CPU miner:
//!
//!  - dials the daemon's GETWORK websocket server — `wss://<daemon>:10100/ws/
//!    <wallet_address>` over TLS with NO certificate verification (the server
//!    presents a random self-signed cert; miner.go:406-413);
//!  - receives JSON job pushes (`rpc.GetBlockTemplate_Result`) ~every 500ms —
//!    no job is sent at connect time, the first arrives on the dispatch tick;
//!  - N worker threads grind the 48-byte miniblock blob with the byte-exact
//!    Go nonce mutation (random12 → [36..48] per job, tid → [47], BE u32
//!    counter → [43..47]) using AstroBWTv3 (heights >= MAJOR_HF2_HEIGHT) and
//!    submit `{"jobid","mbl_blob"}` over the same socket on
//!    `CheckPowHashBig(pow, difficulty)`;
//!  - the server NEVER replies to a submit: outcomes surface as the
//!    blocks/miniblocks/rejected counters in later job pushes;
//!  - reconnect: 10s backoff on dial failure, immediate redial on read error
//!    (miner.go:414-427);
//!  - 1 Hz status line (miner.go:225-294), stdin command loop, and `--bench`.
//!
//! Knowingly dropped vs Go (cosmetics/platform): readline autocomplete +
//! ANSI-colored prompt (plain stderr line here), Unix RLIMIT_NOFILE=20
//! (fdlimits.go — Unix-only), thread-affinity pinning (thread_windows.go —
//! a nice-to-have optimization). The Go "status" command is advertised in
//! help but unimplemented — quirk replicated.

mod affinity;
mod bench;
mod job;
mod stats_api;
mod sustained;
mod term;
mod tls;
mod worker;
mod ws;

use std::io::{self, BufRead, Write as _};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use clap::Parser;

use dero_protocol::Address;
use job::{GetBlockTemplateResult, SubmitBlockParams};
use term::{LineBuf, Palette};
use worker::Shared;

/// Go: config.MAJOR_HF2_HEIGHT — mainnet 481600, testnet 4 (config/config.go:108,129).
const MAJOR_HF2_HEIGHT_MAINNET: u64 = 481_600;
const MAJOR_HF2_HEIGHT_TESTNET: u64 = 4;
const ASTROBWT_KAT_A: [u8; 32] = [
    0x54, 0xe2, 0x32, 0x4d, 0xda, 0xcc, 0x3f, 0x03, 0x83, 0x50, 0x1a, 0x9e, 0x57, 0x60, 0xf8, 0x5d,
    0x63, 0xe9, 0xbc, 0x67, 0x05, 0xe9, 0x12, 0x4c, 0xa7, 0xae, 0xf8, 0x90, 0x16, 0xab, 0x81, 0xea,
];

// Modern Termux cannot exec() binaries from app data directly (Android 10+
// W^X), so it routes them through bionic's linker64 — even a static-PIE musl
// binary with no PT_INTERP. Bionic aborts any executable whose PT_TLS p_align
// is < 64 ("executable's TLS segment is underaligned: … needs to be at least
// 64 for ARM64 Bionic", StaticTlsLayout::reserve_exe_segment_and_tcb), and
// the TLS this target otherwise emits (musl libc's own __thread) only reaches
// p_align = 8 — v0.2.5 died exactly this way on-device. `thread_local!`
// cannot fix it: aarch64-unknown-linux-musl has no native-TLS lowering (no
// `target_thread_local` cfg), so the macro lands in pthread keys, never in
// PT_TLS. Emit the 64-aligned TLS anchor directly; SHF_GNU_RETAIN ("R")
// keeps --gc-sections from dropping it without any runtime reference.
// scripts/verify-arm64-elf.sh hard-gates the resulting p_align.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
core::arch::global_asm!(
    ".pushsection .tbss.bionic_tls_align_anchor,\"awTR\",@nobits",
    ".balign 64",
    "bionic_tls_align_anchor:",
    ".zero 64",
    ".popsection",
);

#[derive(Parser, Debug)]
#[command(
    name = "dero-miner",
    version,
    about = "DERO CPU Miner for AstroBWT. ONE CPU, ONE VOTE.\n(Rust port of derohe cmd/dero-miner)"
)]
struct Cli {
    /// This address is rewarded when a block is mined successfully.
    #[arg(short = 'w', long)]
    wallet_address: Option<String>,
    /// Miner will connect to daemon getwork on this address
    /// (default: dero-node.mysrv.cloud:10100; testnet: 127.0.0.1:10100).
    #[arg(short = 'd', long)]
    daemon_rpc_address: Option<String>,
    /// Number of CPU threads for mining (default: all logical CPUs, max 255).
    #[arg(short = 't', long)]
    mining_threads: Option<i64>,
    /// Use testnet address prefix + testnet PoW switch height.
    #[arg(long)]
    testnet: bool,
    /// Verbose logging (received jobs, submits).
    #[arg(long)]
    debug: bool,
    /// Run benchmark mode (offline AstroBWTv3 throughput table).
    #[arg(long)]
    bench: bool,
    /// Verify the packaged AstroBWTv3 mining path against a known answer.
    #[arg(long)]
    selftest: bool,
    /// Run the SUSTAINED throughput benchmark (counter-summed over a fixed
    /// window — the honest, hybrid-CPU-fair scoreboard). Uses `-t` threads.
    #[arg(long)]
    sustained: bool,
    /// Sustained-benchmark window in seconds (default 30).
    #[arg(long, default_value_t = 30)]
    secs: u64,
    /// Pin each worker thread to a logical core during --sustained.
    #[arg(long)]
    pin: bool,
    /// Disable P-core-first thread pinning on the real miner (pinning is ON by
    /// default — ~+5% at 20T on the 13700HX for under-subscribed runs).
    #[arg(long)]
    no_pin: bool,
    /// Keep NORMAL process priority (HIGH is the default on the real miner — the
    /// single best throughput lever, ~+8%).
    #[arg(long)]
    normal_priority: bool,
    /// Explicit comma-separated logical-core pin list (overrides the default map),
    /// e.g. --pin-cores 0,2,4,6,8,10,12,14,16,17,18,19.
    #[arg(long)]
    pin_cores: Option<String>,
    /// Allocate the AstroBWTv3 scratch (op-loop stream + suffix array) from 2 MB
    /// large pages (needs SeLockMemoryPrivilege). Off by default — measured
    /// per-CPU; the `--sustained` scoreboard uses it.
    #[arg(long)]
    large_pages: bool,
    /// Force the FUSED suffix-array→SHA path. By default the miner MATERIALIZES
    /// the SA then hashes it when under-subscribed (threads < logical CPUs) —
    /// measured +5.3% at 20T; fused is auto-selected only at full occupancy.
    #[arg(long)]
    fused: bool,
    /// Disable the 2-way SHA-NI pipeline (2 nonces per thread). It is ON by
    /// default on shani2 builds — measured byte-exact +2.5% at 20T / +4% at 24T.
    #[arg(long)]
    no_2way: bool,
    /// Serve plain-text miner stats over HTTP on this address, e.g.
    /// 127.0.0.1:44011 (for HiveOS/mmpOS farm agents). Off unless given.
    #[arg(long)]
    api_bind_address: Option<String>,
}

/// `dero1qyq...hnwk` — enough to recognise the address, short enough not to
/// wrap a phone terminal twice.
///
/// The ASCII guard is not theoretical: `wallet_address` falls back to the raw
/// argument when re-encoding fails, so a multi-byte character straddling the
/// cut would panic the miner at startup.
fn elide_wallet(addr: &str) -> String {
    const HEAD: usize = 8;
    const TAIL: usize = 4;
    if !addr.is_ascii() || addr.len() <= HEAD + TAIL + 3 {
        return addr.to_string();
    }
    format!("{}...{}", &addr[..HEAD], &addr[addr.len() - TAIL..])
}

fn run_selftest() {
    let mut scratch = dero_astrobwt::AstroBwtScratch::new();
    let got = dero_astrobwt::astrobwtv3_with_scratch(b"a", &mut scratch);
    if got != ASTROBWT_KAT_A {
        eprintln!(
            "AstroBWTv3 self-test: FAIL\nexpected: {}\nactual:   {}",
            hex::encode(ASTROBWT_KAT_A),
            hex::encode(got)
        );
        std::process::exit(1);
    }
    println!("AstroBWTv3 self-test: PASS");
}

fn main() {
    // Before anything prints, including the argument diagnostics below: this
    // resolves whether stderr is a terminal and turns on ANSI processing, which
    // on Windows is what stops escapes rendering as literal text.
    term::init();

    let cli = Cli::parse();

    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut threads = cli.mining_threads.unwrap_or(cpus as i64);
    if threads > cpus as i64 {
        crate::warn!(
            "Mining threads is more than available CPUs. This is NOT optimal thread_count={threads} max_possible={cpus}"
        );
    }

    if cli.no_2way {
        std::env::set_var("MINER_2WAY", "0");
    }

    // Suffix-array hashing path (byte-exact either way). MATERIALIZE+SHA the SA
    // wins when the box is UNDER-SUBSCRIBED — bandwidth headroom makes the SA
    // write/read roundtrip cheap and the simpler control flow wins: measured
    // +5.3% at 20T on the 13700HX. The FUSED stream (no materialization) wins at
    // FULL occupancy (24-thread bandwidth saturation). Auto-select by occupancy;
    // `--fused` forces fused. An explicit DERO_MATERIALIZE env is always honored.
    // The occupancy split above is an x86 measurement and does not transfer to
    // aarch64. Measured on a native Neoverse-N2 runner (arm_bench, fixed work,
    // 7 repeats, within-job spread <= 1.4%), materializing wins at BOTH ends of
    // the occupancy range rather than only when under-subscribed:
    //     1 thread        fused 737_112 ns/hash   materialized 708_315  (-3.9%)
    //     4 of 4 threads  fused 186_844 ns/hash   materialized 181_706  (-2.8%)
    // Note the large-page benefit that motivates materializing on Windows is a
    // no-op off it (astrobwt/src/lpbuf.rs), so this is bandwidth and control
    // flow, not TLB coverage. In practice a phone at `-t 7` of 8 cores already
    // took this branch via the under-subscription rule; arch-gating it only
    // changes the full-occupancy case, and aligns it with measurement.
    // CI silicon is not phone silicon (an N2 has 1 MiB L2/core and 128 MiB L3
    // against a phone's far smaller caches, which is exactly what a doubled SA
    // working set is sensitive to), so this is pending an on-device A/B.
    if std::env::var_os("DERO_MATERIALIZE").is_none() && !cli.fused {
        let materialize = if cfg!(target_arch = "aarch64") {
            true
        } else {
            threads < cpus as i64
        };
        if materialize {
            std::env::set_var("DERO_MATERIALIZE", "1");
        }
    }

    if cli.selftest {
        run_selftest();
        return;
    }

    // Go runs bench before the panic checks (miner.go:181-219).
    if cli.bench {
        bench::run_bench(threads.max(1) as usize);
        std::process::exit(0);
    }
    if cli.sustained {
        sustained::run_sustained(threads.max(1) as usize, cli.secs, cli.pin);
        std::process::exit(0);
    }

    if !(1..=2048).contains(&threads) {
        // Go: panic("Invalid parameters\n") (miner.go:219-222)
        panic!("Invalid parameters");
    }
    if threads > 255 {
        crate::warn!("This program supports maximum 256 CPU cores. available={threads}");
        threads = 255;
    }
    let threads = threads as usize;

    // Perf levers are ON by default on the real miner (byte-exact — thread
    // placement + process priority only, never the hash). Translate the CLI
    // opt-outs to the env knobs `pin_worker` reads; CLI wins over the
    // environment. Done here while still single-threaded, before any spawn.
    if cli.no_pin {
        std::env::set_var("MINER_PIN", "0");
    }
    if cli.normal_priority {
        std::env::set_var("MINER_HIGHPRIO", "0");
    }
    if let Some(cores) = cli.pin_cores.as_deref() {
        std::env::set_var("MINER_PIN_CORES", cores);
    }
    // --wallet-address: bech32-validated + network prefix check
    // (globals.ParseValidateAddress; miner.go:149-156).
    let Some(wallet_raw) = cli.wallet_address.as_deref() else {
        crate::error!("Wallet address is required (--wallet-address=dero1...)");
        std::process::exit(1);
    };
    let wallet_address = match Address::from_string(wallet_raw) {
        Ok(addr) => {
            if addr.mainnet == cli.testnet {
                crate::error!(
                    "Wallet address has the wrong network prefix (expected {})",
                    if cli.testnet {
                        "deto1... (testnet)"
                    } else {
                        "dero1... (mainnet)"
                    }
                );
                std::process::exit(1);
            }
            // Go normalizes through addr.String(); ours round-trips the same way.
            addr.to_string().unwrap_or_else(|_| wallet_raw.to_string())
        }
        Err(e) => {
            crate::error!("Wallet address is invalid: {e}");
            std::process::exit(1);
        }
    };

    // miner.go:158-166 — default depends on network, flag overrides.
    let daemon_rpc_address = cli.daemon_rpc_address.clone().unwrap_or_else(|| {
        if cli.testnet {
            "127.0.0.1:10100".to_string()
        } else {
            // minernode1.dero.live is DNS-dead (2026); this community derod
            // getwork node is live. Override with -d for your own pool/node.
            "dero-node.mysrv.cloud:10100".to_string()
        }
    });

    let hf2_height = if cli.testnet {
        MAJOR_HF2_HEIGHT_TESTNET
    } else {
        MAJOR_HF2_HEIGHT_MAINNET
    };

    // Startup block. The wallet is elided because it is long enough to wrap
    // twice on a phone, and it is echoed back by the installer anyway.
    crate::info!(
        "Dirtybird Rust Miner v{} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    crate::info!("Server:  {daemon_rpc_address}");
    crate::info!("Wallet:  {}", elide_wallet(&wallet_address));
    crate::info!("Threads: {threads}");
    if cli.testnet {
        crate::info!("Network: testnet");
    }
    eprintln!();

    let shared = Arc::new(Shared::new());
    let (submit_tx, submit_rx) = mpsc::channel::<SubmitBlockParams>();

    // Optional 2 MB large pages for the per-worker scratch (op-loop stream + SA).
    // Must run before any worker allocates `AstroBwtScratch`. Mirrors the
    // `--sustained` harness (sustained.rs); off by default pending per-CPU A/B.
    //
    // Ordered ahead of the getwork spawn so its line cannot race `Connecting`:
    // the constraint is only that it precede worker allocation, and workers
    // start below.
    if cli.large_pages {
        let lp = dero_astrobwt::enable_large_pages();
        crate::info!(
            "Large pages: {}",
            if lp {
                "2MB enabled"
            } else {
                "unavailable (4KB)"
            }
        );
    }

    // getwork connection thread (Go: go getwork(wallet_address), miner.go:316)
    {
        let shared = Arc::clone(&shared);
        let daemon = daemon_rpc_address.clone();
        let wallet = wallet_address.clone();
        let debug = cli.debug;
        std::thread::Builder::new()
            .name("getwork".into())
            .spawn(move || getwork(&daemon, &wallet, &shared, submit_rx, debug))
            .expect("spawn getwork");
    }

    // worker threads (Go: go mineblock(i), miner.go:318-320)
    for tid in 0..threads {
        let shared = Arc::clone(&shared);
        let submit = submit_tx.clone();
        let debug = cli.debug;
        std::thread::Builder::new()
            .name(format!("miner-{tid}"))
            .spawn(move || worker::mine_thread(tid as u8, shared, submit, hf2_height, debug))
            .expect("spawn worker");
    }

    // Farm-manager stats endpoint (HiveOS/mmpOS poll it over localhost).
    // `api` exists whether or not the listener does: stats_loop publishes its
    // per-tick rate through it unconditionally, which is cheaper than making
    // the publish conditional and keeps stats_loop ignorant of the flag.
    let api = Arc::new(stats_api::ApiState::new());
    if let Some(addr) = cli.api_bind_address.clone() {
        let api = Arc::clone(&api);
        let shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("stats-api".into())
            .spawn(move || stats_api::serve(&addr, api, shared))
            .expect("spawn stats-api");
    }

    // 1 Hz status repaint (Go: the prompt goroutine, miner.go:225-294)
    {
        let shared = Arc::clone(&shared);
        let testnet = cli.testnet;
        std::thread::Builder::new()
            .name("stats".into())
            .spawn(move || stats_loop(&shared, &api, testnet))
            .expect("spawn stats");
    }

    command_loop(&shared);
}

/// The connect/read/submit loop — Go `getwork()` (miner.go:401-451) plus the
/// share writer (Go submits from the workers under `connection_mutex`,
/// miner.go:509-514; here the workers hand shares to this thread over a
/// channel and we interleave writes with 100ms read polls on the same socket —
/// worst-case submit latency 100ms).
fn getwork(
    daemon_rpc_address: &str,
    wallet_address: &str,
    shared: &Shared,
    submit_rx: mpsc::Receiver<SubmitBlockParams>,
    debug: bool,
) {
    let path = format!("/ws/{wallet_address}");

    'reconnect: loop {
        // Cleared here rather than at each `continue 'reconnect` (there are
        // four, and a fifth would be easy to add without noticing): every path
        // back to the top of this loop is a disconnect, so one store covers
        // them all.
        shared.connected.store(false, Ordering::Relaxed);
        if shared.exit.load(Ordering::Relaxed) {
            return;
        }
        crate::info!("Connecting ({daemon_rpc_address})");
        // Spans DNS + TCP + TLS + the WebSocket upgrade, reported only on
        // success. Note this is a CONNECT time, not a ping: our TLS is the
        // pure-Rust provider, so a software P-256 handshake is inside it.
        let connect_start = Instant::now();

        // dial + TLS (long timeouts for the handshakes)
        let stream = match tls::connect_tls(daemon_rpc_address, Duration::from_secs(10)) {
            Ok(s) => s,
            Err(e) => {
                crate::error!("Connection failed ({daemon_rpc_address}): {e}");
                crate::info!("Retrying in 10s");
                std::thread::sleep(Duration::from_secs(10)); // miner.go:417
                continue;
            }
        };
        let mut conn = match ws::WsClient::handshake(stream, daemon_rpc_address, &path) {
            Ok(c) => c,
            Err(e) => {
                crate::error!("Connection failed ({daemon_rpc_address}): {e}");
                crate::info!("Retrying in 10s");
                std::thread::sleep(Duration::from_secs(10));
                continue;
            }
        };
        // short read timeout from here on: poll reads, interleave submits
        if let Err(e) = conn
            .get_mut()
            .sock
            .set_read_timeout(Some(Duration::from_millis(100)))
        {
            crate::warn!("set_read_timeout: {e}");
        }
        crate::info!(
            "Connected ({daemon_rpc_address}) ({} ms)",
            connect_start.elapsed().as_millis()
        );
        shared.connected.store(true, Ordering::Relaxed);

        // drop shares queued while disconnected — their jobs are stale anyway
        // (Go simply loses them when connection.WriteJSON panics/errors)
        while submit_rx.try_recv().is_ok() {}

        loop {
            if shared.exit.load(Ordering::Relaxed) {
                return;
            }
            // pending shares first (time-critical: ~1 miniblock/second network-wide)
            while let Ok(share) = submit_rx.try_recv() {
                let txt = serde_json::to_string(&share).expect("submit serialize");
                if debug {
                    crate::debug!("submitting share: {txt}");
                }
                if let Err(e) = conn.write_text(txt.as_bytes()) {
                    crate::error!("connection error (submit): {e}");
                    continue 'reconnect; // immediate redial, like miner.go:425-427
                }
            }
            match conn.try_read_message() {
                Ok(Some(ws::WsMessage::Text(data))) | Ok(Some(ws::WsMessage::Binary(data))) => {
                    let result: GetBlockTemplateResult = match serde_json::from_slice(&data) {
                        Ok(r) => r,
                        Err(e) => {
                            // gorilla ReadJSON would error too => reconnect
                            crate::error!("connection error (bad job json): {e}");
                            continue 'reconnect;
                        }
                    };
                    if debug {
                        crate::debug!("recv: {}", String::from_utf8_lossy(&data).trim_end());
                    }
                    // miner.go:430-445
                    {
                        let mut g = shared.job.write().unwrap();
                        *g = result.clone();
                    }
                    shared.job_counter.fetch_add(1, Ordering::Release);
                    if !result.lasterror.is_empty() {
                        crate::warn!("received error: err={}", result.lasterror);
                    }
                    shared.block_counter.store(result.blocks, Ordering::Relaxed);
                    shared
                        .mini_block_counter
                        .store(result.miniblocks, Ordering::Relaxed);
                    shared.rejected.store(result.rejected, Ordering::Relaxed);
                    shared
                        .difficulty
                        .store(result.difficultyuint64, Ordering::Relaxed);
                    shared.our_height.store(result.height, Ordering::Relaxed);
                }
                Ok(Some(ws::WsMessage::Close)) => {
                    crate::error!("connection error: server closed the websocket");
                    continue 'reconnect;
                }
                Ok(None) => {} // read timeout — poll again
                Err(e) => {
                    crate::error!("connection error: {e}");
                    continue 'reconnect;
                }
            }
        }
    }
}

const HASHRATE_WINDOW_SLOTS: usize = 10;

#[derive(Clone, Copy)]
struct HashratePoint {
    at: Instant,
    hashes: u64,
}

struct HashrateWindow {
    points: [HashratePoint; HASHRATE_WINDOW_SLOTS],
    next: usize,
}

impl HashrateWindow {
    fn new(at: Instant, hashes: u64) -> Self {
        Self {
            points: [HashratePoint { at, hashes }; HASHRATE_WINDOW_SLOTS],
            next: 0,
        }
    }

    fn sample(&mut self, at: Instant, hashes: u64) -> f64 {
        let old = self.points[self.next];
        self.points[self.next] = HashratePoint { at, hashes };
        self.next = (self.next + 1) % self.points.len();
        hashes.checked_sub(old.hashes).map_or(0.0, |delta| {
            rate_khs(delta, at.saturating_duration_since(old.at))
        })
    }
}

fn rate_khs(hashes: u64, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        0.0
    } else {
        hashes as f64 / elapsed.as_secs_f64() / 1_000.0
    }
}

/// Humanize difficulty using the compact DIRTYBIRD family units.
fn difficulty_string(difficulty: u64) -> String {
    if difficulty >= 1_000_000_000 {
        format!("{}G", difficulty / 1_000_000_000)
    } else if difficulty >= 1_000_000 {
        format!("{}M", difficulty / 1_000_000)
    } else if difficulty >= 1_000 {
        format!("{}K", difficulty / 1_000)
    } else {
        difficulty.to_string()
    }
}

/// Every value the status line can show, sampled once.
///
/// Sampling up front rather than re-reading the atomics inside each candidate
/// layout keeps the fields consistent with one another — the old code loaded
/// them again per layout, so a job push landing mid-selection could produce a
/// line whose height and counters came from different jobs.
struct StatusFields {
    rate: f64,
    average: f64,
    height: u64,
    mini: u64,
    blocks: u64,
    rejected: u64,
    diff: String,
    hh: u64,
    mm: u64,
    ss: u64,
    testnet: bool,
}

impl StatusFields {
    fn sample(
        shared: &Shared,
        rate: f64,
        average: f64,
        uptime: Duration,
        testnet: bool,
    ) -> StatusFields {
        let seconds = uptime.as_secs();
        StatusFields {
            rate,
            average,
            height: shared.our_height.load(Ordering::Relaxed),
            mini: shared.mini_block_counter.load(Ordering::Relaxed),
            blocks: shared.block_counter.load(Ordering::Relaxed),
            rejected: shared.rejected.load(Ordering::Relaxed),
            diff: difficulty_string(shared.difficulty.load(Ordering::Relaxed)),
            hh: seconds / 3_600,
            mm: seconds / 60 % 60,
            ss: seconds % 60,
            testnet,
        }
    }
}

/// The layout ladder, widest first (ported from the C miner's `render_tier`,
/// `console.cpp:186-267`). Each rung drops one field, so a narrowing terminal
/// degrades a field at a time instead of falling off a cliff — which is what
/// happens with only three rungs, where a phone loses the height, counters and
/// uptime all at once the moment the miniblock count reaches double digits.
type TierRender = fn(&mut LineBuf, &Palette, &StatusFields);

const TIERS: [TierRender; 5] = [
    render_full,
    render_medium,
    render_narrow,
    render_compact,
    render_minimal,
];

/// Full labels, every field. Plain-rendered, this is byte-identical to the
/// pre-colour status line, which is what lets the existing format test stand
/// unchanged as a regression fence.
fn render_full(lb: &mut LineBuf, p: &Palette, s: &StatusFields) {
    lb.esc(p.label);
    txt!(lb, "[DIRTYBIRD] ");
    lb.esc(p.rate);
    txt!(lb, "{:.2} KH/s", s.rate);
    lb.esc(p.text);
    txt!(lb, " (");
    lb.esc(p.avg);
    txt!(lb, "{:.2} KH/s avg", s.average);
    lb.esc(p.text);
    txt!(lb, ") | ");
    lb.esc(p.height);
    txt!(lb, "Height:{}", s.height);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.mini);
    txt!(lb, "Miniblocks:{}", s.mini);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.block);
    txt!(lb, "Blocks:{}", s.blocks);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.rej(s.rejected));
    txt!(lb, "REJ:{}", s.rejected);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.diff);
    txt!(lb, "Diff:{}", s.diff);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.time);
    txt!(lb, "{:02}:{:02}:{:02}", s.hh, s.mm, s.ss);
    // Only the widest rung carries the testnet marker; the narrower ones have
    // no room, and the startup banner names the network anyway.
    if s.testnet {
        lb.esc(p.text);
        txt!(lb, " | TESTNET");
    }
}

/// Abbreviated labels, every field kept.
fn render_medium(lb: &mut LineBuf, p: &Palette, s: &StatusFields) {
    lb.esc(p.label);
    txt!(lb, "[DIRTYBIRD] ");
    lb.esc(p.rate);
    txt!(lb, "{:.2} KH/s", s.rate);
    lb.esc(p.text);
    txt!(lb, " (");
    lb.esc(p.avg);
    txt!(lb, "{:.2} avg", s.average);
    lb.esc(p.text);
    txt!(lb, ") | ");
    lb.esc(p.height);
    txt!(lb, "H:{}", s.height);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.mini);
    txt!(lb, "MB:{}", s.mini);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.block);
    txt!(lb, "B:{}", s.blocks);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.rej(s.rejected));
    txt!(lb, "R:{}", s.rejected);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.diff);
    txt!(lb, "D:{}", s.diff);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.time);
    txt!(lb, "{:02}:{:02}:{:02}", s.hh, s.mm, s.ss);
}

/// Fits the classic 80-column terminal: drops the average.
fn render_narrow(lb: &mut LineBuf, p: &Palette, s: &StatusFields) {
    lb.esc(p.label);
    txt!(lb, "[DIRTYBIRD] ");
    lb.esc(p.rate);
    txt!(lb, "{:.2} KH/s", s.rate);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.height);
    txt!(lb, "H:{}", s.height);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.mini);
    txt!(lb, "MB:{}", s.mini);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.block);
    txt!(lb, "B:{}", s.blocks);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.rej(s.rejected));
    txt!(lb, "R:{}", s.rejected);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.diff);
    txt!(lb, "D:{}", s.diff);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.time);
    txt!(lb, "{:02}:{:02}:{:02}", s.hh, s.mm, s.ss);
}

/// Phone-sized: short tag, drops the difficulty, keeps the uptime. This is the
/// rung a ~54-column Termux window renders.
fn render_compact(lb: &mut LineBuf, p: &Palette, s: &StatusFields) {
    lb.esc(p.label);
    txt!(lb, "[DB] ");
    lb.esc(p.rate);
    txt!(lb, "{:.2} KH/s", s.rate);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.height);
    txt!(lb, "H:{}", s.height);
    lb.esc(p.text);
    txt!(lb, " ");
    lb.esc(p.mini);
    txt!(lb, "MB:{}", s.mini);
    lb.esc(p.text);
    txt!(lb, " ");
    lb.esc(p.block);
    txt!(lb, "B:{}", s.blocks);
    lb.esc(p.text);
    txt!(lb, " ");
    lb.esc(p.rej(s.rejected));
    txt!(lb, "R:{}", s.rejected);
    lb.esc(p.text);
    txt!(lb, " | ");
    lb.esc(p.time);
    txt!(lb, "{:02}:{:02}:{:02}", s.hh, s.mm, s.ss);
}

/// Rate plus the two counters worth watching.
fn render_minimal(lb: &mut LineBuf, p: &Palette, s: &StatusFields) {
    lb.esc(p.label);
    txt!(lb, "[DB] ");
    lb.esc(p.rate);
    txt!(lb, "{:.2} KH/s", s.rate);
    lb.esc(p.text);
    txt!(lb, " ");
    lb.esc(p.mini);
    txt!(lb, "MB:{}", s.mini);
    lb.esc(p.text);
    txt!(lb, " ");
    lb.esc(p.block);
    txt!(lb, "B:{}", s.blocks);
}

fn format_status_line(
    shared: &Shared,
    rate: f64,
    average: f64,
    uptime: Duration,
    testnet: bool,
) -> String {
    let fields = StatusFields::sample(shared, rate, average, uptime, testnet);
    let mut lb = LineBuf::new();
    render_full(&mut lb, &Palette::PLAIN, &fields);
    lb.text
}

/// Longest rung that fits, measured in COLUMNS.
///
/// Fitting on `LineBuf::width` rather than string length is what makes colour
/// safe: SGR escapes occupy no columns but plenty of bytes, so a byte-length
/// comparison would reject every rung on every terminal and pin the output to
/// the narrowest one.
fn format_terminal_status_line(
    shared: &Shared,
    rate: f64,
    average: f64,
    uptime: Duration,
    testnet: bool,
    measured_width: Option<usize>,
    palette: &Palette,
) -> LineBuf {
    let budget = status_width_budget(measured_width);
    let fields = StatusFields::sample(shared, rate, average, uptime, testnet);

    for render in TIERS {
        let mut lb = LineBuf::new();
        render(&mut lb, palette, &fields);
        if lb.width <= budget {
            lb.esc(palette.reset);
            return lb;
        }
    }

    // Narrower than the smallest rung. Render UNCOLOURED and clip: truncating a
    // coloured line can cut an escape in half, which wedges the terminal's
    // colour state and prints the escape's tail as literal text. The C miner
    // keeps colour here with an escape-aware compactor (`console.cpp:270-310`);
    // dropping colour is three lines instead of thirty and a terminal this
    // narrow has bigger problems.
    let mut lb = LineBuf::new();
    render_minimal(&mut lb, &Palette::PLAIN, &fields);
    lb.truncate_visible(budget);
    lb
}

/// Column budget for the status line.
///
/// The `-1` keeps the line off the final column: a line that ends exactly at
/// the edge leaves the cursor in a pending-wrap state that some emulators
/// resolve by scrolling.
///
/// The default when the width cannot be read is 80, not 40 — "console of
/// unknown size" is a real case (Git Bash/mintty report a terminal but fail the
/// size query on a pty handle), and assuming a classic 80 keeps the line on one
/// row there. Assuming narrow instead just discards fields nobody asked to
/// lose. `console.cpp:67-73` reasons the same way.
fn status_width_budget(measured_width: Option<usize>) -> usize {
    measured_width.unwrap_or(80).saturating_sub(1)
}

/// Emit a 1 Hz status repaint to a terminal or complete records to a log.
/// Whether the live status row has anything true to report this tick.
///
/// A displayed 0.00 KH/s is not a rare fault — it is what every launch prints.
/// getwork sends no job at connect time (the first arrives on a dispatch tick
/// ~500ms later), so dial + TLS + upgrade + first job is ~1-3s of genuine zero
/// and the first tick at t=1s lands inside it. Reconnect is the same story: the
/// retry sleep here is a flat 10s (miner.go:417), so a flapping link spends
/// most of its time in this state.
///
/// No DERO miner in the ecosystem displays a live zero. tnn-miner suppresses
/// its row two ways (`if (!isConnected) return 1;`, plus a first-hashrate gate
/// commented "Mining hasn't started yet - don't print status, just accumulate
/// stats"); 8lecramm's C miner calls print_status only from inside the worker
/// thread, after the job check; netrunner's GUI shows a grey "---" placeholder
/// and a separate "Offline" label.
///
/// Suppressing beats printing a reason because the transitions are already
/// logged, and a log record rewinds and erases the row before writing — so no
/// stale row is left behind.
fn status_row_has_something_to_say(connected: bool, job_counter: u64) -> bool {
    connected && job_counter > 0
}

fn stats_loop(shared: &Shared, api: &stats_api::ApiState, testnet: bool) {
    let con = term::get();
    let started_at = Instant::now();
    let started_hashes = shared.counter.load(Ordering::Relaxed);
    let mut rates = HashrateWindow::new(started_at, started_hashes);
    let mut last_width = 0usize;
    loop {
        if shared.exit.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
        if shared.exit.load(Ordering::Relaxed) {
            return;
        }

        let now = Instant::now();
        let counter = shared.counter.load(Ordering::Relaxed);
        let uptime = now.saturating_duration_since(started_at);
        let rate = rates.sample(now, counter);
        api.publish_rate_khs(rate);
        let average = counter
            .checked_sub(started_hashes)
            .map_or(0.0, |hashes| rate_khs(hashes, uptime));
        if con.tty {
            // Sampling above runs on every tick, printed or not: skipping it
            // would let the sliding window go stale and the rate would read
            // wrong for ~10s after mining resumes.
            //
            // Only the interactive row is suppressed; the redirected branch
            // below keeps emitting one record per tick, because that stream is
            // machine-parsed and a run of 0.00 during an outage is the correct
            // report there while a gap is not.
            if !status_row_has_something_to_say(
                shared.connected.load(Ordering::Relaxed),
                shared.job_counter.load(Ordering::Relaxed),
            ) {
                // Nothing painted, so nothing to overwrite next time.
                last_width = 0;
                continue;
            }
            let width = term::columns();
            let line = format_terminal_status_line(
                shared,
                rate,
                average,
                uptime,
                testnet,
                width,
                con.palette,
            );

            // Build the whole repaint and emit it with ONE locked write. The
            // line carries no newline, so the cursor rests mid-row between
            // ticks; a log record from the getwork thread landing in the middle
            // of a partial write would wrap the row and leave debris that never
            // gets cleaned up.
            let mut out = String::with_capacity(line.text.len() + 16);
            out.push('\r');
            out.push_str(&line.text);
            if con.vt {
                out.push_str("\x1b[K");
            } else {
                // No erase-to-EOL available. Overwrite the tail of the previous,
                // longer line with spaces — counted in COLUMNS, since with
                // escapes present a byte count would be wildly wrong. Safe to
                // pad here because no VT also means no colour, so the spaces
                // cannot inherit a pen.
                let pad = last_width
                    .min(status_width_budget(width))
                    .saturating_sub(line.width);
                for _ in 0..pad {
                    out.push(' ');
                }
            }
            last_width = line.width;

            let mut err = io::stderr().lock();
            let _ = err.write_all(out.as_bytes());
            let _ = err.flush();
        } else {
            // Redirected: complete records, no escapes, no carriage returns, so
            // `2> miner.log` stays greppable.
            eprintln!(
                "{}",
                format_status_line(shared, rate, average, uptime, testnet)
            );
        }
    }
}

/// Go usage() (miner.go:543-552) — note "status" is listed but NOT
/// implemented (it falls through to the default echo), a Go quirk we keep.
fn usage() {
    eprintln!("commands:");
    eprintln!("\thelp\t\tthis help");
    eprintln!("\tstatus\t\tShow general information");
    eprintln!("\tbye\t\tQuit the miner");
    eprintln!("\tversion\t\tShow version");
    eprintln!("\texit\t\tQuit the miner");
    eprintln!("\tquit\t\tQuit the miner");
}

/// The interactive command loop (miner.go:322-370).
fn command_loop(shared: &Shared) {
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    loop {
        let mut line = String::new();
        match handle.read_line(&mut line) {
            Ok(0) => {
                // EOF: Go blocks on Exit_In_Progress — keep mining forever.
                drop(handle);
                loop {
                    if shared.exit.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(3600));
                }
            }
            Ok(_) => {}
            Err(e) => {
                crate::error!("stdin error: {e}");
                return;
            }
        }
        let line = line.trim();
        let lower = line.to_lowercase();
        let command = lower.split_whitespace().next().unwrap_or("");
        match () {
            _ if line == "help" => usage(),
            _ if line.starts_with("say") => {
                if line[3..].trim().is_empty() {
                    println!("say what?");
                }
            }
            _ if command == "version" => {
                println!(
                    "Version {} OS:{} ARCH:{}",
                    env!("CARGO_PKG_VERSION"),
                    std::env::consts::OS,
                    std::env::consts::ARCH
                );
            }
            _ if lower == "bye" || lower == "exit" || lower == "quit" => {
                shared.exit.store(true, Ordering::SeqCst);
                // The status line is redrawn in place and carries no newline,
                // so without this the shell prompt lands mid-row wearing
                // whatever colour was last set.
                term::restore_on_exit();
                std::process::exit(0);
            }
            _ if line.is_empty() => {}
            _ => println!("you said: {line:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_row_stays_silent_until_there_is_something_to_say() {
        // Every launch: not connected, no job. This is the tick that used to
        // print "[DIRTYBIRD] 0.00 KH/s (0.00 KH/s avg) | Height:0 | ..."
        assert!(!status_row_has_something_to_say(false, 0));
        // Connected, but getwork has not pushed a job yet — workers are still
        // parked, so the rate is genuinely zero.
        assert!(!status_row_has_something_to_say(true, 0));
        // Mining.
        assert!(status_row_has_something_to_say(true, 1));
        // Dropped mid-run: a job was seen earlier so job_counter stays high,
        // but nothing can hash until the redial succeeds. Having once had a job
        // must not keep the row alive.
        assert!(!status_row_has_something_to_say(false, 5));
    }

    #[test]
    fn short_benchmark_flags_parse() {
        let cli = Cli::try_parse_from([
            "dero-miner",
            "-d",
            "127.0.0.1:10100",
            "-w",
            "dero1qypw4nalj2u5q9wfkzeajqw6udlvdrm5m6n7gjzvwm2st2k7fttuqqgwtmndv",
            "-t",
            "20",
        ])
        .expect("short miner flags must parse");

        assert_eq!(cli.daemon_rpc_address.as_deref(), Some("127.0.0.1:10100"));
        assert_eq!(
            cli.wallet_address.as_deref(),
            Some("dero1qypw4nalj2u5q9wfkzeajqw6udlvdrm5m6n7gjzvwm2st2k7fttuqqgwtmndv")
        );
        assert_eq!(cli.mining_threads, Some(20));
    }

    #[test]
    fn hashrate_window_uses_elapsed_time_and_guards_resets() {
        let start = Instant::now();
        let baseline = 42_000;
        let mut steady = HashrateWindow::new(start, baseline);
        for second in 1..=11 {
            assert_eq!(
                steady.sample(
                    start + Duration::from_secs(second),
                    baseline + second * 1_000,
                ),
                1.0
            );
        }

        let mut irregular = HashrateWindow::new(start, baseline);
        assert_eq!(
            irregular.sample(start + Duration::from_secs(2), baseline + 1_000),
            0.5
        );
        assert_eq!(rate_khs(1_000, Duration::ZERO), 0.0);
        assert_eq!(
            irregular.sample(start + Duration::from_secs(3), baseline - 1),
            0.0
        );

        let mut stalled = HashrateWindow::new(start, baseline);
        for second in 1..=5 {
            stalled.sample(
                start + Duration::from_secs(second),
                baseline + second * 1_000,
            );
        }
        for second in 6..=15 {
            let rate = stalled.sample(start + Duration::from_secs(second), baseline + 5_000);
            if second == 10 {
                assert_eq!(rate, 0.5);
            } else if second == 15 {
                assert_eq!(rate, 0.0);
            }
        }
    }

    #[test]
    fn status_line_matches_dirtybird_family_format() {
        let shared = Shared::new();
        shared.our_height.store(2_345_678, Ordering::Relaxed);
        shared.mini_block_counter.store(12, Ordering::Relaxed);
        shared.block_counter.store(3, Ordering::Relaxed);
        shared.rejected.store(1, Ordering::Relaxed);
        shared.difficulty.store(312_979_370, Ordering::Relaxed);

        assert_eq!(
            format_status_line(
                &shared,
                1.234,
                0.987,
                Duration::from_secs(100 * 3_600 + 2 * 60 + 3),
                false,
            ),
            "[DIRTYBIRD] 1.23 KH/s (0.99 KH/s avg) | Height:2345678 | \
             Miniblocks:12 | Blocks:3 | REJ:1 | Diff:312M | 100:02:03"
        );
        assert_eq!(
            format_status_line(&shared, 1.234, 0.987, Duration::from_secs(1), true),
            "[DIRTYBIRD] 1.23 KH/s (0.99 KH/s avg) | Height:2345678 | \
             Miniblocks:12 | Blocks:3 | REJ:1 | Diff:312M | 00:00:01 | TESTNET"
        );
    }

    /// A `Shared` carrying the values used across the layout tests.
    fn sample_shared() -> Shared {
        let shared = Shared::new();
        shared.our_height.store(2_345_678, Ordering::Relaxed);
        shared.mini_block_counter.store(12, Ordering::Relaxed);
        shared.block_counter.store(3, Ordering::Relaxed);
        shared.rejected.store(1, Ordering::Relaxed);
        shared.difficulty.store(312_979_370, Ordering::Relaxed);
        shared
    }

    #[test]
    fn terminal_status_uses_the_longest_layout_that_fits() {
        let shared = sample_shared();
        let args = (1.234, 0.987, Duration::from_secs(3_723), false);
        let plain = &Palette::PLAIN;
        let line = |w: Option<usize>| {
            format_terminal_status_line(&shared, args.0, args.1, args.2, args.3, w, plain)
        };

        // Widest rung is byte-identical to the standalone formatter.
        assert_eq!(
            line(Some(200)).text,
            format_status_line(&shared, args.0, args.1, args.2, args.3)
        );

        // Phone-sized: short tag, uptime kept, difficulty dropped.
        let compact = line(Some(56));
        assert_eq!(
            compact.text,
            "[DB] 1.23 KH/s | H:2345678 MB:12 B:3 R:1 | 01:02:03"
        );
        assert!(compact.width <= 55);

        // 80 columns keeps every field via the abbreviated rungs rather than
        // cliffing to the phone layout.
        let eighty = line(Some(80));
        assert!(
            eighty.text.contains("D:312M"),
            "80 cols keeps difficulty: {}",
            eighty.text
        );
        assert!(eighty.width <= 79);

        // Too narrow for uptime: rate plus the two counters worth watching.
        assert_eq!(line(Some(40)).text, "[DB] 1.23 KH/s MB:12 B:3");

        // Unknown width assumes a classic 80-column console, not a tiny one.
        assert_eq!(line(None).text, eighty.text);
    }

    #[test]
    fn every_layout_stays_within_the_budget() {
        let shared = sample_shared();
        // Values wide enough to push each rung over: a huge height, a huge
        // miniblock count and a four-digit rate.
        shared.our_height.store(u64::MAX, Ordering::Relaxed);
        shared.mini_block_counter.store(u64::MAX, Ordering::Relaxed);

        for width in 1..=200usize {
            for palette in [&Palette::PLAIN, &Palette::COLOUR] {
                let lb = format_terminal_status_line(
                    &shared,
                    123_456_789.12,
                    0.987,
                    Duration::from_secs(3_723),
                    false,
                    Some(width),
                    palette,
                );
                // The anti-wrap invariant: a status line wider than the terminal
                // wraps, and because the repaint only rewinds one row the debris
                // stacks down the screen forever.
                assert!(
                    lb.width <= status_width_budget(Some(width)),
                    "width {} overflowed at terminal {}: {:?}",
                    lb.width,
                    width,
                    lb.text
                );
            }
        }
    }

    #[test]
    fn colour_costs_bytes_but_never_columns() {
        let shared = sample_shared();
        let args = (1.234, 0.987, Duration::from_secs(3_723), false);
        for width in [Some(200), Some(80), Some(56), Some(40), None] {
            let plain = format_terminal_status_line(
                &shared,
                args.0,
                args.1,
                args.2,
                args.3,
                width,
                &Palette::PLAIN,
            );
            let colour = format_terminal_status_line(
                &shared,
                args.0,
                args.1,
                args.2,
                args.3,
                width,
                &Palette::COLOUR,
            );
            // Same layout chosen, same columns occupied...
            assert_eq!(plain.width, colour.width);
            assert_eq!(plain.text.len(), plain.width, "plain must carry no escapes");
            assert!(!plain.text.contains('\u{1b}'));
            // ...but the coloured one is longer in bytes and resets its pen.
            assert!(colour.text.len() > colour.width);
            assert!(colour.text.ends_with("\u{1b}[0m"));
        }
    }

    #[test]
    fn compact_layout_matches_the_reference_miner_on_a_phone() {
        // Pins the exact line from a 54-column Termux session, field for field
        // against the C miner's TIER_COMPACT.
        let shared = Shared::new();
        shared.our_height.store(7_386_579, Ordering::Relaxed);
        let lb = format_terminal_status_line(
            &shared,
            5.04,
            4.9,
            Duration::from_secs(77),
            false,
            Some(54),
            &Palette::PLAIN,
        );
        assert_eq!(
            lb.text,
            "[DB] 5.04 KH/s | H:7386579 MB:0 B:0 R:0 | 00:01:17"
        );
        assert_eq!(lb.width, 50);

        // The same line coloured, pinned byte for byte against the reference
        // miner's per-field palette so a refactor cannot quietly recolour it.
        let colour = format_terminal_status_line(
            &shared,
            5.04,
            4.9,
            Duration::from_secs(77),
            false,
            Some(54),
            &Palette::COLOUR,
        );
        assert_eq!(
            colour.text,
            "\u{1b}[93m[DB] \u{1b}[92m5.04 KH/s\u{1b}[97m | \u{1b}[34mH:7386579\u{1b}[97m \
             \u{1b}[36mMB:0\u{1b}[97m \u{1b}[32mB:0\u{1b}[97m \u{1b}[37mR:0\u{1b}[97m | \
             \u{1b}[37m00:01:17\u{1b}[0m"
        );
        assert_eq!(colour.width, 50, "escapes must not consume columns");
    }

    #[test]
    fn wallet_elision_keeps_head_and_tail() {
        assert_eq!(
            elide_wallet("dero1qyqztaxp2cqdhtve0k0v4dv0cmkpvhs8xukkwhgr5eep9u8urxzqqqgshhnwk"),
            "dero1qyq...hnwk"
        );
        // Too short to gain anything: passed through.
        assert_eq!(elide_wallet("dero1qyq"), "dero1qyq");
        // Non-ASCII would panic a naive byte slice at index 8.
        assert_eq!(
            elide_wallet("dero1qyq\u{00e9}zzzzzzzzzzzz"),
            "dero1qyq\u{00e9}zzzzzzzzzzzz"
        );
    }

    #[test]
    fn difficulty_strings_use_integer_family_units() {
        assert_eq!(difficulty_string(0), "0");
        assert_eq!(difficulty_string(999), "999");
        assert_eq!(difficulty_string(1_500), "1K");
        assert_eq!(difficulty_string(312_979_370), "312M");
        assert_eq!(difficulty_string(2_000_000_000), "2G");
        assert_eq!(difficulty_string(3_500_000_000_000), "3500G");
    }

    #[test]
    fn hf2_heights_match_go_config() {
        assert_eq!(
            MAJOR_HF2_HEIGHT_MAINNET,
            dero_astrobwt::MAJOR_HF2_HEIGHT_MAINNET
        );
        assert_eq!(MAJOR_HF2_HEIGHT_TESTNET, 4); // config/config.go:129
    }
}
