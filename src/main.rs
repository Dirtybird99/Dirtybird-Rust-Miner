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
mod sustained;
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
use worker::Shared;

/// Go: config.MAJOR_HF2_HEIGHT — mainnet 481600, testnet 4 (config/config.go:108,129).
const MAJOR_HF2_HEIGHT_MAINNET: u64 = 481_600;
const MAJOR_HF2_HEIGHT_TESTNET: u64 = 4;

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
}

fn main() {
    let cli = Cli::parse();

    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut threads = cli.mining_threads.unwrap_or(cpus as i64);
    if threads > cpus as i64 {
        eprintln!(
            "Mining threads is more than available CPUs. This is NOT optimal thread_count={threads} max_possible={cpus}"
        );
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
        eprintln!("This program supports maximum 256 CPU cores. available={threads}");
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
    if cli.no_2way {
        std::env::set_var("MINER_2WAY", "0");
    }

    // Suffix-array hashing path (byte-exact either way). MATERIALIZE+SHA the SA
    // wins when the box is UNDER-SUBSCRIBED — bandwidth headroom makes the SA
    // write/read roundtrip cheap and the simpler control flow wins: measured
    // +5.3% at 20T on the 13700HX. The FUSED stream (no materialization) wins at
    // FULL occupancy (24-thread bandwidth saturation). Auto-select by occupancy;
    // `--fused` forces fused. An explicit DERO_MATERIALIZE env is always honored.
    if std::env::var_os("DERO_MATERIALIZE").is_none() {
        let full_occupancy = threads >= cpus.max(1);
        if !cli.fused && !full_occupancy {
            std::env::set_var("DERO_MATERIALIZE", "1");
        }
    }

    // --wallet-address: bech32-validated + network prefix check
    // (globals.ParseValidateAddress; miner.go:149-156).
    let Some(wallet_raw) = cli.wallet_address.as_deref() else {
        eprintln!("Wallet address is required (--wallet-address=dero1...)");
        std::process::exit(1);
    };
    let wallet_address = match Address::from_string(wallet_raw) {
        Ok(addr) => {
            if addr.mainnet == cli.testnet {
                eprintln!(
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
            eprintln!("Wallet address is invalid: {e}");
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

    eprintln!("DERO Stargate HE AstroBWT miner (Rust port)");
    eprintln!(
        "OS:{} ARCH:{} THREADS:{} MODE:{}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        threads,
        if cli.testnet { "testnet" } else { "mainnet" }
    );
    eprintln!("System will mine to \"{wallet_address}\" with {threads} threads. Good Luck!!");

    let shared = Arc::new(Shared::new());
    let (submit_tx, submit_rx) = mpsc::channel::<SubmitBlockParams>();

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

    // Optional 2 MB large pages for the per-worker scratch (op-loop stream + SA).
    // Must run before any worker allocates `AstroBwtScratch`. Mirrors the
    // `--sustained` harness (sustained.rs); off by default pending per-CPU A/B.
    if cli.large_pages {
        let lp = dero_astrobwt::enable_large_pages();
        eprintln!(
            "large pages: {}",
            if lp {
                "2MB enabled"
            } else {
                "unavailable (4KB)"
            }
        );
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

    // 1 Hz status repaint (Go: the prompt goroutine, miner.go:225-294)
    {
        let shared = Arc::clone(&shared);
        let testnet = cli.testnet;
        std::thread::Builder::new()
            .name("stats".into())
            .spawn(move || stats_loop(&shared, testnet))
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
        if shared.exit.load(Ordering::Relaxed) {
            return;
        }
        eprintln!("connecting to url=wss://{daemon_rpc_address}{path}");

        // dial + TLS (long timeouts for the handshakes)
        let stream = match tls::connect_tls(daemon_rpc_address, Duration::from_secs(10)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error connecting to server: {e} server_address={daemon_rpc_address}");
                eprintln!("Will try in 10 secs server_address={daemon_rpc_address}");
                std::thread::sleep(Duration::from_secs(10)); // miner.go:417
                continue;
            }
        };
        let mut conn = match ws::WsClient::handshake(stream, daemon_rpc_address, &path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error connecting to server: {e} server_address={daemon_rpc_address}");
                eprintln!("Will try in 10 secs server_address={daemon_rpc_address}");
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
            eprintln!("set_read_timeout: {e}");
        }

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
                    eprintln!("submitting share: {txt}");
                }
                if let Err(e) = conn.write_text(txt.as_bytes()) {
                    eprintln!("connection error (submit): {e}");
                    continue 'reconnect; // immediate redial, like miner.go:425-427
                }
            }
            match conn.try_read_message() {
                Ok(Some(ws::WsMessage::Text(data))) | Ok(Some(ws::WsMessage::Binary(data))) => {
                    let result: GetBlockTemplateResult = match serde_json::from_slice(&data) {
                        Ok(r) => r,
                        Err(e) => {
                            // gorilla ReadJSON would error too => reconnect
                            eprintln!("connection error (bad job json): {e}");
                            continue 'reconnect;
                        }
                    };
                    if debug {
                        eprintln!("recv: {}", String::from_utf8_lossy(&data).trim_end());
                    }
                    // miner.go:430-445
                    {
                        let mut g = shared.job.write().unwrap();
                        *g = result.clone();
                    }
                    shared.job_counter.fetch_add(1, Ordering::Release);
                    if !result.lasterror.is_empty() {
                        eprintln!("received error: err={}", result.lasterror);
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
                    eprintln!("connection error: server closed the websocket");
                    continue 'reconnect;
                }
                Ok(None) => {} // read timeout — poll again
                Err(e) => {
                    eprintln!("connection error: {e}");
                    continue 'reconnect;
                }
            }
        }
    }
}

/// Go's local-hashrate string (miner.go:253-263): MH/s and KH/s with 3
/// decimals, plain H/s otherwise; empty when not mining.
fn mining_speed_string(speed: f64) -> String {
    if speed > 1_000_000.0 {
        format!("MINING @ {:.3} MH/s", speed as f32 / 1_000_000.0)
    } else if speed > 1_000.0 {
        format!("MINING @ {:.3} KH/s", speed as f32 / 1_000.0)
    } else if speed > 0.0 {
        format!("MINING @ {speed:.0} H/s")
    } else {
        String::new()
    }
}

/// Compact scalar formatting for the daemon's exact job difficulty.
fn difficulty_string(difficulty: u64) -> String {
    if difficulty > 1_000_000_000_000 {
        format!("{:.3}T", difficulty as f64 / 1e12)
    } else if difficulty > 1_000_000_000 {
        format!("{:.3}G", difficulty as f64 / 1e9)
    } else if difficulty > 1_000_000 {
        format!("{:.3}M", difficulty as f64 / 1e6)
    } else if difficulty > 1_000 {
        format!("{:.3}K", difficulty as f64 / 1e3)
    } else {
        difficulty.to_string()
    }
}

/// 1 Hz repaint of the status line (the Go readline prompt, miner.go:225-294;
/// plain `\r` stderr line here — no readline dep).
fn stats_loop(shared: &Shared, testnet: bool) {
    let mut last_counter = 0u64;
    let mut last_counter_time = Instant::now();
    let mut last_height = u64::MAX;
    let mut last_len = 0usize;
    loop {
        if shared.exit.load(Ordering::Relaxed) {
            return;
        }
        let counter = shared.counter.load(Ordering::Relaxed);
        let height = shared.our_height.load(Ordering::Relaxed);
        if counter != last_counter || height != last_height {
            let elapsed = last_counter_time.elapsed().as_secs_f64();
            let speed = (counter - last_counter) as f64 / elapsed.max(1e-9);
            last_counter = counter;
            last_counter_time = Instant::now();
            last_height = height;

            let line = format!(
                "DERO Miner: Height {} BLOCKS {} MiniBlocks {} Rejected {} DIFF {} {}{}>>>",
                height,
                shared.block_counter.load(Ordering::Relaxed),
                shared.mini_block_counter.load(Ordering::Relaxed),
                shared.rejected.load(Ordering::Relaxed),
                difficulty_string(shared.difficulty.load(Ordering::Relaxed)),
                mining_speed_string(speed),
                if testnet { " TESTNET" } else { "" },
            );
            let pad = last_len.saturating_sub(line.len());
            eprint!("\r{line}{}", " ".repeat(pad));
            let _ = io::stderr().flush();
            last_len = line.len();
        }
        std::thread::sleep(Duration::from_secs(1));
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
                eprintln!("stdin error: {e}");
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

    /// Local rate stays Go-compatible; difficulty is an unmodified scalar.
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

        assert_eq!(
            cli.daemon_rpc_address.as_deref(),
            Some("127.0.0.1:10100")
        );
        assert_eq!(
            cli.wallet_address.as_deref(),
            Some("dero1qypw4nalj2u5q9wfkzeajqw6udlvdrm5m6n7gjzvwm2st2k7fttuqqgwtmndv")
        );
        assert_eq!(cli.mining_threads, Some(20));
    }

    #[test]
    fn rate_and_difficulty_strings() {
        assert_eq!(mining_speed_string(0.0), "");
        assert_eq!(mining_speed_string(512.0), "MINING @ 512 H/s");
        assert_eq!(mining_speed_string(1_500.0), "MINING @ 1.500 KH/s");
        assert_eq!(mining_speed_string(2_500_000.0), "MINING @ 2.500 MH/s");

        assert_eq!(difficulty_string(0), "0");
        assert_eq!(difficulty_string(999), "999");
        assert_eq!(difficulty_string(1_500), "1.500K");
        assert_eq!(difficulty_string(312_979_370), "312.979M");
        assert_eq!(difficulty_string(2_000_000_000), "2.000G");
        assert_eq!(difficulty_string(3_500_000_000_000), "3.500T");
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
