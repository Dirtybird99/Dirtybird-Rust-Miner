//! DERO AstroBWTv3 CPU miner — the runnable binary. Connects to a DERO daemon/pool
//! over TLS-WebSocket getwork, mines with 2-way batched AstroBWTv3, submits shares.
use clap::Parser;
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dero_miner::config::Config;
use dero_miner::state::MinerState;
use dero_miner::{hash_once, mining, net, term};

const KAT: &str = "54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea";

fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();

    // Correctness gate — refuse to mine if the hash is wrong (a faster wrong hash is a
    // rejected share).
    let got = hex::encode(hash_once(b"a"));
    if got != KAT {
        eprintln!("FATAL: KAT failed (pow(\"a\")={got})");
        std::process::exit(1);
    }

    if cfg.wallet.is_empty() {
        eprintln!("FATAL: wallet address required (-w <dero...>)");
        std::process::exit(1);
    }
    if !cfg.wallet.starts_with("dero") && !cfg.wallet.starts_with("deto") {
        eprintln!("FATAL: wallet should start with 'dero' (mainnet) or 'deto' (testnet)");
        std::process::exit(1);
    }

    let (host, port) = cfg.host_port();
    let threads = cfg.get_threads();
    term::enable_vt();
    term::log_info("Dirtybird Miner");
    term::log_info_pair("Server", &format!("{host}:{port}"));
    term::log_info_pair("Wallet", &cfg.wallet);
    term::log_info_pair("Threads", &threads.to_string());
    println!();

    let state = Arc::new(MinerState::new());

    {
        let s = state.clone();
        let _ = ctrlc::set_handler(move || {
            eprintln!("\nshutting down…");
            s.quit.store(true, Ordering::Relaxed);
        });
    }

    let net_thread = {
        let s = state.clone();
        let wallet = cfg.wallet.clone();
        std::thread::spawn(move || net::run(s, host, port, wallet))
    };
    let workers = mining::spawn_workers(state.clone(), threads, cfg.affinity);

    // Reporter loop.
    let start = Instant::now();
    let mut prev = 0u64;
    let mut prev_t = Instant::now();
    while !state.quit.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(cfg.report_interval.max(1)));
        if state.quit.load(Ordering::Relaxed) {
            break;
        }
        let now = state.total_hashes.load(Ordering::Relaxed);
        let dt = prev_t.elapsed().as_secs_f64().max(0.001);
        let rate = (now - prev) as f64 / dt / 1000.0;
        let avg = now as f64 / start.elapsed().as_secs_f64().max(0.001) / 1000.0;
        let (height, diff) = state.snapshot().map(|(j, _)| (j.height, j.difficulty)).unwrap_or((0, 0));
        let mb = state.miniblocks.load(Ordering::Relaxed);
        let blk = state.blocks.load(Ordering::Relaxed);
        let rej = state.rejected.load(Ordering::Relaxed);
        let el = start.elapsed().as_secs();
        let (hh, mm, ss) = (el / 3600, (el % 3600) / 60, el % 60);
        let rc = if rej > 0 { term::BRIGHT_RED } else { term::WHITE };
        let w = term::BRIGHT_WHITE;
        // [DIRTYBIRD] rate KH/s (avg KH/s avg) | Height | Miniblocks | Blocks | REJ | Diff | HH:MM:SS
        let mut line = format!(
            "\r\x1b[K{by}[DIRTYBIRD] {bg}{rate:.2} KH/s{w} ({g}{avg:.2} KH/s avg{w}) | \
             {blue}Height:{height}{w} | {mag}Miniblocks:{mb}{w} | {g}Blocks:{blk}{w} | \
             {rc}REJ:{rej}{w} | {mag}Diff:{diff}{w} | {wt}{hh:02}:{mm:02}:{ss:02}{rst}",
            by = term::BRIGHT_YELLOW,
            bg = term::BRIGHT_GREEN,
            g = term::GREEN,
            blue = term::BLUE,
            mag = term::MAGENTA,
            wt = term::WHITE,
            rst = term::RESET,
            diff = term::abbrev(diff),
        );
        if cfg.verbose {
            line.push_str(&format!(
                "{w} | sub:{} drops:{}",
                state.submitted.load(Ordering::Relaxed),
                state.stale_drops.load(Ordering::Relaxed),
            ));
        }
        print!("{line}");
        let _ = std::io::stdout().flush();
        prev = now;
        prev_t = Instant::now();
    }

    for w in workers {
        let _ = w.join();
    }
    let _ = net_thread.join();
    println!("\nminer stopped.");
    Ok(())
}
