//! CLI configuration (DeroLuna-compatible flags).
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "dero-miner", version, about = "DERO AstroBWTv3 CPU miner (Rust) — zero dev fee")]
pub struct Config {
    /// Daemon/pool address as host:port (TLS-WebSocket getwork).
    #[arg(short = 'd', long, default_value = "community-pools.mysrv.cloud:10300")]
    pub daemon: String,

    /// DERO wallet address (rewards paid here). Defaults to the project pool wallet;
    /// pass `-w <your dero1… address>` to mine to your own.
    #[arg(short = 'w', long, default_value = "dero1qyvuemd6z0uzsx5ufc99f0jhyzvvpysmrd2t3526ht7a9dfh7jve2qqt0vu5y")]
    pub wallet: String,

    /// Worker thread count (0 = auto-detect physical cores).
    #[arg(short = 't', long, default_value_t = 0)]
    pub threads: usize,

    /// Pin worker threads to P-cores first + HIGH priority (recommended).
    #[arg(long, default_value_t = true)]
    pub affinity: bool,

    /// Verbose funnel stats.
    #[arg(short = 'V', long, default_value_t = false)]
    pub verbose: bool,

    /// Stats report interval (seconds).
    #[arg(long, default_value_t = 1)]
    pub report_interval: u64,
}

impl Config {
    /// Split `daemon` into (host, port). Defaults port to 10300 if absent.
    pub fn host_port(&self) -> (String, u16) {
        match self.daemon.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(10300)),
            None => (self.daemon.clone(), 10300),
        }
    }

    pub fn get_threads(&self) -> usize {
        if self.threads == 0 {
            num_cpus::get_physical().max(1)
        } else {
            self.threads
        }
    }
}
