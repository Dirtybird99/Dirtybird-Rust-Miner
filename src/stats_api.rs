//! Plain-text stats endpoint for farm managers (HiveOS, mmpOS).
//!
//! Serves one space-separated line per HTTP request:
//!
//! ```text
//! <hashrate_hs> <uptime_secs> <version> <accepted> <rejected>
//! ```
//!
//! The format matches what the field's DERO farm scripts already parse
//! (deroluna's `localhost:44001/stats`), so `h-stats.sh` / `mmp-stats.sh`
//! stay word-splitting one line instead of growing a JSON parser dependency.
//! `accepted` is miniblocks + full blocks — the daemon rewards both, and the
//! farm dashboards only have one "accepted" column.
//!
//! The server is a plain `std::net::TcpListener` on a dedicated thread, one
//! short-lived connection at a time — the xelis-miner `api_stats` shape. Farm
//! agents poll every few seconds from localhost; there is nothing to pool or
//! parallelize, and no async runtime or HTTP crate is worth its weight here.
//! The thread never joins: it holds no state worth flushing, so process exit
//! is its shutdown path.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::worker::Shared;

/// Rate bridge between the 1 Hz status sampler and the API thread.
///
/// The status loop already owns the sliding-window hashrate; re-deriving it
/// here from `Shared::counter` deltas would give two windows that disagree.
/// Instead the status loop publishes its per-tick rate (in H/s, rounded) and
/// the API reports exactly what the status line shows.
pub struct ApiState {
    started_at: Instant,
    rate_hs: AtomicU64,
}

impl ApiState {
    pub fn new() -> ApiState {
        ApiState {
            started_at: Instant::now(),
            rate_hs: AtomicU64::new(0),
        }
    }

    /// Called once per status tick with the windowed rate in KH/s.
    pub fn publish_rate_khs(&self, rate_khs: f64) {
        self.rate_hs
            .store((rate_khs * 1_000.0).round() as u64, Ordering::Relaxed);
    }
}

/// The response body: `<hs> <uptime> <ver> <acc> <rej>`.
fn stats_line(state: &ApiState, shared: &Shared, now: Instant) -> String {
    let uptime = now.saturating_duration_since(state.started_at).as_secs();
    let accepted = shared.mini_block_counter.load(Ordering::Relaxed)
        + shared.block_counter.load(Ordering::Relaxed);
    let rejected = shared.rejected.load(Ordering::Relaxed);
    format!(
        "{} {} {} {} {}",
        state.rate_hs.load(Ordering::Relaxed),
        uptime,
        env!("CARGO_PKG_VERSION"),
        accepted,
        rejected,
    )
}

fn http_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    )
}

/// Bind `addr` and serve forever. Runs on its own thread; returns only if the
/// listener dies (accept errors are per-connection and skipped).
pub fn serve(addr: &str, state: Arc<ApiState>, shared: Arc<Shared>) {
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            crate::error!("stats api: bind {addr} failed: {e}");
            return;
        }
    };
    crate::info!("Stats:   http://{addr}/stats");
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Drain the request line + headers before responding. curl sends the
        // whole GET in one segment; reading it first avoids the RST-on-close
        // that some curl builds report as an error when unread request bytes
        // remain. The timeout bounds a client that connects and sends nothing.
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let body = stats_line(&state, &shared, Instant::now());
        let _ = stream.write_all(http_response(&body).as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_line_is_five_space_separated_fields() {
        let state = ApiState::new();
        state.publish_rate_khs(1.234_56);
        let shared = Shared::new();
        shared
            .mini_block_counter
            .store(12, std::sync::atomic::Ordering::Relaxed);
        shared
            .block_counter
            .store(3, std::sync::atomic::Ordering::Relaxed);
        shared
            .rejected
            .store(1, std::sync::atomic::Ordering::Relaxed);

        let line = stats_line(&state, &shared, state.started_at + Duration::from_secs(90));
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], "1235"); // 1.23456 KH/s -> 1235 H/s, rounded
        assert_eq!(fields[1], "90");
        assert_eq!(fields[2], env!("CARGO_PKG_VERSION"));
        assert_eq!(fields[3], "15"); // miniblocks + blocks
        assert_eq!(fields[4], "1");
    }

    #[test]
    fn zero_rate_and_fresh_counters_stay_parseable() {
        let state = ApiState::new();
        let shared = Shared::new();
        let line = stats_line(&state, &shared, state.started_at);
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], "0");
        assert_eq!(fields[3], "0");
        assert_eq!(fields[4], "0");
    }

    #[test]
    fn response_has_content_length_matching_body() {
        let body = "1235 90 0.2.12 15 1";
        let resp = http_response(body);
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(resp.ends_with(&format!("\r\n\r\n{body}")));
    }
}
