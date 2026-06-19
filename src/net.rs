//! DERO "getwork" client over a TLS-WebSocket (port of net.zig). Synchronous
//! tungstenite; one thread interleaves reading job frames and sending share frames.
use crate::difficulty::target_from_difficulty;
use crate::state::{Job, MinerState, BLOB_LEN};
use std::io::ErrorKind;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, Error, Message, WebSocket};

type Ws = WebSocket<MaybeTlsStream<TcpStream>>;

fn set_read_timeout(ws: &mut Ws, d: Option<Duration>) {
    match ws.get_mut() {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_read_timeout(d);
        }
        MaybeTlsStream::Rustls(s) => {
            let _ = s.get_ref().set_read_timeout(d);
        }
        _ => {}
    }
}

// DERO daemons/pools commonly serve getwork over TLS with a self-signed cert, so the
// original native-tls path set danger_accept_invalid_certs/hostnames. rustls makes that
// explicit: a verifier that accepts any certificate and any signature. (Mining traffic
// is not authenticated by TLS identity here — the share/job protocol stands on its own.)
#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1, ECDSA_SHA1_Legacy, RSA_PKCS1_SHA256, ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384, ECDSA_NISTP384_SHA384, RSA_PKCS1_SHA512, ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, ED25519, ED448,
        ]
    }
}

fn connect(url: &str, host: &str, port: u16) -> anyhow::Result<Ws> {
    // Pin the ring provider explicitly so we never depend on a process-default being
    // installed (ClientConfig::builder() would otherwise panic at runtime if none is).
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(config));
    let stream = TcpStream::connect((host, port))?;
    stream.set_nodelay(true).ok();
    let (mut ws, _resp) =
        tungstenite::client_tls_with_config(url, stream, None, Some(connector))?;
    // 50 ms read timeout so the loop can interleave share-sends + quit checks.
    set_read_timeout(&mut ws, Some(Duration::from_millis(50)));
    Ok(ws)
}

struct Counters {
    miniblocks: i64,
    blocks: i64,
    rejected: i64,
}

fn parse_job(text: &str) -> Option<(Job, Counters)> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let blob_hex = v.get("blockhashing_blob")?.as_str()?;
    if blob_hex.len() != BLOB_LEN * 2 {
        return None;
    }
    let jobid = v.get("jobid")?.as_str()?;
    if jobid.is_empty() {
        return None;
    }
    let bytes = hex::decode(blob_hex).ok()?;
    if bytes.len() != BLOB_LEN {
        return None;
    }
    let mut blob = [0u8; BLOB_LEN];
    blob.copy_from_slice(&bytes);
    let difficulty = v.get("difficultyuint64").and_then(|x| x.as_u64()).unwrap_or(0);
    let height = v.get("height").and_then(|x| x.as_i64()).unwrap_or(0);
    let counters = Counters {
        miniblocks: v.get("miniblocks").and_then(|x| x.as_i64()).unwrap_or(0),
        blocks: v.get("blocks").and_then(|x| x.as_i64()).unwrap_or(0),
        rejected: v.get("rejected").and_then(|x| x.as_i64()).unwrap_or(0),
    };
    let target = target_from_difficulty(difficulty);
    Some((
        Job { blob, jobid: jobid.to_string(), target, difficulty, height },
        counters,
    ))
}

fn build_submit(jobid: &str, blob: &[u8; BLOB_LEN]) -> String {
    format!("{{\"jobid\":\"{}\",\"mbl_blob\":\"{}\"}}", jobid, hex::encode(blob))
}

/// Run one connected session until disconnect/quit. Returns true if it was "useful"
/// (delivered a job or stayed up ≥10 s) so the caller can reset backoff.
fn session(ws: &mut Ws, state: &MinerState) -> bool {
    let start = Instant::now();
    let mut last_data = Instant::now();
    let mut got_job = false;
    loop {
        if state.quit.load(Ordering::Relaxed) {
            return got_job;
        }
        // Drain staged shares.
        while let Some(share) = state.take_share() {
            let msg = build_submit(&share.jobid, &share.blob);
            if ws.send(Message::Text(msg)).is_err() {
                return got_job || start.elapsed() >= Duration::from_secs(10);
            }
            state.submitted.fetch_add(1, Ordering::Relaxed);
        }
        match ws.read() {
            Ok(Message::Text(t)) => {
                last_data = Instant::now();
                if let Some((job, c)) = parse_job(&t) {
                    state.miniblocks.store(c.miniblocks, Ordering::Relaxed);
                    state.blocks.store(c.blocks, Ordering::Relaxed);
                    state.rejected.store(c.rejected, Ordering::Relaxed);
                    state.set_job(job);
                    got_job = true;
                }
            }
            Ok(Message::Binary(_)) | Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                last_data = Instant::now();
            }
            Ok(Message::Close(_)) => return got_job || start.elapsed() >= Duration::from_secs(10),
            Ok(_) => {}
            Err(Error::Io(e)) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // Idle read; dead-link watchdog (60 s of no bytes).
                if last_data.elapsed() > Duration::from_secs(60) {
                    return got_job || start.elapsed() >= Duration::from_secs(10);
                }
            }
            Err(_) => return got_job || start.elapsed() >= Duration::from_secs(10),
        }
    }
}

/// Blocking connect + reconnect loop. Spawn this on its own thread.
pub fn run(state: Arc<MinerState>, host: String, port: u16, wallet: String) {
    let url = format!("wss://{host}:{port}/ws/{wallet}");
    let mut backoff_ms = 1000u64;
    while !state.quit.load(Ordering::Relaxed) {
        crate::term::log_info(&format!("Connecting ({host}:{port})"));
        let t0 = Instant::now();
        match connect(&url, &host, port) {
            Ok(mut ws) => {
                crate::term::log_info(&format!("Connected ({host}:{port}) ({} ms)", t0.elapsed().as_millis()));
                state.connected.store(true, Ordering::Relaxed);
                let useful = session(&mut ws, &state);
                state.connected.store(false, Ordering::Relaxed);
                let _ = ws.close(None);
                backoff_ms = if useful { 1000 } else { (backoff_ms * 2).min(30000) };
            }
            Err(e) => {
                crate::term::log_info(&format!("Connect failed ({host}:{port}): {e}"));
                backoff_ms = (backoff_ms * 2).min(30000);
            }
        }
        let mut slept = 0u64;
        while slept < backoff_ms && !state.quit.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(250));
            slept += 250;
        }
    }
}
