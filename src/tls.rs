//! TLS-over-TCP client with certificate verification disabled — the miner side
//! of Go's `dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}`
//! (cmd/dero-miner/miner.go:410-412).
//!
//! The getwork server is TLS-only (`AddrsTLS`, cmd/derod/rpc/
//! websocket_getwork_server.go:343) and presents a random self-signed EC P-256
//! certificate generated at daemon startup (websocket_getwork_server.go:399-456),
//! so skipping verification IS the protocol, not a shortcut. The `NoVerify`
//! verifier mirrors p2p/node/src/transport/tls.rs:21-55 — copied rather
//! than imported because that module is welded to the KCP session type and this
//! crate must not depend on dero-node.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

/// A verifier that accepts ANY server certificate — Go `InsecureSkipVerify: true`.
#[derive(Debug)]
struct NoVerify {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

fn to_io<E: std::fmt::Debug>(e: E) -> io::Error {
    io::Error::other(format!("tls: {e:?}"))
}

/// rustls client config with the no-op certificate verifier installed.
pub fn no_verify_client_config() -> io::Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let schemes = provider.signature_verification_algorithms.supported_schemes();
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(to_io)
        .map(|b| {
            b.dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify { schemes }))
                .with_no_client_auth()
        })
}

/// The established miner transport: TLS client over a plain TcpStream.
pub type TlsTcpStream = rustls::StreamOwned<ClientConnection, TcpStream>;

/// Dial `host_port` (e.g. `"minernode1.dero.live:10100"`), complete the TLS
/// handshake with no certificate verification, and return the stream. The
/// socket read timeout is left at `timeout` — the caller shortens it after the
/// websocket upgrade to poll reads.
pub fn connect_tls(host_port: &str, timeout: Duration) -> io::Result<TlsTcpStream> {
    let addrs: Vec<_> = host_port.to_socket_addrs()?.collect();
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, format!("no addresses for {host_port}"));
    let mut sock = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => last_err = e,
        }
    }
    let sock = sock.ok_or(last_err)?;
    sock.set_nodelay(true)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    // SNI: the server never checks it (random self-signed cert) and we never
    // verify, so any name works — use the real host when it parses.
    let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    let server_name = ServerName::try_from(host.to_string())
        .or_else(|_| ServerName::try_from("dero.getwork".to_string()))
        .map_err(to_io)?;

    let config = no_verify_client_config()?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name).map_err(to_io)?;
    let mut sock = sock;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| {
            io::Error::new(e.kind(), format!("tls handshake with {host_port}: {e}"))
        })?;
    }
    Ok(rustls::StreamOwned::new(conn, sock))
}
