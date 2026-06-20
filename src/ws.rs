//! Minimal RFC 6455 websocket CLIENT — replaces gorilla/websocket for the
//! getwork connection (cmd/dero-miner/miner.go:406-427).
//!
//! Hand-rolled (workspace policy: no heavyweight deps) covering exactly what
//! the getwork protocol needs:
//!  - HTTP/1.1 Upgrade handshake with a random base64 `Sec-WebSocket-Key`,
//!    verifying `101` + `Sec-WebSocket-Accept == base64(SHA1(key+GUID))`;
//!  - MASKED client frames — REQUIRED: the daemon's nbio websocket server
//!    rejects unmasked client frames (RFC 6455 §5.1);
//!  - text(1)/binary(2)/close(8)/ping(9→pong 10) opcodes, 2/8-byte extended
//!    lengths, continuation-frame reassembly.
//!
//! The frame reader is incremental (`try_read_message` returns `Ok(None)` when
//! the underlying read times out mid-frame) so the connection thread can poll
//! reads on a short socket timeout and interleave share submissions on the
//! same stream — Go instead uses two goroutines over gorilla's split
//! reader/writer (miner.go:425 read loop, miner.go:513 submit under a mutex).

use std::io::{self, Read, Write};

/// RFC 6455 §1.3 handshake GUID.
pub const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

/// Refuse frames larger than this (a job push is <1 KB; this is pure DoS armor).
const MAX_FRAME_PAYLOAD: u64 = 16 * 1024 * 1024;

/// Standard base64 (RFC 4648, with padding). ~20 lines beats a dependency;
/// only used for the handshake key/accept.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 0x3f] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 0x3f] as char } else { '=' });
    }
    out
}

/// `Sec-WebSocket-Accept` for a given `Sec-WebSocket-Key` (RFC 6455 §4.2.2):
/// `base64(SHA1(key + GUID))`. Verified against the RFC's own vector and
/// Go-generated vectors (vectors/minerwork.json).
pub fn compute_accept(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    base64_encode(&h.finalize())
}

/// A complete (reassembled) websocket message.
#[derive(Debug, PartialEq, Eq)]
pub enum WsMessage {
    Text(Vec<u8>),
    Binary(Vec<u8>),
    /// Peer sent a close frame (we echo it before reporting).
    Close,
}

pub(crate) struct RawFrame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// Parse one frame from the front of `buf`. `Ok(None)` = incomplete (need more
/// bytes). On success returns the frame and the number of bytes consumed.
/// Handles both masked and unmasked frames (server frames are unmasked; we
/// tolerate masked for test loopbacks).
pub(crate) fn parse_frame(buf: &[u8]) -> io::Result<Option<(RawFrame, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    if buf[0] & 0x70 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ws: nonzero RSV bits"));
    }
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let mut len = (buf[1] & 0x7f) as u64;
    let mut off = 2usize;
    if len == 126 {
        if buf.len() < 4 {
            return Ok(None);
        }
        len = u16::from_be_bytes([buf[2], buf[3]]) as u64;
        off = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return Ok(None);
        }
        len = u64::from_be_bytes(buf[2..10].try_into().unwrap());
        off = 10;
    }
    if len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("ws: frame too large ({len})")));
    }
    let mut mask = [0u8; 4];
    if masked {
        if buf.len() < off + 4 {
            return Ok(None);
        }
        mask.copy_from_slice(&buf[off..off + 4]);
        off += 4;
    }
    let len = len as usize;
    if buf.len() < off + len {
        return Ok(None);
    }
    let mut payload = buf[off..off + len].to_vec();
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(Some((RawFrame { fin, opcode, payload }, off + len)))
}

/// Encode a single FIN frame. `mask: Some(key)` for client→server frames
/// (mandatory on the wire), `None` for server frames (tests).
pub(crate) fn encode_frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0f));
    let mask_bit = if mask.is_some() { 0x80u8 } else { 0 };
    if payload.len() < 126 {
        out.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// Websocket client over any blocking `Read + Write` stream (here: rustls
/// `StreamOwned` over TCP).
pub struct WsClient<S> {
    stream: S,
    /// Raw bytes read but not yet consumed as frames.
    buf: Vec<u8>,
    /// In-flight fragmented message: (first-frame opcode, payload so far).
    frag: Option<(u8, Vec<u8>)>,
    sent_close: bool,
}

impl<S: Read + Write> WsClient<S> {
    /// Client opening handshake (RFC 6455 §4.1): send the Upgrade request for
    /// `path`, require `HTTP/1.1 101` and the exact `Sec-WebSocket-Accept`.
    /// `host` fills the Host header (Go: url.URL Host = daemon_rpc_address).
    ///
    /// On a non-101 reply the error carries the response head — the getwork
    /// server answers a bad wallet address with a plain "err: ..." body
    /// instead of upgrading (websocket_getwork_server.go:274-303).
    pub fn handshake(mut stream: S, host: &str, path: &str) -> io::Result<Self> {
        let key_bytes: [u8; 16] = rand::random();
        let key = base64_encode(&key_bytes);
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        // read until the end of the response head
        let mut head = Vec::with_capacity(512);
        let mut tmp = [0u8; 1024];
        let head_end = loop {
            if let Some(pos) = find_subslice(&head, b"\r\n\r\n") {
                break pos + 4;
            }
            if head.len() > 64 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "ws: oversized handshake response"));
            }
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("ws: connection closed during handshake: {}", String::from_utf8_lossy(&head)),
                ));
            }
            head.extend_from_slice(&tmp[..n]);
        };
        let leftover = head.split_off(head_end);
        let head_str = String::from_utf8_lossy(&head);

        let status_line = head_str.lines().next().unwrap_or("");
        let code = status_line.split_whitespace().nth(1).unwrap_or("");
        if code != "101" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ws: handshake rejected: {}", head_str.trim_end()),
            ));
        }
        let expected = compute_accept(&key);
        let mut accept_ok = false;
        for line in head_str.lines().skip(1) {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("sec-websocket-accept") {
                    accept_ok = value.trim() == expected;
                }
            }
        }
        if !accept_ok {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ws: bad Sec-WebSocket-Accept"));
        }

        Ok(WsClient { stream, buf: leftover, frag: None, sent_close: false })
    }

    /// Access the underlying stream (e.g. to shorten the socket read timeout
    /// after the handshake).
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Send a masked text frame (gorilla `WriteJSON` equivalent, miner.go:513).
    pub fn write_text(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = encode_frame(OPCODE_TEXT, payload, Some(rand::random()));
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }

    fn write_control(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let frame = encode_frame(opcode, payload, Some(rand::random()));
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }

    /// Try to produce the next complete message. `Ok(None)` means "no full
    /// message buffered and the read timed out / would block" — call again.
    /// Pings are answered transparently; a Close frame is echoed once and
    /// surfaced as `WsMessage::Close`.
    pub fn try_read_message(&mut self) -> io::Result<Option<WsMessage>> {
        loop {
            // consume as many buffered frames as possible
            while let Some((frame, used)) = parse_frame(&self.buf)? {
                self.buf.drain(..used);
                match frame.opcode {
                    OPCODE_PING => self.write_control(OPCODE_PONG, &frame.payload)?,
                    OPCODE_PONG => {}
                    OPCODE_CLOSE => {
                        if !self.sent_close {
                            self.sent_close = true;
                            let _ = self.write_control(OPCODE_CLOSE, &frame.payload);
                        }
                        return Ok(Some(WsMessage::Close));
                    }
                    OPCODE_TEXT | OPCODE_BINARY => {
                        if frame.fin {
                            return Ok(Some(match frame.opcode {
                                OPCODE_TEXT => WsMessage::Text(frame.payload),
                                _ => WsMessage::Binary(frame.payload),
                            }));
                        }
                        self.frag = Some((frame.opcode, frame.payload));
                    }
                    OPCODE_CONTINUATION => {
                        let Some((opcode, mut payload)) = self.frag.take() else {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "ws: continuation without start"));
                        };
                        payload.extend_from_slice(&frame.payload);
                        if frame.fin {
                            return Ok(Some(match opcode {
                                OPCODE_TEXT => WsMessage::Text(payload),
                                _ => WsMessage::Binary(payload),
                            }));
                        }
                        self.frag = Some((opcode, payload));
                    }
                    other => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("ws: unknown opcode {other}")));
                    }
                }
            }
            // need more bytes
            let mut tmp = [0u8; 8192];
            match self.stream.read(&mut tmp) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ws: connection closed")),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    return Ok(None)
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Blocking read of the next message (used where the socket has a long or
    /// no read timeout). The miner main loop polls `try_read_message` instead.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn read_message(&mut self) -> io::Result<WsMessage> {
        loop {
            if let Some(msg) = self.try_read_message()? {
                return Ok(msg);
            }
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn base64_rfc4648_vectors() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn rfc6455_accept_vector() {
        // RFC 6455 §1.3 / §4.2.2 worked example.
        assert_eq!(compute_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn accept_vectors_match_go() {
        // vectors/minerwork.json (go-harness/minerwork): Go crypto/sha1+base64.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/minerwork.json");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = v["ws_accepts"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            assert_eq!(
                compute_accept(c["key"].as_str().unwrap()),
                c["accept"].as_str().unwrap(),
                "key {}",
                c["key"]
            );
        }
    }

    #[test]
    fn frame_roundtrip_masked_and_unmasked() {
        for &mask in &[None, Some([0x37u8, 0xfa, 0x21, 0x3d])] {
            for len in [0usize, 1, 125, 126, 127, 65535, 65536, 70000] {
                let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let frame = encode_frame(OPCODE_TEXT, &payload, mask);
                let (parsed, used) = parse_frame(&frame).unwrap().expect("complete frame");
                assert_eq!(used, frame.len());
                assert!(parsed.fin);
                assert_eq!(parsed.opcode, OPCODE_TEXT);
                assert_eq!(parsed.payload, payload, "len {len} mask {mask:?}");
            }
        }
    }

    #[test]
    fn rfc6455_masked_hello_example() {
        // RFC 6455 §5.7: single-frame masked text "Hello".
        let wire = [0x81u8, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
        let (frame, used) = parse_frame(&wire).unwrap().unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(frame.payload, b"Hello");
        // and our encoder reproduces the exact bytes with the same mask key
        assert_eq!(encode_frame(OPCODE_TEXT, b"Hello", Some([0x37, 0xfa, 0x21, 0x3d])), wire);
    }

    #[test]
    fn parse_frame_incremental() {
        let frame = encode_frame(OPCODE_TEXT, b"job json here", Some([1, 2, 3, 4]));
        for cut in 0..frame.len() {
            assert!(parse_frame(&frame[..cut]).unwrap().is_none(), "cut {cut} must be incomplete");
        }
        assert!(parse_frame(&frame).unwrap().is_some());
    }

    /// Full client handshake + traffic against a thread acting as the getwork
    /// server (plain TCP — WsClient is generic over the stream, TLS adds
    /// nothing to the framing logic). The server side verifies the request
    /// line, computes the accept per RFC, pushes a job-like text frame with a
    /// trailing '\n' (the server's json.Encoder artifact), and checks that the
    /// client's submit frame is MASKED (nbio enforces this).
    #[test]
    fn handshake_and_roundtrip_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut tmp = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut tmp).unwrap();
                req.extend_from_slice(&tmp[..n]);
            }
            let req = String::from_utf8(req).unwrap();
            assert!(req.starts_with("GET /ws/deroABC HTTP/1.1\r\n"), "{req}");
            assert!(req.to_lowercase().contains("upgrade: websocket"));
            let key = req
                .lines()
                .find_map(|l| {
                    let (n, v) = l.split_once(':')?;
                    n.trim().eq_ignore_ascii_case("sec-websocket-key").then(|| v.trim().to_string())
                })
                .expect("key header");
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                compute_accept(&key)
            );
            s.write_all(resp.as_bytes()).unwrap();
            // job push: text frame, unmasked (server side), trailing newline
            let job = b"{\"jobid\":\"1.0.notified\",\"difficulty\":\"9\"}\n";
            s.write_all(&encode_frame(OPCODE_TEXT, job, None)).unwrap();
            // read the client's submit frame: MUST be masked
            let mut buf = Vec::new();
            loop {
                if let Some((frame, _)) = parse_frame(&buf).unwrap() {
                    return (buf[1] & 0x80 != 0, frame.payload);
                }
                let n = s.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
            }
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut ws = WsClient::handshake(stream, &addr.to_string(), "/ws/deroABC").unwrap();
        let msg = ws.read_message().unwrap();
        assert_eq!(msg, WsMessage::Text(b"{\"jobid\":\"1.0.notified\",\"difficulty\":\"9\"}\n".to_vec()));
        ws.write_text(b"{\"jobid\":\"1.0.notified\",\"mbl_blob\":\"00\"}").unwrap();

        let (was_masked, payload) = server.join().unwrap();
        assert!(was_masked, "client frames must be masked (RFC 6455 / nbio server requirement)");
        assert_eq!(payload, b"{\"jobid\":\"1.0.notified\",\"mbl_blob\":\"00\"}");
    }

    #[test]
    fn handshake_rejects_non_101() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut tmp = [0u8; 4096];
            let _ = s.read(&mut tmp).unwrap();
            // the getwork server's bad-address path: plain HTTP, body "err: ..."
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nerr: addr").unwrap();
        });
        let stream = TcpStream::connect(addr).unwrap();
        let err = match WsClient::handshake(stream, &addr.to_string(), "/ws/bad") {
            Err(e) => e,
            Ok(_) => panic!("handshake must fail on a non-101 response"),
        };
        assert!(err.to_string().contains("handshake rejected"), "{err}");
    }
}
