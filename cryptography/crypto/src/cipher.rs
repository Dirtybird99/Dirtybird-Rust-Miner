//! Transfer-payload cryptography. Port of `cryptography/crypto/userdata.go`:
//! SHAKE256 KDF, ECDH shared secret, and the XChaCha20 (zero-nonce) symmetric
//! XOR used to encrypt the 145-byte RPCPayload.

use crate::keccak::keccak256;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use dero_bn256::G1;
use num_bigint::BigUint;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Go: `ShakeXOF(prefix, parts...)` — SHAKE256 over prefix ‖ parts, 32-byte out.
pub fn shake_xof(prefix: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(prefix);
    for p in parts {
        h.update(p);
    }
    let mut reader = h.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// Go: `GenerateSharedSecret(secret, peer)` — Keccak256((peer·secret).compress()).
pub fn generate_shared_secret(secret: &BigUint, peer: &G1) -> [u8; 32] {
    let shared = peer.scalar_mult(&secret.to_bytes_be());
    keccak256(&[&shared.compress()])
}

/// Go: `EncryptDecryptUserData(key, input)` — XChaCha20 (24-byte zero nonce),
/// XOR in place. Symmetric (encrypt == decrypt).
pub fn encrypt_decrypt_user_data(key: &[u8; 32], data: &mut [u8]) {
    let nonce = [0u8; 24];
    let mut cipher = XChaCha20::new(key.into(), (&nonce).into());
    cipher.apply_keystream(data);
}
