//! ElGamal homomorphic balance ciphertext. Port of the parts of
//! `algebra_elgamal.go` and `balance_serdes.go` needed to read a balance.
//!
//! A balance is stored on-chain as `NonceBalance = varint(nonce) ‖ ElGamal`,
//! where `ElGamal.Serialize() = Left(33 compressed) ‖ Right(33 compressed)`.
//! For an account with secret `x` (public key `G·x`):
//!   Left  = G·balance + (G·x)·r,   Right = G·r
//! so `Left − x·Right = G·balance`, which is then solved for `balance` by the
//! BSGS decoder.

use dero_bn256::G1;
use num_bigint::BigUint;

/// An ElGamal ciphertext (the homomorphic balance): two G1 points.
#[derive(Clone, Copy, Debug)]
pub struct ElGamal {
    pub left: G1,
    pub right: G1,
}

#[derive(Debug, thiserror::Error)]
pub enum ElGamalError {
    #[error("bad elgamal length: expected 66, got {0}")]
    BadLength(usize),
    #[error("point decode: {0}")]
    Point(&'static str),
}

impl ElGamal {
    /// Go: `ElGamal.Deserialize` — exactly 66 bytes: Left(33) ‖ Right(33).
    pub fn deserialize(data: &[u8]) -> Result<ElGamal, ElGamalError> {
        if data.len() != 66 {
            return Err(ElGamalError::BadLength(data.len()));
        }
        let left = G1::decompress(&data[..33]).map_err(ElGamalError::Point)?;
        let right = G1::decompress(&data[33..66]).map_err(ElGamalError::Point)?;
        Ok(ElGamal { left, right })
    }

    /// Go: `ElGamal.Serialize` — Left(33 compressed) ‖ Right(33 compressed).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(66);
        out.extend_from_slice(&self.left.compress());
        out.extend_from_slice(&self.right.compress());
        out
    }

    /// Go: `ElGamal.Plus(value)` — add a *clear* amount to the balance:
    /// `Left += G·value` (G = the DERO base generator `base_g`). Used to credit
    /// registration starter balances and the miner block reward.
    pub fn plus(&self, value: u64) -> ElGamal {
        let gv = crate::generators::base_g().scalar_mult(&BigUint::from(value).to_bytes_be());
        ElGamal {
            left: G1::add(&self.left, &gv),
            right: self.right,
        }
    }

    /// Go: `ConstructElGamal(pubkey, ElGamal_BASE_G)` — a registration
    /// zero-balance (`Left = pubkey`, `Right = base_g`), before any `Plus`.
    pub fn registration_zero(pubkey: &G1) -> ElGamal {
        ElGamal {
            left: *pubkey,
            right: crate::generators::base_g(),
        }
    }

    /// Homomorphic add of two ElGamal ciphertexts (component-wise point add).
    /// Used by the chain to apply a transfer's commitment to a stored balance:
    /// `new = balance + (C_i, D)`.
    pub fn add(&self, other: &ElGamal) -> ElGamal {
        ElGamal {
            left: G1::add(&self.left, &other.left),
            right: G1::add(&self.right, &other.right),
        }
    }

    /// Go: `balance_point = Left + (−(Right·secret))` — the ElGamal decryption
    /// that yields `G·balance`.
    pub fn decrypt_to_point(&self, secret: &BigUint) -> G1 {
        let right_x = self.right.scalar_mult(&secret.to_bytes_be());
        G1::add(&self.left, &G1::neg(&right_x))
    }
}

/// Go: `crypto.NonceBalance` (`balance_serdes.go`) — the value stored per account
/// in the balance tree: `varint(nonce_height) ‖ ElGamal.Serialize()`.
#[derive(Clone, Copy, Debug)]
pub struct NonceBalance {
    pub nonce_height: u64,
    pub balance: ElGamal,
}

impl NonceBalance {
    /// Go: `NonceBalance.Marshal/Serialize`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut x = self.nonce_height;
        while x >= 0x80 {
            out.push((x as u8) | 0x80);
            x >>= 7;
        }
        out.push(x as u8);
        out.extend_from_slice(&self.balance.serialize());
        out
    }

    /// Go: `NonceBalance.Unmarshal` — varint nonce then the 66-byte ElGamal.
    pub fn deserialize(buf: &[u8]) -> Result<NonceBalance, ElGamalError> {
        let mut nonce_height: u64 = 0;
        let mut shift = 0u32;
        let mut i = 0usize;
        loop {
            if i >= buf.len() {
                return Err(ElGamalError::BadLength(buf.len()));
            }
            let b = buf[i];
            i += 1;
            if b < 0x80 {
                nonce_height |= (b as u64) << shift;
                break;
            }
            nonce_height |= ((b & 0x7f) as u64) << shift;
            shift += 7;
        }
        let balance = ElGamal::deserialize(&buf[i..])?;
        Ok(NonceBalance { nonce_height, balance })
    }
}
