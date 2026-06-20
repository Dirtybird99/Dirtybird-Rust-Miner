//! Zether `Statement` and `Witness`, and the Statement serialization.
//! Port of `cryptography/crypto/protocol_structures.go`.
//!
//! The public-key "pointers" are `blake2s-256(compressed_pubkey)[..bytes_per_pk]`
//! (Go uses `graviton.Sum`, which is BLAKE2s-256).

use blake2::{Blake2s256, Digest};
use dero_bn256::G1;
use num_bigint::BigUint;

/// LEB128 unsigned varint (Go `binary.PutUvarint`); local copy to keep
/// dero-crypto independent of dero-protocol.
fn put_uvarint(out: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        out.push((x as u8) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
}

/// BLAKE2s-256 (Go: `graviton.Sum`).
pub fn graviton_sum(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Smallest power `p` with `2^p == n` (Go: `GetPowerof2`).
pub fn power_of_2(n: usize) -> u8 {
    assert!(n.is_power_of_two() && n >= 1, "ring size must be a power of 2");
    n.trailing_zeros() as u8
}

/// Go: `Statement`. `cln`/`crn`/`publickeylist` are present for proving but are
/// NOT serialized into the tx (the chain reconstructs them); serialization
/// writes power, bytes_per_pk, fees, D, pubkey pointers, C, and roothash.
#[derive(Clone, Debug, Default)]
pub struct Statement {
    pub ring_size: u64,
    pub cln: Vec<G1>,
    pub crn: Vec<G1>,
    pub bytes_per_publickey: u8,
    pub publickeylist_pointers: Vec<u8>,
    pub publickeylist: Vec<G1>,
    pub c: Vec<G1>,
    pub d: G1,
    pub fees: u64,
    pub roothash: [u8; 32],
}

/// Go: `Witness`.
#[derive(Clone, Debug)]
pub struct Witness {
    pub secret_key: BigUint,
    pub r: BigUint,
    pub transfer_amount: u64,
    pub balance: u64,
    pub index: Vec<usize>,
}

impl Statement {
    /// Go: `Statement.Serialize` (fresh path: computes pointers from the
    /// public-key list via BLAKE2s). Returns the serialized bytes and fills
    /// `publickeylist_pointers`.
    pub fn serialize(&mut self) -> Vec<u8> {
        let mut w = Vec::new();

        if self.publickeylist_pointers.is_empty() {
            w.push(power_of_2(self.publickeylist.len()));
            w.push(self.bytes_per_publickey);
            put_uvarint(&mut w, self.fees);
            w.extend_from_slice(&self.d.compress());
            let mut pointers = Vec::new();
            for pk in &self.publickeylist {
                let hashed = graviton_sum(&pk.compress());
                let take = &hashed[..self.bytes_per_publickey as usize];
                w.extend_from_slice(take);
                pointers.extend_from_slice(take);
            }
            self.publickeylist_pointers = pointers;
        } else {
            let count = self.publickeylist_pointers.len() / self.bytes_per_publickey as usize;
            w.push(power_of_2(count));
            w.push(self.bytes_per_publickey);
            put_uvarint(&mut w, self.fees);
            w.extend_from_slice(&self.d.compress());
            w.extend_from_slice(&self.publickeylist_pointers);
        }

        let count = self.publickeylist_pointers.len() / self.bytes_per_publickey as usize;
        for i in 0..count {
            w.extend_from_slice(&self.c[i].compress());
        }
        w.extend_from_slice(&self.roothash);
        w
    }

    /// Go: `Statement.Deserialize` — the inverse of [`Statement::serialize`].
    /// The chain reconstructs `cln`/`crn`/`publickeylist` from the pointers, so
    /// those are left empty here (matching the Go reference).
    pub fn deserialize(r: &mut &[u8]) -> Result<Statement, &'static str> {
        use crate::read::{read_uvarint, take, take_g1};

        let power = take(r, 1)?[0];
        // Go (protocol_structures.go:104-107): `RingSize = 1 << length` then
        // reject `RingSize > 128` BEFORE reading bytes_per_publickey. Go's int
        // shift yields 0 for length>=64; `checked_shl(..).unwrap_or(0)` matches
        // that and avoids the debug-mode shift-overflow panic. Rejecting here
        // (rather than only later in verify_tx_stateless) also prevents a
        // memory-DoS: an oversized ring would otherwise allocate
        // `ring_size * bytes_per_publickey` before the downstream reject.
        let ring_size = 1u64.checked_shl(power as u32).unwrap_or(0);
        if ring_size > 128 {
            return Err("ring size is too large");
        }
        let bytes_per_publickey = take(r, 1)?[0];
        if bytes_per_publickey == 0 {
            return Err("statement: bytes_per_publickey == 0");
        }
        let fees = read_uvarint(r)?;
        let d = take_g1(r)?;

        let count = ring_size as usize;
        let pointers = take(r, count * bytes_per_publickey as usize)?.to_vec();

        let mut c = Vec::with_capacity(count);
        for _ in 0..count {
            c.push(take_g1(r)?);
        }

        let roothash: [u8; 32] = take(r, 32)?.try_into().unwrap();

        Ok(Statement {
            ring_size,
            cln: Vec::new(),
            crn: Vec::new(),
            bytes_per_publickey,
            publickeylist_pointers: pointers,
            publickeylist: Vec::new(),
            c,
            d,
            fees,
            roothash,
        })
    }
}

#[cfg(test)]
mod ringsize_tests {
    use super::Statement;

    /// A4b: a ring-size power that yields > 128 is rejected at deserialize (Go
    /// protocol_structures.go:105), and a power >= 64 (which Go's `1<<length`
    /// makes 0) must NOT panic the shift.
    #[test]
    fn rejects_oversized_ringsize() {
        // power = 8 → ring 256 > 128 → "ring size is too large"
        let buf = [8u8];
        let err = Statement::deserialize(&mut &buf[..]).unwrap_err();
        assert_eq!(err, "ring size is too large");
    }

    #[test]
    fn power_ge_64_does_not_panic() {
        // power = 64 → checked_shl→None→0 (matches Go `1<<64`==0); not >128, so
        // it proceeds and fails cleanly reading the next byte from an empty
        // buffer — the point is NO shift-overflow panic.
        let buf = [64u8];
        assert!(Statement::deserialize(&mut &buf[..]).is_err());
    }
}
