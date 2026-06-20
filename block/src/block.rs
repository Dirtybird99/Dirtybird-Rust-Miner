//! Block structure and serialization. Port of `block/block.go`.
//!
//! The block identifier (BLID) is **NIST SHA3-256** of the full serialization
//! (`block.go` imports `golang.org/x/crypto/sha3` → `sha3.Sum256`), which is a
//! different hash from the legacy Keccak used in the wallet/crypto layer. See
//! [`dero_crypto::sha3_256`].

use crate::miniblock::{MiniBlock, MiniBlocksCollection, MINIBLOCK_SIZE};
use crate::transaction::Transaction;
use crate::varint::{put_uvarint, read_uvarint};
use dero_crypto::sha3_256;

/// Go: `config.BLOCK_TIME` (seconds).
pub const BLOCK_TIME: u64 = 18;
/// Go: `config.MINIBLOCK_HIGHDIFF`.
pub const MINIBLOCK_HIGHDIFF: u64 = 9;
/// Soft-fork height after which the strict non-final miniblock count is enforced.
pub const MINIBLOCK_COUNT_SOFT_HF_HEIGHT: u64 = 399000;

/// Go: `block.Block`. `tips` and `tx_hashes` are 32-byte hashes; the only fully
/// embedded transaction is `miner_tx` (a COINBASE) — the rest of the block's
/// transactions are referenced by hash.
#[derive(Clone, Debug)]
pub struct Block {
    pub major_version: u64,
    pub minor_version: u64,
    /// Milliseconds since epoch (serialized big-endian, 8 bytes).
    pub timestamp: u64,
    pub height: u64,
    pub miner_tx: Transaction,
    /// 32-byte balance-tree root hash recorded by the block.
    pub proof: [u8; 32],
    pub tips: Vec<[u8; 32]>,
    pub miniblocks: Vec<MiniBlock>,
    pub tx_hashes: Vec<[u8; 32]>,
}

impl Block {
    /// Go: `serialize(skiplastminiblock)`. With `skip_last_miniblock == false`
    /// this is `Serialize()`; with `true`, `SerializeWithoutLastMiniBlock()`.
    pub fn serialize_inner(&self, skip_last_miniblock: bool) -> Vec<u8> {
        let mut out = Vec::new();

        put_uvarint(&mut out, self.major_version);
        put_uvarint(&mut out, self.minor_version);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        put_uvarint(&mut out, self.height);

        out.extend_from_slice(&self.miner_tx.serialize());
        out.extend_from_slice(&self.proof);

        put_uvarint(&mut out, self.tips.len() as u64);
        for tip in &self.tips {
            out.extend_from_slice(tip);
        }

        // Go writes a literal 0 byte when there are no miniblocks; that is
        // identical to `put_uvarint(0)`. With skiplastminiblock it emits one
        // fewer miniblock.
        if self.miniblocks.is_empty() {
            out.push(0);
        } else {
            let n = if skip_last_miniblock {
                self.miniblocks.len() - 1
            } else {
                self.miniblocks.len()
            };
            put_uvarint(&mut out, n as u64);
            for mbl in &self.miniblocks[..n] {
                out.extend_from_slice(&mbl.serialize());
            }
        }

        put_uvarint(&mut out, self.tx_hashes.len() as u64);
        for h in &self.tx_hashes {
            out.extend_from_slice(h);
        }

        out
    }

    /// Go: `Serialize` — full block (block header + miner tx + miniblocks + txs).
    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_inner(false)
    }

    /// Go: `SerializeWithoutLastMiniBlock`.
    pub fn serialize_without_last_miniblock(&self) -> Vec<u8> {
        self.serialize_inner(true)
    }

    /// Go: `GetHash` — the BLID, `sha3.Sum256(Serialize())` (NIST SHA3-256).
    pub fn get_hash(&self) -> [u8; 32] {
        sha3_256(&[&self.serialize()])
    }

    /// Go: `GetHashSkipLastMiniBlock`.
    pub fn get_hash_skip_last_miniblock(&self) -> [u8; 32] {
        sha3_256(&[&self.serialize_without_last_miniblock()])
    }

    /// Go: `GetTipsHash` — SHA3-256 over the concatenated tip hashes.
    pub fn get_tips_hash(&self) -> [u8; 32] {
        let concat: Vec<u8> = self.tips.iter().flat_map(|t| t.iter().copied()).collect();
        sha3_256(&[&concat])
    }

    /// Go: `GetTXSHash` — SHA3-256 over the concatenated tx hashes.
    pub fn get_txs_hash(&self) -> [u8; 32] {
        let concat: Vec<u8> = self.tx_hashes.iter().flat_map(|t| t.iter().copied()).collect();
        sha3_256(&[&concat])
    }

    /// Go: `Verify_MiniBlocks` (blockchain/miniblocks_consensus.go) — the
    /// (stateless) structural consensus checks on a block's miniblock set:
    /// counts, the mandatory final miniblock, per-miniblock height/tip linkage,
    /// and the deduplicated non-final count after the soft fork.
    pub fn verify_miniblocks(&self) -> Result<(), String> {
        if self.height == 0 && !self.miniblocks.is_empty() {
            return Err("Genesis block cannot have miniblocks".into());
        }
        if self.height == 0 {
            return Ok(());
        }
        if self.miniblocks.is_empty() {
            return Err("All blocks except genesis must have miniblocks".into());
        }

        let final_count = self.miniblocks.iter().filter(|m| m.final_).count();
        if final_count < 1 {
            return Err("No final miniblock".into());
        }

        let expected = BLOCK_TIME - MINIBLOCK_HIGHDIFF + 1;
        if self.miniblocks.len() as u64 != expected {
            return Err(format!(
                "incorrect number of miniblocks expected {} actual {}",
                expected,
                self.miniblocks.len()
            ));
        }

        let mut collection = MiniBlocksCollection::new();
        for mbl in &self.miniblocks {
            if self.height != mbl.height {
                return Err(format!(
                    "MiniBlock has invalid height block height {} mbl height {}",
                    self.height, mbl.height
                ));
            }
            if self.tips.len() != mbl.past_count as usize {
                return Err("MiniBlock has wrong number of tips".into());
            }
            match self.tips.len() {
                0 => return Err("all miniblocks genesis must point to tip".into()),
                1 => {
                    let tip0 = u32::from_be_bytes(self.tips[0][..4].try_into().unwrap());
                    if tip0 != mbl.past[0] {
                        return Err("MiniBlock has invalid tip".into());
                    }
                }
                _ => return Err("we only support 1 tips".into()),
            }
            // final miniblocks are rejected by the collection (ignored, as in Go)
            let _ = collection.insert_miniblock(mbl.clone());
        }

        if self.height >= MINIBLOCK_COUNT_SOFT_HF_HEIGHT {
            let want = BLOCK_TIME - MINIBLOCK_HIGHDIFF;
            if collection.count() as u64 != want {
                return Err(format!(
                    "block contains invalid number of miniblocks count {} expected {}",
                    collection.count(),
                    want
                ));
            }
        }
        Ok(())
    }

    /// Go: `Verify_MiniBlocks_HashCheck` (blockchain/miniblocks_consensus.go:32-50)
    /// — the final-miniblock binding check: the LAST miniblock must be HighDiff +
    /// Final, and its `KeyHash[0..16]` must equal
    /// `sha3_256(SerializeWithoutLastMiniBlock())[0..16]`, binding the mined PoW
    /// to the block's content (miner_tx/tips/tx_hashes + the non-final
    /// miniblocks). Non-final miniblocks are exempt — their keyhash is the
    /// miner-address keyhash.
    ///
    /// Go enforces this for every non-genesis complete block
    /// (`Add_Complete_Block`, blockchain.go:585-590); the bound keyhash is
    /// produced by `ConvertBlockToMiniblock`'s final branch
    /// (miner_block.go:364-374), which hashes the template's full `Serialize()`
    /// *before* the final miniblock is appended — byte-identical input.
    pub fn verify_miniblocks_hashcheck(&self) -> Result<(), String> {
        let last = self.miniblocks.last().ok_or("corrupted block")?;
        if !last.high_diff {
            return Err("corrupted block".into());
        }
        if !last.final_ {
            return Err("corrupted block".into());
        }
        let block_header_hash = sha3_256(&[&self.serialize_without_last_miniblock()]);
        if last.key_hash[..] != block_header_hash[..16] {
            return Err(format!(
                "MiniBlock has corrupted header expected {} actual {}",
                hex::encode(block_header_hash),
                hex::encode(last.key_hash)
            ));
        }
        Ok(())
    }

    /// Go: `Deserialize` — parse a complete block from its raw serialization.
    pub fn deserialize(buf: &[u8]) -> Result<Block, &'static str> {
        let mut rest = buf;
        // Go `Deserialize` caps the varint byte-count (`done`) per call site:
        // tips ≤1 byte (`block.go:256` `done>1`), miniblocks ≤2 (`block.go:274`
        // `done>2`); version/height/tx_count only reject `done<=0`. A non-minimal
        // varint (e.g. `0x80 0x00` = 2-byte encoding of 0) is thus accepted at
        // tx_count but REJECTED at tips/miniblocks. `max_bytes==0` = uncapped.
        let take_varint = |rest: &mut &[u8], max_bytes: usize| -> Result<u64, &'static str> {
            let (v, n) = read_uvarint(rest);
            if n == 0 || (max_bytes != 0 && n > max_bytes) {
                return Err("block: invalid varint");
            }
            *rest = &rest[n..];
            Ok(v)
        };

        let major_version = take_varint(&mut rest, 0)?;
        let minor_version = take_varint(&mut rest, 0)?;

        if rest.len() < 8 {
            return Err("block: incomplete timestamp");
        }
        let timestamp = u64::from_be_bytes(rest[..8].try_into().unwrap());
        rest = &rest[8..];

        let height = take_varint(&mut rest, 0)?;

        // miner tx (COINBASE) — advance by exactly the bytes it consumed.
        let (miner_tx, consumed) = Transaction::deserialize(rest)?;
        rest = &rest[consumed..];

        if rest.len() < 32 {
            return Err("block: incomplete proof");
        }
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&rest[..32]);
        rest = &rest[32..];

        let tips_count = take_varint(&mut rest, 1)?;
        let mut tips = Vec::with_capacity(tips_count as usize);
        for _ in 0..tips_count {
            if rest.len() < 32 {
                return Err("block: truncated tips");
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&rest[..32]);
            rest = &rest[32..];
            tips.push(h);
        }

        let miniblocks_count = take_varint(&mut rest, 2)?;
        let mut miniblocks = Vec::with_capacity(miniblocks_count as usize);
        for _ in 0..miniblocks_count {
            if rest.len() < MINIBLOCK_SIZE {
                return Err("block: truncated miniblock");
            }
            let mbl = MiniBlock::deserialize(&rest[..MINIBLOCK_SIZE])?;
            rest = &rest[MINIBLOCK_SIZE..];
            miniblocks.push(mbl);
        }

        let tx_count = take_varint(&mut rest, 0)?;
        let mut tx_hashes = Vec::with_capacity(tx_count as usize);
        for _ in 0..tx_count {
            if rest.len() < 32 {
                return Err("block: truncated tx hashes");
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&rest[..32]);
            rest = &rest[32..];
            tx_hashes.push(h);
        }

        Ok(Block {
            major_version,
            minor_version,
            timestamp,
            height,
            miner_tx,
            proof,
            tips,
            miniblocks,
            tx_hashes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block() -> Block {
        let height = 7_000_000u64;
        let mut tip0 = [0u8; 32];
        tip0[..4].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
        let past0 = 0xAABBCCDDu32;

        // 9 distinct non-final + 1 final == BLOCK_TIME - MINIBLOCK_HIGHDIFF + 1 = 10
        let mut miniblocks = Vec::new();
        for i in 0..9u32 {
            miniblocks.push(MiniBlock {
                version: 1,
                high_diff: false,
                final_: false,
                past_count: 1,
                timestamp: i as u16,
                height,
                past: [past0, 0],
                key_hash: [0u8; 16],
                flags: 0,
                nonce: [i, 0, 0], // distinct → no collision
            });
        }
        miniblocks.push(MiniBlock {
            version: 1,
            high_diff: true,
            final_: true,
            past_count: 1,
            timestamp: 99,
            height,
            past: [past0, 0],
            key_hash: [0u8; 16],
            flags: 0,
            nonce: [0xFF, 0, 0],
        });

        Block {
            major_version: 1,
            minor_version: 1,
            timestamp: 0,
            height,
            miner_tx: Transaction::new_coinbase([0u8; 33]),
            proof: [0u8; 32],
            tips: vec![tip0],
            miniblocks,
            tx_hashes: vec![],
        }
    }

    #[test]
    fn verify_miniblocks_accepts_valid() {
        assert!(sample_block().verify_miniblocks().is_ok());
    }

    #[test]
    fn verify_miniblocks_rejects_wrong_count() {
        let mut b = sample_block();
        b.miniblocks.pop(); // 9 total
        assert!(b.verify_miniblocks().is_err());
    }

    #[test]
    fn verify_miniblocks_rejects_no_final() {
        let mut b = sample_block();
        b.miniblocks.last_mut().unwrap().final_ = false;
        assert!(b.verify_miniblocks().is_err());
    }

    #[test]
    fn verify_miniblocks_rejects_height_mismatch() {
        let mut b = sample_block();
        b.miniblocks[0].height += 1;
        assert!(b.verify_miniblocks().is_err());
    }

    #[test]
    fn verify_miniblocks_rejects_bad_tip_linkage() {
        let mut b = sample_block();
        b.miniblocks[0].past[0] ^= 0xFF;
        assert!(b.verify_miniblocks().is_err());
    }

    #[test]
    fn verify_miniblocks_rejects_duplicate_nonfinal() {
        let mut b = sample_block();
        // make two non-final identical → collision drops the count below 9
        b.miniblocks[1] = b.miniblocks[0].clone();
        assert!(b.verify_miniblocks().is_err());
    }

    /// Bind the final miniblock's keyhash the way `ConvertBlockToMiniblock`'s
    /// final branch does: sha3-256 over the block WITHOUT the final miniblock.
    fn bind_final_keyhash(b: &mut Block) {
        let bh = sha3_256(&[&b.serialize_without_last_miniblock()]);
        b.miniblocks.last_mut().unwrap().key_hash.copy_from_slice(&bh[..16]);
    }

    #[test]
    fn hashcheck_accepts_bound_final_miniblock() {
        let mut b = sample_block();
        b.tx_hashes = vec![[0x61u8; 32], [0x62u8; 32]];
        bind_final_keyhash(&mut b);
        b.verify_miniblocks_hashcheck().expect("bound final keyhash must pass");
    }

    #[test]
    fn hashcheck_rejects_tampered_tx_hashes() {
        let mut b = sample_block();
        b.tx_hashes = vec![[0x61u8; 32], [0x62u8; 32]];
        bind_final_keyhash(&mut b);
        // an attacker swaps the tx set under the validly-PoW'd final miniblock
        b.tx_hashes[0][0] ^= 0xff;
        let err = b.verify_miniblocks_hashcheck().unwrap_err();
        assert!(err.contains("corrupted header"), "got: {err}");
    }

    #[test]
    fn hashcheck_rejects_wrong_final_flags() {
        // Go returns "corrupted block" when the last miniblock is not
        // HighDiff+Final (miniblocks_consensus.go:35-41).
        let mut b = sample_block();
        bind_final_keyhash(&mut b);
        b.miniblocks.last_mut().unwrap().high_diff = false;
        assert_eq!(b.verify_miniblocks_hashcheck().unwrap_err(), "corrupted block");

        let mut b = sample_block();
        bind_final_keyhash(&mut b);
        b.miniblocks.last_mut().unwrap().final_ = false;
        assert_eq!(b.verify_miniblocks_hashcheck().unwrap_err(), "corrupted block");

        let mut b = sample_block();
        b.miniblocks.clear();
        assert_eq!(b.verify_miniblocks_hashcheck().unwrap_err(), "corrupted block");
    }
}
