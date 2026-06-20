//! MiniBlock structure and serialization. Port of `block/miniblock.go`.
//!
//! A MiniBlock serializes to **exactly 48 bytes** (the DERO HE STARGATE layout).
//! Big-endian throughout. It is the unit over which the AstroBWT PoW is computed
//! (`GetPoWHash`), and blocks embed a fixed-size array of them.

use dero_crypto::sha3_256;

/// Fixed serialized size of a miniblock (Go: `MINIBLOCK_SIZE`).
pub const MINIBLOCK_SIZE: usize = 48;

/// Go: `block.MiniBlock`. The first byte packs version/flags/past-count:
/// `version | past_count<<6 | (high_diff?0x10) | (final?0x20)`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MiniBlock {
    /// Lower 4 bits of byte 0 (current network version == 1).
    pub version: u8,
    /// Bit 4 (0x10) of byte 0 — triggers high difficulty.
    pub high_diff: bool,
    /// Bit 5 (0x20) of byte 0 — final miniblock.
    pub final_: bool,
    /// Bits 6-7 of byte 0 — number of past tips (1 or 2).
    pub past_count: u8,
    /// Rolling timestamp (ms granularity, wraps), 2 bytes BE.
    pub timestamp: u16,
    /// Block height, serialized in 5 bytes BE (must be < 2^40).
    pub height: u64,
    /// Up to 2 past miniblock collision-tips (4 bytes BE each).
    pub past: [u32; 2],
    /// First 16 bytes of the miner keyhash (the rest of the 32-byte hash is
    /// trimmed and not serialized).
    pub key_hash: [u8; 16],
    /// Miner flags / extra nonce (4 bytes BE).
    pub flags: u32,
    /// 12-byte nonce as three BE u32 (2^96 search space).
    pub nonce: [u32; 3],
}

/// Go: `MiniBlockKey` — the DAG key (height + past tips) a miniblock sorts under.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MiniBlockKey {
    pub height: u64,
    pub past0: u32,
    pub past1: u32,
}

/// Go: `MiniBlocksCollection` — groups miniblocks by [`MiniBlockKey`], used to
/// count/dedup the non-final miniblocks of a block (final ones are rejected).
#[derive(Default)]
pub struct MiniBlocksCollection {
    pub collection: std::collections::HashMap<MiniBlockKey, Vec<MiniBlock>>,
}

impl MiniBlocksCollection {
    pub fn new() -> Self {
        MiniBlocksCollection::default()
    }

    /// Total miniblocks held (Go: `Count`).
    pub fn count(&self) -> usize {
        self.collection.values().map(|v| v.len()).sum()
    }

    /// Go: `MiniBlocksCollection.IsCollision` — whether this exact miniblock is
    /// already held under its DAG key.
    pub fn is_collision(&self, mbl: &MiniBlock) -> bool {
        self.collection
            .get(&mbl.get_key())
            .is_some_and(|v| v.iter().any(|m| m == mbl))
    }

    /// Go: `InsertMiniBlock` — rejects Final miniblocks and exact-duplicate
    /// collisions; otherwise appends under the miniblock's key.
    pub fn insert_miniblock(&mut self, mbl: MiniBlock) -> Result<(), &'static str> {
        if mbl.final_ {
            return Err("Final cannot be inserted");
        }
        if self.is_collision(&mbl) {
            return Err("collision");
        }
        self.collection.entry(mbl.get_key()).or_default().push(mbl);
        Ok(())
    }
}

impl MiniBlock {
    /// Go: `GetKey`.
    pub fn get_key(&self) -> MiniBlockKey {
        MiniBlockKey {
            height: self.height,
            past0: self.past[0],
            past1: self.past[1],
        }
    }

    /// Go: `SanityCheck`. A consensus-level validity check (not required for
    /// byte-faithful serialization of already-valid miniblocks).
    pub fn sanity_check(&self) -> Result<(), &'static str> {
        if self.version >= 16 {
            return Err("version not supported");
        }
        if self.past_count > 2 {
            return Err("tips cannot be more than 2");
        }
        if self.past_count == 0 {
            return Err("miniblock must have tips");
        }
        if self.height >= 0xff_ffff_ffff {
            return Err("miniblock height not possible");
        }
        if self.past_count == 2 && self.past[0] == self.past[1] {
            return Err("tips cannot collide");
        }
        Ok(())
    }

    /// Go: `Serialize` — exactly 48 bytes. (Go panics on a failed SanityCheck;
    /// we leave validation to [`MiniBlock::sanity_check`] so this stays
    /// infallible for the round-trip path — valid miniblocks are unaffected.)
    pub fn serialize(&self) -> [u8; MINIBLOCK_SIZE] {
        let mut out = [0u8; MINIBLOCK_SIZE];

        let mut version_byte = self.version | (self.past_count << 6);
        if self.high_diff {
            version_byte |= 0x10;
        }
        if self.final_ {
            version_byte |= 0x20;
        }
        out[0] = version_byte;

        out[1..3].copy_from_slice(&self.timestamp.to_be_bytes());

        // height: lower 5 bytes of its big-endian u64 encoding (bytes 3..8).
        let h = self.height.to_be_bytes();
        out[3..8].copy_from_slice(&h[3..8]);

        out[8..12].copy_from_slice(&self.past[0].to_be_bytes());
        out[12..16].copy_from_slice(&self.past[1].to_be_bytes());

        out[16..32].copy_from_slice(&self.key_hash);

        out[32..36].copy_from_slice(&self.flags.to_be_bytes());
        out[36..40].copy_from_slice(&self.nonce[0].to_be_bytes());
        out[40..44].copy_from_slice(&self.nonce[1].to_be_bytes());
        out[44..48].copy_from_slice(&self.nonce[2].to_be_bytes());

        out
    }

    /// Go: `Deserialize`. Requires at least `MINIBLOCK_SIZE` bytes; reads exactly
    /// 48. Enforces `version == 1` and runs the SanityCheck (matching Go).
    pub fn deserialize(buf: &[u8]) -> Result<MiniBlock, &'static str> {
        if buf.len() < MINIBLOCK_SIZE {
            return Err("miniblock: short buffer");
        }
        let version = buf[0] & 0x0f;
        if version != 1 {
            return Err("miniblock: unknown version");
        }
        let past_count = buf[0] >> 6;
        let high_diff = buf[0] & 0x10 > 0;
        let final_ = buf[0] & 0x20 > 0;

        let timestamp = u16::from_be_bytes([buf[1], buf[2]]);

        // Go: BigEndian.Uint64(buf[0:]) & 0x000000ffffffffff → lower 40 bits =
        // bytes 3..8, with the version/timestamp bytes masked out.
        let height = u64::from_be_bytes(buf[0..8].try_into().unwrap()) & 0x0000_00ff_ffff_ffff;

        let past = [
            u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            u32::from_be_bytes(buf[12..16].try_into().unwrap()),
        ];

        let mut key_hash = [0u8; 16];
        key_hash.copy_from_slice(&buf[16..32]);

        let flags = u32::from_be_bytes(buf[32..36].try_into().unwrap());
        let nonce = [
            u32::from_be_bytes(buf[36..40].try_into().unwrap()),
            u32::from_be_bytes(buf[40..44].try_into().unwrap()),
            u32::from_be_bytes(buf[44..48].try_into().unwrap()),
        ];

        let mbl = MiniBlock {
            version,
            high_diff,
            final_,
            past_count,
            timestamp,
            height,
            past,
            key_hash,
            flags,
            nonce,
        };
        mbl.sanity_check()?;
        Ok(mbl)
    }

    /// Go: `GetHash` — SHA3-256 of the serialization (used to dedup miniblocks).
    pub fn get_hash(&self) -> [u8; 32] {
        sha3_256(&[&self.serialize()])
    }
}
