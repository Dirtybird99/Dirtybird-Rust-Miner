//! Balance decoder — solves the discrete log `balance` from `G·balance` via a
//! precomputed baby-step/giant-step table. Port of
//! `walletapi/balance_decoder.go`.
//!
//! The table maps the high 40 bits of (compressed `G·i`, bytes 25..30) to the
//! index `i` (in the low 24 bits). Lookup subtracts `table_size·G` per giant
//! step until the residual's key is found, then verifies the full point.

use crate::generators::base_g;
use dero_bn256::G1;

const MASK: u64 = 0xffff_ffff_ff00_0000; // high 40 bits (point part)
const INDEX_MASK: u64 = 0x00ff_ffff; // low 24 bits (index part)

/// Default table size (Go default is `1 << 16`).
pub const DEFAULT_TABLE_SIZE: usize = 1 << 16;

/// A precomputed lookup table (single table; sorted ascending).
pub struct BalanceDecoder {
    table: Vec<u64>,
}

impl BalanceDecoder {
    /// Go: `Initialize_LookupTable(1, table_size)`. `table_size` must be a
    /// multiple of 256.
    pub fn new(table_size: usize) -> BalanceDecoder {
        assert!(table_size % 256 == 0, "table size must be a multiple of 256");
        let g = base_g();
        let mut table = vec![0u64; table_size];
        let mut acc = G1::infinity(); // G·0
        for i in 0..table_size {
            let mut c = acc.compress(); // compressed G·i (33 bytes)
            // replace the low 3 bytes with the index i
            c[32] = (i & 0xff) as u8;
            c[31] = ((i >> 8) & 0xff) as u8;
            c[30] = ((i >> 16) & 0xff) as u8;
            table[i] = u64::from_be_bytes(c[25..33].try_into().unwrap());
            acc = G1::add(&acc, &g); // G·(i+1)
        }
        table.sort_unstable();
        BalanceDecoder { table }
    }

    /// Default-size table (`DEFAULT_TABLE_SIZE`).
    pub fn default_table() -> BalanceDecoder {
        BalanceDecoder::new(DEFAULT_TABLE_SIZE)
    }

    fn g_times(n: u64) -> G1 {
        base_g().scalar_mult(&n.to_be_bytes())
    }

    /// Go: `LookupTable.Lookup` — recover `balance` such that `G·balance == p`.
    /// `hint` is an optional likely value checked first (0 to skip).
    pub fn lookup(&self, p: &G1, hint: u64) -> u64 {
        let target = p.marshal();
        if hint != 0 && Self::g_times(hint).marshal() == target {
            return hint;
        }

        let n = self.table.len() as u64;
        let work_per_loop = G1::neg(&Self::g_times(n)); // −(G·table_size)
        let mut pcopy = *p;
        let mut balance: u64 = 0;
        let mut loop_counter: u64 = 0;

        loop {
            if loop_counter != 0 {
                pcopy = G1::add(&pcopy, &work_per_loop);
            }
            loop_counter += 1;

            let mut c = pcopy.compress();
            c[30] = 0;
            c[31] = 0;
            c[32] = 0;
            let big_part = u64::from_be_bytes(c[25..33].try_into().unwrap());

            // binary search: first index whose (entry & MASK) >= big_part
            let mut index = self
                .table
                .partition_point(|&e| (e & MASK) < big_part);

            loop {
                if index < self.table.len() && (self.table[index] & MASK) == big_part {
                    let balance_part = self.table[index] & INDEX_MASK;
                    let candidate = balance + balance_part;
                    if Self::g_times(candidate).marshal() == target {
                        return candidate;
                    }
                    // partial (40-bit) collision; try the next equal entry
                    index += 1;
                    continue;
                } else {
                    // not in this table; advance one full table and giant-step
                    balance += n;
                    break;
                }
            }
        }
    }
}
