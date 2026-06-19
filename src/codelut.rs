//! CodeLUT and the wolfBranch micro-op interpreter (codelut.zig + astrobwt.zig).
//!
//! Each `CODELUT[op]` is a u32 packing 4 micro-ops (one per byte, executed MSB→LSB),
//! each byte a value 0..15 selecting one of 16 byte transforms. `wolf_branch` runs them.
//! 152 "regular" ops (no pos2val dependence) are precomputed into a 152×256 byte LUT
//! (`Reglut`); the 104 "branched" ops depend on `pos2val = prev_chunk[p2]` at runtime.

/// 256 opcode words. Each is 4 nibble-valued micro-ops, high byte first.
pub const CODELUT: [u32; 256] = [
    0x090F020A, 0x060B0500, 0x09080609, 0x0A0D030B, 0x04070A01, 0x09030607, 0x060D0401, 0x000A0904,
    0x040F0F06, 0x030E070C, 0x04020D02, 0x0B0F050A, 0x0C020C04, 0x0B03070F, 0x07060206, 0x0C060501,
    0x0E020B04, 0x03020F04, 0x0E0D0B0F, 0x010F0600, 0x0503080C, 0x0B030005, 0x0608020B, 0x0D0B0905,
    0x00070E0F, 0x090D0A01, 0x02090008, 0x0F050E0F, 0x0600000F, 0x02030700, 0x050E0F06, 0x040C0602,
    0x0C080D0C, 0x0A0E0802, 0x01060601, 0x00040B03, 0x090B0C0B, 0x0A070702, 0x070D090A, 0x0C030705,
    0x0A030903, 0x0F010D0E, 0x0B0D0C0A, 0x05000501, 0x09090D0A, 0x0F0F0509, 0x09000F0E, 0x0F050F06,
    0x0A04040F, 0x0900080E, 0x080D000B, 0x030E0E0F, 0x0A070409, 0x00090E0E, 0x08030404, 0x080E0E0B,
    0x0C02040B, 0x0A0F0D08, 0x080C0500, 0x0B020A04, 0x0304020D, 0x0F060D0F, 0x05040C00, 0x0F090100,
    0x03080E02, 0x0F0D0C02, 0x0C080E0B, 0x0B090C0F, 0x05040E03, 0x00020807, 0x0302070E, 0x0F040206,
    0x08090306, 0x09080F01, 0x020D0805, 0x0209050E, 0x0A0C0F07, 0x0D000609, 0x0A080201, 0x0E0C0002,
    0x0A060005, 0x0E060A09, 0x03040407, 0x06080D08, 0x010B0600, 0x07030A06, 0x0E0A0E04, 0x000D0E00,
    0x0C0B0204, 0x0002040C, 0x080F0B07, 0x09050E08, 0x09040905, 0x0C020500, 0x0B0A0506, 0x0B040F0F,
    0x0C0C090B, 0x0B060907, 0x0E06070E, 0x0E010807, 0x0A060809, 0x07090704, 0x0D01000D, 0x0B08030A,
    0x08090F00, 0x060D0A0C, 0x080E0B02, 0x070C0F0B, 0x0304050C, 0x020A030C, 0x000C0C07, 0x02080207,
    0x0D040F01, 0x0F0B0904, 0x0B080A04, 0x0A0F050D, 0x05030906, 0x060D0605, 0x0700060F, 0x080C0403,
    0x0C020308, 0x07000902, 0x0E0A0F0C, 0x05040D0D, 0x0C0C0304, 0x080C0007, 0x0D0B0F08, 0x06020503,
    0x0A0C0C0F, 0x04090907, 0x070A0B0E, 0x010B0902, 0x05080F0C, 0x030F0C06, 0x040E0B05, 0x070C0008,
    0x0701030F, 0x0F07080A, 0x03030001, 0x0F0D0C0D, 0x0B0C030F, 0x0B010900, 0x050F080C, 0x050D0706,
    0x0A06040A, 0x080E0C0E, 0x05060509, 0x04060E02, 0x050F0601, 0x03080100, 0x06060605, 0x00060206,
    0x0704060C, 0x0B0D0404, 0x0F040309, 0x01030903, 0x07070D0B, 0x07060A0B, 0x090D000B, 0x01030A03,
    0x07080B0D, 0x03030F0A, 0x02080C01, 0x06010E0B, 0x02090104, 0x0E030600, 0x0D000C04, 0x04040207,
    0x0A050A0B, 0x0B060E05, 0x01080102, 0x0D010908, 0x0E01060B, 0x04060200, 0x040A0909, 0x0D01020F,
    0x0302030F, 0x090C0C05, 0x0500040B, 0x0C000708, 0x070E0301, 0x04060C0F, 0x030B0F0E, 0x00010102,
    0x06020F03, 0x040E0F07, 0x0C0E0107, 0x0304000D, 0x0E090E0E, 0x0F0E0301, 0x0F07050C, 0x000D0A07,
    0x00060002, 0x05060A0B, 0x050A0605, 0x090C030E, 0x0D08060B, 0x0E0A0202, 0x0707080B, 0x04000203,
    0x07090808, 0x0D0C0E04, 0x03040A0F, 0x03050B0A, 0x0F0C0A03, 0x090E0600, 0x0E080809, 0x0F0D0909,
    0x0000070D, 0x0F080901, 0x0C0A0F04, 0x0E00010A, 0x0A0C0303, 0x00060D01, 0x03010704, 0x03050602,
    0x0A040105, 0x0F000B0E, 0x08040201, 0x0E0D0508, 0x0B060806, 0x0F030408, 0x07060302, 0x0D030A01,
    0x0C0B0D06, 0x0407080D, 0x08010203, 0x04060105, 0x00070009, 0x0D0A0C09, 0x02050A0A, 0x0D070308,
    0x02020E0F, 0x0B090D09, 0x05020703, 0x0C020D04, 0x03000501, 0x0F060C0D, 0x00000D01, 0x0F0B0205,
    0x04000506, 0x0E09030B, 0x00000103, 0x0F0C090B, 0x040C080F, 0x010F0C07, 0x000B0700, 0x0F0C0F04,
    0x0401090F, 0x080E0E0A, 0x050A090E, 0x0009080C, 0x080E0C06, 0x0D0C030D, 0x090D0C0D, 0x090D0C0D,
];

/// Apply the 4 micro-ops packed in `opcode` to `val`. `pos2val` is only read by
/// micro-ops 3 (`^=`) and 5 (`&=`) — zero for regular ops where they never appear.
#[inline(always)]
pub fn wolf_branch(val_in: u8, pos2val: u8, opcode: u32) -> u8 {
    let mut val = val_in;
    let mut shift: i32 = 24;
    while shift >= 0 {
        let insn = (opcode >> shift) & 0xff;
        val = match insn {
            0 => val.wrapping_add(val),
            1 => val.wrapping_sub(val ^ 97),
            2 => val.wrapping_mul(val),
            3 => val ^ pos2val,
            4 => !val,
            5 => val & pos2val,
            6 => ((val as u16) << (val & 3)) as u8,
            7 => val >> (val & 3),
            8 => val.reverse_bits(),
            9 => val ^ (val.count_ones() as u8),
            10 => val.rotate_left((val & 7) as u32),
            11 => val.rotate_left(1),
            12 => val ^ val.rotate_left(2),
            13 => val.rotate_left(3),
            14 => val ^ val.rotate_left(4),
            15 => val.rotate_left(5),
            _ => val,
        };
        shift -= 8;
    }
    val
}

/// True if `op`'s CodeLUT word contains micro-op 3 or 5 (i.e. depends on pos2val).
#[inline]
pub const fn is_branched(op: u8) -> bool {
    let w = CODELUT[op as usize];
    let mut shift = 0;
    while shift < 32 {
        let n = (w >> shift) & 0xff;
        if n == 3 || n == 5 {
            return true;
        }
        shift += 8;
    }
    false
}

/// Precomputed 152×256 byte map for the regular (pos2val-independent) ops.
pub struct Reglut {
    /// reg_idx[op] = 0xFF if branched, else its compact row index (0..151).
    pub reg_idx: [u8; 256],
    /// lut[row*256 + v] = wolf_branch(v, 0, CODELUT[op]).
    pub lut: Vec<u8>,
}

impl Reglut {
    pub fn new() -> Self {
        let mut reg_idx = [0xFFu8; 256];
        let mut rows: u8 = 0;
        for op in 0..=255u8 {
            if !is_branched(op) {
                reg_idx[op as usize] = rows;
                rows += 1;
            }
        }
        let mut lut = vec![0u8; rows as usize * 256];
        for op in 0..=255u8 {
            let ridx = reg_idx[op as usize];
            if ridx != 0xFF {
                let base = ridx as usize * 256;
                let code = CODELUT[op as usize];
                for v in 0..=255u8 {
                    lut[base + v as usize] = wolf_branch(v, 0, code);
                }
            }
        }
        Reglut { reg_idx, lut }
    }
}

impl Default for Reglut {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The validated Zig source lists exactly 104 branched ops; our CodeLUT-derived
    // predicate must agree (count + membership), or a CodeLUT entry was mis-transcribed.
    const BRANCHED_OPS: [u8; 104] = [
        1, 3, 5, 9, 11, 13, 15, 17, 20, 21, 23, 27, 29, 30, 35, 39, 40, 43, 45, 47, 51, 54, 58, 60,
        62, 64, 68, 70, 72, 74, 75, 80, 82, 85, 91, 92, 93, 94, 103, 108, 109, 115, 116, 117, 119,
        120, 123, 124, 127, 132, 133, 134, 136, 138, 140, 142, 143, 146, 148, 149, 150, 154, 155,
        159, 161, 165, 168, 169, 176, 177, 178, 180, 182, 184, 187, 189, 190, 193, 194, 195, 199,
        202, 203, 204, 212, 214, 215, 216, 219, 221, 222, 223, 226, 227, 230, 231, 234, 236, 239,
        240, 241, 242, 250, 253,
    ];

    #[test]
    fn branched_set_matches_oracle() {
        let mut derived = [false; 256];
        for op in 0..=255u8 {
            derived[op as usize] = is_branched(op);
        }
        let mut expected = [false; 256];
        for &op in &BRANCHED_OPS {
            expected[op as usize] = true;
        }
        let n_branched = derived.iter().filter(|&&b| b).count();
        assert_eq!(n_branched, 104, "expected 104 branched ops, got {n_branched}");
        for op in 0..256 {
            assert_eq!(derived[op], expected[op], "branched mismatch at op {op}");
        }
    }

    #[test]
    fn reglut_builds_152_rows() {
        let r = Reglut::new();
        let rows = r.reg_idx.iter().filter(|&&x| x != 0xFF).count();
        assert_eq!(rows, 152);
        assert_eq!(r.lut.len(), 152 * 256);
    }
}
