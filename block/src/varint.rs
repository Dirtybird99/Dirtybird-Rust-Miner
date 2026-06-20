//! Unsigned LEB128 varints, matching Go's `encoding/binary.PutUvarint` /
//! `Uvarint`.

/// Append `x` to `out` as an unsigned LEB128 varint (Go: `binary.PutUvarint`).
pub fn put_uvarint(out: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        out.push((x as u8) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
}

/// Read an unsigned LEB128 varint from the front of `buf`.
/// Returns (value, bytes_consumed). bytes_consumed == 0 on error/overflow
/// (matching Go's `binary.Uvarint` convention of `n <= 0`).
pub fn read_uvarint(buf: &[u8]) -> (u64, usize) {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == 10 {
            return (0, 0); // overflow
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return (0, 0); // overflow
            }
            return (x | (b as u64) << s, i + 1);
        }
        x |= ((b & 0x7f) as u64) << s;
        s += 7;
    }
    (0, 0) // incomplete
}
