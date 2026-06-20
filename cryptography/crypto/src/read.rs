//! Minimal cursor helpers for deserialization. A `&mut &[u8]` acts as a cursor:
//! each helper consumes from the front and advances it, mirroring how Go threads
//! a `*bytes.Reader` through nested `Deserialize` calls.

use crate::G1;
use num_bigint::BigUint;

/// Consume exactly `n` bytes from the front of the cursor.
pub fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], &'static str> {
    if r.len() < n {
        return Err("short read");
    }
    let (a, b) = r.split_at(n);
    *r = b;
    Ok(a)
}

/// Read a 33-byte compressed G1 point.
pub fn take_g1(r: &mut &[u8]) -> Result<G1, &'static str> {
    let b = take(r, 33)?;
    G1::decompress(b)
}

/// Read a 32-byte big-endian scalar.
pub fn take_scalar(r: &mut &[u8]) -> Result<BigUint, &'static str> {
    let b = take(r, 32)?;
    Ok(BigUint::from_bytes_be(b))
}

/// Read an unsigned LEB128 varint (Go `binary.ReadUvarint`).
pub fn read_uvarint(r: &mut &[u8]) -> Result<u64, &'static str> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    let mut i = 0usize;
    loop {
        if i >= r.len() {
            return Err("varint: short read");
        }
        let b = r[i];
        if i == 10 {
            return Err("varint: overflow");
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return Err("varint: overflow");
            }
            x |= (b as u64) << s;
            *r = &r[i + 1..];
            return Ok(x);
        }
        x |= ((b & 0x7f) as u64) << s;
        s += 7;
        i += 1;
    }
}
