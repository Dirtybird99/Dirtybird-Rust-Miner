//! Bech32 (BIP-173) — faithful port of `rpc/bech32.go`. DERO removes the 90-char
//! length check (`length_check = false`), so encode/decode work for arbitrary
//! lengths. Charset and checksum are standard bech32.

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [i64; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

#[derive(Debug, thiserror::Error)]
pub enum Bech32Error {
    #[error("invalid hrp: {0}")]
    InvalidHrp(String),
    #[error("mixed case")]
    MixedCase,
    #[error("separator '1' at invalid position: pos={0}, len={1}")]
    Separator(isize, usize),
    #[error("invalid character in data part")]
    InvalidDataChar,
    #[error("invalid data value: {0}")]
    InvalidDataValue(i64),
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("invalid data range")]
    InvalidDataRange,
    #[error("non-zero padding")]
    NonZeroPadding,
    #[error("illegal zero padding")]
    IllegalZeroPadding,
}

fn polymod(values: &[i64]) -> i64 {
    let mut chk: i64 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        for i in 0..5 {
            if (top >> i) & 1 == 1 {
                chk ^= GENERATOR[i];
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<i64> {
    let mut ret = Vec::new();
    for c in hrp.bytes() {
        ret.push((c >> 5) as i64);
    }
    ret.push(0);
    for c in hrp.bytes() {
        ret.push((c & 31) as i64);
    }
    ret
}

fn verify_checksum(hrp: &str, data: &[i64]) -> bool {
    let mut v = hrp_expand(hrp);
    v.extend_from_slice(data);
    polymod(&v) == 1
}

fn create_checksum(hrp: &str, data: &[i64]) -> Vec<i64> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let mod_ = polymod(&values) ^ 1;
    let mut ret = vec![0i64; 6];
    for p in 0..6 {
        ret[p] = (mod_ >> (5 * (5 - p))) & 31;
    }
    ret
}

/// Go: `Encode`. DERO addresses are lowercase.
pub fn encode(hrp: &str, data: &[i64]) -> Result<String, Bech32Error> {
    if hrp.is_empty() {
        return Err(Bech32Error::InvalidHrp(hrp.to_string()));
    }
    for c in hrp.bytes() {
        if c < 33 || c > 126 {
            return Err(Bech32Error::InvalidHrp(hrp.to_string()));
        }
    }
    if hrp.to_uppercase() != hrp && hrp.to_lowercase() != hrp {
        return Err(Bech32Error::MixedCase);
    }
    let lower = hrp.to_lowercase() == hrp;
    let hrp_l = hrp.to_lowercase();
    let mut combined = data.to_vec();
    combined.extend_from_slice(&create_checksum(&hrp_l, data));
    let mut ret = String::new();
    ret.push_str(&hrp_l);
    ret.push('1');
    for (idx, &p) in combined.iter().enumerate() {
        if p < 0 || p as usize >= CHARSET.len() {
            return Err(Bech32Error::InvalidDataValue(idx as i64));
        }
        ret.push(CHARSET[p as usize] as char);
    }
    if lower {
        Ok(ret)
    } else {
        Ok(ret.to_uppercase())
    }
}

/// Go: `Decode` — returns (hrp, data without the 6 checksum symbols).
pub fn decode(bech: &str) -> Result<(String, Vec<i64>), Bech32Error> {
    if bech.to_lowercase() != bech && bech.to_uppercase() != bech {
        return Err(Bech32Error::MixedCase);
    }
    let bech = bech.to_lowercase();
    let pos = bech.rfind('1').map(|p| p as isize).unwrap_or(-1);
    if pos < 1 || (pos as usize) + 7 > bech.len() {
        return Err(Bech32Error::Separator(pos, bech.len()));
    }
    let pos = pos as usize;
    let hrp = &bech[..pos];
    for c in hrp.bytes() {
        if c < 33 || c > 126 {
            return Err(Bech32Error::InvalidHrp(hrp.to_string()));
        }
    }
    let mut data = Vec::new();
    for c in bech[pos + 1..].bytes() {
        match CHARSET.iter().position(|&x| x == c) {
            Some(d) => data.push(d as i64),
            None => return Err(Bech32Error::InvalidDataChar),
        }
    }
    if !verify_checksum(hrp, &data) {
        return Err(Bech32Error::InvalidChecksum);
    }
    let n = data.len();
    Ok((hrp.to_string(), data[..n - 6].to_vec()))
}

/// Go: `convertbits`.
pub fn convertbits(data: &[i64], frombits: u32, tobits: u32, pad: bool) -> Result<Vec<i64>, Bech32Error> {
    let mut acc: i64 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: i64 = (1 << tobits) - 1;
    for &value in data {
        if value < 0 || (value >> frombits) != 0 {
            return Err(Bech32Error::InvalidDataRange);
        }
        acc = (acc << frombits) | value;
        bits += frombits;
        while bits >= tobits {
            bits -= tobits;
            ret.push((acc >> bits) & maxv);
        }
    }
    if pad {
        if bits > 0 {
            ret.push((acc << (tobits - bits)) & maxv);
        }
    } else if bits >= frombits {
        return Err(Bech32Error::IllegalZeroPadding);
    } else if ((acc << (tobits - bits)) & maxv) != 0 {
        return Err(Bech32Error::NonZeroPadding);
    }
    Ok(ret)
}
