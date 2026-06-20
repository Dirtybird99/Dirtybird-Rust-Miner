//! DERO address — port of `rpc/address.go` (base + integrated + proof
//! addresses).
//!
//! Layout: bech32(hrp, convertbits_8to5( [version=1] ‖ compressed_pubkey(33B)
//! ‖ Arguments-CBOR(optional) )).
//!
//! hrp selection (Go `Address.MarshalText`, address.go:43-55, in this exact
//! order): start with `dero` (mainnet) / `deto` (testnet); append `i` when the
//! address carries >=1 service `Arguments` (-> `deroi`/`detoi`); finally a
//! proof address overrides the whole hrp with `deroproof` (used by tx payload
//! proofs: args `H`(Hash)=shared key + `V`(Uint64)=amount,
//! walletapi/daemon_communication.go:979).
//!
//! The argument tail is `Arguments.MarshalBinary()` — the canonical
//! core-deterministic CBOR map already byte-exact-verified for SCDATA
//! (`crate::arguments`). Landmine: Go decodes the tail with fxamacker/cbor
//! which ERRORS on trailing bytes, while `Arguments::unmarshal_binary` stops
//! after the map; valid addresses encode the map with no padding, so both
//! accept/produce identical strings (the divergence is only for malformed
//! inputs Go rejects).

use crate::arguments::Arguments;
use crate::bech32::{convertbits, decode, encode, Bech32Error};
use dero_bn256::G1;

const ADDRESS_VERSION: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("bech32: {0}")]
    Bech32(#[from] Bech32Error),
    #[error("invalid hrp: {0}")]
    InvalidHrp(String),
    #[error("invalid address version: {0}")]
    InvalidVersion(i64),
    #[error("invalid address length: {0}")]
    InvalidLength(usize),
    #[error("point decode: {0}")]
    Point(&'static str),
    #[error("arguments: {0}")]
    Arguments(&'static str),
}

/// Go: `rpc.Address` (the `Network` field is encode-irrelevant and omitted).
#[derive(Clone, Debug)]
pub struct Address {
    pub mainnet: bool,
    pub proof: bool,
    pub public_key: G1,
    /// Integrated-address service arguments (Go: `Address.Arguments`).
    /// Empty for base addresses.
    pub arguments: Arguments,
}

impl Address {
    /// New mainnet base address from a public-key point
    /// (Go: `NewAddressFromKeys`).
    pub fn from_public_key(public_key: G1) -> Address {
        Address {
            mainnet: true,
            proof: false,
            public_key,
            arguments: Arguments::default(),
        }
    }

    /// Go: `Address.MarshalText` / `String`.
    pub fn to_string(&self) -> Result<String, AddressError> {
        // hrp order matters (address.go:44-55): args-i suffix first, then the
        // proof override.
        let mut hrp: String = if self.mainnet { "dero" } else { "deto" }.to_string();
        if !self.arguments.0.is_empty() {
            hrp.push('i');
        }
        if self.proof {
            hrp = "deroproof".to_string();
        }

        let mut data_bytes = vec![ADDRESS_VERSION];
        for b in self.public_key.compress() {
            data_bytes.push(b as i64);
        }
        if !self.arguments.0.is_empty() {
            for b in self.arguments.marshal_binary() {
                data_bytes.push(b as i64);
            }
        }
        let data_ints = convertbits(&data_bytes, 8, 5, true)?;
        Ok(encode(&hrp, &data_ints)?)
    }

    /// Go: `Address.UnmarshalText` / `NewAddress`.
    pub fn from_string(s: &str) -> Result<Address, AddressError> {
        let (hrp, data) = decode(s)?;
        match hrp.as_str() {
            "dero" | "deroi" | "deto" | "detoi" | "deroproof" => {}
            other => return Err(AddressError::InvalidHrp(other.to_string())),
        }
        if data.is_empty() {
            return Err(AddressError::InvalidLength(0));
        }
        let res = convertbits(&data, 5, 8, false)?;
        if res[0] != ADDRESS_VERSION {
            return Err(AddressError::InvalidVersion(res[0]));
        }
        let res = &res[1..];
        let resbytes: Vec<u8> = res.iter().map(|&b| b as u8).collect();
        if resbytes.len() < 33 {
            return Err(AddressError::InvalidLength(resbytes.len()));
        }
        let public_key = G1::decompress(&resbytes[0..33]).map_err(AddressError::Point)?;

        let mainnet = !(hrp == "deto" || hrp == "detoi");
        let proof = hrp == "deroproof";

        // Go address.go:172-180: exactly 33 bytes for base hrps; integrated /
        // proof hrps decode the CBOR argument tail (an EMPTY tail is an error
        // in Go too — cbor.Unmarshal on zero bytes fails with EOF). A base hrp
        // with trailing bytes is invalid.
        let arguments = if res.len() == 33 && (hrp == "dero" || hrp == "deto") {
            Arguments::default()
        } else if hrp == "deroi" || hrp == "detoi" || hrp == "deroproof" {
            Arguments::unmarshal_binary(&resbytes[33..]).map_err(AddressError::Arguments)?
        } else {
            return Err(AddressError::InvalidLength(res.len()));
        };

        Ok(Address {
            mainnet,
            proof,
            public_key,
            arguments,
        })
    }

    /// Go: `Address.BaseAddress` — same address with the arguments stripped
    /// (turns `deroi`/`detoi` back into `dero`/`deto`).
    pub fn base_address(&self) -> Address {
        Address {
            arguments: Arguments::default(),
            ..self.clone()
        }
    }

    /// Go: `Address.IsIntegratedAddress`.
    pub fn is_integrated(&self) -> bool {
        !self.arguments.0.is_empty()
    }

    /// Compressed 33-byte public key.
    pub fn compressed(&self) -> [u8; 33] {
        self.public_key.compress()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::{ArgValue, Argument};

    fn test_pubkey() -> G1 {
        // any valid point: decompress from a known mainnet dev-address key is
        // overkill here; derive 2*G via the generator used by addresses.
        // dero-crypto is a dependency, but to keep this module self-contained
        // we just roundtrip through a known-good base address from the byte-
        // exact vector file (secret=1 of vectors/address.json).
        Address::from_string(
            "dero1qypw4nalj2u5q9wfkzeajqw6udlvdrm5m6n7gjzvwm2st2k7fttuqqgwtmndv",
        )
        .unwrap()
        .public_key
    }

    fn pong_args() -> Arguments {
        Arguments(vec![
            Argument { name: "D".into(), value: ArgValue::Uint64(0x1234567812345678) },
            Argument { name: "C".into(), value: ArgValue::Str("Purchase PONG".into()) },
            Argument { name: "N".into(), value: ArgValue::Uint64(0) },
            Argument { name: "V".into(), value: ArgValue::Uint64(12345) },
        ])
    }

    #[test]
    fn integrated_hrp_and_roundtrip() {
        let mut a = Address::from_public_key(test_pubkey());
        a.arguments = pong_args();
        let s = a.to_string().unwrap();
        assert!(s.starts_with("deroi1"), "hrp must gain i: {s}");

        let d = Address::from_string(&s).unwrap();
        assert!(d.mainnet && !d.proof && d.is_integrated());
        assert_eq!(d.compressed(), a.compressed());
        // canonical CBOR -> argument round-trip is order-normalized; compare
        // re-encodings (and the full string) instead of vec order.
        assert_eq!(d.to_string().unwrap(), s);
        assert_eq!(
            d.arguments.marshal_binary(),
            a.arguments.marshal_binary()
        );

        a.mainnet = false;
        let s = a.to_string().unwrap();
        assert!(s.starts_with("detoi1"), "testnet hrp must gain i: {s}");
        let d = Address::from_string(&s).unwrap();
        assert!(!d.mainnet);
        assert_eq!(d.to_string().unwrap(), s);
    }

    #[test]
    fn proof_hrp_overrides() {
        let mut a = Address::from_public_key(test_pubkey());
        a.proof = true;
        a.arguments = Arguments(vec![
            Argument { name: "V".into(), value: ArgValue::Uint64(100000) },
            Argument { name: "H".into(), value: ArgValue::Hash([7u8; 32]) },
        ]);
        let s = a.to_string().unwrap();
        assert!(s.starts_with("deroproof1"), "{s}");
        let d = Address::from_string(&s).unwrap();
        assert!(d.proof && d.mainnet);
        assert_eq!(d.arguments.get("V"), Some(&ArgValue::Uint64(100000)));
        assert_eq!(d.arguments.get("H"), Some(&ArgValue::Hash([7u8; 32])));
        assert_eq!(d.to_string().unwrap(), s);
    }

    #[test]
    fn base_address_strips_arguments() {
        let base = Address::from_public_key(test_pubkey());
        let base_str = base.to_string().unwrap();

        let mut a = base.clone();
        a.arguments = pong_args();
        assert!(a.is_integrated());
        let b = a.base_address();
        assert!(!b.is_integrated());
        assert_eq!(b.to_string().unwrap(), base_str);
        // original untouched
        assert!(a.is_integrated());
    }

    #[test]
    fn integrated_hrp_with_empty_tail_is_error() {
        // encode a BASE payload (no CBOR tail) under the deroi hrp by hand:
        // Go fails decoding this too (cbor EOF on empty input).
        let pk = test_pubkey();
        let mut data_bytes = vec![1i64];
        for b in pk.compress() {
            data_bytes.push(b as i64);
        }
        let ints = convertbits(&data_bytes, 8, 5, true).unwrap();
        let s = encode("deroi", &ints).unwrap();
        assert!(matches!(
            Address::from_string(&s),
            Err(AddressError::Arguments(_))
        ));
    }

    #[test]
    fn base_hrp_with_trailing_bytes_is_error() {
        // dero hrp + argument tail = invalid length per Go's default case.
        let pk = test_pubkey();
        let mut data_bytes = vec![1i64];
        for b in pk.compress() {
            data_bytes.push(b as i64);
        }
        for b in pong_args().marshal_binary() {
            data_bytes.push(b as i64);
        }
        let ints = convertbits(&data_bytes, 8, 5, true).unwrap();
        let s = encode("dero", &ints).unwrap();
        assert!(matches!(
            Address::from_string(&s),
            Err(AddressError::InvalidLength(_))
        ));
    }
}
