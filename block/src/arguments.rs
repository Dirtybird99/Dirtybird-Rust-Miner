//! `rpc.Arguments` — the SCDATA payload of an SC transaction. Port of the
//! CBOR (de)serialization in `rpc/rpc.go`.
//!
//! Go marshals a `map[string]interface{}` (key = `Name`+DataType-char) with
//! `github.com/fxamacker/cbor/v2` using **Core Deterministic** encoding
//! (`SortCoreDeterministic`): map keys are emitted sorted by their encoded
//! bytes (length-first, then lexicographic). We hand-roll the canonical CBOR
//! for all rpc data types: uint64 "U", int64 "I", string "S", hash "H",
//! address "A", float64 "F" and time "T".
//!
//! Floats follow fxamacker's `ShortestFloat16` + `NaNConvert7e00` +
//! `InfConvertFloat16` options (rpc/rpc.go:17-24): the shortest of
//! f16/f32/f64 that preserves the value exactly, any NaN as `0xf97e00`, ±Inf
//! as float16. Times follow `TimeTag: EncTagRequired` with the default
//! `TimeUnix` mode: tag(1) + integer epoch seconds — except Go's zero time,
//! which encodes as CBOR null (fxamacker encode.go `encodeTime`).
//! Byte-exact against the Go reference via `vectors/scdata.json` and
//! `vectors/scdataft.json` (go-harness/scdata, go-harness/scdataft).
//!
//! The DECODER ([`Arguments::unmarshal_binary_exact`]) is a faithful port of
//! `rpc.Arguments.UnmarshalBinary` = `dec.Unmarshal(data, &map[string]interface{})`
//! (vendored fxamacker/cbor v2, default `DecOptions` + `TimeTag: DecTagRequired`)
//! followed by rpc.go's per-key dispatch — including Go's exact error strings.
//! Notable Go behaviors replicated (all pinned by `vectors/argdecode.json`,
//! go-harness/argdecode):
//! - two-phase decode: a well-formedness pass (valid.go) whose syntax errors
//!   ("EOF", "unexpected EOF", `cbor: ...`) precede all value errors, and
//!   which only validates the FIRST item — trailing garbage is ignored;
//! - indefinite-length maps/arrays and chunked byte/text strings (UTF-8 is
//!   validated per chunk, so a rune split across text chunks errors);
//! - duplicate identical full keys: last occurrence wins (Go map overwrite);
//! - the `fillNil` quirk: a null map key is a no-op on the REUSED string
//!   key variable, inheriting the previous pair's key ("" for the first);
//! - CBOR simple values <20 / 24 decode as Go `uint64` (fxamacker `parse`);
//! - "H" accepts any byte-string length (`copy` zero-pads / truncates);
//! - "A" zero-pads/truncates to 33 bytes then mirrors `Point.DecodeCompressed`
//!   including bn256 changes.go `marshal()` IGNORING `G1.Unmarshal` errors:
//!   an x >= p input "succeeds" as a broken z=0 point that re-encodes as 33
//!   zero bytes; non-0/1 parity flags are normalized on re-compression;
//! - "T" tag-1: ints wrap via `int64()`, floats via `math.Modf` (with the
//!   amd64 cvttsd2si out-of-range -> i64::MIN conversion), NaN/Inf give the
//!   zero time with NO error; tag-0: RFC3339 via Go's general layout parser
//!   (single-digit hours allowed, ',' fractions, offsets to ±24:60) with
//!   go1.26 `time.ParseError` texts reproduced verbatim.
//!
//! Documented divergence (unobservable): Go iterates the decoded localmap in
//! random order, so when a map contains TWO OR MORE rpc-layer-offending
//! entries the reported error is nondeterministic in Go; we deterministically
//! report the first offender in CBOR document order. Same-name argument order
//! after Go's non-stable Sort is likewise unspecified; we sort stably.
//! Unreachable corner (documented, not vectored): Go's `xToY` builds
//! `y2 = p - y1` unreduced, so `y1 == 0` would make `y2 = p` — but no x with
//! x³+3 ≡ 0 (mod p) exists (-3 is not a cubic residue mod this p).

/// SC argument names (Go: `rpc/rpc_sc.go`).
pub const SC_ACTION: &str = "SC_ACTION";
pub const SC_CODE: &str = "SC_CODE";
pub const SC_ID: &str = "SC_ID";

/// Service argument names (Go: `rpc/rpc.go:369-377`).
pub const RPC_DESTINATION_PORT: &str = "D";
pub const RPC_SOURCE_PORT: &str = "S";
pub const RPC_VALUE_TRANSFER: &str = "V";
pub const RPC_COMMENT: &str = "C";
pub const RPC_EXPIRY: &str = "E";
pub const RPC_REPLYBACK_ADDRESS: &str = "R";
pub const RPC_NEEDS_REPLYBACK_ADDRESS: &str = "N";

/// Unix seconds of Go's zero `time.Time` (0001-01-01T00:00:00 UTC).
/// `ArgValue::Time(GO_ZERO_TIME_UNIX)` is Go's zero time: it marshals to CBOR
/// null (and, like Go, such a payload then fails to unmarshal).
pub const GO_ZERO_TIME_UNIX: i64 = -62_135_596_800;

/// A typed argument value. The CBOR map key is `name` + the type char below.
#[derive(Clone, Debug, PartialEq)]
pub enum ArgValue {
    Uint64(u64),
    Int64(i64),
    Str(String),
    Hash([u8; 32]),
    Address([u8; 33]),
    /// "F" — Go `float64` (rpc.DataFloat64).
    Float64(f64),
    /// "T" — Go `time.Time` (rpc.DataTime) at second precision (the codec's
    /// `TimeUnix` mode discards sub-second precision and zone). Stored as Unix
    /// seconds; see [`GO_ZERO_TIME_UNIX`] for the zero time.
    Time(i64),
}

impl ArgValue {
    fn type_char(&self) -> char {
        match self {
            ArgValue::Uint64(_) => 'U',
            ArgValue::Int64(_) => 'I',
            ArgValue::Str(_) => 'S',
            ArgValue::Hash(_) => 'H',
            ArgValue::Address(_) => 'A',
            ArgValue::Float64(_) => 'F',
            ArgValue::Time(_) => 'T',
        }
    }
}

/// Go: `rpc.Argument`.
#[derive(Clone, Debug, PartialEq)]
pub struct Argument {
    pub name: String,
    pub value: ArgValue,
}

/// Go: `rpc.Arguments`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Arguments(pub Vec<Argument>);

// ---- canonical CBOR primitives ----
fn enc_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n < 0x100 {
        out.push(m | 24);
        out.push(n as u8);
    } else if n < 0x1_0000 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < 0x1_0000_0000 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn enc_text(out: &mut Vec<u8>, s: &str) {
    enc_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn enc_bytes(out: &mut Vec<u8>, b: &[u8]) {
    enc_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn enc_int(out: &mut Vec<u8>, i: i64) {
    if i >= 0 {
        enc_head(out, 0, i as u64);
    } else {
        enc_head(out, 1, (-1 - i) as u64);
    }
}

/// Canonical float encoding per the codec's fxamacker options (rpc/rpc.go:17-24,
/// vendored cbor/v2 encode.go:640-713): `NaNConvert7e00` (any NaN → `f9 7e00`),
/// `InfConvertFloat16` (±Inf → float16), `ShortestFloat16` (the smallest of
/// f16/f32/f64 that represents the value exactly; the round-trip test below is
/// equivalent to fxamacker's `PrecisionExact`/`PrecisionUnknown` logic).
fn enc_float(out: &mut Vec<u8>, f: f64) {
    if f.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
        return;
    }
    if f.is_infinite() {
        out.extend_from_slice(&[0xf9, if f.is_sign_positive() { 0x7c } else { 0xfc }, 0x00]);
        return;
    }
    let f32v = f as f32;
    if (f32v as f64) == f {
        let h = f32_to_f16_bits(f32v);
        if f16_bits_to_f32(h) == f32v {
            out.push(0xf9);
            out.extend_from_slice(&h.to_be_bytes());
            return;
        }
        out.push(0xfa);
        out.extend_from_slice(&f32v.to_bits().to_be_bytes());
        return;
    }
    out.push(0xfb);
    out.extend_from_slice(&f.to_bits().to_be_bytes());
}

/// Time encoding (fxamacker encode.go `encodeTime`, with `EncTagRequired` +
/// default `TimeUnix`): zero time → CBOR null (even though a tag is required),
/// anything else → tag(1) + integer epoch seconds.
fn enc_time(out: &mut Vec<u8>, secs: i64) {
    if secs == GO_ZERO_TIME_UNIX {
        out.push(0xf6);
        return;
    }
    out.push(0xc1);
    enc_int(out, secs);
}

fn enc_value(out: &mut Vec<u8>, v: &ArgValue) {
    match v {
        ArgValue::Uint64(u) => enc_head(out, 0, *u),
        ArgValue::Int64(i) => enc_int(out, *i),
        ArgValue::Str(s) => enc_text(out, s),
        ArgValue::Hash(h) => enc_bytes(out, h),
        ArgValue::Address(a) => enc_bytes(out, a),
        ArgValue::Float64(f) => enc_float(out, *f),
        ArgValue::Time(secs) => enc_time(out, *secs),
    }
}

// ---- IEEE binary16 <-> binary32 (the x448/float16 conversions fxamacker uses) ----

/// f32 → binary16 bits, round-to-nearest-even (x448/float16 `Fromfloat32`).
fn f32_to_f16_bits(value: f32) -> u16 {
    let x = value.to_bits();
    let sign = ((x >> 16) & 0x8000) as u16;
    let exp = ((x >> 23) & 0xff) as i32;
    let man = x & 0x007f_ffff;
    if exp == 0xff {
        // Inf / NaN (enc_float never reaches this; kept for totality)
        let nan_bit = if man != 0 && (man >> 13) == 0 { 0x0200 } else { 0 };
        return sign | 0x7c00 | nan_bit | (man >> 13) as u16;
    }
    let unbiased = exp - 127;
    if unbiased >= 16 {
        return sign | 0x7c00; // overflows f16 → ±Inf
    }
    if unbiased >= -14 {
        // normal f16; rounding may carry into the exponent (and up to Inf)
        let mut h = (sign as u32) | ((((unbiased + 15) as u32) << 10) | (man >> 13));
        let round = man & 0x1fff;
        if round > 0x1000 || (round == 0x1000 && h & 1 == 1) {
            h += 1;
        }
        return h as u16;
    }
    if unbiased >= -24 {
        // subnormal f16: value = (man|implicit)·2^(unbiased-23), f16 lsb = 2^-24
        let m = man | 0x0080_0000;
        let shift = (-(unbiased + 1)) as u32; // 14..=23
        let mut h = (sign as u32) | (m >> shift);
        let rem = m & ((1u32 << shift) - 1);
        let half = 1u32 << (shift - 1);
        if rem > half || (rem == half && h & 1 == 1) {
            h += 1;
        }
        return h as u16;
    }
    sign // underflow → ±0 (always inexact; the encoder only uses exact round-trips)
}

/// binary16 bits → f32 (exact; x448/float16 `Float32`).
fn f16_bits_to_f32(h: u16) -> f32 {
    let sign = ((h & 0x8000) as u32) << 16;
    let exp = ((h >> 10) & 0x1f) as u32;
    let man = (h & 0x03ff) as u32;
    if exp == 0 {
        if man == 0 {
            return f32::from_bits(sign); // ±0
        }
        // subnormal: normalize into f32
        let mut e: i32 = 127 - 15 + 1;
        let mut m = man << 13;
        while m & 0x0080_0000 == 0 {
            m <<= 1;
            e -= 1;
        }
        return f32::from_bits(sign | ((e as u32) << 23) | (m & 0x007f_ffff));
    }
    if exp == 0x1f {
        return f32::from_bits(sign | 0x7f80_0000 | (man << 13)); // ±Inf / NaN
    }
    f32::from_bits(sign | ((exp + 127 - 15) << 23) | (man << 13))
}

impl Arguments {
    /// Go: `Arguments.MarshalBinary` (canonical CBOR map).
    pub fn marshal_binary(&self) -> Vec<u8> {
        // build (encoded_key, encoded_value) pairs, dedup by key (last wins)
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for arg in &self.0 {
            let key = format!("{}{}", arg.name, arg.value.type_char());
            let mut ek = Vec::new();
            enc_text(&mut ek, &key);
            let mut ev = Vec::new();
            enc_value(&mut ev, &arg.value);
            if let Some(slot) = pairs.iter_mut().find(|(k, _)| *k == ek) {
                slot.1 = ev;
            } else {
                pairs.push((ek, ev));
            }
        }
        // Core Deterministic: sort by encoded-key bytes (length-first then lex,
        // which bytewise comparison of the CBOR text-string encoding gives).
        pairs.sort_by(|a, b| a.0.cmp(&b.0));

        let mut out = Vec::new();
        enc_head(&mut out, 5, pairs.len() as u64);
        for (k, v) in pairs {
            out.extend_from_slice(&k);
            out.extend_from_slice(&v);
        }
        out
    }

    /// Go: `Arguments.UnmarshalBinary` — same ACCEPTANCE as
    /// [`Arguments::unmarshal_binary_exact`] but with the error collapsed to a
    /// static placeholder (kept so callers that store a `&'static str` keep
    /// compiling; use `unmarshal_binary_exact` when the Go error text matters,
    /// e.g. for the wallet's persisted `payloaderror`).
    pub fn unmarshal_binary(data: &[u8]) -> Result<Arguments, &'static str> {
        Self::unmarshal_binary_exact(data).map_err(|_| "SCDATA: invalid arguments payload")
    }

    /// Go: `Arguments.UnmarshalBinary` (rpc/rpc.go:223-308) with Go's exact
    /// error strings (vendored fxamacker/cbor v2 + rpc.go `fmt.Errorf` texts).
    /// Vector-gated by `vectors/argdecode.json`.
    pub fn unmarshal_binary_exact(data: &[u8]) -> Result<Arguments, String> {
        // Go: dec.Unmarshal(data, &localmap) — cbor errors are returned verbatim.
        let localmap = cbor_unmarshal_localmap(data)?;

        let mut args: Vec<Argument> = Vec::with_capacity(localmap.len());
        for (k, v) in localmap {
            // rpc.go:233-235: len() is the BYTE length.
            if k.len() < 2 {
                return Err(format!("Invalid encoding for key '{k}'"));
            }
            let tchar = *k.as_bytes().last().unwrap();
            // Go splits the key at the last BYTE. The split prefix is only a
            // (guaranteed-valid-UTF-8) name when the last byte is one of the
            // ASCII type chars; otherwise we fall to the default arm, which
            // formats the FULL key (rpc.go:294-296).
            let value = match tchar {
                // rpc.go:240-247: int64 directly, or uint64 via a wrapping
                // int64() conversion; anything else errors (note the 'typei'
                // typo and trailing newline in Go's format string).
                b'I' => match v {
                    Cval::I64(i) => ArgValue::Int64(i),
                    Cval::U64(u) => ArgValue::Int64(u as i64),
                    other => return Err(rpc_type_err(&k, tchar, &other)),
                },
                b'U' => match v {
                    Cval::U64(u) => ArgValue::Uint64(u),
                    other => return Err(rpc_type_err(&k, tchar, &other)),
                },
                b'F' => match v {
                    Cval::F64(f) => ArgValue::Float64(f),
                    other => return Err(rpc_type_err(&k, tchar, &other)),
                },
                // rpc.go:260-267: copy(hash[:], value) — any length accepted;
                // short input is zero-padded, long input truncated.
                b'H' => match v {
                    Cval::Bytes(b) => {
                        let mut h = [0u8; 32];
                        let n = b.len().min(32);
                        h[..n].copy_from_slice(&b[..n]);
                        ArgValue::Hash(h)
                    }
                    other => return Err(rpc_type_err(&k, tchar, &other)),
                },
                // rpc.go:268-281: 33-byte copy (pad/truncate) then
                // Point.DecodeCompressed; its error is returned verbatim.
                b'A' => match v {
                    Cval::Bytes(b) => ArgValue::Address(decode_address_go(&b)?),
                    other => return Err(rpc_type_err(&k, tchar, &other)),
                },
                b'S' => match v {
                    Cval::Text(s) => ArgValue::Str(s),
                    other => return Err(rpc_type_err(&k, tchar, &other)),
                },
                b'T' => match v {
                    Cval::Time(unix) => ArgValue::Time(unix),
                    other => return Err(rpc_type_err(&k, tchar, &other)),
                },
                _ => {
                    return Err(format!(
                        "I don't know about typeaa {}  {}!\n",
                        go_type_name(&v),
                        k
                    ))
                }
            };
            let name = k[..k.len() - 1].to_string(); // last byte is ASCII here
            args.push(Argument { name, value });
        }
        // Go sorts the decoded arguments by name (rpc.go:305, Sort rpc.go:355-364);
        // a stable name sort is a deterministic refinement of it (Go's order for
        // equal names is unspecified: non-stable sort over random map iteration).
        args.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Arguments(args))
    }

    /// Find an argument by name.
    pub fn get(&self, name: &str) -> Option<&ArgValue> {
        self.0.iter().find(|a| a.name == name).map(|a| &a.value)
    }
}

// ===========================================================================
// Go-exact decode path: fxamacker/cbor v2 (vendored in derohe-reference) with
// rpc.go's dec_options (defaults + TimeTag: DecTagRequired), decoding into
// `map[string]interface{}`, plus rpc.go's per-key dispatch. Error strings are
// reproduced verbatim; everything below is pinned by vectors/argdecode.json.
// ===========================================================================

const GO_MAP_TYPE: &str = "map[string]interface {}";

/// The Go `interface{}` values fxamacker's `parse` can produce for our inputs
/// (decode.go:864-994). Variants that can never satisfy an rpc.go type
/// assertion carry no payload — only their Go `%T` name matters.
#[derive(Debug)]
enum Cval {
    U64(u64),
    I64(i64),
    /// `big.Int` — negative ints below -2^63 and tag 2/3 bignums.
    Big,
    F64(f64),
    Bytes(Vec<u8>),
    Text(String),
    Bool,
    /// CBOR null/undefined → Go `nil` (`%T` prints `<nil>`).
    Nil,
    /// `[]interface {}`.
    Arr,
    /// `map[interface {}]interface {}`.
    Map,
    /// `cbor.Tag{Number, Content}` — non-built-in tag numbers. The content is
    /// kept only for Go's recursive map-key hashability check.
    Tag(Box<Cval>),
    /// `time.Time` from tag 0/1, reduced to Unix seconds (floor — matches the
    /// `Unix()` Go uses for both re-marshaling and wallet rendering; the
    /// sub-second part and zone are intentionally dropped from the model).
    Time(i64),
}

fn go_type_name(v: &Cval) -> &'static str {
    match v {
        Cval::U64(_) => "uint64",
        Cval::I64(_) => "int64",
        Cval::Big => "big.Int",
        Cval::F64(_) => "float64",
        Cval::Bytes(_) => "[]uint8",
        Cval::Text(_) => "string",
        Cval::Bool => "bool",
        Cval::Nil => "<nil>",
        Cval::Arr => "[]interface {}",
        Cval::Map => "map[interface {}]interface {}",
        Cval::Tag(_) => "cbor.Tag",
        Cval::Time(_) => "time.Time",
    }
}

/// fxamacker `isHashableValue` (decode.go:1841-1855): slices, maps and
/// `big.Int` can't be Go map keys; a `cbor.Tag` is hashable iff its content is.
fn go_hashable(v: &Cval) -> bool {
    match v {
        Cval::Bytes(_) | Cval::Arr | Cval::Map | Cval::Big => false,
        Cval::Tag(content) => go_hashable(content),
        _ => true,
    }
}

/// rpc.go:246/252/...: `fmt.Errorf("%+v has invalid data type[i] %T\n", arg, v)`
/// — `Argument` implements Stringer, so `%+v` prints
/// `Name:<name> Type:<DataType.String()> Value:'<verb of nil>'`; the value is
/// still nil at that point. Note DataInt64's "typei" typo (rpc.go:246).
fn rpc_type_err(key: &str, tchar: u8, v: &Cval) -> String {
    let name = &key[..key.len() - 1];
    let (tname, verb) = match tchar {
        b'S' => ("string", 's'),
        b'I' => ("int64", 'd'),
        b'U' => ("uint64", 'd'),
        b'F' => ("float64", 'f'),
        b'H' => ("hash", 's'),
        b'A' => ("address", 's'),
        b'T' => ("time", 's'),
        _ => unreachable!("rpc_type_err only called for known type chars"),
    };
    let typei = if tchar == b'I' { "typei" } else { "type" };
    format!(
        "Name:{name} Type:{tname} Value:'%!{verb}(<nil>)' has invalid data {typei} {}\n",
        go_type_name(v)
    )
}

/// fxamacker `UnmarshalTypeError.Error()` (decode.go:131-142), no struct field.
fn fill_err(cbor_type: &str, go_type: &str) -> String {
    format!("cbor: cannot unmarshal {cbor_type} into Go value of type {go_type}")
}

fn fill_err_msg(cbor_type: &str, go_type: &str, msg: &str) -> String {
    format!("cbor: cannot unmarshal {cbor_type} into Go value of type {go_type} ({msg})")
}

/// Decimal text of the negative integer encoded by CBOR major-1 head `val`
/// (-1 - val; needs i128 for val ≥ 2^63).
fn neg_big_str(val: u64) -> String {
    (-1i128 - val as i128).to_string()
}

/// fxamacker `cborType.String()` (decode.go:515-536).
fn major_name(major: u8) -> &'static str {
    match major {
        0 => "positive integer",
        1 => "negative integer",
        2 => "byte string",
        3 => "UTF-8 text string",
        4 => "array",
        5 => "map",
        6 => "tag",
        _ => "primitives",
    }
}

/// fxamacker `validBuiltinTag` (decode.go:1857-1881).
fn valid_builtin_tag(tag_num: u64, content_head: u8) -> Result<(), String> {
    let t = content_head >> 5;
    match tag_num {
        0 => {
            if t != 3 {
                return Err(format!(
                    "cbor: tag number 0 must be followed by text string, got {}",
                    major_name(t)
                ));
            }
        }
        1 => {
            if t != 0 && t != 1 && !(0xf9..=0xfb).contains(&content_head) {
                return Err(format!(
                    "cbor: tag number 1 must be followed by integer or floating-point number, got {}",
                    major_name(t)
                ));
            }
        }
        2 | 3 => {
            if t != 2 {
                return Err(format!(
                    "cbor: tag number 2 or 3 must be followed by byte string, got {}",
                    major_name(t)
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

// ---- phase 1: well-formedness (port of fxamacker valid.go, default limits:
// MaxNestedLevels 32, MaxArrayElements/MaxMapPairs 131072, indefinite-length
// and tags ALLOWED). Validates only the FIRST item; trailing bytes ignored. ----

const MAX_NESTED_LEVELS: usize = 32;
const MAX_ARRAY_ELEMENTS: u64 = 131072;
const MAX_MAP_PAIRS: u64 = 131072;

struct Validator<'a> {
    d: &'a [u8],
    off: usize,
}

impl<'a> Validator<'a> {
    /// valid.go `validHead`.
    fn valid_head(&mut self) -> Result<(u8, u8, u64), String> {
        let data_len = self.d.len() - self.off;
        if data_len == 0 {
            return Err("unexpected EOF".to_string());
        }
        let t = self.d[self.off] >> 5;
        let ai = self.d[self.off] & 0x1f;
        let mut val = ai as u64;
        self.off += 1;
        match ai {
            0..=23 => {}
            24 => {
                if data_len < 2 {
                    return Err("unexpected EOF".to_string());
                }
                val = self.d[self.off] as u64;
                self.off += 1;
                if t == 7 && val < 32 {
                    return Err(format!(
                        "cbor: invalid simple value {val} for type primitives"
                    ));
                }
            }
            25 => {
                if data_len < 3 {
                    return Err("unexpected EOF".to_string());
                }
                val = u16::from_be_bytes(self.d[self.off..self.off + 2].try_into().unwrap())
                    as u64;
                self.off += 2;
            }
            26 => {
                if data_len < 5 {
                    return Err("unexpected EOF".to_string());
                }
                val = u32::from_be_bytes(self.d[self.off..self.off + 4].try_into().unwrap())
                    as u64;
                self.off += 4;
            }
            27 => {
                if data_len < 9 {
                    return Err("unexpected EOF".to_string());
                }
                val = u64::from_be_bytes(self.d[self.off..self.off + 8].try_into().unwrap());
                self.off += 8;
            }
            31 => match t {
                0 | 1 | 6 => {
                    return Err(format!(
                        "cbor: invalid additional information {ai} for type {}",
                        major_name(t)
                    ))
                }
                7 => return Err("cbor: unexpected \"break\" code".to_string()),
                _ => {}
            },
            _ => {
                // ai == 28, 29, 30
                return Err(format!(
                    "cbor: invalid additional information {ai} for type {}",
                    major_name(t)
                ));
            }
        }
        Ok((t, ai, val))
    }

    /// valid.go `validInternal` — returns max depth.
    fn valid_internal(&mut self, mut depth: usize) -> Result<usize, String> {
        let (t, ai, val) = self.valid_head()?;
        match t {
            2 | 3 => {
                if ai == 31 {
                    return self.valid_indefinite_string(t, depth);
                }
                // Go: int(val) < 0 — 64-bit int overflow detection
                if val > i64::MAX as u64 {
                    return Err(format!(
                        "cbor: {} length {val} is too large, causing integer overflow",
                        major_name(t)
                    ));
                }
                if ((self.d.len() - self.off) as u64) < val {
                    return Err("unexpected EOF".to_string());
                }
                self.off += val as usize;
            }
            4 | 5 => {
                depth += 1;
                if depth > MAX_NESTED_LEVELS {
                    return Err(format!("cbor: exceeded max nested level {MAX_NESTED_LEVELS}"));
                }
                if ai == 31 {
                    return self.valid_indefinite_array_or_map(t, depth);
                }
                if val > i64::MAX as u64 {
                    return Err(format!(
                        "cbor: {} length {val} is too large, it would cause integer overflow",
                        major_name(t)
                    ));
                }
                if t == 4 {
                    if val > MAX_ARRAY_ELEMENTS {
                        return Err(format!(
                            "cbor: exceeded max number of elements {MAX_ARRAY_ELEMENTS} for CBOR array"
                        ));
                    }
                } else if val > MAX_MAP_PAIRS {
                    return Err(format!(
                        "cbor: exceeded max number of key-value pairs {MAX_MAP_PAIRS} for CBOR map"
                    ));
                }
                let count = if t == 5 { 2 } else { 1 };
                let mut max_depth = depth;
                for _ in 0..count {
                    for _ in 0..val {
                        let dpt = self.valid_internal(depth)?;
                        if dpt > max_depth {
                            max_depth = dpt;
                        }
                    }
                }
                depth = max_depth;
            }
            6 => {
                // Scan nested tag numbers to avoid recursion (valid.go:155-170).
                loop {
                    if self.d.len() == self.off {
                        // Tag number must be followed by tag content.
                        return Err("unexpected EOF".to_string());
                    }
                    if self.d[self.off] >> 5 != 6 {
                        break;
                    }
                    self.valid_head()?;
                    depth += 1;
                    if depth > MAX_NESTED_LEVELS {
                        return Err(format!(
                            "cbor: exceeded max nested level {MAX_NESTED_LEVELS}"
                        ));
                    }
                }
                return self.valid_internal(depth);
            }
            _ => {}
        }
        Ok(depth)
    }

    /// valid.go `validIndefiniteString`.
    fn valid_indefinite_string(&mut self, t: u8, mut depth: usize) -> Result<usize, String> {
        loop {
            if self.d.len() == self.off {
                return Err("unexpected EOF".to_string());
            }
            if self.d[self.off] == 0xff {
                self.off += 1;
                break;
            }
            let nt = self.d[self.off] >> 5;
            if nt != t {
                return Err(format!(
                    "cbor: wrong element type {} for indefinite-length {}",
                    major_name(nt),
                    major_name(t)
                ));
            }
            if self.d[self.off] & 0x1f == 31 {
                return Err(format!(
                    "cbor: indefinite-length {} chunk is not definite-length",
                    major_name(t)
                ));
            }
            depth = self.valid_internal(depth)?;
        }
        Ok(depth)
    }

    /// valid.go `validIndefiniteArrayOrMap`.
    fn valid_indefinite_array_or_map(&mut self, t: u8, depth: usize) -> Result<usize, String> {
        let mut max_depth = depth;
        let mut i: u64 = 0;
        loop {
            if self.d.len() == self.off {
                return Err("unexpected EOF".to_string());
            }
            if self.d[self.off] == 0xff {
                self.off += 1;
                break;
            }
            let dpt = self.valid_internal(depth)?;
            if dpt > max_depth {
                max_depth = dpt;
            }
            i += 1;
            if t == 4 {
                if i > MAX_ARRAY_ELEMENTS {
                    return Err(format!(
                        "cbor: exceeded max number of elements {MAX_ARRAY_ELEMENTS} for CBOR array"
                    ));
                }
            } else if i % 2 == 0 && i / 2 > MAX_MAP_PAIRS {
                return Err(format!(
                    "cbor: exceeded max number of key-value pairs {MAX_MAP_PAIRS} for CBOR map"
                ));
            }
        }
        if t == 5 && i % 2 == 1 {
            return Err("cbor: unexpected \"break\" code".to_string());
        }
        Ok(max_depth)
    }
}

// ---- phase 2: parse (port of fxamacker decode.go `parseToValue`/`parse`/
// `parseMapToMap`/`parseToTime`; assumes phase-1-validated data). ----

/// Go: `dec.Unmarshal(data, &localmap)` — the localmap as insertion-ordered
/// (key, value) pairs with keep-last duplicate semantics. Go iterates its map
/// randomly; CBOR document order is our deterministic refinement.
fn cbor_unmarshal_localmap(data: &[u8]) -> Result<Vec<(String, Cval)>, String> {
    // decoder.value(): empty input → io.EOF; then a full validity pass whose
    // errors precede all parse errors (decode.go:479-499, valid.go:72-78).
    if data.is_empty() {
        return Err("EOF".to_string());
    }
    Validator { d: data, off: 0 }.valid_internal(0)?;
    Parser { d: data, off: 0 }.parse_top_to_map()
}

struct Parser<'a> {
    d: &'a [u8],
    off: usize,
}

impl<'a> Parser<'a> {
    fn next_major(&self) -> u8 {
        self.d[self.off] >> 5
    }

    /// decode.go `getHead` — assumes well-formed data.
    fn get_head(&mut self) -> (u8, u8, u64) {
        let t = self.d[self.off] >> 5;
        let ai = self.d[self.off] & 0x1f;
        let mut val = ai as u64;
        self.off += 1;
        match ai {
            24 => {
                val = self.d[self.off] as u64;
                self.off += 1;
            }
            25 => {
                val = u16::from_be_bytes(self.d[self.off..self.off + 2].try_into().unwrap())
                    as u64;
                self.off += 2;
            }
            26 => {
                val = u32::from_be_bytes(self.d[self.off..self.off + 4].try_into().unwrap())
                    as u64;
                self.off += 4;
            }
            27 => {
                val = u64::from_be_bytes(self.d[self.off..self.off + 8].try_into().unwrap());
                self.off += 8;
            }
            _ => {}
        }
        (t, ai, val)
    }

    /// decode.go `skip`.
    fn skip(&mut self) {
        let (t, ai, val) = self.get_head();
        if ai == 31 && matches!(t, 2 | 3 | 4 | 5) {
            loop {
                if self.d[self.off] == 0xff {
                    self.off += 1;
                    return;
                }
                self.skip();
            }
        }
        match t {
            2 | 3 => self.off += val as usize,
            4 => {
                for _ in 0..val {
                    self.skip();
                }
            }
            5 => {
                for _ in 0..val.saturating_mul(2) {
                    self.skip();
                }
            }
            6 => self.skip(),
            _ => {}
        }
    }

    /// decode.go `foundBreak`.
    fn found_break(&mut self) -> bool {
        if self.d[self.off] == 0xff {
            self.off += 1;
            return true;
        }
        false
    }

    /// decode.go `parseByteString` (chunked indefinite supported).
    fn parse_byte_string(&mut self) -> Vec<u8> {
        let (_, ai, val) = self.get_head();
        if ai != 31 {
            let b = self.d[self.off..self.off + val as usize].to_vec();
            self.off += val as usize;
            return b;
        }
        let mut b = Vec::new();
        while !self.found_break() {
            let (_, _, n) = self.get_head();
            b.extend_from_slice(&self.d[self.off..self.off + n as usize]);
            self.off += n as usize;
        }
        b
    }

    /// decode.go `parseTextString` — NOTE: UTF-8 is validated PER CHUNK, so a
    /// rune split across indefinite-length chunks is rejected.
    fn parse_text_string(&mut self) -> Result<String, String> {
        const ERR: &str = "cbor: invalid UTF-8 string";
        let (_, ai, val) = self.get_head();
        if ai != 31 {
            let b = &self.d[self.off..self.off + val as usize];
            self.off += val as usize;
            return match std::str::from_utf8(b) {
                Ok(s) => Ok(s.to_string()),
                Err(_) => Err(ERR.to_string()),
            };
        }
        let mut b = Vec::new();
        while !self.found_break() {
            let (_, _, n) = self.get_head();
            let x = &self.d[self.off..self.off + n as usize];
            self.off += n as usize;
            if std::str::from_utf8(x).is_err() {
                while !self.found_break() {
                    self.skip(); // skip remaining chunks on error
                }
                return Err(ERR.to_string());
            }
            b.extend_from_slice(x);
        }
        // valid chunks concatenate to a valid string
        Ok(String::from_utf8(b).expect("chunks individually validated"))
    }

    /// parseToValue's strip of self-described CBOR tag 55799 (decode.go:565-573).
    fn strip_self_described(&mut self) {
        while self.next_major() == 6 {
            let save = self.off;
            let (_, _, num) = self.get_head();
            if num != 55799 {
                self.off = save;
                break;
            }
        }
    }

    /// The validity-of-built-in-tags check both parseToValue and parse perform
    /// before dispatching (decode.go:576-584, 877-886). Consumes the tag and
    /// skips its content on error, restores the offset on success.
    fn check_builtin_tag(&mut self) -> Result<(), String> {
        if self.next_major() == 6 {
            let save = self.off;
            let (_, _, num) = self.get_head();
            if let Err(e) = valid_builtin_tag(num, self.d[self.off]) {
                self.skip();
                return Err(e);
            }
            self.off = save;
        }
        Ok(())
    }

    /// decode.go `parse(skipSelfDescribedTag)` → Go `interface{}` (IntDecConvertNone).
    /// Always consumes exactly one item, even on error.
    fn parse(&mut self, skip_self_described_tag: bool) -> Result<Cval, String> {
        if skip_self_described_tag {
            self.strip_self_described();
        }
        self.check_builtin_tag()?;
        match self.next_major() {
            0 => {
                let (_, _, val) = self.get_head();
                Ok(Cval::U64(val))
            }
            1 => {
                let (_, _, val) = self.get_head();
                if val > i64::MAX as u64 {
                    // overflows int64 → big.Int (decode.go:903-911)
                    Ok(Cval::Big)
                } else {
                    Ok(Cval::I64(-1 - val as i64))
                }
            }
            2 => Ok(Cval::Bytes(self.parse_byte_string())),
            3 => self.parse_text_string().map(Cval::Text),
            4 => {
                // parseArray: elements parsed with parse(true); the first
                // error is captured and parsing continues (decode.go:1046-1066).
                let (_, ai, val) = self.get_head();
                let has_size = ai != 31;
                let mut first_err: Option<String> = None;
                let mut i: u64 = 0;
                loop {
                    if has_size {
                        if i >= val {
                            break;
                        }
                    } else if self.found_break() {
                        break;
                    }
                    i += 1;
                    if let Err(e) = self.parse(true) {
                        first_err.get_or_insert(e);
                    }
                }
                match first_err {
                    Some(e) => Err(e),
                    None => Ok(Cval::Arr),
                }
            }
            5 => {
                // parseMap → map[interface{}]interface{} with the hashable-key
                // check (decode.go:1120-1177).
                let (_, ai, val) = self.get_head();
                let has_size = ai != 31;
                let mut first_err: Option<String> = None;
                let mut i: u64 = 0;
                loop {
                    if has_size {
                        if i >= val {
                            break;
                        }
                    } else if self.found_break() {
                        break;
                    }
                    i += 1;
                    match self.parse(true) {
                        Err(e) => {
                            first_err.get_or_insert(e);
                            self.skip(); // skip value
                            continue;
                        }
                        Ok(k) => {
                            if !go_hashable(&k) {
                                first_err.get_or_insert(format!(
                                    "cbor: invalid map key type: {}",
                                    go_type_name(&k)
                                ));
                                self.skip(); // skip value
                                continue;
                            }
                        }
                    }
                    if let Err(e) = self.parse(true) {
                        first_err.get_or_insert(e);
                    }
                }
                match first_err {
                    Some(e) => Err(e),
                    None => Ok(Cval::Map),
                }
            }
            6 => {
                let tag_off = self.off;
                let (_, _, num) = self.get_head();
                match num {
                    0 | 1 => {
                        self.off = tag_off;
                        self.parse_to_time().map(Cval::Time)
                    }
                    2 | 3 => {
                        let _ = self.parse_byte_string();
                        Ok(Cval::Big)
                    }
                    _ => {
                        let content = self.parse(false)?;
                        Ok(Cval::Tag(Box::new(content)))
                    }
                }
            }
            _ => {
                let (_, ai, val) = self.get_head();
                if ai < 20 || ai == 24 {
                    // simple values decode to Go uint64 (decode.go:969-971)!
                    return Ok(Cval::U64(val));
                }
                match ai {
                    20 | 21 => Ok(Cval::Bool),
                    22 | 23 => Ok(Cval::Nil),
                    25 => Ok(Cval::F64(f16_bits_to_f32(val as u16) as f64)),
                    26 => Ok(Cval::F64(f32::from_bits(val as u32) as f64)),
                    _ => Ok(Cval::F64(f64::from_bits(val))), // ai == 27
                }
            }
        }
    }

    /// decode.go `parseToTime` with `TimeTag: DecTagRequired` — only entered
    /// from `parse` on tag 0/1, whose content type validBuiltinTag has already
    /// constrained (tag 0 → text, tag 1 → int/float).
    fn parse_to_time(&mut self) -> Result<i64, String> {
        let (_, _, _num) = self.get_head(); // tag 0 or 1
        match self.parse(false)? {
            Cval::U64(c) => Ok(c as i64), // time.Unix(int64(c), 0) — wraps
            Cval::I64(c) => Ok(c),
            Cval::F64(f) => {
                if f.is_nan() || f.is_infinite() {
                    // Go: zero time, NO error (decode.go:822-825)
                    return Ok(GO_ZERO_TIME_UNIX);
                }
                // Go: f1, f2 := math.Modf(c); time.Unix(int64(f1), int64(f2*1e9)).
                // int64(float64) of an out-of-range value is amd64 cvttsd2si:
                // the "integer indefinite" i64::MIN (pinned by t_tag1_f64_huge).
                let t = f.trunc();
                let sec = if (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0)
                    .contains(&t)
                {
                    t as i64
                } else {
                    i64::MIN
                };
                let nsec = ((f - t) * 1e9) as i64; // in (-1e9, 1e9)
                Ok(if nsec < 0 { sec.wrapping_sub(1) } else { sec })
            }
            Cval::Text(s) => match go_parse_rfc3339(&s) {
                Ok(unix) => Ok(unix),
                Err(e) => Err(format!("cbor: cannot set {s} for time.Time: {e}")),
            },
            // tag-1 negint below -2^63 → big.Int → default arm (decode.go:836-838)
            _ => Err(fill_err("tag", "time.Time")),
        }
    }

    /// decode.go `parseToValue` into a `string` map key. Mirrors the reused
    /// `keyValue` variable: CBOR null/undefined keys are a no-op (`fillNil`
    /// ignores string kinds), leaving the PREVIOUS key in `slot`.
    fn parse_key(&mut self, slot: &mut String) -> Result<(), String> {
        self.strip_self_described();
        self.check_builtin_tag()?;
        match self.next_major() {
            0 => {
                self.get_head();
                Err(fill_err("positive integer", "string"))
            }
            1 => {
                let (_, _, val) = self.get_head();
                if val > i64::MAX as u64 {
                    Err(fill_err_msg(
                        "negative integer",
                        "string",
                        &format!("{} overflows Go's int64", neg_big_str(val)),
                    ))
                } else {
                    Err(fill_err("negative integer", "string"))
                }
            }
            2 => {
                let _ = self.parse_byte_string();
                Err(fill_err("byte string", "string"))
            }
            3 => {
                *slot = self.parse_text_string()?;
                Ok(())
            }
            4 => {
                self.skip();
                Err(fill_err("array", "string"))
            }
            5 => {
                self.skip();
                Err(fill_err("map", "string"))
            }
            6 => {
                let (_, _, num) = self.get_head();
                match num {
                    2 => {
                        let b = self.parse_byte_string();
                        let bi = num_bigint::BigUint::from_bytes_be(&b);
                        if bi.bits() <= 64 {
                            Err(fill_err("tag", "string"))
                        } else {
                            Err(fill_err_msg("tag", "string", &format!("{bi} overflows string")))
                        }
                    }
                    3 => {
                        let b = self.parse_byte_string();
                        // value is -(b+1); IsInt64 iff b+1 <= 2^63
                        let bi = num_bigint::BigUint::from_bytes_be(&b) + 1u32;
                        if bi.bits() <= 63 || bi == num_bigint::BigUint::from(1u128 << 63) {
                            Err(fill_err("tag", "string"))
                        } else {
                            Err(fill_err_msg("tag", "string", &format!("-{bi} overflows string")))
                        }
                    }
                    // tag 0/1/55799/other: decode the CONTENT into the key
                    // (decode.go:686-732 falls through to a recursive
                    // parseToValue) — e.g. a tag-0-wrapped text key works.
                    _ => self.parse_key(slot),
                }
            }
            _ => {
                let (_, ai, _) = self.get_head();
                match ai {
                    22 | 23 => Ok(()), // fillNil: no-op for string kinds!
                    _ => Err(fill_err("primitives", "string")),
                }
            }
        }
    }

    /// decode.go `parseToValue` into `interface{}`: strip tag 55799, then `parse`.
    fn parse_value(&mut self) -> Result<Cval, String> {
        self.strip_self_described();
        self.parse(false)
    }

    /// decode.go `parseToValue` with the top-level `map[string]interface{}`
    /// destination: the UnmarshalTypeError table for every non-map CBOR type,
    /// CBOR null/undefined setting the map to nil (= no arguments), and tags
    /// recursing into their content.
    fn parse_top_to_map(&mut self) -> Result<Vec<(String, Cval)>, String> {
        self.strip_self_described();
        self.check_builtin_tag()?;
        match self.next_major() {
            0 => {
                self.get_head();
                Err(fill_err("positive integer", GO_MAP_TYPE))
            }
            1 => {
                let (_, _, val) = self.get_head();
                if val > i64::MAX as u64 {
                    Err(fill_err_msg(
                        "negative integer",
                        GO_MAP_TYPE,
                        &format!("{} overflows Go's int64", neg_big_str(val)),
                    ))
                } else {
                    Err(fill_err("negative integer", GO_MAP_TYPE))
                }
            }
            2 => {
                let _ = self.parse_byte_string();
                Err(fill_err("byte string", GO_MAP_TYPE))
            }
            3 => {
                self.parse_text_string()?; // invalid UTF-8 error wins
                Err(fill_err("UTF-8 text string", GO_MAP_TYPE))
            }
            4 => {
                self.skip();
                Err(fill_err("array", GO_MAP_TYPE))
            }
            5 => self.parse_map_to_localmap(),
            6 => {
                let (_, _, num) = self.get_head();
                match num {
                    2 => {
                        let b = self.parse_byte_string();
                        let bi = num_bigint::BigUint::from_bytes_be(&b);
                        if bi.bits() <= 64 {
                            Err(fill_err("tag", GO_MAP_TYPE))
                        } else {
                            Err(fill_err_msg(
                                "tag",
                                GO_MAP_TYPE,
                                &format!("{bi} overflows {GO_MAP_TYPE}"),
                            ))
                        }
                    }
                    3 => {
                        let b = self.parse_byte_string();
                        let bi = num_bigint::BigUint::from_bytes_be(&b) + 1u32;
                        if bi.bits() <= 63 || bi == num_bigint::BigUint::from(1u128 << 63) {
                            Err(fill_err("tag", GO_MAP_TYPE))
                        } else {
                            Err(fill_err_msg(
                                "tag",
                                GO_MAP_TYPE,
                                &format!("-{bi} overflows {GO_MAP_TYPE}"),
                            ))
                        }
                    }
                    // tag 0/1/other at the top level is NOT time-special for a
                    // map destination: recurse into the content (decode.go:732).
                    _ => self.parse_top_to_map(),
                }
            }
            _ => {
                let (_, ai, _) = self.get_head();
                match ai {
                    // fillNil sets the map to nil → zero arguments, success
                    22 | 23 => Ok(Vec::new()),
                    _ => Err(fill_err("primitives", GO_MAP_TYPE)),
                }
            }
        }
    }

    /// decode.go `parseMapToMap` (K=string, V=interface{}, DupMapKeyQuiet):
    /// last duplicate wins; the first error is remembered while parsing
    /// continues; pairs with failing values are dropped.
    fn parse_map_to_localmap(&mut self) -> Result<Vec<(String, Cval)>, String> {
        let (_, ai, val) = self.get_head();
        let has_size = ai != 31;
        let mut first_err: Option<String> = None;
        let mut key_slot = String::new(); // Go reuses one reflect string value
        let mut entries: Vec<(String, Cval)> = Vec::new();
        let mut i: u64 = 0;
        loop {
            if has_size {
                if i >= val {
                    break;
                }
            } else if self.found_break() {
                break;
            }
            i += 1;
            if let Err(e) = self.parse_key(&mut key_slot) {
                first_err.get_or_insert(e);
                self.skip(); // skip value
                continue;
            }
            match self.parse_value() {
                Err(e) => {
                    first_err.get_or_insert(e);
                    continue; // pair dropped
                }
                Ok(v) => {
                    if let Some(slot) = entries.iter_mut().find(|(k, _)| *k == key_slot) {
                        slot.1 = v; // SetMapIndex overwrite: keep-last
                    } else {
                        entries.push((key_slot.clone(), v));
                    }
                }
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(entries)
    }
}

// ---- DataAddress "A" (rpc.go:268-281 + bn256 changes.go) ----

/// Go: `crypto.Point.DecodeCompressed` on the 33-byte (zero-padded/truncated)
/// buffer, returning the bytes `EncodeCompressed` would re-emit (the wallet's
/// value model keeps the compressed form).
///
/// changes.go `Decompress`: y² = x³+3 with x taken UNREDUCED from the first 32
/// bytes; `ModSqrt` failing (non-residue) is the ONLY error path —
/// "bn256: Cannot decompress". `marshal()` then IGNORES `G1.Unmarshal`'s
/// error, so x ≥ p (or a chosen y = p, unreachable here: no x³+3 ≡ 0 mod p
/// exists) leaves a broken z=0 point that re-encodes as 33 zero bytes.
/// Re-compression normalizes non-0/1 parity flags. All pinned by the `a_*`
/// cases in vectors/argdecode.json.
fn decode_address_go(b: &[u8]) -> Result<[u8; 33], String> {
    use num_bigint::BigUint;

    let mut a = [0u8; 33];
    let n = b.len().min(33);
    a[..n].copy_from_slice(&b[..n]);

    let p = dero_bn256::field_prime();
    let x = BigUint::from_bytes_be(&a[..32]);
    let beta = (&x * &x * &x + 3u32) % &p;
    // p ≡ 3 (mod 4): principal root = beta^((p+1)/4); verify like ModSqrt
    let exp = (&p + 1u32) >> 2;
    let y1 = beta.modpow(&exp, &p);
    if (&y1 * &y1) % &p != beta {
        return Err("bn256: Cannot decompress".to_string());
    }
    let y2 = &p - &y1; // Go: p - y1 even when y1 == 0
    let smaller = y1 < y2;
    let flag = a[32];
    let chosen = if flag == 0x00 && smaller {
        y1
    } else if flag == 0x01 && smaller {
        y2
    } else if flag == 0x00 {
        y2
    } else {
        y1
    };
    if x >= p || chosen >= p {
        // Go swallows G1.Unmarshal's "coordinate exceeds modulus": the point
        // keeps z=0 and EncodeCompressed yields the all-zero compressed form.
        return Ok([0u8; 33]);
    }
    let y_neg = &p - &chosen;
    let mut out = [0u8; 33];
    out[..32].copy_from_slice(&a[..32]);
    out[32] = if chosen < y_neg { 0x00 } else { 0x01 };
    Ok(out)
}

// ---- Go time.Parse(time.RFC3339, ·) (go1.26 time/format.go general parser) ----

const RFC3339_LAYOUT: &str = "2006-01-02T15:04:05Z07:00";

/// time/format.go `quote` (go1.26:865-899): ASCII printables raw ('"' and '\'
/// backslash-escaped); control bytes and every byte of non-ASCII runes as
/// `\xNN` (an invalid byte decodes as U+FFFD with width 1).
fn go_time_quote(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b < 0x80 {
            if b < 0x20 {
                out.push_str(&format!("\\x{b:02x}"));
            } else {
                if b == b'"' || b == b'\\' {
                    out.push('\\');
                }
                out.push(b as char);
            }
            i += 1;
        } else {
            // one rune, Go range-over-string semantics
            let width = if s[i..].starts_with(&[0xef, 0xbf, 0xbd]) {
                3 // a literal U+FFFD
            } else {
                match utf8_sequence_len(&s[i..]) {
                    Some(w) => w,
                    None => 1, // invalid byte → runeError, width 1
                }
            };
            for j in 0..width {
                out.push_str(&format!("\\x{:02x}", s[i + j]));
            }
            i += width;
        }
    }
    out.push('"');
    out
}

/// Length of a valid UTF-8 sequence starting the slice, if any.
fn utf8_sequence_len(s: &[u8]) -> Option<usize> {
    let w = match s[0] {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    if s.len() < w || std::str::from_utf8(&s[..w]).is_err() {
        return None;
    }
    Some(w)
}

/// Go `time.Parse(time.RFC3339, s)` → Unix seconds (floor — fractional
/// seconds are non-negative) — or the exact go1.26 `ParseError` text.
///
/// time.Parse tries the strict `parseRFC3339` fast path first and falls back
/// to the GENERAL layout parser (format.go `parse`), so acceptance and all
/// errors follow the general parser: single-digit hours, ',' fractions and
/// zone offsets up to ±24:60 are accepted; element errors are
/// `cannot parse <rest> as <element>`, range errors `<unit> out of range`,
/// leftover input `extra text: ...`.
fn go_parse_rfc3339(value: &str) -> Result<i64, String> {
    let avalue = value.as_bytes();
    let cannot = |layout_elem: &str, value_elem: &[u8]| -> String {
        format!(
            "parsing time {} as {}: cannot parse {} as {}",
            go_time_quote(avalue),
            go_time_quote(RFC3339_LAYOUT.as_bytes()),
            go_time_quote(value_elem),
            go_time_quote(layout_elem.as_bytes())
        )
    };
    let range_err = |unit: &str| -> String {
        format!("parsing time {}: {unit} out of range", go_time_quote(avalue))
    };
    fn digit(s: &[u8], i: usize) -> bool {
        i < s.len() && s[i].is_ascii_digit()
    }
    /// format.go `getnum`: 1 digit, or 2 (`fixed` forces 2).
    fn getnum(s: &[u8], fixed: bool) -> Option<(i64, &[u8])> {
        if !digit(s, 0) {
            return None;
        }
        if !digit(s, 1) {
            if fixed {
                return None;
            }
            return Some(((s[0] - b'0') as i64, &s[1..]));
        }
        Some((((s[0] - b'0') * 10 + (s[1] - b'0')) as i64, &s[2..]))
    }

    let mut v: &[u8] = avalue;

    // stdLongYear "2006": 4 bytes, first a digit, all digits (atoi)
    let hold = v;
    if v.len() < 4 || !digit(v, 0) {
        return Err(cannot("2006", hold));
    }
    if !v[..4].iter().all(|b| b.is_ascii_digit()) {
        return Err(cannot("2006", hold));
    }
    let year = v[..4].iter().fold(0i64, |acc, b| acc * 10 + (b - b'0') as i64);
    v = &v[4..];

    // literal "-"
    if v.is_empty() || v[0] != b'-' {
        return Err(cannot("-", v));
    }
    v = &v[1..];

    // stdZeroMonth "01" (fixed)
    let hold = v;
    let month = match getnum(v, true) {
        Some((n, rest)) => {
            v = rest;
            n
        }
        None => return Err(cannot("01", hold)),
    };
    if !(1..=12).contains(&month) {
        return Err(range_err("month"));
    }

    // literal "-"
    if v.is_empty() || v[0] != b'-' {
        return Err(cannot("-", v));
    }
    v = &v[1..];

    // stdZeroDay "02" (fixed); the full range check happens after parsing
    let hold = v;
    let day = match getnum(v, true) {
        Some((n, rest)) => {
            v = rest;
            n
        }
        None => return Err(cannot("02", hold)),
    };

    // literal "T"
    if v.is_empty() || v[0] != b'T' {
        return Err(cannot("T", v));
    }
    v = &v[1..];

    // stdHour "15" — NOT fixed: a single digit is accepted!
    let hold = v;
    let hour = match getnum(v, false) {
        Some((n, rest)) => {
            v = rest;
            n
        }
        None => return Err(cannot("15", hold)),
    };
    if hour >= 24 {
        return Err(range_err("hour"));
    }

    // literal ":"
    if v.is_empty() || v[0] != b':' {
        return Err(cannot(":", v));
    }
    v = &v[1..];

    // stdZeroMinute "04" (fixed)
    let hold = v;
    let min = match getnum(v, true) {
        Some((n, rest)) => {
            v = rest;
            n
        }
        None => return Err(cannot("04", hold)),
    };
    if min >= 60 {
        return Err(range_err("minute"));
    }

    // literal ":"
    if v.is_empty() || v[0] != b':' {
        return Err(cannot(":", v));
    }
    v = &v[1..];

    // stdZeroSecond "05" (fixed)
    let hold = v;
    let sec = match getnum(v, true) {
        Some((n, rest)) => {
            v = rest;
            n
        }
        None => return Err(cannot("05", hold)),
    };
    if sec >= 60 {
        return Err(range_err("second"));
    }
    // fractional seconds with no layout element: ('.'|',') + digits consumed;
    // parseNanoseconds cannot fail on all-digit input and nsec >= 0 never
    // moves the floor
    if v.len() >= 2 && (v[0] == b'.' || v[0] == b',') && digit(v, 1) {
        let mut n = 2;
        while n < v.len() && digit(v, n) {
            n += 1;
        }
        v = &v[n..];
    }

    // stdISO8601ColonTZ "Z07:00"
    let mut offset_secs: i64 = 0;
    let hold = v;
    if !v.is_empty() && v[0] == b'Z' {
        v = &v[1..];
    } else {
        if v.len() < 6 || v[3] != b':' {
            return Err(cannot("Z07:00", hold));
        }
        let (sign, hh, mm2) = (v[0], &v[1..3], &v[4..6]);
        let rest = &v[6..];
        let hr = match getnum(hh, true) {
            Some((n, _)) => n,
            None => return Err(cannot("Z07:00", hold)),
        };
        let mm = match getnum(mm2, true) {
            Some((n, _)) => n,
            None => return Err(cannot("Z07:00", hold)),
        };
        // "the range test use > rather than >=" (format.go) — and range
        // errors are reported before the bad-sign errBad
        if hr > 24 {
            return Err(range_err("time zone offset hour"));
        }
        if mm > 60 {
            return Err(range_err("time zone offset minute"));
        }
        offset_secs = (hr * 60 + mm) * 60;
        match sign {
            b'+' => {}
            b'-' => offset_secs = -offset_secs,
            _ => return Err(cannot("Z07:00", hold)),
        }
        v = rest;
    }

    // end of layout: leftover input is an error
    if !v.is_empty() {
        return Err(format!(
            "parsing time {}: extra text: {}",
            go_time_quote(avalue),
            go_time_quote(v)
        ));
    }

    // day-of-month validation (format.go:1373-1375)
    if day < 1 || day > days_in(month, year) {
        return Err(format!(
            "parsing time {}: day out of range",
            go_time_quote(avalue)
        ));
    }

    Ok(days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec - offset_secs)
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

/// Go time.daysIn.
fn days_in(m: i64, y: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Days from 1970-01-01 of a proleptic-Gregorian civil date
/// (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719_468
}

#[cfg(test)]
mod canon_tests {
    use super::*;

    // emit a CBOR map with the given (key,value) pairs in the EXACT order passed
    // (no sorting) — used to build a deliberately NON-canonical scdata blob.
    fn raw_map(pairs: &[(&str, &ArgValue)]) -> Vec<u8> {
        let mut out = Vec::new();
        enc_head(&mut out, 5, pairs.len() as u64);
        for (name, val) in pairs {
            let key = format!("{}{}", name, val.type_char());
            enc_text(&mut out, &key);
            enc_value(&mut out, val);
        }
        out
    }

    /// A2: a non-canonically-ordered scdata blob must decode and RE-CANONICALIZE
    /// to the exact same bytes as the canonical encoding — so the txid (computed
    /// over `marshal_binary()`) is invariant to the wire key order, matching Go's
    /// `SCDATA.MarshalBinary()` at `SerializeHeader`.
    #[test]
    fn noncanonical_scdata_recanonicalizes() {
        let a = ArgValue::Uint64(1);
        let b = ArgValue::Uint64(2);
        let c = ArgValue::Str("x".to_string());

        // canonical: built by marshal_binary (sorts the pairs)
        let canonical = Arguments(vec![
            Argument { name: "alpha".into(), value: a.clone() },
            Argument { name: "beta".into(), value: b.clone() },
            Argument { name: "gamma".into(), value: c.clone() },
        ])
        .marshal_binary();

        // non-canonical wire blob: same logical args, reverse key order
        let noncanon = raw_map(&[("gamma", &c), ("beta", &b), ("alpha", &a)]);
        assert_ne!(noncanon, canonical, "the crafted blob must actually be non-canonical");

        let recanon = Arguments::unmarshal_binary_exact(&noncanon)
            .expect("valid CBOR Arguments")
            .marshal_binary();
        assert_eq!(recanon, canonical, "non-canonical scdata must re-canonicalize identically");
    }

    /// A2 (identity direction): Go-canonical scdata must survive
    /// deserialize→re-serialize UNCHANGED. `marshal_binary` == Go's
    /// `MarshalBinary` (gated by `vectors/scdata.json`), so this proves that the
    /// canonicalize-at-deserialize change is the identity on real (Go-produced)
    /// SC-tx scdata — i.e. it does not alter the stored bytes or txid of a normal
    /// SC tx. (The sibling test only covers the non-canonical → canonical case.)
    #[test]
    fn canonical_scdata_roundtrips_to_itself() {
        // U/I/S/H — the value types real SC_INSTALL/SC_CALL scdata carries
        // (SC_ACTION, SC_CODE, names, amounts, scids). These round-trip to
        // identity, so A2's canonicalize-at-deserialize does not change a normal
        // SC tx's stored bytes or txid. (An `A` Address with an *invalid* point
        // is a separate Go/Rust-agree-on-non-identity quirk gated by `argdecode`;
        // a real wallet-built Address is a valid point that also round-trips.)
        let canonical = Arguments(vec![
            Argument { name: "SC_ACTION".into(), value: ArgValue::Uint64(0) },
            Argument {
                name: "SC_CODE".into(),
                value: ArgValue::Str("Function Initialize() Uint64\n10 RETURN 0\nEnd Function".into()),
            },
            Argument { name: "name".into(), value: ArgValue::Str("alice".into()) },
            Argument { name: "amount".into(), value: ArgValue::Uint64(12_345) },
            Argument { name: "delta".into(), value: ArgValue::Int64(-99) },
            Argument { name: "scid".into(), value: ArgValue::Hash([0x5au8; 32]) },
        ])
        .marshal_binary();
        let roundtrip =
            Arguments::unmarshal_binary_exact(&canonical).expect("valid").marshal_binary();
        assert_eq!(roundtrip, canonical, "canonical scdata must round-trip identically");
    }
}

