//! # dero-astrobwt
//!
//! AstroBWTv3 proof-of-work hash for DERO HE STARGATE. Port of
//! `astrobwt/astrobwtv3/pow.go`.
//!
//! Pipeline (per the DERO reference and the published algorithm spec):
//! 1. `sha256(input)` → 32-byte key
//! 2. Salsa20 keystream (key, 16-byte zero counter) over a 256-byte zero buffer
//! 3. modified-RC4 over that buffer
//! 4. FNV-1a-64 initial hash (`lhash`)
//! 5. data-dependent "branchy" op loop (xxhash / siphash / fnv1a / RC4 re-key)
//! 6. SAIS suffix array of the accumulated stream
//! 7. final `sha256` of the suffix array → 32-byte PoW hash
//!
//! All seven steps are implemented and verified byte-exact against the Go
//! reference: steps 1–4 (the "prologue") plus the op loop, suffix array, and
//! final hash, via [`astrobwtv3`] / [`astrobwtv3_full`] (stage-by-stage
//! intermediates in [`Debug`]).

pub mod difficulty;
pub mod hashes;
pub mod lpbuf;
mod ops_generated;
pub mod pow16;
pub mod rc4;
pub mod sais16;
pub mod sais32;
/// Slow O(n log² n) prefix-doubling suffix array, retained as the
/// differential-fuzz oracle for the SA-IS ports ([`sais32`] / [`sais16`]).
pub mod suffixarray;
/// Alias for the retained reference suffix array (the differential-fuzz oracle).
pub use suffixarray::suffix_array as suffix_array_reference;

pub use difficulty::{
    check_pow_hash_big, pow_hash_at_height, pow_hash_at_height_with_scratch, verify_miniblock_pow,
    verify_miniblock_pow_v3, MAJOR_HF2_HEIGHT_MAINNET, MINIBLOCK_HIGHDIFF,
};
pub use lpbuf::{enable_large_pages, large_pages_enabled};
pub use pow16::pow16;

use hashes::{siphash24, xxh64};
use sha2::{Digest, Sha256};

const FNV64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV64_PRIME: u64 = 0x0000_0100_0000_01b3;
const ASTROBWT_DATA_CAPACITY: usize = 280 * 256;

/// Go: `fnv1a.HashBytes64` — FNV-1a 64-bit (xor-then-multiply).
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h = FNV64_OFFSET;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(FNV64_PRIME);
    }
    h
}

/// Salsa20 keystream over a 256-byte zero buffer with the given 32-byte key and
/// an all-zero 16-byte counter — matching Go's
/// `salsa.XORKeyStream(out, out, &[16]byte{0}, &key)` where `out` is zeroed.
///
/// Go's low-level `salsa20/salsa` uses a 16-byte counter (bytes 0..8 = nonce
/// words 6,7; bytes 8..16 = block counter words 8,9). RustCrypto's `Salsa20`
/// takes an 8-byte nonce (words 6,7) and starts its 64-bit block counter (words
/// 8,9) at 0 — identical state for an all-zero counter. Verified byte-exact
/// against the Go reference.
fn salsa20_keystream_256(key: &[u8; 32]) -> [u8; 256] {
    use salsa20::cipher::{KeyIvInit, StreamCipher};
    use salsa20::Salsa20;

    let nonce = [0u8; 8];
    let mut cipher = Salsa20::new(key.into(), (&nonce).into());
    let mut buf = [0u8; 256];
    cipher.apply_keystream(&mut buf);
    buf
}

/// Intermediate state of the AstroBWTv3 prologue (steps 1–4), exposed so it can
/// be cross-checked stage-by-stage against the Go reference.
#[derive(Clone)]
pub struct Prologue {
    /// `sha256(input)`.
    pub sha_key: [u8; 32],
    /// `step_3` after the Salsa20 keystream.
    pub post_salsa: [u8; 256],
    /// `step_3` after the modified RC4.
    pub post_rc4: [u8; 256],
    /// Initial FNV-1a-64 hash of `post_rc4`.
    pub lhash: u64,
}

/// Run AstroBWTv3 steps 1–4 (sha256 → salsa20 → rc4 → fnv1a).
pub fn prologue(input: &[u8]) -> Prologue {
    let sha_key: [u8; 32] = Sha256::digest(input).into();

    let post_salsa = salsa20_keystream_256(&sha_key);

    let mut step_3 = post_salsa;
    let mut cipher = rc4::Rc4::new(&step_3);
    cipher.xor_key_stream(&mut step_3);
    let post_rc4 = step_3;

    let lhash = fnv1a_64(&post_rc4);

    Prologue {
        sha_key,
        post_salsa,
        post_rc4,
        lhash,
    }
}

/// Per-stage intermediate state of a full AstroBWTv3 run, for byte-exact
/// cross-checking against the Go reference's debug instrumentation.
#[derive(Clone)]
pub struct Debug {
    pub tries: u64,
    pub data_len: u32,
    pub lhash: u64,
    pub prev_lhash: u64,
    pub step3: [u8; 256],
    /// `sha256(scratch.data[:data_len])` — fingerprints the whole op-loop stream.
    pub data_hash: [u8; 32],
    pub output: [u8; 32],
}

/// Suffix-array engine for AstroBWTv3 step 6. Defaults to the verified pure-Rust
/// [`sais32::suffix_array`]; with `feature = "libsais"` (miner-only, opt-in) it
/// uses the faster C [`sais32::suffix_array_libsais`], which produces the
/// identical array (gated byte-for-byte). Output is unchanged either way.
#[inline]
fn sa32(text: &[u8]) -> Vec<i32> {
    #[cfg(feature = "libsais")]
    {
        sais32::suffix_array_libsais(text)
    }
    #[cfg(not(feature = "libsais"))]
    {
        sais32::suffix_array(text)
    }
}

#[inline]
fn sha256_sa_i32_le(sa: &[i32]) -> [u8; 32] {
    #[cfg(target_endian = "little")]
    {
        // SAFETY: i32 is a plain 4-byte scalar, and little-endian memory order
        // matches the PoW's required u32 little-endian serialization.
        let bytes = unsafe {
            core::slice::from_raw_parts(sa.as_ptr().cast::<u8>(), std::mem::size_of_val(sa))
        };
        Sha256::digest(bytes).into()
    }
    #[cfg(not(target_endian = "little"))]
    {
        let mut hasher = Sha256::new();
        for &v in sa {
            hasher.update((v as u32).to_le_bytes());
        }
        hasher.finalize().into()
    }
}

/// Reusable per-thread scratch for the AstroBWTv3 mining fast path.
pub struct AstroBwtScratch {
    data: crate::lpbuf::LpVec<u8>,
    #[cfg(feature = "libsais")]
    sa: crate::lpbuf::LpVec<i32>,
    #[cfg(feature = "libsais")]
    libsais_ctx: sais32::LibsaisCtx,
    #[cfg(feature = "v114")]
    v114_markers: Vec<u16>,
    #[cfg(feature = "v114")]
    v114_flags: Vec<u8>,
}

impl AstroBwtScratch {
    pub fn new() -> Self {
        Self {
            data: crate::lpbuf::LpVec::with_capacity(ASTROBWT_DATA_CAPACITY),
            #[cfg(feature = "libsais")]
            sa: crate::lpbuf::LpVec::with_capacity(ASTROBWT_DATA_CAPACITY),
            #[cfg(feature = "libsais")]
            libsais_ctx: sais32::LibsaisCtx::new(),
            #[cfg(feature = "v114")]
            v114_markers: Vec::with_capacity(320),
            #[cfg(feature = "v114")]
            v114_flags: Vec::with_capacity(320),
        }
    }

    pub fn data_capacity(&self) -> usize {
        self.data.capacity()
    }
}

impl Default for AstroBwtScratch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "v114")]
#[inline]
fn write_v114_marker(markers: &mut Vec<u16>, index: usize, first_chunk: u32, chunk_count: u32) {
    let marker = ((first_chunk << 7) | chunk_count) as u16;
    if index == markers.len() {
        markers.push(marker);
    } else {
        markers[index] = marker;
    }
}

/// Full AstroBWTv3 PoW hash (steps 1–7). Returns the 32-byte hash and the
/// per-stage [`Debug`] intermediates.
pub fn astrobwtv3_full(input: &[u8]) -> ([u8; 32], Debug) {
    // --- prologue (steps 1–4) ---
    let sha_key: [u8; 32] = Sha256::digest(input).into();
    let mut step_3 = salsa20_keystream_256(&sha_key);
    let mut rc4 = rc4::Rc4::new(&step_3);
    rc4.xor_key_stream(&mut step_3);
    let mut lhash = fnv1a_64(&step_3);
    let mut prev_lhash = lhash;

    // --- step 5: branchy op loop ---
    let mut tries: u64 = 0;
    let mut data: Vec<u8> = Vec::with_capacity(280 * 256);
    loop {
        tries += 1;
        let random_switcher = prev_lhash ^ lhash ^ tries;
        let op = random_switcher as u8;
        let mut pos1 = (random_switcher >> 8) as u8;
        let mut pos2 = (random_switcher >> 16) as u8;
        if pos1 > pos2 {
            core::mem::swap(&mut pos1, &mut pos2);
        }
        if pos2 - pos1 > 32 {
            pos2 = pos1.wrapping_add((pos2 - pos1) & 0x1f); // max update 32 bytes
        }

        ops_generated::apply_op(
            op,
            &mut step_3,
            pos1,
            pos2,
            &mut lhash,
            &mut prev_lhash,
            &mut rc4,
        );

        let p2 = pos2 as usize;
        let diff = step_3[pos1 as usize].wrapping_sub(step_3[pos2 as usize]);
        if diff < 0x10 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = xxh64(&step_3[..p2]);
        }
        if diff < 0x20 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = fnv1a_64(&step_3[..p2]);
        }
        if diff < 0x30 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = siphash24(tries, prev_lhash, &step_3[..p2]);
        }
        if diff <= 0x40 {
            rc4.xor_key_stream(&mut step_3);
        }

        step_3[255] = step_3[255] ^ step_3[pos1 as usize] ^ step_3[pos2 as usize];
        data.extend_from_slice(&step_3[..]);

        if tries > 260 + 16 || (step_3[255] >= 0xf0 && tries > 260) {
            break;
        }
    }

    let data_len =
        ((tries - 4) * 256 + (((step_3[253] as u64) << 8 | step_3[254] as u64) & 0x3ff)) as u32;
    let dl = data_len as usize;

    // --- step 6: suffix array of the accumulated stream ---
    // SA-IS (linear-time), byte-identical to the retained prefix-doubling
    // reference under Go's sentinel-smallest convention. Go: text_32_0alloc →
    // sais_8_32 (pow.go:2444).
    let sa = sa32(&data[..dl]);

    // --- step 7: sha256 of the suffix array as little-endian i32 bytes ---
    let output = sha256_sa_i32_le(&sa);

    let data_hash: [u8; 32] = Sha256::digest(&data[..dl]).into();
    let dbg = Debug {
        tries,
        data_len,
        lhash,
        prev_lhash,
        step3: step_3,
        data_hash,
        output,
    };
    (output, dbg)
}

pub fn astrobwtv3_with_scratch(input: &[u8], scratch: &mut AstroBwtScratch) -> [u8; 32] {
    // --- prologue (steps 1–4) ---
    let sha_key: [u8; 32] = Sha256::digest(input).into();
    let mut step_3 = salsa20_keystream_256(&sha_key);
    let mut rc4 = rc4::Rc4::new(&step_3);
    rc4.xor_key_stream(&mut step_3);
    let mut lhash = fnv1a_64(&step_3);
    let mut prev_lhash = lhash;

    // --- step 5: branchy op loop ---
    let mut tries: u64 = 0;
    scratch.data.clear();
    #[cfg(feature = "v114")]
    {
        scratch.v114_markers.clear();
    }
    #[cfg(feature = "v114")]
    let mut v114_template_idx = 0usize;
    #[cfg(feature = "v114")]
    let mut v114_first_chunk = 0u32;
    #[cfg(feature = "v114")]
    let mut v114_chunk_count = 1u32;
    loop {
        tries += 1;
        let random_switcher = prev_lhash ^ lhash ^ tries;
        let op = random_switcher as u8;
        let mut pos1 = (random_switcher >> 8) as u8;
        let mut pos2 = (random_switcher >> 16) as u8;
        if pos1 > pos2 {
            core::mem::swap(&mut pos1, &mut pos2);
        }
        if pos2 - pos1 > 32 {
            pos2 = pos1.wrapping_add((pos2 - pos1) & 0x1f); // max update 32 bytes
        }

        ops_generated::apply_op(
            op,
            &mut step_3,
            pos1,
            pos2,
            &mut lhash,
            &mut prev_lhash,
            &mut rc4,
        );

        let p2 = pos2 as usize;
        let diff = step_3[pos1 as usize].wrapping_sub(step_3[pos2 as usize]);
        if diff < 0x10 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = xxh64(&step_3[..p2]);
        }
        if diff < 0x20 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = fnv1a_64(&step_3[..p2]);
        }
        if diff < 0x30 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = siphash24(tries, prev_lhash, &step_3[..p2]);
        }
        if diff <= 0x40 {
            rc4.xor_key_stream(&mut step_3);
            #[cfg(feature = "v114")]
            {
                write_v114_marker(
                    &mut scratch.v114_markers,
                    v114_template_idx,
                    v114_first_chunk,
                    v114_chunk_count,
                );
                if tries > 1 {
                    v114_template_idx += 1;
                }
                v114_first_chunk = tries as u32 - 1;
                v114_chunk_count = 1;
            }
        } else {
            #[cfg(feature = "v114")]
            {
                v114_chunk_count += 1;
            }
        }

        step_3[255] = step_3[255] ^ step_3[pos1 as usize] ^ step_3[pos2 as usize];
        scratch.data.extend_from_slice(&step_3[..]);

        if tries > 260 + 16 || (step_3[255] >= 0xf0 && tries > 260) {
            break;
        }
    }
    #[cfg(feature = "v114")]
    {
        write_v114_marker(
            &mut scratch.v114_markers,
            v114_template_idx,
            v114_first_chunk,
            v114_chunk_count,
        );
        v114_template_idx += 1;
        scratch.v114_markers.truncate(v114_template_idx);
    }

    let data_len =
        ((tries - 4) * 256 + (((step_3[253] as u64) << 8 | step_3[254] as u64) & 0x3ff)) as usize;
    #[cfg(feature = "v114")]
    {
        // The descriptor SA reads up to 3 bytes PAST data_len (load24 with
        // data_len_with_tail = data_len+3). Those bytes MUST be zero or the
        // descriptor builds a SA that diverges from libsais (wrong PoW hash).
        //
        // BUG FIX: the old code took an `if resize else fill` branch — but
        // `Vec::resize(tail_end, 0)` only zeros the NEWLY-appended bytes
        // [old_len..tail_end]. The op-loop leaves real bytes in [data_len..old_len]
        // (old_len = tries*256 > data_len), so whenever old_len < tail_end the
        // resize branch left real op-loop bytes in [data_len..old_len] non-zero.
        // That is exactly r=(step_3[253..255] & 0x3ff) > 1008, i.e. 15/1024 ≈
        // 1.46% of inputs — the observed descriptor-divergence rate. Always zero
        // the full tail unconditionally.
        let tail_end = data_len + 16;
        if scratch.data.len() < tail_end {
            scratch.data.resize(tail_end, 0);
        }
        scratch.data[data_len..tail_end].fill(0);
    }
    // --- steps 6 + 7: suffix array + final sha256 ---
    // Default: MATERIALIZE the descriptor suffix array into the large-paged
    // `scratch.sa` buffer, then SHA-256 it. The ~280 KB SA is the workload's
    // dTLB hog at 24 threads; mapping it into 2 MB pages (see lpbuf) gives it
    // single-entry TLB coverage — the lever that breaks the saturation tie
    // against the C miner, which runs 4 KB pages on Windows.
    //
    // The fused/streaming variant (build SA → SHA without materializing) avoids
    // the sa write+read but cannot benefit from large pages on the SA; kept
    // behind DERO_FUSE_HASH=1 for A/B measurement. Both are byte-identical.
    #[cfg(feature = "v114")]
    let output = {
        use std::sync::OnceLock;
        static FUSE: OnceLock<bool> = OnceLock::new();
        // Fused (stream SA→SHA, no sa materialization) is the default: at 24-thread
        // bandwidth saturation it beats materialize+large-paged-sa, because the
        // sa write+read roundtrip costs more than the SA's large-page TLB benefit
        // saves. Set DERO_MATERIALIZE=1 to A/B the materialized path.
        let fuse = *FUSE.get_or_init(|| std::env::var_os("DERO_MATERIALIZE").is_none());
        if fuse {
            if let Some(h) = sais32::hash_v114_fused_into(
                &scratch.data,
                data_len,
                &scratch.v114_markers,
                &mut scratch.v114_flags,
            ) {
                h
            } else {
                let used_v114 = sais32::suffix_array_v114_into(
                    &scratch.data,
                    data_len,
                    &scratch.v114_markers,
                    &mut scratch.v114_flags,
                    &mut scratch.sa,
                );
                let sa: &[i32] = if used_v114 {
                    &scratch.sa[..]
                } else {
                    sais32::suffix_array_libsais_into(
                        &scratch.data[..data_len],
                        &mut scratch.sa,
                        &scratch.libsais_ctx,
                    )
                };
                sha256_sa_i32_le(sa)
            }
        } else {
            let used_v114 = sais32::suffix_array_v114_into(
                &scratch.data,
                data_len,
                &scratch.v114_markers,
                &mut scratch.v114_flags,
                &mut scratch.sa,
            );
            let sa: &[i32] = if used_v114 {
                &scratch.sa[..]
            } else {
                sais32::suffix_array_libsais_into(
                    &scratch.data[..data_len],
                    &mut scratch.sa,
                    &scratch.libsais_ctx,
                )
            };
            sha256_sa_i32_le(sa)
        }
    };
    #[cfg(all(feature = "libsais", not(feature = "v114")))]
    let output = {
        let data = &scratch.data[..data_len];
        let sa = sais32::suffix_array_libsais_into(data, &mut scratch.sa, &scratch.libsais_ctx);
        sha256_sa_i32_le(sa)
    };
    #[cfg(not(feature = "libsais"))]
    let output = {
        let data = &scratch.data[..data_len];
        let sa = sais32::suffix_array(data);
        sha256_sa_i32_le(&sa)
    };
    output
}

fn astrobwtv3_hash_only(input: &[u8]) -> [u8; 32] {
    let mut scratch = AstroBwtScratch::new();
    astrobwtv3_with_scratch(input, &mut scratch)
}

/// Diagnostic dumper (v114): run the op-loop for `input` and return the exact
/// `(data[..logical_len], flags, logical_len)` that the descriptor SA backend is
/// fed. Lets an external C++ harness reproduce a divergence with a real
/// AstroBWT-shaped input. Not used by the hot path.
#[cfg(feature = "v114")]
pub fn dump_v114_case(input: &[u8]) -> (Vec<u8>, Vec<u8>, usize) {
    let (_, dbg) = astrobwtv3_full(input);
    let logical_len = dbg.data_len as usize;
    let mut scratch = AstroBwtScratch::new();
    let _ = astrobwtv3_with_scratch(input, &mut scratch);
    let mut flags: Vec<u8> = Vec::new();
    let flag_len = crate::sais32::build_v114_stage5_flags(&scratch.v114_markers, logical_len, &mut flags)
        .unwrap_or(0) as usize;
    flags.truncate(flag_len);
    let data = scratch.data[..logical_len].to_vec();
    (data, flags, logical_len)
}

/// Measurement-only twin of [`astrobwtv3_with_scratch`] that returns per-stage
/// rdtsc cycle counts: `[prologue, op_loop, suffix_array, final_sha256]`. The
/// active suffix-array backend (pure-Rust / libsais / v114) is profiled exactly
/// as the production path selects it. Behind `feature = "profiling"` so the real
/// hot path carries zero instrumentation overhead.
#[cfg(feature = "profiling")]
pub fn astrobwtv3_stage_cycles(input: &[u8], scratch: &mut AstroBwtScratch) -> [u64; 4] {
    #[inline(always)]
    fn rdtsc() -> u64 {
        // SAFETY: x86_64 only; _rdtsc is always available on this target.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    let t0 = rdtsc();
    let sha_key: [u8; 32] = Sha256::digest(input).into();
    let mut step_3 = salsa20_keystream_256(&sha_key);
    let mut rc4 = rc4::Rc4::new(&step_3);
    rc4.xor_key_stream(&mut step_3);
    let mut lhash = fnv1a_64(&step_3);
    let mut prev_lhash = lhash;
    let t1 = rdtsc();

    let mut tries: u64 = 0;
    scratch.data.clear();
    #[cfg(feature = "v114")]
    {
        scratch.v114_markers.clear();
    }
    #[cfg(feature = "v114")]
    let mut v114_template_idx = 0usize;
    #[cfg(feature = "v114")]
    let mut v114_first_chunk = 0u32;
    #[cfg(feature = "v114")]
    let mut v114_chunk_count = 1u32;
    loop {
        tries += 1;
        let random_switcher = prev_lhash ^ lhash ^ tries;
        let op = random_switcher as u8;
        let mut pos1 = (random_switcher >> 8) as u8;
        let mut pos2 = (random_switcher >> 16) as u8;
        if pos1 > pos2 {
            core::mem::swap(&mut pos1, &mut pos2);
        }
        if pos2 - pos1 > 32 {
            pos2 = pos1.wrapping_add((pos2 - pos1) & 0x1f);
        }
        ops_generated::apply_op(
            op, &mut step_3, pos1, pos2, &mut lhash, &mut prev_lhash, &mut rc4,
        );
        let p2 = pos2 as usize;
        let diff = step_3[pos1 as usize].wrapping_sub(step_3[pos2 as usize]);
        if diff < 0x10 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = xxh64(&step_3[..p2]);
        }
        if diff < 0x20 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = fnv1a_64(&step_3[..p2]);
        }
        if diff < 0x30 {
            prev_lhash = lhash.wrapping_add(prev_lhash);
            lhash = siphash24(tries, prev_lhash, &step_3[..p2]);
        }
        if diff <= 0x40 {
            rc4.xor_key_stream(&mut step_3);
            #[cfg(feature = "v114")]
            {
                write_v114_marker(
                    &mut scratch.v114_markers,
                    v114_template_idx,
                    v114_first_chunk,
                    v114_chunk_count,
                );
                if tries > 1 {
                    v114_template_idx += 1;
                }
                v114_first_chunk = tries as u32 - 1;
                v114_chunk_count = 1;
            }
        } else {
            #[cfg(feature = "v114")]
            {
                v114_chunk_count += 1;
            }
        }
        step_3[255] = step_3[255] ^ step_3[pos1 as usize] ^ step_3[pos2 as usize];
        scratch.data.extend_from_slice(&step_3[..]);
        if tries > 260 + 16 || (step_3[255] >= 0xf0 && tries > 260) {
            break;
        }
    }
    #[cfg(feature = "v114")]
    {
        write_v114_marker(
            &mut scratch.v114_markers,
            v114_template_idx,
            v114_first_chunk,
            v114_chunk_count,
        );
        v114_template_idx += 1;
        scratch.v114_markers.truncate(v114_template_idx);
    }
    let data_len =
        ((tries - 4) * 256 + (((step_3[253] as u64) << 8 | step_3[254] as u64) & 0x3ff)) as usize;
    #[cfg(feature = "v114")]
    {
        // See astrobwtv3_with_scratch: always zero the full [data_len..tail_end];
        // resize() alone only zeros newly-appended bytes (the ~1.46% bug).
        let tail_end = data_len + 16;
        if scratch.data.len() < tail_end {
            scratch.data.resize(tail_end, 0);
        }
        scratch.data[data_len..tail_end].fill(0);
    }
    let t2 = rdtsc();

    // --- suffix array (active backend) ---
    #[cfg(feature = "libsais")]
    {
        let data = &scratch.data[..data_len];
        #[cfg(feature = "v114")]
        let sa: &[i32] = {
            let used = sais32::suffix_array_v114_into(
                &scratch.data,
                data_len,
                &scratch.v114_markers,
                &mut scratch.v114_flags,
                &mut scratch.sa,
            );
            if used {
                &scratch.sa[..]
            } else {
                sais32::suffix_array_libsais_into(data, &mut scratch.sa, &scratch.libsais_ctx)
            }
        };
        #[cfg(not(feature = "v114"))]
        let sa: &[i32] =
            sais32::suffix_array_libsais_into(data, &mut scratch.sa, &scratch.libsais_ctx);
        let t3 = rdtsc();
        let _ = sha256_sa_i32_le(sa);
        let t4 = rdtsc();
        return [t1 - t0, t2 - t1, t3 - t2, t4 - t3];
    }
    #[cfg(not(feature = "libsais"))]
    {
        let data = &scratch.data[..data_len];
        let sa = sais32::suffix_array(data);
        let t3 = rdtsc();
        let _ = sha256_sa_i32_le(&sa);
        let t4 = rdtsc();
        [t1 - t0, t2 - t1, t3 - t2, t4 - t3]
    }
}

/// Full AstroBWTv3 PoW hash. Go: `astrobwtv3.AstroBWTv3(input)`.
pub fn astrobwtv3(input: &[u8]) -> [u8; 32] {
    astrobwtv3_hash_only(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DIAGNOSTIC: resolve the "zero tail" contradiction. Agent's standalone
    /// harness says the descriptor SA is byte-exact when the 3 tail bytes past
    /// data_len are zero; our production fuzz says it diverges ~1.4%. Inspect the
    /// ACTUAL tail bytes in production scratch, and test whether explicitly
    /// re-zeroing a generous tail makes suffix_array_v114_into match libsais.
    #[cfg(feature = "v114")]
    #[test]
    #[ignore = "diagnostic; run with --ignored --nocapture"]
    fn diag_tail_zero_hypothesis() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut scratch = AstroBwtScratch::new();
        let mut shown = 0;
        for _ in 0..300_000 {
            let len = (next() % 80 + 1) as usize;
            let mut input = vec![0u8; len];
            for chunk in input.chunks_mut(8) {
                let r = next().to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
            let descriptor = astrobwtv3_with_scratch(&input, &mut scratch);
            let (canonical, dbg) = astrobwtv3_full(&input);
            if descriptor == canonical {
                continue;
            }
            let dl = dbg.data_len as usize;
            let end8 = (dl + 8).min(scratch.data.len());
            eprintln!(
                "DIVERGENT: data_len={dl} scratch.data.len()={} tail[dl..dl+8]={:?}",
                scratch.data.len(),
                &scratch.data[dl..end8]
            );
            let want = crate::sais32::suffix_array_libsais(&scratch.data[..dl]);
            let mut flags: Vec<u8> = Vec::new();
            let mut sa = crate::lpbuf::LpVec::<i32>::with_capacity(0);
            let used = crate::sais32::suffix_array_v114_into(
                &scratch.data, dl, &scratch.v114_markers, &mut flags, &mut sa,
            );
            eprintln!("  as-is        : used={used} sa==libsais={}", used && sa[..] == want[..]);
            let end = (dl + 64).min(scratch.data.len());
            for b in &mut scratch.data[dl..end] {
                *b = 0;
            }
            let used2 = crate::sais32::suffix_array_v114_into(
                &scratch.data, dl, &scratch.v114_markers, &mut flags, &mut sa,
            );
            eprintln!("  zeroed-tail  : used={used2} sa==libsais={}", used2 && sa[..] == want[..]);
            shown += 1;
            if shown >= 5 {
                break;
            }
        }
        assert!(shown > 0, "no divergent case found");
    }

    #[test]
    fn hash_only_fast_path_matches_full_output() {
        let cases: [&[u8]; 4] = [
            b"",
            b"DERO AstroBWTv3",
            b"hash-only fast path regression",
            b"\x00\x01\x02\x03\xfd\xfe\xff",
        ];

        for input in cases {
            let (full_output, dbg) = astrobwtv3_full(input);
            let fast_output = astrobwtv3_hash_only(input);

            assert_eq!(fast_output, full_output);
            assert_eq!(fast_output, dbg.output);
            assert_eq!(astrobwtv3(input), full_output);
        }
    }

    #[test]
    fn scratch_hash_path_matches_full_output_and_reuses_buffers() {
        let cases: [&[u8]; 4] = [
            b"",
            b"DERO AstroBWTv3",
            b"scratch fast path regression",
            b"\x00\x01\x02\x03\xfd\xfe\xff",
        ];
        let mut scratch = AstroBwtScratch::new();
        let mut last_data_capacity = 0usize;

        for input in cases {
            let (full_output, _) = astrobwtv3_full(input);
            let scratch_output = astrobwtv3_with_scratch(input, &mut scratch);

            assert_eq!(scratch_output, full_output);
            assert!(scratch.data_capacity() >= last_data_capacity);
            last_data_capacity = scratch.data_capacity();
        }
    }

    /// Differential fuzz: the fused v114 path (descriptor SA streamed straight
    /// into SHA-256) must agree byte-for-byte with the reference pipeline
    /// (`astrobwtv3_full`, which builds the SA the conventional way and hashes
    /// it) across many varied inputs. Two independent suffix-array
    /// implementations agreeing on thousands of inputs is strong evidence the
    /// fused fast path is correct — wrong PoW hashes would mean rejected shares.
    #[cfg(feature = "v114")]
    #[test]
    fn fused_v114_matches_reference_fuzz() {
        let mut scratch = AstroBwtScratch::new();
        // Deterministic xorshift64* so the test is reproducible.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        const N: usize = 4_000;
        for _ in 0..N {
            // Vary input length 1..=80 bytes with pseudo-random content.
            let len = (next() % 80 + 1) as usize;
            let mut input = vec![0u8; len];
            for chunk in input.chunks_mut(8) {
                let r = next().to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
            let fused = astrobwtv3_with_scratch(&input, &mut scratch);
            let (reference, _) = astrobwtv3_full(&input);
            assert_eq!(fused, reference, "fused v114 != reference for input {input:?}");
        }
    }

    /// Diagnostic: compare the v114 descriptor SA *array* against libsais over
    /// many random inputs, and on the first divergence print enough structure to
    /// characterize the failure (data_len, first differing index, and whether
    /// the descriptor SA is even a valid permutation of 0..n).
    #[cfg(feature = "v114")]
    #[test]
    #[ignore = "diagnostic; run explicitly with --ignored"]
    fn v114_descriptor_sa_array_fuzz_diagnostic() {
        let mut scratch = AstroBwtScratch::new();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut diverged = 0usize;
        let mut diverged_with_tz = 0usize; // divergent AND had trailing zero(s)
        let mut diverged_no_tz = 0usize; // divergent but NO trailing zero (would defeat a tz gate)
        let mut total_tz = 0usize; // inputs with >=1 trailing zero
        let mut canon_mismatch = 0usize; // libsais vs pure-Rust sais32 (must be 0)
        const N: usize = 20_000;
        for _ in 0..N {
            let len = (next() % 80 + 1) as usize;
            let mut input = vec![0u8; len];
            for chunk in input.chunks_mut(8) {
                let r = next().to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
            // Populate scratch.data + markers via the production op-loop.
            let _ = astrobwtv3_with_scratch(&input, &mut scratch);
            let (_, dbg) = astrobwtv3_full(&input);
            let data_len = dbg.data_len as usize;
            if data_len == 0 {
                continue;
            }

            // canonical reference (untrimmed): libsais, cross-checked vs pure-Rust.
            let want = sais32::suffix_array_libsais(&scratch.data[..data_len]);
            let rust_ref = sais32::suffix_array(&scratch.data[..data_len]);
            if want != rust_ref {
                canon_mismatch += 1;
            }

            // trailing-zero count in the SA input.
            let mut tz = 0usize;
            while tz < data_len && scratch.data[data_len - 1 - tz] == 0 {
                tz += 1;
            }
            if tz > 0 {
                total_tz += 1;
            }

            let used = sais32::suffix_array_v114_into(
                &scratch.data,
                data_len,
                &scratch.v114_markers,
                &mut scratch.v114_flags,
                &mut scratch.sa,
            );
            if used && scratch.sa[..] != want[..] {
                diverged += 1;
                if tz > 0 {
                    diverged_with_tz += 1;
                } else {
                    diverged_no_tz += 1;
                }
            }
        }
        println!(
            "descriptor-SA divergences: {diverged}/{N}  (with_tz={diverged_with_tz} no_tz={diverged_no_tz})  inputs_with_tz={total_tz}  canon_mismatch={canon_mismatch}"
        );
        // The actionable question: can a cheap trailing-zero gate catch ALL
        // divergences? If diverged_no_tz == 0, gating on trailing zeros is a
        // sufficient correctness guard.
        assert_eq!(canon_mismatch, 0, "libsais must equal pure-Rust canonical SA");
        assert_eq!(
            diverged_no_tz, 0,
            "a divergence with NO trailing zero defeats the trailing-zero gate"
        );
    }

    #[cfg(feature = "v114")]
    #[test]
    fn v114_descriptor_sa_matches_libsais_on_astrobwt_data() {
        let cases: [&[u8]; 4] = [
            b"",
            b"DERO AstroBWTv3",
            b"v114 descriptor suffix array regression",
            b"\x00\x01\x02\x03\xfd\xfe\xff",
        ];
        let mut scratch = AstroBwtScratch::new();

        for input in cases {
            let (_, dbg) = astrobwtv3_full(input);
            let _ = astrobwtv3_with_scratch(input, &mut scratch);
            let data_len = dbg.data_len as usize;
            let data = &scratch.data[..data_len];
            let want = sais32::suffix_array_libsais(data);

            let used_v114 = sais32::suffix_array_v114_into(
                &scratch.data,
                data_len,
                &scratch.v114_markers,
                &mut scratch.v114_flags,
                &mut scratch.sa,
            );
            assert!(used_v114, "v114 should accept AstroBWT-shaped data");

            assert_eq!(
                &scratch.sa[..],
                want,
                "v114 SA mismatch for input {input:?}"
            );
        }
    }
}
