//! SA-IS suffix array construction for AstroBWTv3 (step 6) — a faithful,
//! line-by-line port of the Go standard-library SAIS used by the DERO reference
//! (`astrobwt/astrobwtv3/sais.go` + `sais2.go`, the `_8_32` + `_32` families).
//!
//! This replaces the O(n log² n) prefix-doubling [`crate::suffixarray`] (kept as
//! the differential-fuzz oracle) with the linear-time induced-sorting algorithm,
//! WITHOUT changing any output: the suffix array is unique under Go's
//! sentinel-smallest convention, so both produce the identical permutation.
//!
//! ## Type widths
//!
//! AstroBWTv3 feeds the SA at most `MAX_LENGTH = 256*384 - 1 = 98303` bytes
//! (see `pow.go`), so every index fits in `i32`. The Go generator emits a `_64`
//! family (`sais_8_64`/`sais_64`) for inputs that do not fit in an `int32`;
//! because the input here is provably `≤ 98303 < i32::MAX`, the `_64` path is
//! **unreachable** and is intentionally not ported. We port the `_8_32` entry +
//! the `_32` recursion family, exactly as Go selects them.
//!
//! ## Structure
//!
//! The functions are named and ordered to mirror Go one-to-one so the port is
//! reviewable line-by-line:
//!
//! - [`sais_8_32`]  — top level, 8-bit text (`text: &[u8]`), `i32` SA.
//! - [`sais_32`]    — recursion level, `i32` text, `i32` SA.
//! - `freq` / `bucket_min` / `bucket_max` (both widths)
//! - `place_lms` / `induce_sub_l` / `induce_sub_s` / `length` / `assign_id`
//! - `map` / `recurse` / `unmap` / `expand` / `induce_l` / `induce_s`
//!
//! Go uses negative `sa[i]` values as work-queue flags; Rust's signed `i32`
//! reproduces that arithmetic exactly. The riskiest piece is [`recurse_32`]'s
//! in-place `dst`/`saTmp`/`text` partition of the `sa` slice, ported with the
//! identical index math (see comments there).

// The `c0, c1 = text[i], c0` swap idiom (the Go "LMS-substring iterator")
// initialises c0 to 0 and overwrites it each iteration before use; Rust flags the
// dead initial store. Kept verbatim to mirror Go line-for-line.
#![allow(unused_assignments)]

/// The text character alphabet size for byte input: 256.
const TEXT_MAX_8: usize = 256;

// ===========================================================================
// Public entry point
// ===========================================================================

/// Build the suffix array of `text` (sentinel-smallest convention), returning a
/// permutation of `0..n` such that `text[sa[0]..] < text[sa[1]..] < …`.
///
/// Go: `text_32_0alloc(text, sa)` → `sais_8_32(text, 256, sa, [2*256]int32{})`
/// (`sa_fast.go`). The caller zeroes `sa`; we allocate it zeroed here.
pub fn suffix_array(text: &[u8]) -> Vec<i32> {
    let n = text.len();
    // `text_32` in Go panics if len doesn't fit in int32; here n ≤ 98303.
    debug_assert!(
        i32::try_from(n).is_ok(),
        "suffixarray: text too long for i32"
    );
    let mut sa = vec![0i32; n];
    // tmp has length 2*256 (the `[2 * 256]int32` stack array in sa_fast.go).
    let mut tmp = vec![0i32; 2 * TEXT_MAX_8];
    sais_8_32(text, TEXT_MAX_8, &mut sa, &mut tmp);
    sa
}

/// libsais-backed suffix array — a drop-in replacement for [`suffix_array`] that
/// produces the **identical** permutation (a suffix array is unique under the
/// sentinel-smallest convention both engines use; proven byte-for-byte by the
/// `sais_vectors` / `full_vectors` gate under `--features libsais`).
///
/// Opt-in (`feature = "libsais"`), used only on the fail-safe mining path; every
/// verification path stays on the pure-Rust [`suffix_array`]. Single-threaded:
/// the miner already parallelizes across nonces, so per-call OpenMP would
/// oversubscribe (hence `default-features = false` on the dep drops `openmp-sys`).
#[cfg(feature = "libsais")]
use std::marker::PhantomData;
#[cfg(feature = "libsais")]
use std::ptr::NonNull;

#[cfg(feature = "libsais")]
pub(crate) struct LibsaisCtx {
    ptr: NonNull<std::os::raw::c_void>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

#[cfg(feature = "libsais")]
impl LibsaisCtx {
    pub(crate) fn new() -> Self {
        let ptr = unsafe { libsais_sys::libsais::libsais_create_ctx() };
        let ptr = NonNull::new(ptr).expect("libsais context allocation failed");
        Self {
            ptr,
            _not_send_or_sync: PhantomData,
        }
    }
}

#[cfg(feature = "libsais")]
impl Drop for LibsaisCtx {
    fn drop(&mut self) {
        unsafe { libsais_sys::libsais::libsais_free_ctx(self.ptr.as_ptr()) };
    }
}

#[cfg(feature = "libsais")]
pub(crate) fn suffix_array_libsais_into<'a>(
    text: &[u8],
    sa: &'a mut crate::lpbuf::LpVec<i32>,
    ctx: &LibsaisCtx,
) -> &'a [i32] {
    match text.len() {
        0 => {
            sa.clear();
            return &sa[..];
        }
        1 => {
            sa.resize(1, 0);
            sa[0] = 0;
            return &sa[..];
        }
        _ => {}
    }

    debug_assert!(
        i32::try_from(text.len()).is_ok(),
        "suffixarray: text too long for i32"
    );
    sa.resize(text.len(), 0);
    let rc = unsafe {
        libsais_sys::libsais::libsais_ctx(
            ctx.ptr.as_ptr(),
            text.as_ptr(),
            sa.as_mut_ptr(),
            text.len() as i32,
            0,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "libsais suffix array construction failed: {rc}");
    assert_eq!(
        sa.len(),
        text.len(),
        "libsais SA length {} != input length {}",
        sa.len(),
        text.len()
    );
    &sa[..]
}

#[cfg(feature = "libsais")]
pub fn suffix_array_libsais(text: &[u8]) -> Vec<i32> {
    let ctx = LibsaisCtx::new();
    let mut sa = crate::lpbuf::LpVec::<i32>::with_capacity(text.len());
    suffix_array_libsais_into(text, &mut sa, &ctx);
    sa.as_slice().to_vec()
}

#[cfg(feature = "v114")]
extern "C" {
    fn v114_sa_build_fused(
        data: *const u8,
        logical_len: u32,
        data_len_with_tail: u32,
        flags: *const u8,
        flag_len: u32,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> std::os::raw::c_int;

    /// Build the descriptor suffix array and stream its little-endian i32 bytes
    /// straight into SHA-256, writing the 32-byte digest to `out_hash`. Never
    /// materializes the full SA. SHA-256 is provided by [`sha_ni_shim`] below
    /// (hardware SHA-NI). Returns 1 on success, 0 if the build refused.
    fn v114_hash_fused(
        data: *const u8,
        logical_len: u32,
        data_len_with_tail: u32,
        flags: *const u8,
        flag_len: u32,
        out_hash: *mut u8,
    ) -> std::os::raw::c_int;
}

/// SHA-256 symbols consumed by the v114 fused-hash sink in `v114_stubs.cpp`.
///
/// The vendored C++ streaming SHA sink calls OpenSSL-style
/// `SHA256_Init/Update/Final`; upstream shipped no-op stubs (the original Zig
/// port hashed in Zig). We supply a real, hardware-accelerated implementation
/// backed by the `sha2` crate (which dispatches to SHA-NI at runtime on this
/// CPU). One PoW hash runs entirely on one thread with a strict
/// Init→Update*→Final sequence and no nesting, so a thread-local context is
/// exact — we ignore the opaque `SHA256_CTX*` the C++ passes.
#[cfg(feature = "v114")]
mod sha_ni_shim {
    use core::ffi::c_void;
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;

    thread_local! {
        static CTX: RefCell<Sha256> = RefCell::new(Sha256::new());
    }

    #[no_mangle]
    pub extern "C" fn SHA256_Init(_c: *mut c_void) -> i32 {
        CTX.with(|c| *c.borrow_mut() = Sha256::new());
        1
    }

    #[no_mangle]
    pub extern "C" fn SHA256_Update(_c: *mut c_void, data: *const c_void, n: usize) -> i32 {
        if !data.is_null() && n != 0 {
            // SAFETY: the C++ sink passes a valid `n`-byte region.
            let bytes = unsafe { core::slice::from_raw_parts(data.cast::<u8>(), n) };
            CTX.with(|c| c.borrow_mut().update(bytes));
        }
        1
    }

    #[no_mangle]
    pub extern "C" fn SHA256_Final(out: *mut u8, _c: *mut c_void) -> i32 {
        CTX.with(|c| {
            let mut taken = Sha256::new();
            core::mem::swap(&mut *c.borrow_mut(), &mut taken);
            let digest = taken.finalize();
            // SAFETY: the sink always passes a 32-byte output buffer.
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
        });
        1
    }
}

#[cfg(feature = "v114")]
pub(crate) fn build_v114_stage5_flags(
    markers: &[u16],
    logical_len: usize,
    flags: &mut Vec<u8>,
) -> Option<u32> {
    if logical_len == 0 {
        return None;
    }

    let logical_len = u32::try_from(logical_len).ok()?;
    let flags_len = (logical_len >> 8) + 1;
    let flags_len_usize = flags_len as usize;
    flags.resize(flags_len_usize, 0);
    flags[..flags_len_usize].fill(0);
    flags[0] = 1;

    let limit = markers.len().min(277);
    for &marker in &markers[..limit] {
        let pos_data = marker as u32;
        let start_group = pos_data >> 7;
        let group_count = pos_data & 0x7f;
        let boundary = start_group + group_count;
        if group_count != 0 && boundary > 0 && boundary < flags_len {
            flags[boundary as usize] = 1;
        }
    }

    Some(flags_len)
}

#[cfg(feature = "v114")]
pub(crate) fn suffix_array_v114_into(
    data_with_tail: &[u8],
    logical_len: usize,
    markers: &[u16],
    flags: &mut Vec<u8>,
    sa: &mut crate::lpbuf::LpVec<i32>,
) -> bool {
    if !cfg!(target_endian = "little") {
        return false;
    }
    if logical_len == 0 {
        sa.clear();
        return true;
    }

    let Some(logical_len_u32) = u32::try_from(logical_len).ok() else {
        return false;
    };
    let Some(data_len_with_tail) = logical_len.checked_add(3) else {
        return false;
    };
    if data_with_tail.len() < data_len_with_tail {
        return false;
    }

    let Some(flag_len) = build_v114_stage5_flags(markers, logical_len, flags) else {
        return false;
    };
    let Some(out_cap) = logical_len.checked_mul(std::mem::size_of::<i32>()) else {
        return false;
    };
    sa.resize(logical_len, 0);

    let mut out_len = 0usize;
    let rc = unsafe {
        v114_sa_build_fused(
            data_with_tail.as_ptr(),
            logical_len_u32,
            data_len_with_tail as u32,
            flags.as_ptr(),
            flag_len,
            sa.as_mut_ptr().cast::<u8>(),
            out_cap,
            &mut out_len,
        )
    };

    rc == 1 && out_len == out_cap
}

/// v114 fused suffix-array → SHA-256: build the descriptor SA and stream its
/// little-endian i32 bytes straight into SHA-256 (SHA-NI), returning the 32-byte
/// PoW hash without ever materializing the ~280 KB suffix array. Returns `None`
/// if the descriptor build refuses the input (caller falls back to the
/// materialized-SA path). Byte-identical to `sha256(suffix_array_v114_into(..))`.
#[cfg(feature = "v114")]
pub(crate) fn hash_v114_fused_into(
    data_with_tail: &[u8],
    logical_len: usize,
    markers: &[u16],
    flags: &mut Vec<u8>,
) -> Option<[u8; 32]> {
    if !cfg!(target_endian = "little") {
        return None;
    }
    // Measurement A/B hook: `DERO_NO_FUSE=1` forces the materialized-SA + sha256
    // path so the fused win can be benchmarked head-to-head. Read once.
    {
        use std::sync::OnceLock;
        static NO_FUSE: OnceLock<bool> = OnceLock::new();
        if *NO_FUSE.get_or_init(|| std::env::var_os("DERO_NO_FUSE").is_some()) {
            return None;
        }
    }
    // logical_len == 0 only for degenerate (empty op-loop) inputs; let the
    // fallback handle the empty-SA → sha256("") corner case.
    if logical_len == 0 {
        return None;
    }
    let logical_len_u32 = u32::try_from(logical_len).ok()?;
    let data_len_with_tail = logical_len.checked_add(3)?;
    if data_with_tail.len() < data_len_with_tail {
        return None;
    }
    let flag_len = build_v114_stage5_flags(markers, logical_len, flags)?;

    let mut out = [0u8; 32];
    let rc = unsafe {
        v114_hash_fused(
            data_with_tail.as_ptr(),
            logical_len_u32,
            data_len_with_tail as u32,
            flags.as_ptr(),
            flag_len,
            out.as_mut_ptr(),
        )
    };
    (rc == 1).then_some(out)
}

// ===========================================================================
// sais_8_32 — top level (8-bit text)
// ===========================================================================

/// Go `sais_8_32`: compute the suffix array of `text` into `sa`.
/// The text must contain only values in `[0, text_max)`; `sa` must be zeroed
/// and `tmp.len() >= text_max` (≥ 2*text_max runs a little faster).
fn sais_8_32(text: &[u8], text_max: usize, sa: &mut [i32], tmp: &mut [i32]) {
    assert!(
        sa.len() == text.len() && tmp.len() >= text_max,
        "suffixarray: misuse of sais_8_32"
    );

    // Trivial base cases. Sorting 0 or 1 things is easy.
    if text.is_empty() {
        return;
    }
    if text.len() == 1 {
        sa[0] = 0;
        return;
    }

    // Establish freq/bucket split inside tmp. If there's only enough tmp for one
    // slice, freq stays None (recomputed each time) and bucket = tmp[:text_max].
    // We track this via the `freq_init` flag + a split borrow of `tmp`.
    let have_freq = tmp.len() >= 2 * text_max;
    if have_freq {
        tmp[0] = -1; // mark freq as uninitialized (freq[0] = -1)
    }

    // The SAIS algorithm. Each of these calls makes one scan through sa.
    let num_lms = place_lms_8_32(text, sa, text_max, tmp, have_freq);
    if num_lms <= 1 {
        // 0 or 1 items are already sorted. Do nothing.
    } else {
        induce_sub_l_8_32(text, sa, text_max, tmp, have_freq);
        induce_sub_s_8_32(text, sa, text_max, tmp, have_freq);
        length_8_32(text, sa, num_lms);
        let max_id = assign_id_8_32(text, sa, num_lms);
        if max_id < num_lms {
            map_32(sa, num_lms);
            recurse_32(sa, tmp, num_lms, max_id);
            unmap_8_32(text, sa, num_lms);
        } else {
            // Each LMS-substring is unique: copy the LMS-substring order into
            // the suffix array destination. Go: copy(sa, sa[len(sa)-numLMS:]).
            let n = sa.len();
            sa.copy_within(n - num_lms.., 0);
        }
        expand_8_32(text, sa, text_max, tmp, have_freq, num_lms);
    }
    induce_l_8_32(text, sa, text_max, tmp, have_freq);
    induce_s_8_32(text, sa, text_max, tmp, have_freq);

    // Mark for caller that we overwrote tmp.
    tmp[0] = -1;
}

// ---------------------------------------------------------------------------
// freq / bucket helpers (8-bit text)
//
// In Go, `freq` and `bucket` are sub-slices of `tmp`: when `have_freq`,
// freq = tmp[:textMax] and bucket = tmp[textMax:2*textMax]; otherwise freq is
// nil and bucket = tmp[:textMax]. We can't hold two `&mut` sub-slices at once in
// safe Rust, so we pass `tmp` whole plus `have_freq`, and these helpers index
// into the right halves with `+ text_max` for the bucket offset.
// ---------------------------------------------------------------------------

/// Compute frequencies into the freq region (tmp[0..text_max]) if not already
/// computed. Returns the offset within `tmp` where the freq table lives.
///
/// Go `freq_8_32`: if `freq != nil && freq[0] >= 0` it's already computed; if
/// freq is nil it uses bucket. Mirrors that selection via `have_freq`.
fn freq_8_32(text: &[u8], text_max: usize, tmp: &mut [i32], have_freq: bool) -> usize {
    if have_freq && tmp[0] >= 0 {
        return 0; // already computed, lives at tmp[0..]
    }
    // freq region: tmp[0..] if have_freq else bucket region tmp[text_max..]
    let off = if have_freq { 0 } else { text_max };
    for i in 0..256 {
        tmp[off + i] = 0;
    }
    for &c in text {
        tmp[off + c as usize] += 1;
    }
    off
}

/// Go `bucketMin_8_32`: bucket[c] = minimum index in c's bucket.
/// Writes the 256 bucket offsets into tmp[text_max..text_max+256].
fn bucket_min_8_32(text: &[u8], text_max: usize, tmp: &mut [i32], have_freq: bool) {
    let foff = freq_8_32(text, text_max, tmp, have_freq);
    let boff = text_max; // bucket region
    let mut total: i32 = 0;
    for i in 0..256 {
        let n = tmp[foff + i];
        tmp[boff + i] = total;
        total += n;
    }
}

/// Go `bucketMax_8_32`: bucket[c] = maximum index (one past final) in c's bucket.
fn bucket_max_8_32(text: &[u8], text_max: usize, tmp: &mut [i32], have_freq: bool) {
    let foff = freq_8_32(text, text_max, tmp, have_freq);
    let boff = text_max;
    let mut total: i32 = 0;
    for i in 0..256 {
        let n = tmp[foff + i];
        total += n;
        tmp[boff + i] = total;
    }
}

// ---------------------------------------------------------------------------
// place_lms / induce / length / assign_id (8-bit text)
// ---------------------------------------------------------------------------

/// Go `placeLMS_8_32`.
fn place_lms_8_32(
    text: &[u8],
    sa: &mut [i32],
    text_max: usize,
    tmp: &mut [i32],
    have_freq: bool,
) -> usize {
    bucket_max_8_32(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut num_lms = 0usize;
    let mut last_b: i32 = -1;

    // "LMS-substring iterator": backward scan tracking type-S/type-L.
    let (mut c0, mut c1, mut is_type_s): (u8, u8, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        // (c0, c1) = (text[i], c0)  — c1 takes the previous c0
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;

            // Bucket the index i+1 for the start of an LMS-substring.
            let b = tmp[boff + c1 as usize] - 1;
            tmp[boff + c1 as usize] = b;
            sa[b as usize] = (i + 1) as i32;
            last_b = b;
            num_lms += 1;
        }
        c1 = c0;
    }

    if num_lms > 1 {
        sa[last_b as usize] = 0;
    }
    num_lms
}

/// Go `induceSubL_8_32`.
fn induce_sub_l_8_32(
    text: &[u8],
    sa: &mut [i32],
    text_max: usize,
    tmp: &mut [i32],
    have_freq: bool,
) {
    bucket_min_8_32(text, text_max, tmp, have_freq);
    let boff = text_max;

    // Process the implicit entry sa[-1] == len(text) (type-L index len(text)-1).
    let mut k: isize = text.len() as isize - 1;
    {
        let c0 = text[(k - 1) as usize];
        let c1 = text[k as usize];
        if c0 < c1 {
            k = -k;
        }
        // cB := c1; b := bucket[cB]; sa[b] = k; b++
        let mut c_b = c1;
        let mut b = tmp[boff + c_b as usize];
        sa[b as usize] = k as i32;
        b += 1;

        for i in 0..sa.len() {
            let j = sa[i] as isize;
            if j == 0 {
                continue; // Skip empty entry.
            }
            if j < 0 {
                // Leave discovered type-S index for caller.
                sa[i] = (-j) as i32;
                continue;
            }
            sa[i] = 0;

            // k := j-1 is L-type; place it. Negate if k-1 is S-type.
            let mut k2: isize = j - 1;
            let c0 = text[(k2 - 1) as usize];
            let c1 = text[k2 as usize];
            if c0 < c1 {
                k2 = -k2;
            }

            if c_b != c1 {
                tmp[boff + c_b as usize] = b;
                c_b = c1;
                b = tmp[boff + c_b as usize];
            }
            sa[b as usize] = k2 as i32;
            b += 1;
        }
    }
}

/// Go `induceSubS_8_32`.
fn induce_sub_s_8_32(
    text: &[u8],
    sa: &mut [i32],
    text_max: usize,
    tmp: &mut [i32],
    have_freq: bool,
) {
    bucket_max_8_32(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut c_b: u8 = 0;
    let mut b = tmp[boff + c_b as usize];

    let mut top = sa.len();
    for i in (0..sa.len()).rev() {
        let j = sa[i] as isize;
        if j == 0 {
            continue; // Skip empty entry.
        }
        sa[i] = 0;
        if j < 0 {
            // Leave discovered LMS-substring start index for caller.
            top -= 1;
            sa[top] = (-j) as i32;
            continue;
        }

        // k := j-1 is S-type; place it. Negate if k-1 is L-type.
        let mut k: isize = j - 1;
        let c1 = text[k as usize];
        let c0 = text[(k - 1) as usize];
        if c0 > c1 {
            k = -k;
        }

        if c_b != c1 {
            tmp[boff + c_b as usize] = b;
            c_b = c1;
            b = tmp[boff + c_b as usize];
        }
        b -= 1;
        sa[b as usize] = k as i32;
    }
}

/// Go `length_8_32`: record each LMS-substring length (or packed text) at sa[j/2].
fn length_8_32(text: &[u8], sa: &mut [i32], _num_lms: usize) {
    let mut end: usize = 0; // 0 indicates the final LMS-substring
    let mut cx: u32 = 0; // pre-inverted packed-incremented bytes (byte-only)

    let (mut c0, mut c1, mut is_type_s): (u8, u8, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        cx = cx << 8 | (c1.wrapping_add(1)) as u32; // byte-only
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;

            let j = i + 1;
            let code: i32 = if end == 0 {
                0
            } else {
                let mut code = (end - j) as i32;
                // byte-only: pack short substrings directly.
                if code <= 32 / 8 && !cx >= text.len() as u32 {
                    code = (!cx) as i32;
                }
                code
            };
            sa[j >> 1] = code;
            end = j + 1;
            cx = (c1.wrapping_add(1)) as u32; // byte-only
        }
        c1 = c0;
    }
}

/// Go `assignID_8_32`: dense ID numbering of LMS-substrings, returns max ID.
fn assign_id_8_32(text: &[u8], sa: &mut [i32], num_lms: usize) -> usize {
    let mut id = 0usize;
    let mut last_len: i32 = -1; // impossible
    let mut last_pos: i32 = 0;
    let base = sa.len() - num_lms;
    for idx in 0..num_lms {
        let j = sa[base + idx];
        // Is the LMS-substring at index j new or the same as the last one?
        let n = sa[(j / 2) as usize];
        let is_new;
        if n != last_len {
            is_new = true;
        } else if (n as u32) >= text.len() as u32 {
            // "Length" is really encoded full text, and they match.
            is_new = false;
        } else {
            // Compare actual texts.
            let nn = n as usize;
            let this = &text[j as usize..][..nn];
            let last = &text[last_pos as usize..][..nn];
            let mut differ = false;
            for i in 0..nn {
                if this[i] != last[i] {
                    differ = true;
                    break;
                }
            }
            is_new = differ;
        }
        if is_new {
            id += 1;
            last_pos = j;
            last_len = n;
        }
        sa[(j / 2) as usize] = id as i32;
    }
    id
}

// ---------------------------------------------------------------------------
// map / recurse (shared by both widths via _32)
// ---------------------------------------------------------------------------

/// Go `map_32`: pack the subproblem (IDs minus 1) into the top of sa.
fn map_32(sa: &mut [i32], _num_lms: usize) {
    let mut w = sa.len();
    let mut i = sa.len() / 2;
    loop {
        let j = sa[i];
        if j > 0 {
            w -= 1;
            sa[w] = j - 1;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
}

/// Go `recurse_32`: solve the subproblem at the right end of `sa`, writing the
/// suffix array result at the left end; the middle is scratch.
///
/// Go partitions:
///   dst   = sa[:numLMS]
///   saTmp = sa[numLMS : len(sa)-numLMS]
///   text  = sa[len(sa)-numLMS:]
/// then chooses `tmp` = the largest of {oldTmp, saTmp} that is ≥ numLMS, or a
/// fresh alloc of `max(maxID, numLMS/2)` (the `forcealloc` fallback). It then
/// clears `dst` and calls `sais_32(text, maxID, dst, tmp)`.
///
/// In Rust, `dst`, `saTmp`, `text` are non-overlapping sub-slices of `sa`, but
/// `sais_32` needs `text` (read-only) and `dst` (write) simultaneously, and
/// `tmp` may be `saTmp` (also a slice of `sa`). To honor the borrow checker
/// while keeping the *identical* index math and data flow, we:
///   1. snapshot `text` into an owned `Vec<i32>` (the recursion only reads it),
///   2. choose `tmp`: prefer `oldTmp` then `saTmp` when one is ≥ numLMS, else a
///      fresh alloc — exactly Go's size decision; when `saTmp` is chosen we use a
///      fresh buffer of `saTmp.len()` since the in-place middle would alias `dst`.
/// The recursion writes only into `dst` (sa[:numLMS]) and `tmp`; `saTmp`/`text`
/// regions of `sa` are not used after the snapshot, so producing the byte-exact
/// `dst` is all that matters (unmap_8_32 then reads only sa[:numLMS] and the top
/// numLMS entries, which the caller refills).
fn recurse_32(sa: &mut [i32], old_tmp: &mut [i32], num_lms: usize, max_id: usize) {
    let len = sa.len();
    // Snapshot the recursion's input text (sa[len-numLMS..]). Read-only there.
    let text: Vec<i32> = sa[len - num_lms..].to_vec();

    // Go's tmp size decision. saTmp length = len - 2*numLMS.
    let sa_tmp_len = len - 2 * num_lms;
    // tmp := oldTmp; if len(tmp) < len(saTmp) { tmp = saTmp }
    // We need a scratch buffer of length max(oldTmp.len(), saTmp.len()) that does
    // not alias `dst`. oldTmp does not alias sa; saTmp does. Either way the
    // recursion only requires tmp.len() >= maxID, so a fresh buffer of the same
    // chosen length is byte-exactly equivalent (tmp content is transient).
    let mut chosen_len = old_tmp.len();
    if chosen_len < sa_tmp_len {
        chosen_len = sa_tmp_len;
    }
    if chosen_len < num_lms {
        // forcealloc fallback: n = max(maxID, numLMS/2)
        let mut n = max_id;
        if n < num_lms / 2 {
            n = num_lms / 2;
        }
        chosen_len = n;
    }
    let mut tmp = vec![0i32; chosen_len];

    // Clear dst (sa[:numLMS]) — Go does this explicitly.
    for i in 0..num_lms {
        sa[i] = 0;
    }
    // sais_32(text, maxID, dst, tmp) — dst = sa[:numLMS].
    sais_32(&text, max_id, &mut sa[..num_lms], &mut tmp);
}

/// Go `unmap_8_32`: map the subproblem suffix array back to LMS-substring indexes.
fn unmap_8_32(text: &[u8], sa: &mut [i32], num_lms: usize) {
    let base = sa.len() - num_lms;
    let mut j = num_lms; // len(unmap)

    // "LMS-substring iterator": fill the inverse map into sa[base..].
    let (mut c0, mut c1, mut is_type_s): (u8, u8, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            j -= 1;
            sa[base + j] = (i + 1) as i32;
        }
        c1 = c0;
    }

    // Apply inverse map to subproblem suffix array (sa[:numLMS]).
    for i in 0..num_lms {
        let k = sa[i] as usize;
        sa[i] = sa[base + k];
    }
}

/// Go `expand_8_32`: distribute sorted LMS-suffix indexes into bucket tops.
fn expand_8_32(
    text: &[u8],
    sa: &mut [i32],
    text_max: usize,
    tmp: &mut [i32],
    have_freq: bool,
    num_lms: usize,
) {
    bucket_max_8_32(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut x = num_lms - 1;
    let mut sa_x = sa[x];
    let mut c = text[sa_x as usize];
    let mut b = tmp[boff + c as usize] - 1;
    tmp[boff + c as usize] = b;

    for i in (0..sa.len()).rev() {
        if i as i32 != b {
            sa[i] = 0;
            continue;
        }
        sa[i] = sa_x;

        if x > 0 {
            x -= 1;
            sa_x = sa[x];
            c = text[sa_x as usize];
            b = tmp[boff + c as usize] - 1;
            tmp[boff + c as usize] = b;
        }
    }
}

/// Go `induceL_8_32`.
fn induce_l_8_32(text: &[u8], sa: &mut [i32], text_max: usize, tmp: &mut [i32], have_freq: bool) {
    bucket_min_8_32(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut k: isize = text.len() as isize - 1;
    let c0 = text[(k - 1) as usize];
    let c1 = text[k as usize];
    if c0 < c1 {
        k = -k;
    }

    let mut c_b = c1;
    let mut b = tmp[boff + c_b as usize];
    sa[b as usize] = k as i32;
    b += 1;

    for i in 0..sa.len() {
        let j = sa[i] as isize;
        if j <= 0 {
            continue; // Skip empty or negated entry (including negated zero).
        }

        let mut k2: isize = j - 1;
        let c1 = text[k2 as usize];
        if k2 > 0 {
            let c0 = text[(k2 - 1) as usize];
            if c0 < c1 {
                k2 = -k2;
            }
        }

        if c_b != c1 {
            tmp[boff + c_b as usize] = b;
            c_b = c1;
            b = tmp[boff + c_b as usize];
        }
        sa[b as usize] = k2 as i32;
        b += 1;
    }
}

/// Go `induceS_8_32`.
fn induce_s_8_32(text: &[u8], sa: &mut [i32], text_max: usize, tmp: &mut [i32], have_freq: bool) {
    bucket_max_8_32(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut c_b: u8 = 0;
    let mut b = tmp[boff + c_b as usize];

    for i in (0..sa.len()).rev() {
        let mut j = sa[i] as isize;
        if j >= 0 {
            continue; // Skip non-flagged entry.
        }

        j = -j;
        sa[i] = j as i32;

        let mut k: isize = j - 1;
        let c1 = text[k as usize];
        if k > 0 {
            let c0 = text[(k - 1) as usize];
            if c0 <= c1 {
                k = -k;
            }
        }

        if c_b != c1 {
            tmp[boff + c_b as usize] = b;
            c_b = c1;
            b = tmp[boff + c_b as usize];
        }
        b -= 1;
        sa[b as usize] = k as i32;
    }
}

// ===========================================================================
// sais_32 — recursion level (i32 text, i32 SA)
// ===========================================================================

/// Go `sais_32`: suffix array of an `i32` text into `sa`.
fn sais_32(text: &[i32], text_max: usize, sa: &mut [i32], tmp: &mut [i32]) {
    assert!(
        sa.len() == text.len() && tmp.len() >= text_max,
        "suffixarray: misuse of sais_32"
    );

    if text.is_empty() {
        return;
    }
    if text.len() == 1 {
        sa[0] = 0;
        return;
    }

    // freq/bucket: here textMax is dynamic (= maxID of the parent), so the freq
    // region is tmp[0..text_max] and the bucket region tmp[text_max..2*text_max].
    let have_freq = tmp.len() >= 2 * text_max;
    if have_freq {
        tmp[0] = -1;
    }

    let num_lms = place_lms_32(text, sa, text_max, tmp, have_freq);
    if num_lms <= 1 {
        // 0 or 1 items already sorted.
    } else {
        induce_sub_l_32(text, sa, text_max, tmp, have_freq);
        induce_sub_s_32(text, sa, text_max, tmp, have_freq);
        length_32(text, sa, num_lms);
        let max_id = assign_id_32(text, sa, num_lms);
        if max_id < num_lms {
            map_32(sa, num_lms);
            recurse_32_inner(sa, tmp, num_lms, max_id);
            unmap_32(text, sa, num_lms);
        } else {
            let n = sa.len();
            sa.copy_within(n - num_lms.., 0);
        }
        expand_32(text, sa, text_max, tmp, have_freq, num_lms);
    }
    induce_l_32(text, sa, text_max, tmp, have_freq);
    induce_s_32(text, sa, text_max, tmp, have_freq);

    tmp[0] = -1;
}

/// `recurse_32` for the `i32`-text recursion level. Identical to [`recurse_32`]
/// but the snapshot text is `i32` (the parent's IDs), matching Go's `recurse_32`
/// being shared between `sais_8_32` and `sais_32` (it always operates on `i32`).
fn recurse_32_inner(sa: &mut [i32], old_tmp: &mut [i32], num_lms: usize, max_id: usize) {
    let len = sa.len();
    let text: Vec<i32> = sa[len - num_lms..].to_vec();

    let sa_tmp_len = len - 2 * num_lms;
    let mut chosen_len = old_tmp.len();
    if chosen_len < sa_tmp_len {
        chosen_len = sa_tmp_len;
    }
    if chosen_len < num_lms {
        let mut n = max_id;
        if n < num_lms / 2 {
            n = num_lms / 2;
        }
        chosen_len = n;
    }
    let mut tmp = vec![0i32; chosen_len];

    for i in 0..num_lms {
        sa[i] = 0;
    }
    sais_32(&text, max_id, &mut sa[..num_lms], &mut tmp);
}

// ---------------------------------------------------------------------------
// freq / bucket helpers (i32 text)
//
// NOTE: in the `_32` family there is no "256" fast-path — the freq loop ranges
// over `text_max` (dynamic), matching Go's `freq_32` / `bucketMin_32` /
// `bucketMax_32` which omit the `freq[:256]` / `bucket[:256]` reslicing.
// ---------------------------------------------------------------------------

/// Go `freq_32`. Frequencies are computed into the freq region — which in Go is
/// `freq = tmp[:textMax]` when `have_freq`, else `freq = bucket = tmp[:textMax]`
/// — i.e. ALWAYS offset 0. Returns that offset (0). When `!have_freq`, freq and
/// bucket alias the same `tmp[:textMax]`, exactly as Go.
fn freq_32(text: &[i32], text_max: usize, tmp: &mut [i32], have_freq: bool) -> usize {
    if have_freq && tmp[0] >= 0 {
        return 0; // already computed
    }
    for i in 0..text_max {
        tmp[i] = 0;
    }
    for &c in text {
        tmp[c as usize] += 1;
    }
    0
}

/// Bucket region offset within `tmp`: `tmp[textMax:2*textMax]` when `have_freq`,
/// else `tmp[:textMax]` (aliasing freq).
#[inline]
fn boff_32(text_max: usize, have_freq: bool) -> usize {
    if have_freq {
        text_max
    } else {
        0
    }
}

/// Go `bucketMin_32`.
fn bucket_min_32(text: &[i32], text_max: usize, tmp: &mut [i32], have_freq: bool) {
    let foff = freq_32(text, text_max, tmp, have_freq);
    let boff = boff_32(text_max, have_freq);
    let mut total: i32 = 0;
    for i in 0..text_max {
        let n = tmp[foff + i];
        tmp[boff + i] = total;
        total += n;
    }
}

/// Go `bucketMax_32`.
fn bucket_max_32(text: &[i32], text_max: usize, tmp: &mut [i32], have_freq: bool) {
    let foff = freq_32(text, text_max, tmp, have_freq);
    let boff = boff_32(text_max, have_freq);
    let mut total: i32 = 0;
    for i in 0..text_max {
        let n = tmp[foff + i];
        total += n;
        tmp[boff + i] = total;
    }
}

// ---------------------------------------------------------------------------
// place_lms / induce / length / assign_id (i32 text)
// ---------------------------------------------------------------------------

/// Go `placeLMS_32`.
fn place_lms_32(
    text: &[i32],
    sa: &mut [i32],
    text_max: usize,
    tmp: &mut [i32],
    have_freq: bool,
) -> usize {
    bucket_max_32(text, text_max, tmp, have_freq);
    let boff = boff_32(text_max, have_freq);

    let mut num_lms = 0usize;
    let mut last_b: i32 = -1;

    let (mut c0, mut c1, mut is_type_s): (i32, i32, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            let b = tmp[boff + c1 as usize] - 1;
            tmp[boff + c1 as usize] = b;
            sa[b as usize] = (i + 1) as i32;
            last_b = b;
            num_lms += 1;
        }
        c1 = c0;
    }

    if num_lms > 1 {
        sa[last_b as usize] = 0;
    }
    num_lms
}

/// Go `induceSubL_32`.
fn induce_sub_l_32(
    text: &[i32],
    sa: &mut [i32],
    text_max: usize,
    tmp: &mut [i32],
    have_freq: bool,
) {
    bucket_min_32(text, text_max, tmp, have_freq);
    let boff = boff_32(text_max, have_freq);

    let mut k: isize = text.len() as isize - 1;
    let c0 = text[(k - 1) as usize];
    let c1 = text[k as usize];
    if c0 < c1 {
        k = -k;
    }

    let mut c_b = c1;
    let mut b = tmp[boff + c_b as usize];
    sa[b as usize] = k as i32;
    b += 1;

    for i in 0..sa.len() {
        let j = sa[i] as isize;
        if j == 0 {
            continue;
        }
        if j < 0 {
            sa[i] = (-j) as i32;
            continue;
        }
        sa[i] = 0;

        let mut k2: isize = j - 1;
        let c0 = text[(k2 - 1) as usize];
        let c1 = text[k2 as usize];
        if c0 < c1 {
            k2 = -k2;
        }

        if c_b != c1 {
            tmp[boff + c_b as usize] = b;
            c_b = c1;
            b = tmp[boff + c_b as usize];
        }
        sa[b as usize] = k2 as i32;
        b += 1;
    }
}

/// Go `induceSubS_32`.
fn induce_sub_s_32(
    text: &[i32],
    sa: &mut [i32],
    text_max: usize,
    tmp: &mut [i32],
    have_freq: bool,
) {
    bucket_max_32(text, text_max, tmp, have_freq);
    let boff = boff_32(text_max, have_freq);

    let mut c_b: i32 = 0;
    let mut b = tmp[boff + c_b as usize];

    let mut top = sa.len();
    for i in (0..sa.len()).rev() {
        let j = sa[i] as isize;
        if j == 0 {
            continue;
        }
        sa[i] = 0;
        if j < 0 {
            top -= 1;
            sa[top] = (-j) as i32;
            continue;
        }

        let mut k: isize = j - 1;
        let c1 = text[k as usize];
        let c0 = text[(k - 1) as usize];
        if c0 > c1 {
            k = -k;
        }

        if c_b != c1 {
            tmp[boff + c_b as usize] = b;
            c_b = c1;
            b = tmp[boff + c_b as usize];
        }
        b -= 1;
        sa[b as usize] = k as i32;
    }
}

/// Go `length_32`. NOTE: the `_32` (non-byte) family OMITS the `cx` packing
/// (the "byte-only" lines are stripped by the generator), so `code` is always
/// just `end - j`.
fn length_32(text: &[i32], sa: &mut [i32], _num_lms: usize) {
    let mut end: usize = 0;

    let (mut c0, mut c1, mut is_type_s): (i32, i32, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            let j = i + 1;
            let code: i32 = if end == 0 { 0 } else { (end - j) as i32 };
            sa[j >> 1] = code;
            end = j + 1;
        }
        c1 = c0;
    }
}

/// Go `assignID_32`.
fn assign_id_32(text: &[i32], sa: &mut [i32], num_lms: usize) -> usize {
    let mut id = 0usize;
    let mut last_len: i32 = -1;
    let mut last_pos: i32 = 0;
    let base = sa.len() - num_lms;
    for idx in 0..num_lms {
        let j = sa[base + idx];
        let n = sa[(j / 2) as usize];
        let is_new;
        if n != last_len {
            is_new = true;
        } else if (n as u32) >= text.len() as u32 {
            is_new = false;
        } else {
            let nn = n as usize;
            let this = &text[j as usize..][..nn];
            let last = &text[last_pos as usize..][..nn];
            let mut differ = false;
            for i in 0..nn {
                if this[i] != last[i] {
                    differ = true;
                    break;
                }
            }
            is_new = differ;
        }
        if is_new {
            id += 1;
            last_pos = j;
            last_len = n;
        }
        sa[(j / 2) as usize] = id as i32;
    }
    id
}

/// Go `unmap_32`.
fn unmap_32(text: &[i32], sa: &mut [i32], num_lms: usize) {
    let base = sa.len() - num_lms;
    let mut j = num_lms;

    let (mut c0, mut c1, mut is_type_s): (i32, i32, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            j -= 1;
            sa[base + j] = (i + 1) as i32;
        }
        c1 = c0;
    }

    for i in 0..num_lms {
        let k = sa[i] as usize;
        sa[i] = sa[base + k];
    }
}

/// Go `expand_32`.
fn expand_32(
    text: &[i32],
    sa: &mut [i32],
    text_max: usize,
    tmp: &mut [i32],
    have_freq: bool,
    num_lms: usize,
) {
    bucket_max_32(text, text_max, tmp, have_freq);
    let boff = boff_32(text_max, have_freq);

    let mut x = num_lms - 1;
    let mut sa_x = sa[x];
    let mut c = text[sa_x as usize];
    let mut b = tmp[boff + c as usize] - 1;
    tmp[boff + c as usize] = b;

    for i in (0..sa.len()).rev() {
        if i as i32 != b {
            sa[i] = 0;
            continue;
        }
        sa[i] = sa_x;

        if x > 0 {
            x -= 1;
            sa_x = sa[x];
            c = text[sa_x as usize];
            b = tmp[boff + c as usize] - 1;
            tmp[boff + c as usize] = b;
        }
    }
}

/// Go `induceL_32`.
fn induce_l_32(text: &[i32], sa: &mut [i32], text_max: usize, tmp: &mut [i32], have_freq: bool) {
    bucket_min_32(text, text_max, tmp, have_freq);
    let boff = boff_32(text_max, have_freq);

    let mut k: isize = text.len() as isize - 1;
    let c0 = text[(k - 1) as usize];
    let c1 = text[k as usize];
    if c0 < c1 {
        k = -k;
    }

    let mut c_b = c1;
    let mut b = tmp[boff + c_b as usize];
    sa[b as usize] = k as i32;
    b += 1;

    for i in 0..sa.len() {
        let j = sa[i] as isize;
        if j <= 0 {
            continue;
        }

        let mut k2: isize = j - 1;
        let c1 = text[k2 as usize];
        if k2 > 0 {
            let c0 = text[(k2 - 1) as usize];
            if c0 < c1 {
                k2 = -k2;
            }
        }

        if c_b != c1 {
            tmp[boff + c_b as usize] = b;
            c_b = c1;
            b = tmp[boff + c_b as usize];
        }
        sa[b as usize] = k2 as i32;
        b += 1;
    }
}

/// Go `induceS_32`.
fn induce_s_32(text: &[i32], sa: &mut [i32], text_max: usize, tmp: &mut [i32], have_freq: bool) {
    bucket_max_32(text, text_max, tmp, have_freq);
    let boff = boff_32(text_max, have_freq);

    let mut c_b: i32 = 0;
    let mut b = tmp[boff + c_b as usize];

    for i in (0..sa.len()).rev() {
        let mut j = sa[i] as isize;
        if j >= 0 {
            continue;
        }

        j = -j;
        sa[i] = j as i32;

        let mut k: isize = j - 1;
        let c1 = text[k as usize];
        if k > 0 {
            let c0 = text[(k - 1) as usize];
            if c0 <= c1 {
                k = -k;
            }
        }

        if c_b != c1 {
            tmp[boff + c_b as usize] = b;
            c_b = c1;
            b = tmp[boff + c_b as usize];
        }
        b -= 1;
        sa[b as usize] = k as i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suffixarray::suffix_array as reference_sa;

    fn check(text: &[u8]) {
        let got = suffix_array(text);
        let want = reference_sa(text);
        assert_eq!(got, want, "SA mismatch for {:?}", text);
    }

    #[test]
    fn edge_lengths() {
        check(b"");
        check(b"a");
        check(b"ab");
        check(b"ba");
        check(b"aa");
        check(b"aaa");
        check(b"banana");
        check(b"abracadabra");
        check(b"mississippi");
    }

    #[test]
    fn patterns() {
        // monotone increasing / decreasing
        let inc: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
        check(&inc);
        let dec: Vec<u8> = (0..200u32).map(|i| (199 - i) as u8).collect();
        check(&dec);
        // all-equal
        check(&vec![7u8; 257]);
        // SLSL alternation (recursion-forcing)
        let alt: Vec<u8> = (0..512).map(|i| if i % 2 == 0 { 1 } else { 2 }).collect();
        check(&alt);
        // periodic
        let per: Vec<u8> = (0..600).map(|i| (i % 3) as u8).collect();
        check(&per);
    }
}
