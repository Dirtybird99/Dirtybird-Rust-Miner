//! Pure-Rust port of the v1.14 descriptor suffix-array backend — the fused
//! call graph of `vendor/v114/v114_stubs.cpp`.
//!
//! Derived from the Dirtybird v1.14 descriptor suffix-array bridge
//! (<https://github.com/Dirtybird99/dirtybird-miner>), MIT licensed,
//! Copyright (c) 2026 Dirtybird99. As a derivative work this module remains
//! subject to that notice; see `vendor/v114/THIRD-PARTY-LICENSES`, which is
//! retained after the C++ sources are removed.
//!
//! The descriptor SA exploits the repeat structure recorded by wolfCompute
//! (per-template group markers → `flags`) to build the EXACT suffix array of
//! the Wolf-permuted, period-256 self-similar op-loop output ~2× faster than
//! libsais. Byte-identical to the canonical suffix array on accepted inputs;
//! it refuses where the descriptor path is invalid, so the caller's pure-Rust
//! `sais32` fallback handles the same inputs.
//!
//! The streaming/hash path is a faithful port in the `sais16.rs` house style;
//! its items cite their C++ source (`v114_stubs.cpp` line numbers). The
//! materialized x2 path uses a measured Rust/Zig-style run builder over the
//! same descriptor stages. Only code reachable from the two wrapper entry
//! points (`v114_sa_build_fused`, `v114_hash_fused`) is retained.
//!
//! Intentional deviations (all invisible in the output bytes):
//! - SHA-256 comes from the `sha2` crate directly; the C++ called OpenSSL-style
//!   symbols that `sha_ni_shim` (deleted) supplied. Same LE byte stream in.
//! - The suffix array is written as `&mut [i32]` rather than a `u8` buffer +
//!   `write_u32_le`. Identical bytes on little-endian, which the caller
//!   already requires.
//! - The env-gated `DLUNA_PROFILE_STAGE5_FUSED` rdtsc counters are dropped
//!   (measurement-only). The `profiling` crate feature is unaffected.
//! - Per-thread scratch is a `thread_local!` `RefCell` that drops at thread
//!   exit, not the C++'s deliberately-leaked `new` (a MinGW emutls workaround
//!   that does not apply here).

use std::cell::RefCell;
use std::cmp::Ordering;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

// ===========================================================================
// Constants — v114_stubs.cpp:53-55
// ===========================================================================

/// C++ `kDescriptorArenaIndexCount` (l.53): capacity of the 17-bit descriptor
/// arena-index field; also the largest `logical_len` the build accepts.
const DESCRIPTOR_ARENA_INDEX_COUNT: u32 = 0x20000;
/// C++ `kStage4MaxGroupCount` (l.54): longest full-group run, 512 groups.
const STAGE4_MAX_GROUP_COUNT: u32 = DESCRIPTOR_ARENA_INDEX_COUNT >> 8;
/// C++ `kStage4ShortRunMax` (l.55).
const STAGE4_SHORT_RUN_MAX: u32 = 25;
/// C++ `FusedHashSink::kBufferWords` (l.1570).
const SINK_BUFFER_WORDS: usize = 2048;
/// The pure-Zig materializer copies eight positions unconditionally, then
/// advances by the run's real length. Seven initialized tail words keep the
/// final short copy within the allocated scratch slices.
pub(crate) const MATERIALIZED_SA_TAIL_WORDS: usize = 7;
const MATERIALIZED_SA_COPY_WORDS: usize = MATERIALIZED_SA_TAIL_WORDS + 1;

/// C++ `env_flag_enabled` (l.57): true iff the value is exactly `"1"`.
fn env_flag_enabled(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1"))
}

/// C++ `static const bool count1_singletons = env_flag_enabled(...)`
/// (l.2480, l.2566) — read once per process, not per call.
fn count1_singletons() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| env_flag_enabled("DLUNA_STAGE5_COUNT1_SINGLETONS"))
}

// ===========================================================================
// Input views — v114_stubs.cpp:151-167
//
// The fused entry points build these from raw parts (l.2452-2462); the header
// parsers are replay-only. `data` is sliced to exactly `data_len` bytes, so
// the padded loads' `pos < data_len` guards are the slice's own bounds.
// ===========================================================================

/// C++ `Stage4InputView` (l.151).
struct Stage4View<'a> {
    logical_len: u32,
    flags: &'a [u8],
    data: &'a [u8],
}

/// C++ `Stage5InputView` (l.159). The fused path never populates
/// `int_arena`/`desc` (l.2459-2462), so only the live fields are carried.
struct Stage5View<'a> {
    logical_len: u32,
    data: &'a [u8],
}

// ===========================================================================
// Key loads — v114_stubs.cpp:217-244, 814-823
// ===========================================================================

/// C++ `load24_padded` (l.217): the 3-byte little-endian key at `pos`, with
/// bytes at or past `data_len` reading as zero.
///
/// Unreachable in the fused path (`has_load24_padding` always holds — see
/// [`sa_build_compact_fused`]), but kept as the faithful fallback that
/// [`load24_fast`] selects, exactly as the C++ does.
#[inline]
fn load24_padded(data: &[u8], pos: u32) -> u32 {
    let pos = pos as usize;
    let mut v = 0u32;
    if pos < data.len() {
        v |= u32::from(data[pos]);
    }
    if pos + 1 < data.len() {
        v |= u32::from(data[pos + 1]) << 8;
    }
    if pos + 2 < data.len() {
        v |= u32::from(data[pos + 2]) << 16;
    }
    v
}

/// C++ `load24_unchecked` (l.231). The fused entrypoints expose three tail
/// bytes and every emitted position is below `logical_len`, so this four-byte
/// unaligned read is within `data` even for the last suffix.
#[inline(always)]
fn load24_unchecked(data: &[u8], pos: u32) -> u32 {
    let pos = pos as usize;
    debug_assert!(pos.checked_add(4).is_some_and(|end| end <= data.len()));
    // SAFETY: all callers operate on positions in `0..logical_len`, while the
    // validated input slice is `logical_len + 3` bytes long.
    unsafe {
        u32::from_le(std::ptr::read_unaligned(
            data.as_ptr().add(pos).cast::<u32>(),
        )) & 0x00ff_ffff
    }
}

/// C++ `has_load24_padding` (l.237), strengthened for the four-byte masked
/// load used above. `logical_len <= 0x20000`, so the addition cannot overflow.
#[inline]
fn has_load24_padding(view: &Stage4View) -> bool {
    view.data.len() as u64 >= u64::from(view.logical_len) + 3
}

/// C++ `load24_fast` (l.241).
#[inline]
fn load24_fast(view: &Stage4View, pos: u32, padded: bool) -> u32 {
    if padded {
        load24_unchecked(view.data, pos)
    } else {
        load24_padded(view.data, pos)
    }
}

/// C++ `load_be64` (l.814).
#[inline(always)]
fn load_be64(data: &[u8], pos: usize) -> u64 {
    debug_assert!(pos.checked_add(8).is_some_and(|end| end <= data.len()));
    // SAFETY: comparator callers prove an eight-byte common suffix window
    // before reaching this load.
    unsafe {
        u64::from_be(std::ptr::read_unaligned(
            data.as_ptr().add(pos).cast::<u64>(),
        ))
    }
}

// ===========================================================================
// Suffix comparators — v114_stubs.cpp:363-374, 825-850, 1033-1037
// ===========================================================================

/// C++ Stage4 `compare_suffixes` (l.363): byte-wise order of the suffixes at
/// `a` and `b` within `data[..logical_len]`; a proper prefix sorts first.
fn compare_suffixes_s4(view: &Stage4View, a: u32, b: u32) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let ll = view.logical_len as usize;
    let (mut a, mut b) = (a as usize, b as usize);
    while a < ll && b < ll {
        let av = view.data[a];
        let bv = view.data[b];
        if av != bv {
            return av.cmp(&bv);
        }
        a += 1;
        b += 1;
    }
    if a == ll && b == ll {
        return Ordering::Equal;
    }
    if a == ll {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Full suffix order used by the pure-Zig group-run builder: compare unsigned
/// bytes eight at a time as big-endian integers, finish the short remainder
/// byte-wise, then put the shorter suffix first when one is a proper prefix.
fn compare_suffixes_full_8(view: &Stage5View, a: u32, b: u32) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let logical_len = view.logical_len as usize;
    let a = a as usize;
    let b = b as usize;
    let a_len = logical_len - a;
    let b_len = logical_len - b;
    let common = a_len.min(b_len);
    let mut offset = 0usize;

    while offset + 8 <= common {
        let cmp = load_be64(view.data, a + offset).cmp(&load_be64(view.data, b + offset));
        if cmp != Ordering::Equal {
            return cmp;
        }
        offset += 8;
    }
    while offset < common {
        let cmp = view.data[a + offset].cmp(&view.data[b + offset]);
        if cmp != Ordering::Equal {
            return cmp;
        }
        offset += 1;
    }
    a_len.cmp(&b_len)
}

/// C++ `compare_suffixes_after_key` (l.825): order the suffixes at `a` and `b`
/// knowing their 3-byte keys are equal — skip the key, take an 8-byte
/// big-endian fast path, memcmp the rest.
///
/// The `common == 8` case re-compares the (already equal) 8 bytes through the
/// else-branch memcmp, exactly as the C++ does (l.844-846): the `> 8` guard is
/// strict. Redundant but behavior-identical; kept for line fidelity.
fn compare_suffixes_after_key(view: &Stage5View, a: u32, b: u32) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let ll = view.logical_len as usize;
    let (a, b) = (a as usize, b as usize);
    let a_len = ll - a;
    let b_len = ll - b;
    let common_with_key = a_len.min(b_len);
    if common_with_key <= 3 {
        return a_len.cmp(&b_len);
    }

    let common = common_with_key - 3;
    let ap = a + 3;
    let bp = b + 3;
    if common >= 8 {
        let av = load_be64(view.data, ap);
        let bv = load_be64(view.data, bp);
        if av != bv {
            return av.cmp(&bv);
        }
    }
    let cmp = if common > 8 {
        view.data[ap + 8..ap + common].cmp(&view.data[bp + 8..bp + common])
    } else {
        view.data[ap..ap + common].cmp(&view.data[bp..bp + common])
    };
    if cmp != Ordering::Equal {
        return cmp;
    }
    a_len.cmp(&b_len)
}

/// C++ `suffix_less_after_key` (l.1033): strict weak order for equal-key
/// merging, position as final tiebreak.
#[inline]
fn suffix_less_after_key(view: &Stage5View, a: u32, b: u32) -> bool {
    match compare_suffixes_after_key(view, a, b) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => a < b,
    }
}

/// C++ `sort_stage4_suffix_order_small` (l.515): insertion sort by full suffix
/// order.
fn sort_stage4_suffix_order_small(view: &Stage4View, order: &mut [u32]) {
    for i in 1..order.len() {
        let pos = order[i];
        let mut j = i;
        while j > 0 && compare_suffixes_s4(view, pos, order[j - 1]) == Ordering::Less {
            order[j] = order[j - 1];
            j -= 1;
        }
        order[j] = pos;
    }
}

/// The `rel > 0` tail shared by every emit variant (C++ l.1275-1281,
/// l.1326-1340, l.1398-1412, l.1473-1487): step every position back one byte,
/// then re-establish order with an insertion sort keyed on the NEW leading
/// byte alone. Correct because the suffixes were already ordered by what
/// follows that byte.
#[inline]
fn step_back_and_reorder(data: &[u8], order: &mut [u32]) {
    debug_assert!(order
        .iter()
        .all(|&pos| pos > 0 && (pos as usize) < data.len()));
    let order_ptr = order.as_mut_ptr();
    let data_ptr = data.as_ptr();
    // SAFETY: the caller's positions are in `1..data.len()`. Every order
    // access is below `order.len()` and every shifted position came from that
    // already-validated set.
    unsafe {
        for i in 0..order.len() {
            *order_ptr.add(i) -= 1;
        }
        for i in 1..order.len() {
            let pos = *order_ptr.add(i);
            let key = *data_ptr.add(pos as usize);
            let mut j = i;
            while j > 0 {
                let previous = *order_ptr.add(j - 1);
                if *data_ptr.add(previous as usize) <= key {
                    break;
                }
                j -= 1;
            }
            if j < i {
                std::ptr::copy(order_ptr.add(j), order_ptr.add(j + 1), i - j);
            }
            *order_ptr.add(j) = pos;
        }
    }
}

// ===========================================================================
// Stage5Run — v114_stubs.cpp:283-287, 859-885
// ===========================================================================

/// C++ `Stage5Run` (l.859): a 24-bit key plus a packed field that is either a
/// literal position (encoded count 0 ⇒ one position) or `(count << 17) | begin`.
#[derive(Clone, Copy, Default)]
struct Stage5Run {
    key: u32,
    packed: u32,
}

/// C++ `stage5_radix_order_key` (l.283): byte-swap the 24-bit little-endian
/// key so ascending integer order equals lexicographic byte order.
#[inline]
fn stage5_radix_order_key(key: u32) -> u32 {
    ((key & 0x0000ff) << 16) | (key & 0x00ff00) | ((key & 0xff0000) >> 16)
}

/// C++ `make_stage5_run` (l.865).
///
/// No overflow is possible on the fused path, so plain arithmetic is used and
/// the debug-overflow tripwire is preserved: `begin` is a position or arena
/// index `< 0x20000` (17 bits, exactly the field the shift vacates), and
/// `count` is bounded by the group count, `<= 512`.
#[inline]
fn make_stage5_run(key: u32, begin: u32, count: u32, scratch: bool) -> Stage5Run {
    debug_assert!(begin < DESCRIPTOR_ARENA_INDEX_COUNT);
    debug_assert!(scratch || count <= STAGE4_MAX_GROUP_COUNT);
    Stage5Run {
        key,
        packed: if scratch {
            begin
        } else {
            (count << 17) + begin
        },
    }
}

/// C++ `stage5_run_encoded_count` (l.870).
#[inline]
fn stage5_run_encoded_count(run: Stage5Run) -> u32 {
    run.packed >> 17
}

/// C++ `stage5_run_is_literal` (l.874).
#[inline]
fn stage5_run_is_literal(run: Stage5Run) -> bool {
    stage5_run_encoded_count(run) == 0
}

/// C++ `stage5_run_begin` (l.878).
#[inline]
fn stage5_run_begin(run: Stage5Run) -> u32 {
    run.packed & 0x1ffff
}

/// C++ `stage5_run_count` (l.882).
#[inline]
fn stage5_run_count(run: Stage5Run) -> u32 {
    let count = stage5_run_encoded_count(run);
    if count == 0 {
        1
    } else {
        count
    }
}

/// C++ `fused_run_pos` (l.1191).
#[inline]
fn fused_run_pos(arena_positions: &[u32], run: Stage5Run, rel: u32) -> u32 {
    let begin = stage5_run_begin(run);
    if stage5_run_is_literal(run) {
        return begin;
    }
    arena_positions[begin as usize + rel as usize]
}

// ===========================================================================
// Radix sort — v114_stubs.cpp:973-1022
// (`radix_sort_runs_by_key`, l.947, is replay-only: not ported.)
// ===========================================================================

/// Three-pass LSB radix sort over the logical `runs[..n]` prefix. Both vectors
/// may stay sized for the largest hash seen by this thread; the final swap is
/// O(1) and the caller keeps tracking `n` separately.
fn radix_sort_runs_by_stored_key_prefix(
    runs: &mut Vec<Stage5Run>,
    tmp: &mut Vec<Stage5Run>,
    n: usize,
) {
    if n <= 1 {
        return;
    }
    debug_assert!(runs.len() >= n);
    debug_assert!(tmp.len() >= n);

    let mut counts0 = [0u32; 256];
    let mut counts1 = [0u32; 256];
    let mut counts2 = [0u32; 256];
    for run in &runs[..n] {
        counts0[(run.key & 0xff) as usize] += 1;
        counts1[((run.key >> 8) & 0xff) as usize] += 1;
        counts2[((run.key >> 16) & 0xff) as usize] += 1;
    }

    // Pass 0: runs → tmp
    let mut sum = 0u32;
    for c in counts0.iter_mut() {
        let n = *c;
        *c = sum;
        sum += n;
    }
    for run in &runs[..n] {
        let slot = &mut counts0[(run.key & 0xff) as usize];
        let dst = *slot as usize;
        debug_assert!(dst < n);
        // SAFETY: prefix sums assign every input run one slot in `0..n`.
        unsafe { *tmp.get_unchecked_mut(dst) = *run };
        *slot += 1;
    }

    // Pass 1: tmp → runs
    let mut sum = 0u32;
    for c in counts1.iter_mut() {
        let n = *c;
        *c = sum;
        sum += n;
    }
    for run in &tmp[..n] {
        let slot = &mut counts1[((run.key >> 8) & 0xff) as usize];
        let dst = *slot as usize;
        debug_assert!(dst < n);
        // SAFETY: prefix sums assign every input run one slot in `0..n`.
        unsafe { *runs.get_unchecked_mut(dst) = *run };
        *slot += 1;
    }

    // Pass 2: runs → tmp, then swap back (C++ `runs->swap(*tmp)`, l.1021).
    let mut sum = 0u32;
    for c in counts2.iter_mut() {
        let n = *c;
        *c = sum;
        sum += n;
    }
    for run in &runs[..n] {
        let slot = &mut counts2[((run.key >> 16) & 0xff) as usize];
        let dst = *slot as usize;
        debug_assert!(dst < n);
        // SAFETY: prefix sums assign every input run one slot in `0..n`.
        unsafe { *tmp.get_unchecked_mut(dst) = *run };
        *slot += 1;
    }
    std::mem::swap(runs, tmp);
}

/// C++ `radix_sort_runs_by_stored_key` (l.973): streaming-path wrapper whose
/// logical length is still represented by `Vec::len()`.
fn radix_sort_runs_by_stored_key(runs: &mut Vec<Stage5Run>, tmp: &mut Vec<Stage5Run>) {
    let n = runs.len();
    if n <= 1 {
        return;
    }
    if tmp.len() < n {
        tmp.resize(n, Stage5Run::default());
    }
    radix_sort_runs_by_stored_key_prefix(runs, tmp, n);
    // `tmp` can be a retained materialized buffer larger than this streaming
    // run set. The streaming path continues to use `runs.len()` as canonical.
    runs.truncate(n);
}

// ===========================================================================
// Equal-key merge — v114_stubs.cpp:1039-1108
// ===========================================================================

/// C++ `merge_sorted_suffix_positions_after_key` (l.1039).
fn merge_sorted_suffix_positions_after_key(
    view: &Stage5View,
    src: &[u32],
    left_begin: usize,
    left_end: usize,
    right_end: usize,
    dst: &mut [u32],
    dst_begin: usize,
) {
    let mut left = left_begin;
    let mut right = left_end;
    let mut out = dst_begin;
    while left < left_end && right < right_end {
        let lpos = src[left];
        let rpos = src[right];
        if suffix_less_after_key(view, lpos, rpos) {
            dst[out] = lpos;
            left += 1;
        } else {
            dst[out] = rpos;
            right += 1;
        }
        out += 1;
    }
    while left < left_end {
        dst[out] = src[left];
        left += 1;
        out += 1;
    }
    while right < right_end {
        dst[out] = src[right];
        right += 1;
        out += 1;
    }
}

/// C++ `merge_equal_key_runs_after_key` (l.1068): bottom-up pairwise merge of
/// the per-run sorted segments of `positions` (lengths in `run_lengths`) until
/// one run remains.
///
/// The C++ ping-pongs raw pointers and finishes with
/// `if (src != positions) positions->swap(*src)` (l.1105-1107); this tracks the
/// same parity in `flipped` and honors the same postcondition — the merged
/// result always lands in `positions`.
fn merge_equal_key_runs_after_key(
    view: &Stage5View,
    positions: &mut Vec<u32>,
    merge_positions: &mut Vec<u32>,
    run_lengths: &mut Vec<u32>,
    next_run_lengths: &mut Vec<u32>,
) {
    if run_lengths.len() <= 1 {
        return;
    }

    // `resize` alone, exactly as the C++ (l.1075): every slot the merge reads is
    // written first. A `clear()` first would re-zero the whole reused buffer on
    // every equal-key fallback group.
    merge_positions.resize(positions.len(), 0);

    let mut flipped = false;
    while run_lengths.len() > 1 {
        let (src, dst): (&[u32], &mut [u32]) = if flipped {
            (merge_positions.as_slice(), positions.as_mut_slice())
        } else {
            (positions.as_slice(), merge_positions.as_mut_slice())
        };

        next_run_lengths.clear();
        let mut in_base = 0usize;
        let mut out_base = 0usize;
        let mut i = 0usize;
        while i < run_lengths.len() {
            let left_len = run_lengths[i] as usize;
            if i + 1 == run_lengths.len() {
                // Odd tail: copy through. C++ `continue` inside `for (...; i += 2u)`
                // still advances i — the increment must happen here too.
                dst[out_base..out_base + left_len]
                    .copy_from_slice(&src[in_base..in_base + left_len]);
                next_run_lengths.push(left_len as u32);
                in_base += left_len;
                out_base += left_len;
                i += 2;
                continue;
            }

            let right_len = run_lengths[i + 1] as usize;
            merge_sorted_suffix_positions_after_key(
                view,
                src,
                in_base,
                in_base + left_len,
                in_base + left_len + right_len,
                dst,
                out_base,
            );
            next_run_lengths.push((left_len + right_len) as u32);
            in_base += left_len + right_len;
            out_base += left_len + right_len;
            i += 2;
        }
        std::mem::swap(run_lengths, next_run_lengths);
        flipped = !flipped;
    }

    // After an odd number of passes the result sits in `merge_positions`.
    if flipped {
        std::mem::swap(positions, merge_positions);
    }
}

// ===========================================================================
// Fused Stage-4 emit — v114_stubs.cpp:1200-1491
// ===========================================================================

/// C++ `FusedStage5Scratch` (l.924), minus the profiling members.
///
/// `keys` is not a C++ member: there it is a stack array (`uint32_t
/// keys[kStage4MaxGroupCount]`, l.1449) left deliberately uninitialized. Rust
/// has no uninitialized stack array without `unsafe`, and a `[0u32; 512]`
/// literal would zero 2 KiB on every group-run call, so it joins the reused
/// scratch instead — grown once, then only ever written before read.
#[derive(Default)]
struct FusedScratch {
    order: Vec<u32>,
    keys: Vec<u32>,
    arena_positions: Vec<u32>,
    group_positions: Vec<u32>,
    merge_positions: Vec<u32>,
    run_lengths: Vec<u32>,
    next_run_lengths: Vec<u32>,
    runs: Vec<Stage5Run>,
    radix_tmp: Vec<Stage5Run>,
    materialized_arena_len: usize,
    materialized_runs_len: usize,
}

/// The four buffers the Stage-4 emit walk touches, borrowed as disjoint fields
/// so `order`/`keys` and `runs`/`arena` can be held mutably at once.
struct Emit<'a> {
    runs: &'a mut Vec<Stage5Run>,
    arena: &'a mut Vec<u32>,
    order: &'a mut Vec<u32>,
    keys: &'a mut Vec<u32>,
}

thread_local! {
    /// C++ `static thread_local FusedStage5Scratch* scratch` (l.2464, l.2550).
    static SCRATCH: RefCell<FusedScratch> = RefCell::new(FusedScratch::default());
}

/// C++ `append_fused_order_group` (l.1200).
fn append_fused_order_group(
    runs: &mut Vec<Stage5Run>,
    arena_positions: &mut Vec<u32>,
    key: u32,
    order: &[u32],
    first: usize,
    count: u32,
    count1_singletons: bool,
) -> bool {
    if count == 0 {
        return false;
    }
    let ordered_key = stage5_radix_order_key(key);

    if count == 1 && !count1_singletons {
        runs.push(make_stage5_run(ordered_key, order[first], 1, true));
        return true;
    }

    let begin = arena_positions.len() as u64;
    let cap = u64::from(DESCRIPTOR_ARENA_INDEX_COUNT);
    if begin > cap || u64::from(count) > cap - begin {
        return false;
    }
    arena_positions.extend_from_slice(&order[first..first + count as usize]);
    runs.push(make_stage5_run(ordered_key, begin as u32, count, false));
    true
}

/// C++ `emit_fused_literal_records` (l.1226).
fn emit_fused_literal_records(
    view: &Stage4View,
    start: u32,
    count: u32,
    emit: &mut Emit,
    count1_singletons: bool,
) -> bool {
    let padded = has_load24_padding(view);
    for rel in 0..count {
        let pos = start + rel;
        let one = [pos];
        if !append_fused_order_group(
            emit.runs,
            emit.arena,
            load24_fast(view, pos, padded),
            &one,
            0,
            1,
            count1_singletons,
        ) {
            return false;
        }
    }
    true
}

/// C++ `emit_full_group_run_compact_fused_two` (l.1243): the `group_count == 2`
/// specialization, whose reorder step is a single compare-and-swap.
fn emit_fused_two(
    view: &Stage4View,
    start_group: u32,
    emit: &mut Emit,
    count1_singletons: bool,
) -> bool {
    let padded = has_load24_padding(view);
    let base = start_group << 8;
    let mut order = [base + 255, base + 511];
    if compare_suffixes_s4(view, order[1], order[0]) == Ordering::Less {
        order.swap(0, 1);
    }

    for rel in (0..=255u32).rev() {
        let key0 = load24_fast(view, order[0], padded);
        let key1 = load24_fast(view, order[1], padded);
        if key0 == key1 {
            if !append_fused_order_group(
                emit.runs,
                emit.arena,
                key0,
                &order,
                0,
                2,
                count1_singletons,
            ) {
                return false;
            }
        } else if !append_fused_order_group(
            emit.runs,
            emit.arena,
            key0,
            &order,
            0,
            1,
            count1_singletons,
        ) || !append_fused_order_group(
            emit.runs,
            emit.arena,
            key1,
            &order,
            1,
            1,
            count1_singletons,
        ) {
            return false;
        }

        if rel > 0 {
            order[0] -= 1;
            order[1] -= 1;
            if view.data[order[0] as usize] > view.data[order[1] as usize] {
                order.swap(0, 1);
            }
        }
    }

    true
}

/// The 256-step scan shared by C++ `emit_full_group_run_compact_fused_fixed<N>`
/// (l.1287), `..._fused_short` (l.1346), and the general arm of
/// `..._compact_fused` (l.1450). The C++ split them only to get compile-time
/// array sizes; `order[..n]` / `keys[..n]` carry that here.
///
/// `order` must already hold the `n` seed positions; this sorts them.
fn emit_fused_group_scan(
    view: &Stage4View,
    n: usize,
    presorted: bool,
    emit: &mut Emit,
    count1_singletons: bool,
) -> bool {
    let padded = has_load24_padding(view);
    let Emit {
        runs,
        arena,
        order,
        keys,
    } = emit;
    let order = &mut order[..n];
    let keys = &mut keys[..n];

    if !presorted {
        sort_stage4_suffix_order_small(view, order);
    }

    for rel in (0..=255u32).rev() {
        for i in 0..n {
            keys[i] = load24_fast(view, order[i], padded);
        }

        let mut group_start = 0usize;
        while group_start < n {
            let key = keys[group_start];
            let mut group_end = group_start + 1;
            while group_end < n && keys[group_end] == key {
                group_end += 1;
            }
            if !append_fused_order_group(
                runs,
                arena,
                key,
                order,
                group_start,
                (group_end - group_start) as u32,
                count1_singletons,
            ) {
                return false;
            }
            group_start = group_end;
        }

        if rel > 0 {
            step_back_and_reorder(view.data, order);
        }
    }

    true
}

/// Seed `emit.order[..n]` with the run's per-group anchor positions
/// (C++ `order[chunk] = base + (chunk << 8) + 255u`) and size `emit.keys`.
/// `resize` only grows the reused buffers; it never re-zeros live elements.
fn seed_order(emit: &mut Emit, base: u32, n: usize) {
    emit.order.clear();
    emit.order
        .extend((0..n as u32).map(|chunk| base + (chunk << 8) + 255));
    if emit.keys.len() < n {
        emit.keys.resize(n, 0);
    }
}

/// C++ `emit_full_group_run_compact_fused_short` (l.1346). The C++'s
/// `_fused_fixed<3>` / `<4>` specializations fold into the same scan.
fn emit_fused_short(
    view: &Stage4View,
    start_group: u32,
    end_group: u32,
    emit: &mut Emit,
    count1_singletons: bool,
) -> bool {
    let group_count = end_group - start_group;
    if group_count == 0 || group_count > STAGE4_SHORT_RUN_MAX {
        return false;
    }
    if group_count == 2 {
        return emit_fused_two(view, start_group, emit, count1_singletons);
    }

    let n = group_count as usize;
    seed_order(emit, start_group << 8, n);
    emit_fused_group_scan(view, n, false, emit, count1_singletons)
}

/// C++ `emit_full_group_run_compact_fused` (l.1418): the run dispatcher.
fn emit_fused_full_group_run(
    view: &Stage4View,
    start_group: u32,
    end_group: u32,
    emit: &mut Emit,
    count1_singletons: bool,
) -> bool {
    let group_count = end_group - start_group;
    if group_count == 0 {
        return true;
    }
    if group_count > STAGE4_MAX_GROUP_COUNT {
        return false;
    }

    let base = start_group << 8;
    if group_count == 1 {
        return emit_fused_literal_records(view, base, 256, emit, count1_singletons);
    }
    if group_count <= STAGE4_SHORT_RUN_MAX {
        return emit_fused_short(view, start_group, end_group, emit, count1_singletons);
    }

    // General path (C++ l.1438-1447): `std::sort` by full suffix order rather
    // than the short path's insertion sort, then the identical 256-step scan.
    // `sort_unstable_by` matches `std::sort`: both leave equal elements in
    // unspecified order, and no two positions compare equal here (they are
    // distinct suffixes of one string, so the comparator is a total order).
    let n = group_count as usize;
    seed_order(emit, base, n);
    emit.order[..n].sort_unstable_by(|&a, &b| compare_suffixes_s4(view, a, b));
    emit_fused_group_scan(view, n, true, emit, count1_singletons)
}

// ===========================================================================
// Equal-key group writers — v114_stubs.cpp:1493-1567
// ===========================================================================

/// C++ `kMaxStackLiteralGroup` (l.1496).
const MAX_STACK_LITERAL_GROUP: usize = 32;

/// The shared prologue of the four `..._equal_key_group_after_key` variants
/// (C++ l.1493-1515, l.1643-1665): if every run in the group is a literal and
/// the group is small, insertion-sort their positions by after-key order.
/// Returns `None` when the C++ would `return false` and fall through.
fn sorted_literal_group(
    view: &Stage5View,
    runs: &[Stage5Run],
    group_start: usize,
    group_end: usize,
) -> Option<([u32; MAX_STACK_LITERAL_GROUP], usize)> {
    let count = group_end - group_start;
    if count == 0 || count > MAX_STACK_LITERAL_GROUP {
        return None;
    }

    let mut positions = [0u32; MAX_STACK_LITERAL_GROUP];
    for i in 0..count {
        let run = runs[group_start + i];
        if !stage5_run_is_literal(run) {
            return None;
        }
        positions[i] = stage5_run_begin(run);
    }

    for i in 1..count {
        let pos = positions[i];
        let mut j = i;
        while j > 0 && suffix_less_after_key(view, pos, positions[j - 1]) {
            positions[j] = positions[j - 1];
            j -= 1;
        }
        positions[j] = pos;
    }
    Some((positions, count))
}

/// C++ `fused_try_write_two_equal_key_runs_after_key` (l.1526) and
/// `fused_try_hash_two_equal_key_runs_after_key` (l.1673): the exactly-two-runs
/// specialization — a straight merge, no scratch. Emits through `sink`.
fn try_two_equal_key_runs<F: FnMut(u32)>(
    view: &Stage5View,
    arena_positions: &[u32],
    runs: &[Stage5Run],
    group_start: usize,
    group_end: usize,
    mut sink: F,
) -> bool {
    if group_end != group_start + 2 {
        return false;
    }

    let left = runs[group_start];
    let right = runs[group_start + 1];
    let left_count = stage5_run_count(left);
    let right_count = stage5_run_count(right);
    let mut left_rel = 0u32;
    let mut right_rel = 0u32;

    while left_rel < left_count && right_rel < right_count {
        let lpos = fused_run_pos(arena_positions, left, left_rel);
        let rpos = fused_run_pos(arena_positions, right, right_rel);
        if suffix_less_after_key(view, lpos, rpos) {
            sink(lpos);
            left_rel += 1;
        } else {
            sink(rpos);
            right_rel += 1;
        }
    }
    while left_rel < left_count {
        sink(fused_run_pos(arena_positions, left, left_rel));
        left_rel += 1;
    }
    while right_rel < right_count {
        sink(fused_run_pos(arena_positions, right, right_rel));
        right_rel += 1;
    }

    true
}

/// The general equal-key fallback (C++ l.1804-1832 / l.1888-1910): gather every
/// run's positions, merge the per-run sorted segments, leave the result in
/// `scratch.group_positions`.
fn merge_equal_key_group(
    view: &Stage5View,
    scratch: &mut FusedScratch,
    group_start: usize,
    group_end: usize,
) {
    let FusedScratch {
        runs,
        arena_positions,
        group_positions,
        merge_positions,
        run_lengths,
        next_run_lengths,
        ..
    } = scratch;

    group_positions.clear();
    run_lengths.clear();
    let mut total = 0usize;
    for run in &runs[group_start..group_end] {
        let count = stage5_run_count(*run);
        total += count as usize;
        run_lengths.push(count);
    }
    group_positions.reserve(total);
    for run in &runs[group_start..group_end] {
        for rel in 0..stage5_run_count(*run) {
            group_positions.push(fused_run_pos(arena_positions, *run, rel));
        }
    }
    merge_equal_key_runs_after_key(
        view,
        group_positions,
        merge_positions,
        run_lengths,
        next_run_lengths,
    );
}

// ===========================================================================
// Streaming SHA-256 sink — v114_stubs.cpp:1569-1641
// ===========================================================================

/// C++ `FusedHashSink` (l.1569): buffer suffix-array positions and feed
/// SHA-256 in 8 KiB blocks, never materializing the ~280 KB array.
struct FusedHashSink {
    ctx: Sha256,
    buffer: [u32; SINK_BUFFER_WORDS],
    buffered: usize,
    positions: usize,
}

impl FusedHashSink {
    /// C++ `fused_hash_sink_init` (l.1578).
    fn new() -> Self {
        Self {
            ctx: Sha256::new(),
            buffer: [0u32; SINK_BUFFER_WORDS],
            buffered: 0,
            positions: 0,
        }
    }

    /// C++ `fused_hash_sink_write_pos` (l.1591).
    #[inline]
    fn write_pos(&mut self, pos: u32) {
        self.buffer[self.buffered] = pos;
        self.buffered += 1;
        self.positions += 1;
        if self.buffered == SINK_BUFFER_WORDS {
            self.ctx.update(bytemuck::cast_slice(&self.buffer));
            self.buffered = 0;
        }
    }

    /// C++ `fused_hash_sink_write_positions` (l.1601), little-endian arm: hash
    /// whole buffer-sized blocks straight out of `positions` when the buffer is
    /// empty, otherwise top the buffer up. `cast_slice` is `bytemuck`'s safe
    /// `u32 → u8` reinterpretation (never panics: size and alignment always
    /// divide), which reproduces the C++'s memcpy-free path without `unsafe`.
    ///
    /// Only reached on little-endian: `sa_build_compact_fused` /
    /// `hash_compact_fused` refuse otherwise, as the C++ callers did.
    fn write_positions(&mut self, mut positions: &[u32]) {
        while !positions.is_empty() {
            if self.buffered == 0 && positions.len() >= SINK_BUFFER_WORDS {
                let full = positions.len() & !(SINK_BUFFER_WORDS - 1);
                self.ctx.update(bytemuck::cast_slice(&positions[..full]));
                self.positions += full;
                positions = &positions[full..];
                continue;
            }

            let space = SINK_BUFFER_WORDS - self.buffered;
            let chunk = positions.len().min(space);
            self.buffer[self.buffered..self.buffered + chunk].copy_from_slice(&positions[..chunk]);
            self.buffered += chunk;
            self.positions += chunk;
            positions = &positions[chunk..];
            if self.buffered == SINK_BUFFER_WORDS {
                self.ctx.update(bytemuck::cast_slice(&self.buffer));
                self.buffered = 0;
            }
        }
    }

    /// C++ `fused_hash_sink_flush` + `fused_hash_sink_final` (l.1584, l.1638).
    fn finalize(mut self) -> [u8; 32] {
        if self.buffered != 0 {
            self.ctx
                .update(bytemuck::cast_slice(&self.buffer[..self.buffered]));
        }
        self.ctx.finalize().into()
    }
}

// ===========================================================================
// Run emission — v114_stubs.cpp:1711-1920
// ===========================================================================

/// Pure-Zig-style materialized emitter. The backing vectors remain sized for
/// the largest hash seen by the thread; these two counters are the canonical
/// logical lengths. Writes use indexed assignment into initialized storage,
/// avoiding a `Vec::push`/capacity branch for every emitted run and position.
struct MaterializedBuilder<'scratch, 'data> {
    data: &'data [u8],
    logical_len: u32,
    arena: &'scratch mut [u32],
    runs: &'scratch mut [Stage5Run],
    arena_len: usize,
    runs_len: usize,
}

impl MaterializedBuilder<'_, '_> {
    /// Record one already suffix-sorted, same-prefix run.
    #[inline(always)]
    fn append_run(&mut self, positions: &[u32]) {
        let count = positions.len();
        debug_assert!((1..=STAGE4_MAX_GROUP_COUNT as usize).contains(&count));
        let begin = self.arena_len;
        let end = begin + count;
        debug_assert!(end <= self.arena.len());
        debug_assert!(self.runs_len < self.runs.len());

        // SAFETY: the builder owns disjoint scratch fields; the capacity and
        // non-empty run invariants are checked when the builder is created.
        unsafe {
            std::ptr::copy_nonoverlapping(
                positions.as_ptr(),
                self.arena.as_mut_ptr().add(begin),
                count,
            );
            let first = *positions.get_unchecked(0);
            self.runs
                .as_mut_ptr()
                .add(self.runs_len)
                .write(make_stage5_run(
                    stage5_radix_order_key(load24_unchecked(self.data, first)),
                    begin as u32,
                    count as u32,
                    false,
                ));
        }
        self.arena_len = end;
        self.runs_len += 1;
    }

    /// Emit consecutive positions as arena-backed singleton runs. Keep this
    /// direct: it is the common one-chunk/tail path and can account for tens of
    /// thousands of records per hash.
    #[inline]
    fn emit_literals(&mut self, start: u32, count: u32) {
        let count = count as usize;
        debug_assert!(self.arena_len + count <= self.arena.len());
        debug_assert!(self.runs_len + count <= self.runs.len());
        debug_assert!(start as usize + count <= self.logical_len as usize);
        // SAFETY: the grow-only scratch slices were sized to `logical_len`;
        // this batch's ranges were proved above and positions stay below it.
        unsafe {
            let arena = self.arena.as_mut_ptr().add(self.arena_len);
            let runs = self.runs.as_mut_ptr().add(self.runs_len);
            for rel in 0..count {
                let pos = start + rel as u32;
                arena.add(rel).write(pos);
                runs.add(rel).write(make_stage5_run(
                    stage5_radix_order_key(load24_unchecked(self.data, pos)),
                    (self.arena_len + rel) as u32,
                    1,
                    false,
                ));
            }
        }
        self.arena_len += count;
        self.runs_len += count;
    }

    /// At rel=255 the same-offset suffixes are fully sorted once. Each earlier
    /// rel prepends one byte and restores order by a stable insertion on that
    /// byte alone (`>` deliberately preserves ties).
    fn emit_group_run(&mut self, start_group: u32, end_group: u32, order: &mut [u32]) {
        let group_count = end_group - start_group;
        if group_count == 0 {
            return;
        }
        debug_assert!(group_count <= STAGE4_MAX_GROUP_COUNT);

        let base = start_group << 8;
        if group_count == 1 {
            self.emit_literals(base, 256);
            return;
        }

        let n = group_count as usize;
        debug_assert!(order.len() >= n);
        let order = &mut order[..n];
        for (chunk, pos) in order.iter_mut().enumerate() {
            *pos = base + ((chunk as u32) << 8) + 255;
        }
        let suffix_view = Stage5View {
            logical_len: self.logical_len,
            data: self.data,
        };
        order.sort_by(|&a, &b| compare_suffixes_full_8(&suffix_view, a, b));

        for rel in (0..=255u32).rev() {
            let mut group_start = 0usize;
            while group_start < n {
                let key = load24_unchecked(self.data, order[group_start]);
                let mut group_end = group_start + 1;
                while group_end < n && load24_unchecked(self.data, order[group_end]) == key {
                    group_end += 1;
                }
                self.append_run(&order[group_start..group_end]);
                group_start = group_end;
            }

            if rel > 0 {
                step_back_and_reorder(self.data, order);
            }
        }
    }
}

/// Build the arena-backed group runs used only by the materialized/x2 path.
/// The older C++-faithful emitter remains intact for streaming x1 hashing.
fn build_materialized_group_runs(
    data: &[u8],
    logical_len: u32,
    flags: &[u8],
    scratch: &mut FusedScratch,
) -> bool {
    if logical_len == 0 || logical_len > DESCRIPTOR_ARENA_INDEX_COUNT {
        return false;
    }
    let group_limit = logical_len >> 8;
    if flags.len() as u64 <= u64::from(group_limit) {
        return false;
    }
    let Some(data_len) = (logical_len as usize).checked_add(3) else {
        return false;
    };
    if data.len() < data_len {
        return false;
    }

    let logical_len_usize = logical_len as usize;
    let padded_len = logical_len_usize + MATERIALIZED_SA_TAIL_WORDS;
    // Zig uses fixed per-thread arrays. A grow-only initialized Vec has the
    // same steady-state behavior while retaining this port's larger accepted
    // descriptor bound and safe indexing.
    if scratch.order.len() < STAGE4_MAX_GROUP_COUNT as usize {
        scratch.order.resize(STAGE4_MAX_GROUP_COUNT as usize, 0);
    }
    if scratch.arena_positions.len() < padded_len {
        scratch.arena_positions.resize(padded_len, 0);
    }
    if scratch.runs.len() < logical_len_usize {
        scratch.runs.resize(logical_len_usize, Stage5Run::default());
    }
    if scratch.radix_tmp.len() < logical_len_usize {
        scratch
            .radix_tmp
            .resize(logical_len_usize, Stage5Run::default());
    }
    if scratch.group_positions.len() < padded_len {
        scratch.group_positions.resize(padded_len, 0);
    }
    scratch.materialized_arena_len = 0;
    scratch.materialized_runs_len = 0;

    let data = &data[..data_len];
    let full_groups = logical_len >> 8;
    let (arena_len, runs_len) = {
        let FusedScratch {
            order,
            arena_positions,
            runs,
            ..
        } = scratch;
        let mut builder = MaterializedBuilder {
            data,
            logical_len,
            arena: &mut arena_positions[..logical_len_usize],
            runs: &mut runs[..logical_len_usize],
            arena_len: 0,
            runs_len: 0,
        };
        let mut run_start_group = 0u32;
        for group in 1..=full_groups {
            if flags[group as usize] != 0 || group == full_groups {
                builder.emit_group_run(run_start_group, group, order);
                run_start_group = group;
            }
        }
        builder.emit_literals(full_groups << 8, logical_len & 0xff);
        (builder.arena_len, builder.runs_len)
    };

    if arena_len != logical_len_usize || runs_len > logical_len_usize {
        return false;
    }
    scratch.materialized_arena_len = arena_len;
    scratch.materialized_runs_len = runs_len;
    true
}

/// Copy one arena-backed run with the same unconditional eight-word move as
/// the current Zig implementation. The source and destination both include
/// seven initialized tail words, so the final short run remains in bounds.
#[inline]
fn copy_materialized_run(
    dst: &mut [u32],
    dst_begin: usize,
    arena: &[u32],
    run: Stage5Run,
) -> usize {
    debug_assert!(!stage5_run_is_literal(run));
    let begin = stage5_run_begin(run) as usize;
    let count = stage5_run_count(run) as usize;
    debug_assert!((1..=STAGE4_MAX_GROUP_COUNT as usize).contains(&count));
    debug_assert!(begin + count <= arena.len() - MATERIALIZED_SA_TAIL_WORDS);
    debug_assert!(dst_begin + count.max(MATERIALIZED_SA_COPY_WORDS) <= dst.len());

    // SAFETY: both scratch buffers include seven initialized tail words, the
    // decoded run is inside the logical arena, and mutable/immutable borrows
    // guarantee these regions do not overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(
            arena.as_ptr().add(begin),
            dst.as_mut_ptr().add(dst_begin),
            count.max(MATERIALIZED_SA_COPY_WORDS),
        );
    }
    count
}

/// Sort runs globally by their three-byte key, then materialize each key
/// bucket exactly like the pure-Zig builder: direct fixed-width copy for one
/// run, fixed-width gather plus a full suffix sort for multiple runs.
fn materialize_group_runs_to_sa(
    view: &Stage5View,
    scratch: &mut FusedScratch,
    out: &mut [i32],
) -> bool {
    let logical_len = view.logical_len as usize;
    let Some(padded_len) = logical_len.checked_add(MATERIALIZED_SA_TAIL_WORDS) else {
        return false;
    };
    let runs_len = scratch.materialized_runs_len;
    if out.len() < padded_len
        || scratch.materialized_arena_len != logical_len
        || runs_len > logical_len
        || scratch.arena_positions.len() < padded_len
        || scratch.runs.len() < runs_len
        || scratch.radix_tmp.len() < runs_len
        || scratch.group_positions.len() < padded_len
    {
        return false;
    }

    radix_sort_runs_by_stored_key_prefix(&mut scratch.runs, &mut scratch.radix_tmp, runs_len);

    let out: &mut [u32] = &mut bytemuck::cast_slice_mut(out)[..padded_len];
    let FusedScratch {
        runs,
        arena_positions,
        group_positions,
        ..
    } = scratch;
    let runs = &runs[..runs_len];
    let arena_positions = &arena_positions[..padded_len];
    let group_positions = &mut group_positions[..padded_len];

    let mut run_start = 0usize;
    let mut out_pos = 0usize;
    while run_start < runs.len() {
        let mut run_end = run_start + 1;
        while run_end < runs.len() && runs[run_start].key == runs[run_end].key {
            run_end += 1;
        }

        if run_end == run_start + 1 {
            let copied = copy_materialized_run(out, out_pos, arena_positions, runs[run_start]);
            out_pos += copied;
        } else {
            let mut gathered = 0usize;
            for &run in &runs[run_start..run_end] {
                gathered += copy_materialized_run(group_positions, gathered, arena_positions, run);
            }
            group_positions[..gathered].sort_by(|&a, &b| compare_suffixes_full_8(view, a, b));
            out[out_pos..out_pos + gathered].copy_from_slice(&group_positions[..gathered]);
            out_pos += gathered;
        }
        run_start = run_end;
    }

    out_pos == logical_len
}

/// C++ `write_fused_runs_to_hash` (l.1847): the same walk, streaming straight
/// into SHA-256 instead of materializing the suffix array.
fn write_fused_runs_to_hash(view: &Stage5View, scratch: &mut FusedScratch) -> Option<[u8; 32]> {
    radix_sort_runs_by_stored_key(&mut scratch.runs, &mut scratch.radix_tmp);

    let mut sink = FusedHashSink::new();
    let mut group_start = 0usize;
    while group_start < scratch.runs.len() {
        let mut group_end = group_start + 1;
        while group_end < scratch.runs.len()
            && scratch.runs[group_start].key == scratch.runs[group_end].key
        {
            group_end += 1;
        }

        if group_end == group_start + 1 {
            let run = scratch.runs[group_start];
            if !stage5_run_is_literal(run) {
                let begin = stage5_run_begin(run) as usize;
                let count = stage5_run_count(run) as usize;
                sink.write_positions(&scratch.arena_positions[begin..begin + count]);
            } else {
                sink.write_pos(stage5_run_begin(run));
            }
        } else if let Some((positions, count)) =
            sorted_literal_group(view, &scratch.runs, group_start, group_end)
        {
            for &pos in &positions[..count] {
                sink.write_pos(pos);
            }
        } else if !try_two_equal_key_runs(
            view,
            &scratch.arena_positions,
            &scratch.runs,
            group_start,
            group_end,
            |pos| sink.write_pos(pos),
        ) {
            merge_equal_key_group(view, scratch, group_start, group_end);
            sink.write_positions(&scratch.group_positions);
        }
        group_start = group_end;
    }

    (sink.positions == view.logical_len as usize).then(|| sink.finalize())
}

// ===========================================================================
// Entry points — v114_stubs.cpp:2431-2587
// ===========================================================================

/// The shared prologue of both fused entry points (C++ l.2439-2505,
/// l.2526-2584): validate, reset the scratch, walk the template-group runs.
/// Returns `false` where the C++ returned `false` (the caller falls back).
fn run_fused_emit(
    data: &[u8],
    logical_len: u32,
    flags: &[u8],
    scratch: &mut FusedScratch,
) -> Option<()> {
    // C++ l.2443-2450.
    if logical_len == 0 || logical_len > DESCRIPTOR_ARENA_INDEX_COUNT {
        return None;
    }
    if (data.len() as u64) < u64::from(logical_len) {
        return None;
    }
    let group_limit = logical_len >> 8;
    if flags.len() as u64 <= u64::from(group_limit) {
        return None;
    }

    let view = Stage4View {
        logical_len,
        flags,
        data,
    };

    scratch.arena_positions.clear();
    scratch.group_positions.clear();
    scratch.merge_positions.clear();
    scratch.run_lengths.clear();
    scratch.next_run_lengths.clear();
    scratch.runs.clear();
    scratch.arena_positions.reserve(logical_len as usize);
    scratch.runs.reserve(logical_len as usize);

    let singletons = count1_singletons();
    let full_groups = logical_len >> 8;
    let mut run_start = 0u32;

    let FusedScratch {
        runs,
        arena_positions,
        order,
        keys,
        ..
    } = scratch;
    let mut emit = Emit {
        runs,
        arena: arena_positions,
        order,
        keys,
    };

    // C++ l.2487: a run ends at a template boundary (`flags[group] != 0`) or at
    // the last full group.
    for group in 1..=full_groups {
        if view.flags[group as usize] != 0 || group == full_groups {
            if !emit_fused_full_group_run(&view, run_start, group, &mut emit, singletons) {
                return None;
            }
            run_start = group;
        }
    }

    // C++ l.2499: the ragged tail past the last full group.
    if !emit_fused_literal_records(
        &view,
        full_groups << 8,
        logical_len & 0xff,
        &mut emit,
        singletons,
    ) {
        return None;
    }
    Some(())
}

/// C++ `stage_v114_sa_build_compact_fused_raw` (l.2431), reached through the
/// `v114_sa_build_fused` wrapper. Fills `sa[..logical_len]` and returns `true`,
/// or returns `false` if the descriptor build refuses (caller: libsais).
///
/// `data` must expose at least `logical_len + 3` bytes (the caller's tail), and
/// `sa` at least `logical_len + 7` initialized slots. The canonical suffix
/// array remains `sa[..logical_len]`; the tail is temporary copy headroom.
pub(crate) fn sa_build_compact_fused(
    data_with_tail: &[u8],
    logical_len: usize,
    flags: &[u8],
    sa: &mut [i32],
) -> bool {
    if !cfg!(target_endian = "little") {
        return false;
    }
    let Ok(logical_len_u32) = u32::try_from(logical_len) else {
        return false;
    };
    let Some(data_len) = logical_len.checked_add(3) else {
        return false;
    };
    let Some(padded_len) = logical_len.checked_add(MATERIALIZED_SA_TAIL_WORDS) else {
        return false;
    };
    if data_with_tail.len() < data_len || sa.len() < padded_len {
        return false;
    }
    let data = &data_with_tail[..data_len];

    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        let built = build_materialized_group_runs(data, logical_len_u32, flags, &mut scratch);
        if !built {
            return false;
        }
        let stage5 = Stage5View {
            logical_len: logical_len_u32,
            data,
        };
        materialize_group_runs_to_sa(&stage5, &mut scratch, sa)
    })
}

/// C++ `stage_v114_hash_compact_fused_raw` (l.2520), reached through the
/// `v114_hash_fused` wrapper. Streams the descriptor SA into SHA-256 and
/// returns the 32-byte PoW hash, or `None` if the build refuses.
///
/// Byte-identical to `sha256(sa_build_compact_fused(..) as LE i32 bytes)`.
pub(crate) fn hash_compact_fused(
    data_with_tail: &[u8],
    logical_len: usize,
    flags: &[u8],
) -> Option<[u8; 32]> {
    if !cfg!(target_endian = "little") {
        return None;
    }
    let logical_len_u32 = u32::try_from(logical_len).ok()?;
    let data_len = logical_len.checked_add(3)?;
    if data_with_tail.len() < data_len {
        return None;
    }
    let data = &data_with_tail[..data_len];

    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        run_fused_emit(data, logical_len_u32, flags, &mut scratch)?;
        let stage5 = Stage5View {
            logical_len: logical_len_u32,
            data,
        };
        write_fused_runs_to_hash(&stage5, &mut scratch)
    })
}

#[cfg(test)]
mod materialized_group_tests {
    use super::*;

    fn bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn singleton_chunk_flags(len: usize) -> Vec<u8> {
        vec![1; (len >> 8) + 1]
    }

    fn assert_direct_builder_matches(data: &[u8], flags: &[u8]) {
        let logical_len = data.len();
        let mut padded_data = data.to_vec();
        padded_data.extend_from_slice(&[0; 3]);

        const GUARD: i32 = -0x1357_2468;
        let mut out = vec![GUARD; logical_len + MATERIALIZED_SA_TAIL_WORDS + 1];
        assert!(sa_build_compact_fused(
            &padded_data,
            logical_len,
            flags,
            &mut out,
        ));
        assert_eq!(
            out[logical_len + MATERIALIZED_SA_TAIL_WORDS],
            GUARD,
            "fixed-width copy crossed the seven-word tail for len={logical_len}"
        );

        let expected = crate::sais32::suffix_array(data);
        assert_eq!(
            &out[..logical_len],
            expected.as_slice(),
            "direct group-run SA mismatch for len={logical_len}"
        );

        SCRATCH.with(|cell| {
            let scratch = cell.borrow();
            assert!(scratch.arena_positions.len() >= logical_len + MATERIALIZED_SA_TAIL_WORDS);
            assert_eq!(scratch.materialized_arena_len, logical_len);
            assert!(scratch.materialized_runs_len <= logical_len);
            assert!(scratch.runs.len() >= scratch.materialized_runs_len);
            let mut positions = 0usize;
            for &run in &scratch.runs[..scratch.materialized_runs_len] {
                assert!(!stage5_run_is_literal(run));
                assert!(run.key <= 0x00ff_ffff);
                let begin = stage5_run_begin(run) as usize;
                let count = stage5_run_count(run) as usize;
                assert!((1..=STAGE4_MAX_GROUP_COUNT as usize).contains(&count));
                assert!(begin + count <= logical_len);
                positions += count;
            }
            assert_eq!(positions, logical_len);
        });
    }

    #[test]
    fn materialized_group_builder_matches_reference_at_boundaries() {
        for &len in &[1usize, 2, 3, 7, 8, 9, 255, 256, 257, 511, 512, 513] {
            let data = bytes(len, 0x9e37_79b9_7f4a_7c15 ^ len as u64);
            assert_direct_builder_matches(&data, &singleton_chunk_flags(len));
        }

        // Exercise the rel=255 full sort + stable leading-byte insertion path.
        let chunk = bytes(256, 0x1234_5678_9abc_def0);
        let mut periodic = Vec::with_capacity(4 * 256 + 13);
        for _ in 0..4 {
            periodic.extend_from_slice(&chunk);
        }
        periodic.extend_from_slice(&chunk[..13]);
        let mut one_group = vec![0; (periodic.len() >> 8) + 1];
        one_group[0] = 1;
        assert_direct_builder_matches(&periodic, &one_group);

        // Force a multi-run equal-key bucket through the fixed-eight gather.
        SCRATCH.with(|cell| cell.borrow_mut().group_positions.clear());
        let collisions = vec![0u8; 33];
        assert_direct_builder_matches(&collisions, &singleton_chunk_flags(collisions.len()));
        SCRATCH.with(|cell| {
            assert!(
                cell.borrow().group_positions.len()
                    >= collisions.len() + MATERIALIZED_SA_TAIL_WORDS
            );
        });

        // Production's largest observed length: worst-case run count, plus a
        // 255-nonzero tail that stresses both source and destination slack.
        let max_data = bytes(70_911, 0xd1b5_4a32_d192_ed03);
        assert_direct_builder_matches(&max_data, &singleton_chunk_flags(max_data.len()));

        // The opposite production-max shape: no interior boundary, so all 276
        // complete chunks exercise one large rel=255/stable-insertion group.
        let mut max_group_data = Vec::with_capacity(70_911);
        while max_group_data.len() < 70_911 {
            max_group_data.extend_from_slice(&chunk);
        }
        max_group_data.truncate(70_911);
        let mut max_group_flags = vec![0; (max_group_data.len() >> 8) + 1];
        max_group_flags[0] = 1;
        assert_direct_builder_matches(&max_group_data, &max_group_flags);

        let data = bytes(9, 7);
        let mut padded_data = data.clone();
        padded_data.extend_from_slice(&[0; 3]);
        let flags = singleton_chunk_flags(data.len());
        let mut short = vec![0; data.len() + MATERIALIZED_SA_TAIL_WORDS - 1];
        assert!(!sa_build_compact_fused(
            &padded_data,
            data.len(),
            &flags,
            &mut short,
        ));
        let mut just_enough = vec![0; data.len() + MATERIALIZED_SA_TAIL_WORDS];
        assert!(sa_build_compact_fused(
            &padded_data,
            data.len(),
            &flags,
            &mut just_enough,
        ));

        let mut zero_out = vec![0; MATERIALIZED_SA_TAIL_WORDS];
        assert!(!sa_build_compact_fused(&[0; 3], 0, &[1], &mut zero_out));
    }

    #[test]
    fn fixed_eight_multi_run_gather_stays_inside_seven_word_tail() {
        let mut arena = (0..24u32).map(|x| x * 7 + 3).collect::<Vec<_>>();
        arena.extend_from_slice(&[0; MATERIALIZED_SA_TAIL_WORDS]);
        let runs = [
            make_stage5_run(0x010203, 0, 7, false),
            make_stage5_run(0x010203, 7, 8, false),
            make_stage5_run(0x010203, 15, 9, false),
        ];
        const GUARD: u32 = 0xa5a5_5a5a;
        let total = 24usize;
        let mut gathered = vec![GUARD; total + MATERIALIZED_SA_TAIL_WORDS + 1];
        let mut out = 0usize;
        for run in runs {
            out += copy_materialized_run(
                &mut gathered[..total + MATERIALIZED_SA_TAIL_WORDS],
                out,
                &arena,
                run,
            );
        }
        assert_eq!(out, total);
        assert_eq!(&gathered[..total], &arena[..total]);
        assert_eq!(gathered[total + MATERIALIZED_SA_TAIL_WORDS], GUARD);
    }
}
