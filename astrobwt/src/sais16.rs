//! SA-IS suffix array construction for the legacy POW16 PoW — a faithful,
//! line-by-line port of `astrobwt/sais16.go` (the `_8_16` + `_16` families)
//! used by `astrobwt.POW16` over the fixed 9973-byte stage1.
//!
//! Identical in structure to [`crate::sais32`] but with `i16` indices: POW16's
//! suffix array is over exactly `stage1_length = 9973 < i16::MAX = 32767`
//! positions, so every index fits in `int16` (Go uses `[]int16`). All
//! intermediate arithmetic (negation flags, `length_8_16`'s `cx` packing into a
//! `u16`, `assignID`'s `uint16(n) >= len(text)` comparison) is done at `i16`/
//! `u16` width to match Go bit-for-bit.
//!
//! Like sais32, this reproduces the (unique) suffix array byte-for-byte; the
//! retained prefix-doubling [`crate::suffixarray`] is the differential-fuzz
//! oracle. POW16 feeds text in `[0, 256)` at the top, and the recursion alphabet
//! (maxID) also fits in `i16`.

// See sais32.rs: the Go LMS-substring-iterator swap idiom leaves a dead initial
// store on c0; kept verbatim to mirror Go line-for-line.
#![allow(unused_assignments)]

/// The text character alphabet size for byte input: 256.
const TEXT_MAX_8: usize = 256;

// ===========================================================================
// Public entry point
// ===========================================================================

/// Build the suffix array of `text` (sentinel-smallest convention) as `i16`
/// indices. Go: `text_16_0alloc(text, sa)` → `sais_8_16(text, 256, sa,
/// [2*256]int16{})` (`astrobwt.go`). Returns `Vec<i16>` of length `text.len()`.
pub fn suffix_array(text: &[u8]) -> Vec<i16> {
    let n = text.len();
    debug_assert!(
        i16::try_from(n).is_ok(),
        "suffixarray: text too long for i16"
    );
    let mut sa = vec![0i16; n];
    let mut tmp = vec![0i16; 2 * TEXT_MAX_8];
    sais_8_16(text, TEXT_MAX_8, &mut sa, &mut tmp);
    sa
}

// ===========================================================================
// sais_8_16 — top level (8-bit text)
// ===========================================================================

/// Go `sais_8_16`.
fn sais_8_16(text: &[u8], text_max: usize, sa: &mut [i16], tmp: &mut [i16]) {
    assert!(
        sa.len() == text.len() && tmp.len() >= text_max,
        "suffixarray: misuse of sais_8_16"
    );

    if text.is_empty() {
        return;
    }
    if text.len() == 1 {
        sa[0] = 0;
        return;
    }

    let have_freq = tmp.len() >= 2 * text_max;
    if have_freq {
        tmp[0] = -1;
    }

    let num_lms = place_lms_8_16(text, sa, text_max, tmp, have_freq);
    if num_lms <= 1 {
        // 0 or 1 items already sorted.
    } else {
        induce_sub_l_8_16(text, sa, text_max, tmp, have_freq);
        induce_sub_s_8_16(text, sa, text_max, tmp, have_freq);
        length_8_16(text, sa, num_lms);
        let max_id = assign_id_8_16(text, sa, num_lms);
        if max_id < num_lms {
            map_16(sa, num_lms);
            recurse_16(sa, tmp, num_lms, max_id);
            unmap_8_16(text, sa, num_lms);
        } else {
            let n = sa.len();
            sa.copy_within(n - num_lms.., 0);
        }
        expand_8_16(text, sa, text_max, tmp, have_freq, num_lms);
    }
    induce_l_8_16(text, sa, text_max, tmp, have_freq);
    induce_s_8_16(text, sa, text_max, tmp, have_freq);

    tmp[0] = -1;
}

// ---------------------------------------------------------------------------
// freq / bucket helpers (8-bit text)
// ---------------------------------------------------------------------------

fn freq_8_16(text: &[u8], text_max: usize, tmp: &mut [i16], have_freq: bool) -> usize {
    if have_freq && tmp[0] >= 0 {
        return 0;
    }
    let off = if have_freq { 0 } else { text_max };
    for i in 0..256 {
        tmp[off + i] = 0;
    }
    for &c in text {
        tmp[off + c as usize] += 1;
    }
    off
}

fn bucket_min_8_16(text: &[u8], text_max: usize, tmp: &mut [i16], have_freq: bool) {
    let foff = freq_8_16(text, text_max, tmp, have_freq);
    let boff = text_max;
    let mut total: i16 = 0;
    for i in 0..256 {
        let n = tmp[foff + i];
        tmp[boff + i] = total;
        total = total.wrapping_add(n);
    }
}

fn bucket_max_8_16(text: &[u8], text_max: usize, tmp: &mut [i16], have_freq: bool) {
    let foff = freq_8_16(text, text_max, tmp, have_freq);
    let boff = text_max;
    let mut total: i16 = 0;
    for i in 0..256 {
        let n = tmp[foff + i];
        total = total.wrapping_add(n);
        tmp[boff + i] = total;
    }
}

// ---------------------------------------------------------------------------
// place_lms / induce / length / assign_id (8-bit text)
// ---------------------------------------------------------------------------

fn place_lms_8_16(
    text: &[u8],
    sa: &mut [i16],
    text_max: usize,
    tmp: &mut [i16],
    have_freq: bool,
) -> usize {
    bucket_max_8_16(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut num_lms = 0usize;
    let mut last_b: i16 = -1;

    let (mut c0, mut c1, mut is_type_s): (u8, u8, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            let b = tmp[boff + c1 as usize] - 1;
            tmp[boff + c1 as usize] = b;
            sa[b as usize] = (i + 1) as i16;
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

fn induce_sub_l_8_16(
    text: &[u8],
    sa: &mut [i16],
    text_max: usize,
    tmp: &mut [i16],
    have_freq: bool,
) {
    bucket_min_8_16(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut k: isize = text.len() as isize - 1;
    let c0 = text[(k - 1) as usize];
    let c1 = text[k as usize];
    if c0 < c1 {
        k = -k;
    }

    let mut c_b = c1;
    let mut b = tmp[boff + c_b as usize];
    sa[b as usize] = k as i16;
    b += 1;

    for i in 0..sa.len() {
        let j = sa[i] as isize;
        if j == 0 {
            continue;
        }
        if j < 0 {
            sa[i] = (-j) as i16;
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
        sa[b as usize] = k2 as i16;
        b += 1;
    }
}

fn induce_sub_s_8_16(
    text: &[u8],
    sa: &mut [i16],
    text_max: usize,
    tmp: &mut [i16],
    have_freq: bool,
) {
    bucket_max_8_16(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut c_b: u8 = 0;
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
            sa[top] = (-j) as i16;
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
        sa[b as usize] = k as i16;
    }
}

/// Go `length_8_16`. The `cx` packing uses `u16` (16/8 = 2-byte threshold).
fn length_8_16(text: &[u8], sa: &mut [i16], _num_lms: usize) {
    let mut end: usize = 0;
    let mut cx: u16 = 0; // byte-only

    let (mut c0, mut c1, mut is_type_s): (u8, u8, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        cx = cx << 8 | (c1.wrapping_add(1)) as u16; // byte-only
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            let j = i + 1;
            let code: i16 = if end == 0 {
                0
            } else {
                let mut code = (end - j) as i16;
                if code <= 16 / 8 && !cx >= text.len() as u16 {
                    code = (!cx) as i16;
                }
                code
            };
            sa[j >> 1] = code;
            end = j + 1;
            cx = (c1.wrapping_add(1)) as u16; // byte-only
        }
        c1 = c0;
    }
}

fn assign_id_8_16(text: &[u8], sa: &mut [i16], num_lms: usize) -> usize {
    let mut id = 0usize;
    let mut last_len: i16 = -1;
    let mut last_pos: i16 = 0;
    let base = sa.len() - num_lms;
    for idx in 0..num_lms {
        let j = sa[base + idx];
        let n = sa[(j / 2) as usize];
        let is_new;
        if n != last_len {
            is_new = true;
        } else if (n as u16) >= text.len() as u16 {
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
        sa[(j / 2) as usize] = id as i16;
    }
    id
}

// ---------------------------------------------------------------------------
// map / recurse (shared via _16)
// ---------------------------------------------------------------------------

fn map_16(sa: &mut [i16], _num_lms: usize) {
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

/// Go `recurse_16`. See [`crate::sais32`]'s `recurse_32` for the borrow-split
/// rationale; identical here with `i16` storage.
fn recurse_16(sa: &mut [i16], old_tmp: &mut [i16], num_lms: usize, max_id: usize) {
    let len = sa.len();
    let text: Vec<i16> = sa[len - num_lms..].to_vec();

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
    let mut tmp = vec![0i16; chosen_len];

    for i in 0..num_lms {
        sa[i] = 0;
    }
    sais_16(&text, max_id, &mut sa[..num_lms], &mut tmp);
}

fn unmap_8_16(text: &[u8], sa: &mut [i16], num_lms: usize) {
    let base = sa.len() - num_lms;
    let mut j = num_lms;

    let (mut c0, mut c1, mut is_type_s): (u8, u8, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            j -= 1;
            sa[base + j] = (i + 1) as i16;
        }
        c1 = c0;
    }

    for i in 0..num_lms {
        let k = sa[i] as usize;
        sa[i] = sa[base + k];
    }
}

fn expand_8_16(
    text: &[u8],
    sa: &mut [i16],
    text_max: usize,
    tmp: &mut [i16],
    have_freq: bool,
    num_lms: usize,
) {
    bucket_max_8_16(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut x = num_lms - 1;
    let mut sa_x = sa[x];
    let mut c = text[sa_x as usize];
    let mut b = tmp[boff + c as usize] - 1;
    tmp[boff + c as usize] = b;

    for i in (0..sa.len()).rev() {
        if i as i16 != b {
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

fn induce_l_8_16(text: &[u8], sa: &mut [i16], text_max: usize, tmp: &mut [i16], have_freq: bool) {
    bucket_min_8_16(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut k: isize = text.len() as isize - 1;
    let c0 = text[(k - 1) as usize];
    let c1 = text[k as usize];
    if c0 < c1 {
        k = -k;
    }

    let mut c_b = c1;
    let mut b = tmp[boff + c_b as usize];
    sa[b as usize] = k as i16;
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
        sa[b as usize] = k2 as i16;
        b += 1;
    }
}

fn induce_s_8_16(text: &[u8], sa: &mut [i16], text_max: usize, tmp: &mut [i16], have_freq: bool) {
    bucket_max_8_16(text, text_max, tmp, have_freq);
    let boff = text_max;

    let mut c_b: u8 = 0;
    let mut b = tmp[boff + c_b as usize];

    for i in (0..sa.len()).rev() {
        let mut j = sa[i] as isize;
        if j >= 0 {
            continue;
        }

        j = -j;
        sa[i] = j as i16;

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
        sa[b as usize] = k as i16;
    }
}

// ===========================================================================
// sais_16 — recursion level (i16 text, i16 SA)
// ===========================================================================

fn sais_16(text: &[i16], text_max: usize, sa: &mut [i16], tmp: &mut [i16]) {
    assert!(
        sa.len() == text.len() && tmp.len() >= text_max,
        "suffixarray: misuse of sais_16"
    );

    if text.is_empty() {
        return;
    }
    if text.len() == 1 {
        sa[0] = 0;
        return;
    }

    let have_freq = tmp.len() >= 2 * text_max;
    if have_freq {
        tmp[0] = -1;
    }

    let num_lms = place_lms_16(text, sa, text_max, tmp, have_freq);
    if num_lms <= 1 {
    } else {
        induce_sub_l_16(text, sa, text_max, tmp, have_freq);
        induce_sub_s_16(text, sa, text_max, tmp, have_freq);
        length_16(text, sa, num_lms);
        let max_id = assign_id_16(text, sa, num_lms);
        if max_id < num_lms {
            map_16(sa, num_lms);
            recurse_16_inner(sa, tmp, num_lms, max_id);
            unmap_16(text, sa, num_lms);
        } else {
            let n = sa.len();
            sa.copy_within(n - num_lms.., 0);
        }
        expand_16(text, sa, text_max, tmp, have_freq, num_lms);
    }
    induce_l_16(text, sa, text_max, tmp, have_freq);
    induce_s_16(text, sa, text_max, tmp, have_freq);

    tmp[0] = -1;
}

fn recurse_16_inner(sa: &mut [i16], old_tmp: &mut [i16], num_lms: usize, max_id: usize) {
    let len = sa.len();
    let text: Vec<i16> = sa[len - num_lms..].to_vec();

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
    let mut tmp = vec![0i16; chosen_len];

    for i in 0..num_lms {
        sa[i] = 0;
    }
    sais_16(&text, max_id, &mut sa[..num_lms], &mut tmp);
}

// ---------------------------------------------------------------------------
// freq / bucket helpers (i16 text)
// ---------------------------------------------------------------------------

/// Go `freq_16`. Frequencies are computed into the freq region — which in Go is
/// `freq = tmp[:textMax]` when `have_freq`, else `freq = bucket = tmp[:textMax]`
/// — i.e. ALWAYS offset 0. Returns that offset (0). When `!have_freq`, freq and
/// bucket alias the same `tmp[:textMax]`, exactly as Go.
fn freq_16(text: &[i16], text_max: usize, tmp: &mut [i16], have_freq: bool) -> usize {
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
fn boff_16(text_max: usize, have_freq: bool) -> usize {
    if have_freq {
        text_max
    } else {
        0
    }
}

fn bucket_min_16(text: &[i16], text_max: usize, tmp: &mut [i16], have_freq: bool) {
    let foff = freq_16(text, text_max, tmp, have_freq);
    let boff = boff_16(text_max, have_freq);
    let mut total: i16 = 0;
    for i in 0..text_max {
        let n = tmp[foff + i];
        tmp[boff + i] = total;
        total = total.wrapping_add(n);
    }
}

fn bucket_max_16(text: &[i16], text_max: usize, tmp: &mut [i16], have_freq: bool) {
    let foff = freq_16(text, text_max, tmp, have_freq);
    let boff = boff_16(text_max, have_freq);
    let mut total: i16 = 0;
    for i in 0..text_max {
        let n = tmp[foff + i];
        total = total.wrapping_add(n);
        tmp[boff + i] = total;
    }
}

// ---------------------------------------------------------------------------
// place_lms / induce / length / assign_id (i16 text)
// ---------------------------------------------------------------------------

fn place_lms_16(
    text: &[i16],
    sa: &mut [i16],
    text_max: usize,
    tmp: &mut [i16],
    have_freq: bool,
) -> usize {
    bucket_max_16(text, text_max, tmp, have_freq);
    let boff = boff_16(text_max, have_freq);

    let mut num_lms = 0usize;
    let mut last_b: i16 = -1;

    let (mut c0, mut c1, mut is_type_s): (i16, i16, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            let b = tmp[boff + c1 as usize] - 1;
            tmp[boff + c1 as usize] = b;
            sa[b as usize] = (i + 1) as i16;
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

fn induce_sub_l_16(
    text: &[i16],
    sa: &mut [i16],
    text_max: usize,
    tmp: &mut [i16],
    have_freq: bool,
) {
    bucket_min_16(text, text_max, tmp, have_freq);
    let boff = boff_16(text_max, have_freq);

    let mut k: isize = text.len() as isize - 1;
    let c0 = text[(k - 1) as usize];
    let c1 = text[k as usize];
    if c0 < c1 {
        k = -k;
    }

    let mut c_b = c1;
    let mut b = tmp[boff + c_b as usize];
    sa[b as usize] = k as i16;
    b += 1;

    for i in 0..sa.len() {
        let j = sa[i] as isize;
        if j == 0 {
            continue;
        }
        if j < 0 {
            sa[i] = (-j) as i16;
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
        sa[b as usize] = k2 as i16;
        b += 1;
    }
}

fn induce_sub_s_16(
    text: &[i16],
    sa: &mut [i16],
    text_max: usize,
    tmp: &mut [i16],
    have_freq: bool,
) {
    bucket_max_16(text, text_max, tmp, have_freq);
    let boff = boff_16(text_max, have_freq);

    let mut c_b: i16 = 0;
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
            sa[top] = (-j) as i16;
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
        sa[b as usize] = k as i16;
    }
}

/// Go `length_16`. The `_16` (non-byte) family omits the `cx` packing.
fn length_16(text: &[i16], sa: &mut [i16], _num_lms: usize) {
    let mut end: usize = 0;

    let (mut c0, mut c1, mut is_type_s): (i16, i16, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            let j = i + 1;
            let code: i16 = if end == 0 { 0 } else { (end - j) as i16 };
            sa[j >> 1] = code;
            end = j + 1;
        }
        c1 = c0;
    }
}

fn assign_id_16(text: &[i16], sa: &mut [i16], num_lms: usize) -> usize {
    let mut id = 0usize;
    let mut last_len: i16 = -1;
    let mut last_pos: i16 = 0;
    let base = sa.len() - num_lms;
    for idx in 0..num_lms {
        let j = sa[base + idx];
        let n = sa[(j / 2) as usize];
        let is_new;
        if n != last_len {
            is_new = true;
        } else if (n as u16) >= text.len() as u16 {
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
        sa[(j / 2) as usize] = id as i16;
    }
    id
}

fn unmap_16(text: &[i16], sa: &mut [i16], num_lms: usize) {
    let base = sa.len() - num_lms;
    let mut j = num_lms;

    let (mut c0, mut c1, mut is_type_s): (i16, i16, bool) = (0, 0, false);
    for i in (0..text.len()).rev() {
        c0 = text[i];
        if c0 < c1 {
            is_type_s = true;
        } else if c0 > c1 && is_type_s {
            is_type_s = false;
            j -= 1;
            sa[base + j] = (i + 1) as i16;
        }
        c1 = c0;
    }

    for i in 0..num_lms {
        let k = sa[i] as usize;
        sa[i] = sa[base + k];
    }
}

fn expand_16(
    text: &[i16],
    sa: &mut [i16],
    text_max: usize,
    tmp: &mut [i16],
    have_freq: bool,
    num_lms: usize,
) {
    bucket_max_16(text, text_max, tmp, have_freq);
    let boff = boff_16(text_max, have_freq);

    let mut x = num_lms - 1;
    let mut sa_x = sa[x];
    let mut c = text[sa_x as usize];
    let mut b = tmp[boff + c as usize] - 1;
    tmp[boff + c as usize] = b;

    for i in (0..sa.len()).rev() {
        if i as i16 != b {
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

fn induce_l_16(text: &[i16], sa: &mut [i16], text_max: usize, tmp: &mut [i16], have_freq: bool) {
    bucket_min_16(text, text_max, tmp, have_freq);
    let boff = boff_16(text_max, have_freq);

    let mut k: isize = text.len() as isize - 1;
    let c0 = text[(k - 1) as usize];
    let c1 = text[k as usize];
    if c0 < c1 {
        k = -k;
    }

    let mut c_b = c1;
    let mut b = tmp[boff + c_b as usize];
    sa[b as usize] = k as i16;
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
        sa[b as usize] = k2 as i16;
        b += 1;
    }
}

fn induce_s_16(text: &[i16], sa: &mut [i16], text_max: usize, tmp: &mut [i16], have_freq: bool) {
    bucket_max_16(text, text_max, tmp, have_freq);
    let boff = boff_16(text_max, have_freq);

    let mut c_b: i16 = 0;
    let mut b = tmp[boff + c_b as usize];

    for i in (0..sa.len()).rev() {
        let mut j = sa[i] as isize;
        if j >= 0 {
            continue;
        }

        j = -j;
        sa[i] = j as i16;

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
        sa[b as usize] = k as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suffixarray::suffix_array as reference_sa;

    fn check(text: &[u8]) {
        let got = suffix_array(text);
        let want: Vec<i16> = reference_sa(text).iter().map(|&v| v as i16).collect();
        assert_eq!(got, want, "POW16 SA mismatch for len {}", text.len());
    }

    #[test]
    fn edge_and_patterns() {
        check(b"");
        check(b"a");
        check(b"ab");
        check(b"banana");
        check(b"mississippi");
        let alt: Vec<u8> = (0..512).map(|i| if i % 2 == 0 { 1 } else { 2 }).collect();
        check(&alt);
        check(&vec![5u8; 257]);
    }
}
