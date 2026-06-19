//! Suffix-array stage (≈85% of per-hash cost). FFI to the v1.14 "descriptor" SA
//! (default, ~2× faster on Wolf-permuted data) with a libsais fallback. Both are
//! byte-identical — the descriptor path just exploits wolfCompute's repeat structure.
//!
//! C ABI (vendor/v114/v114_wrapper.cpp, vendor/libsais/libsais.h):
//!   int v114_sa_build_fused(const u8* data, u32 logical_len, u32 data_len_with_tail,
//!                           const u8* flags, u32 flag_len,
//!                           u8* out, size_t out_cap, size_t* out_len);  // 1=ok, 0=fallback
//!   int32 libsais(const u8* T, i32* SA, i32 n, i32 fs, i32* freq);      // 0=ok
use std::os::raw::c_int;

extern "C" {
    fn libsais(t: *const u8, sa: *mut i32, n: i32, fs: i32, freq: *mut i32) -> c_int;
    fn v114_sa_build_fused(
        data: *const u8,
        logical_len: u32,
        data_len_with_tail: u32,
        flags: *const u8,
        flag_len: u32,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> c_int;
}

/// Port of build_v114_stage5_flags (sa_v114.zig:28). Writes group-boundary flags,
/// returns the count (0 on failure). `flags` must hold ≥ (logical_len>>8)+1 bytes.
pub fn build_stage5_flags(markers: &[u16], n_templates: u32, logical_len: u32, flags: &mut [u8]) -> u32 {
    if logical_len == 0 {
        return 0;
    }
    let flags_len = (logical_len >> 8) + 1;
    if (flags.len() as u32) < flags_len {
        return 0;
    }
    for f in &mut flags[..flags_len as usize] {
        *f = 0;
    }
    flags[0] = 1;
    let limit = n_templates.min(277) as usize;
    for &m in &markers[..limit.min(markers.len())] {
        let pos_data = m as u32;
        let start_group = pos_data >> 7;
        let group_count = pos_data & 0x7f;
        let boundary = start_group + group_count;
        if group_count != 0 && boundary > 0 && boundary < flags_len {
            flags[boundary as usize] = 1;
        }
    }
    flags_len
}

/// Build the suffix array of `data[0..logical_len]` into `sa` (libsais i32 layout).
/// Tries the v114 descriptor path first; falls back to libsais. `data` must have at
/// least `logical_len + 16` readable bytes (the descriptor SA reads a small tail).
pub fn build_sa(data: &[u8], logical_len: u32, markers: &[u16], n_templates: u32, sa: &mut [i32]) {
    let n = logical_len as usize;
    debug_assert!(sa.len() >= n);
    debug_assert!(data.len() >= n + 16);

    let mut flags = [0u8; 320];
    let flag_len = build_stage5_flags(markers, n_templates, logical_len, &mut flags);
    if flag_len != 0 {
        let cap = n * 4;
        let mut out_len = 0usize;
        let rc = unsafe {
            v114_sa_build_fused(
                data.as_ptr(),
                logical_len,
                logical_len + 3,
                flags.as_ptr(),
                flag_len,
                sa.as_mut_ptr() as *mut u8,
                cap,
                &mut out_len,
            )
        };
        if rc == 1 && out_len == cap {
            return;
        }
    }
    libsais_sa(&data[..n], &mut sa[..n]);
}

/// Direct libsais (the exact fallback / oracle path).
pub fn libsais_sa(data: &[u8], sa: &mut [i32]) {
    let rc = unsafe { libsais(data.as_ptr(), sa.as_mut_ptr(), data.len() as i32, 0, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "libsais failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn libsais_banana() {
        let mut sa = [0i32; 6];
        libsais_sa(b"banana", &mut sa);
        assert_eq!(sa, [5, 3, 1, 0, 4, 2]);
    }
}
