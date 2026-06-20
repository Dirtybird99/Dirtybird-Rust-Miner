//! Large-page (2 MB) backed buffers for the bandwidth/TLB-bound AstroBWTv3 hot
//! path. The descriptor suffix array makes large strided accesses over the
//! ~70 KB op-loop `data` buffer (and, in the materialized path, the ~280 KB SA);
//! with 4 KB pages these blow the dTLB. Mapping them into 2 MB large pages gives
//! the whole working set a single TLB entry, which is the lever that breaks the
//! 24-thread saturation tie against a miner that can't do this (the C miner runs
//! 4 KB pages on Windows).
//!
//! Ported from the Zig miner's `system.zig` (enableLockMemoryPrivilege +
//! allocLargePages): enable `SeLockMemoryPrivilege` once at startup, then
//! `VirtualAlloc(MEM_LARGE_PAGES)`; gracefully fall back to the heap when the
//! privilege isn't held or contiguous physical memory is unavailable, with the
//! hash bytes unchanged either way.

use std::sync::atomic::{AtomicU8, Ordering};

/// 0 = unknown, 1 = enabled, 2 = unavailable.
static LARGE_PAGES_STATE: AtomicU8 = AtomicU8::new(0);

/// Enable `SeLockMemoryPrivilege` for this process (idempotent). Returns true if
/// large pages are usable. Call once at startup before allocating scratch.
pub fn enable_large_pages() -> bool {
    match LARGE_PAGES_STATE.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let ok = imp::enable();
    LARGE_PAGES_STATE.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    ok
}

/// True iff [`enable_large_pages`] has succeeded this process.
pub fn large_pages_enabled() -> bool {
    LARGE_PAGES_STATE.load(Ordering::Relaxed) == 1
}

/// A growable, large-page-backed buffer of `Copy` scalars with a heap fallback.
/// Exposes the subset of the `Vec` API the hot path needs.
pub struct LpVec<T: Copy> {
    ptr: *mut T,
    len: usize,
    cap: usize,
    kind: Kind,
}

enum Kind {
    /// VirtualAlloc'd large pages; free with VirtualFree(MEM_RELEASE).
    Large,
    /// Heap fallback: `ptr`/`cap` came from a leaked `Vec<T>`.
    Heap,
}

// SAFETY: LpVec owns its allocation exclusively; the raw pointer is just an
// owned heap/VirtualAlloc region. Send/Sync parity with Vec<T> for Copy T.
unsafe impl<T: Copy + Send> Send for LpVec<T> {}
unsafe impl<T: Copy + Sync> Sync for LpVec<T> {}

impl<T: Copy> LpVec<T> {
    /// Allocate with `cap` elements of headroom. Tries large pages first (when
    /// [`enable_large_pages`] succeeded) and falls back to the heap.
    pub fn with_capacity(cap: usize) -> Self {
        let bytes = cap.saturating_mul(std::mem::size_of::<T>()).max(1);
        if large_pages_enabled() {
            if let Some((ptr, real_bytes)) = imp::alloc_large(bytes) {
                return LpVec {
                    ptr: ptr as *mut T,
                    len: 0,
                    cap: real_bytes / std::mem::size_of::<T>().max(1),
                    kind: Kind::Large,
                };
            }
        }
        Self::heap(cap)
    }

    fn heap(cap: usize) -> Self {
        let mut v: Vec<T> = Vec::with_capacity(cap.max(1));
        let ptr = v.as_mut_ptr();
        let real_cap = v.capacity();
        std::mem::forget(v);
        LpVec {
            ptr,
            len: 0,
            cap: real_cap,
            kind: Kind::Heap,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: ptr..ptr+len is initialized and owned.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as above; exclusive borrow.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Ensure capacity for at least `needed` elements, growing (and migrating off
    /// large pages to the heap) if the fixed large-page block is exceeded. The
    /// hot path sizes capacity above the algorithm's hard max so this never runs
    /// in practice; it exists purely so the buffer is never unsound.
    #[cold]
    fn grow_to(&mut self, needed: usize) {
        let new_cap = needed.max(self.cap.saturating_mul(2)).max(8);
        let mut v: Vec<T> = Vec::with_capacity(new_cap);
        // SAFETY: copy the live prefix into the new allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr, v.as_mut_ptr(), self.len);
            v.set_len(self.len);
        }
        let new_ptr = v.as_mut_ptr();
        let real_cap = v.capacity();
        std::mem::forget(v);
        self.free();
        self.ptr = new_ptr;
        self.cap = real_cap;
        self.kind = Kind::Heap;
    }

    #[inline]
    pub fn extend_from_slice(&mut self, src: &[T]) {
        let new_len = self.len + src.len();
        if new_len > self.cap {
            self.grow_to(new_len);
        }
        // SAFETY: capacity now covers new_len; src and dst don't overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.add(self.len), src.len());
        }
        self.len = new_len;
    }

    /// Resize to `new_len`, filling any new tail with `value`.
    #[inline]
    pub fn resize(&mut self, new_len: usize, value: T) {
        if new_len > self.cap {
            self.grow_to(new_len);
        }
        if new_len > self.len {
            // SAFETY: [len, new_len) is within capacity.
            unsafe {
                let mut p = self.ptr.add(self.len);
                for _ in self.len..new_len {
                    p.write(value);
                    p = p.add(1);
                }
            }
        }
        self.len = new_len;
    }

    fn free(&mut self) {
        match self.kind {
            Kind::Large => imp::free_large(self.ptr as *mut u8),
            Kind::Heap => {
                // SAFETY: reconstruct the leaked Vec to drop the allocation.
                unsafe {
                    drop(Vec::from_raw_parts(self.ptr, 0, self.cap));
                }
            }
        }
        self.ptr = std::ptr::NonNull::dangling().as_ptr();
        self.cap = 0;
        self.len = 0;
    }
}

impl<T: Copy> Drop for LpVec<T> {
    fn drop(&mut self) {
        self.free();
    }
}

impl<T: Copy> std::ops::Deref for LpVec<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}
impl<T: Copy> std::ops::DerefMut for LpVec<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

// ===========================================================================
// Platform implementation
// ===========================================================================

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    type Dword = u32;
    type Bool = i32;
    type Handle = *mut c_void;

    const TOKEN_ADJUST_PRIVILEGES: Dword = 0x0020;
    const TOKEN_QUERY: Dword = 0x0008;
    const SE_PRIVILEGE_ENABLED: Dword = 0x0002;
    const MEM_RESERVE: Dword = 0x2000;
    const MEM_COMMIT: Dword = 0x1000;
    const MEM_LARGE_PAGES: Dword = 0x2000_0000;
    const MEM_RELEASE: Dword = 0x8000;
    const PAGE_READWRITE: Dword = 0x04;

    #[repr(C)]
    struct Luid {
        low: Dword,
        high: i32,
    }
    #[repr(C)]
    struct LuidAndAttributes {
        luid: Luid,
        attributes: Dword,
    }
    #[repr(C)]
    struct TokenPrivileges {
        count: Dword,
        privilege: [LuidAndAttributes; 1],
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: Dword, token: *mut Handle) -> Bool;
        fn LookupPrivilegeValueA(system: *const u8, name: *const u8, luid: *mut Luid) -> Bool;
        fn AdjustTokenPrivileges(
            token: Handle,
            disable_all: Bool,
            new: *const TokenPrivileges,
            len: Dword,
            prev: *mut c_void,
            ret_len: *mut Dword,
        ) -> Bool;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(h: Handle) -> Bool;
        fn GetLastError() -> Dword;
        fn GetLargePageMinimum() -> usize;
        fn VirtualAlloc(addr: *mut c_void, size: usize, typ: Dword, protect: Dword) -> *mut c_void;
        fn VirtualFree(addr: *mut c_void, size: usize, typ: Dword) -> Bool;
    }

    pub fn enable() -> bool {
        if GetLargePageMinimumSafe() == 0 {
            return false;
        }
        unsafe {
            let mut token: Handle = std::ptr::null_mut();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            ) == 0
            {
                return false;
            }
            let mut luid = Luid { low: 0, high: 0 };
            // "SeLockMemoryPrivilege\0"
            let name = b"SeLockMemoryPrivilege\0";
            if LookupPrivilegeValueA(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
                CloseHandle(token);
                return false;
            }
            let tp = TokenPrivileges {
                count: 1,
                privilege: [LuidAndAttributes {
                    luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(
                token,
                0,
                &tp,
                std::mem::size_of::<TokenPrivileges>() as Dword,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            // AdjustTokenPrivileges returns TRUE even on ERROR_NOT_ALL_ASSIGNED
            // (1300); the privilege is only really granted if GetLastError()==0.
            let granted = GetLastError() == 0;
            CloseHandle(token);
            granted
        }
    }

    fn GetLargePageMinimumSafe() -> usize {
        unsafe { GetLargePageMinimum() }
    }

    pub fn alloc_large(bytes: usize) -> Option<(*mut u8, usize)> {
        let page_min = GetLargePageMinimumSafe();
        if page_min == 0 {
            return None;
        }
        let rounded = (bytes + page_min - 1) / page_min * page_min;
        let p = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                rounded,
                MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                PAGE_READWRITE,
            )
        };
        if p.is_null() {
            None
        } else {
            Some((p as *mut u8, rounded))
        }
    }

    pub fn free_large(ptr: *mut u8) {
        if !ptr.is_null() {
            unsafe {
                VirtualFree(ptr as *mut c_void, 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn enable() -> bool {
        false
    }
    pub fn alloc_large(_bytes: usize) -> Option<(*mut u8, usize)> {
        None
    }
    pub fn free_large(_ptr: *mut u8) {}
}
