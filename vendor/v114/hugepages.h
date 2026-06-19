/*
 * hugepages.h -- memory allocation with huge page support
 *
 * Try huge pages first (2 MB on Linux, system-configured on Windows).
 * Fall back to malloc + VirtualLock/mlock to pin pages in RAM.
 * DeroLuna uses VirtualLock -- zero page faults after startup.
 */
#pragma once
#include <cstddef>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>

static inline bool enable_huge_page_privilege(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME,
                              &tp.Privileges[0].Luid)) {
        CloseHandle(tok);
        return false;
    }
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(tok);
    return err == ERROR_SUCCESS;
}

static inline void *alloc_huge(size_t size) {
    SIZE_T hp = GetLargePageMinimum();
    if (!hp) return NULL;
    size = (size + hp - 1) & ~(hp - 1);
    return VirtualAlloc(NULL, size,
                        MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                        PAGE_READWRITE);
}

static inline void free_huge(void *p) {
    if (p) VirtualFree(p, 0, MEM_RELEASE);
}

#else /* POSIX */
#include <sys/mman.h>

static inline bool enable_huge_page_privilege(void) { return true; }

static inline void *alloc_huge(size_t size) {
    size = (size + (2<<20) - 1) & ~((2<<20) - 1);
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

static inline void free_huge(void *p) {
    if (p) munmap(p, 0);
}
#endif

/*
 * alloc_pinned -- the allocation strategy:
 *   1. Try huge pages (eliminates TLB misses, 2MB pages)
 *   2. Fall back to malloc + pin (VirtualLock/mlock)
 */
static inline void *alloc_pinned(size_t size, bool *huge) {
    void *p = alloc_huge(size);
    if (p) { *huge = true; return p; }

    *huge = false;
    p = std::malloc(size);
    if (p) {
#ifdef _WIN32
        VirtualLock(p, size);
#else
        mlock(p, size);
#endif
    }
    return p;
}

static inline void free_pinned(void *p, size_t size, bool huge) {
    if (!p) return;
    if (huge) { free_huge(p); return; }
#ifdef _WIN32
    VirtualUnlock(p, size);
#else
    munlock(p, size);
#endif
    std::free(p);
}
