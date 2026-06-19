//! Platform helpers: P-core-first affinity ordering + HIGH priority / power-throttle-off
//! (the Zig log's +12% sustained-clock setup).

/// i7-13700HX logical-id order: 8 distinct P-cores, then E-cores, then HT siblings.
/// For n=10 this is `[0,2,4,6,8,10,12,14,16,17]` — exactly Zig's `AFF_MAPS[0]`.
pub fn affinity_order(n: usize) -> Vec<usize> {
    let pcores = [0usize, 2, 4, 6, 8, 10, 12, 14];
    let ecores = [16usize, 17, 18, 19, 20, 21, 22, 23];
    let ht = [1usize, 3, 5, 7, 9, 11, 13, 15];
    let mut order: Vec<usize> = pcores.iter().chain(&ecores).chain(&ht).copied().collect();
    if order.is_empty() {
        order.push(0);
    }
    let mut i = 0;
    while order.len() < n {
        order.push(order[i % order.len()]);
        i += 1;
    }
    order.truncate(n.max(1));
    order
}

/// Pin the current thread to a logical core and set max performance (highest priority +
/// power throttling disabled).
pub fn pin_and_boost(core: usize) {
    let ids = core_affinity::get_core_ids().unwrap_or_default();
    if let Some(id) = ids.iter().find(|c| c.id == core).copied() {
        core_affinity::set_for_current(id);
    }
    #[cfg(windows)]
    win::thread_max_perf();
}

pub fn process_high_priority() {
    #[cfg(windows)]
    win::process_high_priority();
}

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetCurrentThread() -> isize;
        fn SetPriorityClass(h: isize, class: u32) -> i32;
        fn SetThreadPriority(h: isize, prio: i32) -> i32;
        fn SetThreadInformation(h: isize, class: i32, info: *const c_void, size: u32) -> i32;
    }
    const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
    const THREAD_PRIORITY_HIGHEST: i32 = 2;
    const THREAD_POWER_THROTTLING: i32 = 4;

    #[repr(C)]
    struct PowerThrottlingState {
        version: u32,
        control_mask: u32,
        state_mask: u32,
    }

    pub fn process_high_priority() {
        unsafe {
            SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        }
    }

    pub fn thread_max_perf() {
        unsafe {
            let t = GetCurrentThread();
            SetThreadPriority(t, THREAD_PRIORITY_HIGHEST);
            let st = PowerThrottlingState { version: 1, control_mask: 1, state_mask: 0 };
            SetThreadInformation(
                t,
                THREAD_POWER_THROTTLING,
                &st as *const _ as *const c_void,
                std::mem::size_of::<PowerThrottlingState>() as u32,
            );
        }
    }
}
