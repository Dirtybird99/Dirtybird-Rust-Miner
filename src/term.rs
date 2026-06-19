//! Terminal helpers: a `DD/MM HH:MM:SS.mmm  INFO` logger and ANSI colors for the live
//! status line, matching the C "DIRTYBIRD" miner's display. On Windows we enable virtual
//! terminal processing so the escape codes render in cmd.exe too.
use std::io::Write;

// ANSI SGR codes (mirror the C miner's setcolor table: `\e[<bold>;<fg>m`).
pub const BRIGHT_YELLOW: &str = "\x1b[1;33m";
pub const BRIGHT_GREEN: &str = "\x1b[1;32m";
pub const GREEN: &str = "\x1b[0;32m";
pub const BLUE: &str = "\x1b[0;34m";
pub const BRIGHT_BLUE: &str = "\x1b[1;34m";
pub const MAGENTA: &str = "\x1b[0;35m";
pub const BRIGHT_RED: &str = "\x1b[1;31m";
pub const WHITE: &str = "\x1b[0;37m";
pub const BRIGHT_WHITE: &str = "\x1b[1;37m";
pub const RESET: &str = "\x1b[0m";

/// Enable ANSI escape handling on the Windows console (no-op elsewhere). Idempotent.
#[cfg(windows)]
pub fn enable_vt() {
    extern "system" {
        fn GetStdHandle(which: u32) -> isize;
        fn GetConsoleMode(h: isize, mode: *mut u32) -> i32;
        fn SetConsoleMode(h: isize, mode: u32) -> i32;
    }
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // (DWORD)-11
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) != 0 {
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}
#[cfg(not(windows))]
pub fn enable_vt() {}

/// `DD/MM HH:MM:SS.mmm` in local time (matches the C miner's getTimestamp()).
pub fn timestamp() -> String {
    chrono::Local::now().format("%d/%m %H:%M:%S%.3f").to_string()
}

/// `DD/MM HH:MM:SS.mmm  INFO  <msg>`. The leading `\r\x1b[K` wipes any in-place status
/// line so the log lands cleanly on its own row.
pub fn log_info(msg: &str) {
    print!("\r\x1b[K");
    println!("{}  INFO  {}", timestamp(), msg);
    let _ = std::io::stdout().flush();
}

/// `…INFO  <label>:   <value>` with the label (incl. colon) left-padded to 8 (C's `%-8s`).
pub fn log_info_pair(label: &str, value: &str) {
    let lbl = format!("{label}:");
    print!("\r\x1b[K");
    println!("{}  INFO  {:<8} {}", timestamp(), lbl, value);
    let _ = std::io::stdout().flush();
}

/// Humanize a difficulty: `20000 -> "20K"`, `5_000_000 -> "5M"` (integer division, the C thresholds).
pub fn abbrev(d: u64) -> String {
    if d >= 1_000_000_000 {
        format!("{}G", d / 1_000_000_000)
    } else if d >= 1_000_000 {
        format!("{}M", d / 1_000_000)
    } else if d >= 1_000 {
        format!("{}K", d / 1_000)
    } else {
        d.to_string()
    }
}
