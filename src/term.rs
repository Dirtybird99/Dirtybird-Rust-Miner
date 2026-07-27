//! Console primitives: colour palette, VT setup, column-counting line buffer,
//! terminal width, and timestamped logging.
//!
//! This module owns the *primitives*; the status-line layouts live in `main.rs`
//! because they read `Shared`. Everything here writes to **stderr** — stdout is
//! reserved for the interactive command loop and the offline bench harnesses,
//! so a status line redrawn in place there would race the REPL's echo.
//!
//! Ported from the sibling C miner's `console.cpp` (per-field colours, the
//! column-counting writer, the width policy, and the log-record shape), so the
//! two miners read as the same tool side by side.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write as _};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

/// Per-field SGR codes, identical across every layout so the line still reads
/// as the same miner when it shrinks (`console.cpp:126-140`).
///
/// Held as `&'static str` rather than generated per tick: at 1 Hz the cost is
/// irrelevant, but a palette that can be swapped for [`Palette::PLAIN`] is what
/// makes "colour off" mean *byte-identical to the uncoloured formatter* instead
/// of "mostly the same". Several tests depend on exactly that.
pub struct Palette {
    pub label: &'static str,
    pub rate: &'static str,
    pub text: &'static str,
    pub avg: &'static str,
    pub height: &'static str,
    pub mini: &'static str,
    pub block: &'static str,
    pub diff: &'static str,
    pub time: &'static str,
    rej_ok: &'static str,
    rej_hi: &'static str,
    pub reset: &'static str,
}

impl Palette {
    /// Every field empty, so `esc()` appends nothing and the rendered bytes
    /// equal the rendered columns. This is what non-TTY output and the unit
    /// tests use.
    pub const PLAIN: Palette = Palette {
        label: "",
        rate: "",
        text: "",
        avg: "",
        height: "",
        mini: "",
        block: "",
        diff: "",
        time: "",
        rej_ok: "",
        rej_hi: "",
        reset: "",
    };

    /// `console.cpp:128-139`, field for field.
    pub const COLOUR: Palette = Palette {
        label: "\x1b[93m",  // [DIRTYBIRD] / [DB]   bright yellow
        rate: "\x1b[92m",   // instantaneous KH/s   bright green
        text: "\x1b[97m",   // separators           bright white
        avg: "\x1b[32m",    // average KH/s         green
        height: "\x1b[34m", // Height               blue
        mini: "\x1b[36m",   // Miniblocks           cyan
        block: "\x1b[32m",  // Blocks               green
        diff: "\x1b[35m",   // Diff                 magenta
        time: "\x1b[37m",   // uptime               white
        rej_ok: "\x1b[37m", // REJ == 0             white
        rej_hi: "\x1b[91m", // REJ  > 0             bright red
        reset: "\x1b[0m",
    };

    /// Rejections turn red the moment there are any — the one field whose
    /// colour carries information rather than just structure.
    pub fn rej(&self, rejected: u64) -> &'static str {
        if rejected > 0 {
            self.rej_hi
        } else {
            self.rej_ok
        }
    }

    /// Pure resolution rule, split out so it is testable without touching the
    /// process environment (env-var tests race under cargo's test threads).
    pub fn resolve(vt: bool, no_color: bool) -> &'static Palette {
        if vt && !no_color {
            &Palette::COLOUR
        } else {
            &Palette::PLAIN
        }
    }
}

// ---------------------------------------------------------------------------
// Console state
// ---------------------------------------------------------------------------

pub struct Console {
    /// stderr is an interactive terminal.
    pub tty: bool,
    /// ANSI cursor control (`\x1b[K`) is usable. Separate from colour on
    /// purpose: NO_COLOR suppresses *colour*, but a NO_COLOR user still wants
    /// the status line repainted in place rather than scrolling forever.
    pub vt: bool,
    pub palette: &'static Palette,
}

static CONSOLE: OnceLock<Console> = OnceLock::new();

/// Resolve console capabilities once. Call first thing in `main()`, before any
/// output — including argument-validation errors — mirroring the C miner's
/// `dluna_console_init()`.
pub fn init() -> &'static Console {
    get()
}

pub fn get() -> &'static Console {
    CONSOLE.get_or_init(|| {
        let tty = io::stderr().is_terminal();
        let vt = tty && enable_vt();
        // The spec is explicit that any NON-EMPTY value disables colour, so
        // `NO_COLOR=` must not.
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Console {
            tty,
            vt,
            palette: Palette::resolve(vt, no_color),
        }
    })
}

/// Turn on ANSI processing for stderr.
///
/// Without this, legacy conhost prints `←[93m` as literal text rather than
/// colouring anything — so on Windows the return value gates colour entirely.
/// Returns false when stderr is redirected or the console is too old, which is
/// exactly when we want to fall back to plain output.
#[cfg(windows)]
fn enable_vt() -> bool {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_ERROR_HANDLE,
    };
    // SAFETY: the standard error handle is borrowed for two calls that do not
    // retain it, and `mode` is initialised writable storage.
    unsafe {
        let h = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode: u32 = 0;
        if GetConsoleMode(h, &mut mode) == 0 {
            return false; // redirected, or not a console at all
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

/// POSIX terminals understand the handful of sequences used here
/// (`console.cpp:61` reasons the same way).
#[cfg(unix)]
fn enable_vt() -> bool {
    true
}

#[cfg(not(any(unix, windows)))]
fn enable_vt() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Column-counting line buffer
// ---------------------------------------------------------------------------

/// Append-only writer that tracks **columns**, not bytes.
///
/// This is the piece that makes colour safe. Layout selection compares a
/// rendered line against the terminal width, and SGR escapes occupy zero
/// columns but plenty of bytes — a 50-column coloured status line is ~117
/// bytes. Selecting on byte length would fail every layout and collapse to the
/// narrowest one on *every* terminal, so adding colour without this would be a
/// visible regression rather than a cosmetic change. `console.cpp:145-185`.
pub struct LineBuf {
    pub text: String,
    pub width: usize,
}

impl Default for LineBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl LineBuf {
    pub fn new() -> Self {
        LineBuf {
            text: String::with_capacity(192),
            width: 0,
        }
    }

    /// Append bytes that occupy no columns: SGR codes, `\r`, erase-to-EOL.
    pub fn esc(&mut self, seq: &str) {
        self.text.push_str(seq);
    }

    /// Append printable text. Every layout here is pure ASCII, so bytes and
    /// columns coincide for the printable part.
    pub fn txt(&mut self, args: std::fmt::Arguments<'_>) {
        let before = self.text.len();
        let _ = self.text.write_fmt(args);
        self.width += self.text.len() - before;
    }

    /// Truncate to a column budget.
    ///
    /// Only ever called on a PLAIN render: cutting a coloured line can land
    /// mid-escape, which wedges the terminal's colour state and prints the
    /// escape's tail as text. The C miner solves that with a 32-line
    /// escape-aware compactor (`console.cpp:270-310`); rendering the fallback
    /// uncoloured achieves the same safety in three lines, and a terminal too
    /// narrow for the smallest layout has bigger problems than colour.
    pub fn truncate_visible(&mut self, budget: usize) {
        if self.width > budget {
            self.text.truncate(budget);
            self.width = budget;
        }
    }
}

/// `lb.txt(format_args!(..))` without the ceremony.
#[macro_export]
macro_rules! txt {
    ($lb:expr, $($arg:tt)*) => { $lb.txt(format_args!($($arg)*)) };
}

// ---------------------------------------------------------------------------
// Terminal width
// ---------------------------------------------------------------------------

/// Visible width of the stderr console in columns, or `None` when stderr is not
/// a console at all. Queried fresh every tick (one cheap syscall per second on
/// a cold path), which is how a resize is picked up without a SIGWINCH handler.
#[cfg(unix)]
pub fn columns() -> Option<usize> {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `size` is initialised writable storage of the type TIOCGWINSZ
    // expects, and the fd is borrowed only for the call.
    if unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_col > 0
    {
        Some(size.ws_col.into())
    } else {
        None
    }
}

#[cfg(windows)]
pub fn columns() -> Option<usize> {
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_ERROR_HANDLE,
    };
    // SAFETY: `info` is initialised writable storage; the handle is borrowed.
    unsafe {
        let h = GetStdHandle(STD_ERROR_HANDLE);
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(h, &mut info) == 0 {
            return None;
        }
        // conhost wraps at the screen BUFFER width while only the window is on
        // screen; the smaller of the two keeps the line both unwrapped and
        // fully visible (`console.cpp:99-101`).
        let window = i32::from(info.srWindow.Right - info.srWindow.Left) + 1;
        let buffer = i32::from(info.dwSize.X);
        let cols = window.min(buffer);
        if cols > 0 {
            Some(cols as usize)
        } else {
            None
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub fn columns() -> Option<usize> {
    None
}

// ---------------------------------------------------------------------------
// Wall-clock time
// ---------------------------------------------------------------------------

/// Broken-down local civil time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
}

/// Days-from-epoch to civil date (Howard Hinnant's algorithm).
///
/// `div_euclid`/`rem_euclid` rather than `/` and `%` so pre-epoch instants
/// floor correctly instead of truncating toward zero. Used directly on targets
/// without a platform local-time call, and as the fallback when one fails.
pub fn civil_from_epoch(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);

    let z = days + 719_468; // shift the epoch to 0000-03-01
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (mp + if mp < 10 { 3 } else { -9 }) as u32; // [1, 12]
    let y = (yoe + era * 400 + i64::from(m <= 2)) as i32;

    Civil {
        year: y,
        month: m,
        day: d,
        hour: (rem / 3600) as u32,
        min: (rem % 3600 / 60) as u32,
        sec: (rem % 60) as u32,
    }
}

/// Current local time plus milliseconds.
///
/// Local rather than UTC because the whole point is sitting next to the C
/// miner's output on one screen; a UTC line would read hours apart from it.
/// Timezone resolution is the platform's: bionic reads `persist.sys.timezone`,
/// glibc/musl read `TZ` and `/etc/localtime`. Note the generic musl arm64
/// artifact run *on Android* (which the README tells people not to do) has
/// neither, and would print UTC while formatting it as local.
#[cfg(unix)]
pub fn now_local() -> (Civil, u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let ms = now.subsec_millis();

    let t = secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `localtime_r` is the thread-safe variant and writes only into
    // `tm`, which is initialised storage of the right type.
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if !ok {
        return (civil_from_epoch(secs), ms);
    }
    (
        Civil {
            year: tm.tm_year + 1900,
            month: (tm.tm_mon + 1) as u32,
            day: tm.tm_mday as u32,
            hour: tm.tm_hour as u32,
            min: tm.tm_min as u32,
            sec: tm.tm_sec as u32,
        },
        ms,
    )
}

#[cfg(windows)]
pub fn now_local() -> (Civil, u32) {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: `st` is initialised writable storage of the expected type.
    unsafe {
        let mut st = std::mem::zeroed::<windows_sys::Win32::Foundation::SYSTEMTIME>();
        GetLocalTime(&mut st);
        (
            Civil {
                year: i32::from(st.wYear),
                month: u32::from(st.wMonth),
                day: u32::from(st.wDay),
                hour: u32::from(st.wHour),
                min: u32::from(st.wMinute),
                sec: u32::from(st.wSecond),
            },
            u32::from(st.wMilliseconds),
        )
    }
}

#[cfg(not(any(unix, windows)))]
pub fn now_local() -> (Civil, u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (civil_from_epoch(now.as_secs() as i64), now.subsec_millis())
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// `DD/MM HH:MM:SS.mmm  LEVEL msg` (`console.cpp:363`).
///
/// The level is padded to five columns, which is why INFO and WARN show two
/// spaces before the message while ERROR shows one. Hardcoding two spaces looks
/// right until the first error line.
pub fn format_log_record(c: &Civil, ms: u32, level: &str, msg: &str) -> String {
    format!(
        "{:02}/{:02} {:02}:{:02}:{:02}.{:03}  {:<5} {}",
        c.day, c.month, c.hour, c.min, c.sec, ms, level, msg
    )
}

/// Emit one log record to stderr.
///
/// The whole record — cursor rewind, erase, text, newline — is built into a
/// single `String` and written under one `stderr` lock, because the status line
/// is redrawn in place and leaves the cursor mid-row. Without the rewind, a
/// message from the getwork thread appends to a partial status line and wraps;
/// without the single write, two threads can interleave inside one row.
pub fn log(level: &str, args: std::fmt::Arguments<'_>) {
    let con = get();
    let (c, ms) = now_local();

    let mut msg = String::with_capacity(96);
    let _ = msg.write_fmt(args);

    let mut rec = String::with_capacity(msg.len() + 48);
    if con.tty {
        rec.push('\r');
        if con.vt {
            rec.push_str("\x1b[K");
        }
    }
    rec.push_str(&format_log_record(&c, ms, level, &msg));
    if con.tty && !con.vt {
        // Legacy console with no erase-to-EOL: overwrite whatever the status
        // line left on this row. Plain text only (no VT implies no colour).
        let budget = columns().unwrap_or(80).saturating_sub(1);
        let visible = format_log_record(&c, ms, level, &msg).chars().count();
        for _ in visible..budget {
            rec.push(' ');
        }
    }
    rec.push('\n');

    let mut err = io::stderr().lock();
    let _ = err.write_all(rec.as_bytes());
    let _ = err.flush();
}

/// Leave the terminal in a sane state on the way out: without this the shell
/// prompt inherits whatever colour the status line was mid-way through, and the
/// cursor sits at the end of a partial row.
pub fn restore_on_exit() {
    let con = get();
    if !con.tty {
        return;
    }
    // The reset is only meaningful where VT is processed; emitting it on a
    // legacy console would print the escape as text, which is the opposite of
    // tidying up. The newline is wanted either way, to get off the status row.
    let bytes: &[u8] = if con.vt { b"\x1b[0m\n" } else { b"\n" };
    let mut err = io::stderr().lock();
    let _ = err.write_all(bytes);
    let _ = err.flush();
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::term::log("INFO", format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::term::log("WARN", format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::term::log("ERROR", format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::term::log("DEBUG", format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_epoch_matches_known_instants() {
        let e = civil_from_epoch(0);
        assert_eq!((e.year, e.month, e.day), (1970, 1, 1));
        assert_eq!((e.hour, e.min, e.sec), (0, 0, 0));

        // 2000-02-29: a leap day in a century year, the case naive leap-year
        // logic gets wrong.
        let leap = civil_from_epoch(951_782_400);
        assert_eq!((leap.year, leap.month, leap.day), (2000, 2, 29));

        // Pre-epoch: proves the euclidean division, where `%` would yield -1.
        let before = civil_from_epoch(-1);
        assert_eq!((before.year, before.month, before.day), (1969, 12, 31));
        assert_eq!((before.hour, before.min, before.sec), (23, 59, 59));
    }

    #[test]
    fn log_record_pads_the_level_field() {
        let c = Civil {
            year: 2026,
            month: 7,
            day: 26,
            hour: 18,
            min: 7,
            sec: 22,
        };
        assert_eq!(
            format_log_record(&c, 967, "INFO", "Dirtybird Rust Miner"),
            "26/07 18:07:22.967  INFO  Dirtybird Rust Miner"
        );
        // ERROR already fills the five columns, so it gets ONE trailing space.
        assert_eq!(
            format_log_record(&c, 967, "ERROR", "connection lost"),
            "26/07 18:07:22.967  ERROR connection lost"
        );
    }

    #[test]
    fn palette_resolution_rules() {
        // Compared by effect, not by address: `const` items have no stable
        // identity — each use site gets its own copy — so pointer equality here
        // would be testing the optimiser rather than the rule.
        assert_eq!(Palette::resolve(true, false).label, "\x1b[93m");
        assert_eq!(Palette::resolve(true, true).label, "", "NO_COLOR wins");
        // No VT means no colour regardless of NO_COLOR: the escapes would print
        // as literal text rather than colouring anything.
        assert_eq!(Palette::resolve(false, false).label, "");
    }

    #[test]
    fn plain_palette_is_transparent_and_colour_is_not() {
        let mut plain = LineBuf::new();
        plain.esc(Palette::PLAIN.label);
        txt!(plain, "[DB] ");
        assert_eq!(plain.text.len(), plain.width);
        assert!(!plain.text.contains('\u{1b}'));

        let mut coloured = LineBuf::new();
        coloured.esc(Palette::COLOUR.label);
        txt!(coloured, "[DB] ");
        assert_eq!(coloured.width, plain.width, "escapes occupy no columns");
        assert!(coloured.text.len() > coloured.width);
    }

    #[test]
    fn rejections_turn_red_only_when_nonzero() {
        assert_eq!(Palette::COLOUR.rej(0), "\x1b[37m");
        assert_eq!(Palette::COLOUR.rej(1), "\x1b[91m");
        assert_eq!(Palette::PLAIN.rej(1), "");
    }
}
