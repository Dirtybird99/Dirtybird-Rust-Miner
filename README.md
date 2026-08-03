# DERO AstroBWTv3 CPU Miner — Rust (fused, pure-Rust suffix array)

A Rust CPU miner for **DERO**'s AstroBWTv3 proof-of-work — a port of the Go reference
`cmd/dero-miner`. The hot **v114 descriptor suffix-array** stage (~74–88% of every hash) is
**pure Rust** (`astrobwt/src/v114.rs`, with narrowly audited unsafe loads/copies), ported
from the C++ that used to be vendored under `astrobwt/vendor/v114/`. ONE CPU, ONE VOTE.

> **The pure-Rust line.** The whole AstroBWTv3 hash path *and* the pool TLS are Rust — on
> x86/Windows the shipped binary needs no C toolchain to build and links no C/assembly
> dependency. (arm64 gained one build-time exception in v0.2.8, the price of ARM's hardware
> SHA-256 — see [Build](#build).) It defaults
> to a materialized suffix-array path with P-core pinning + HIGH priority and, on CPUs with
> SHA-NI, a 2-way multibuffer SHA that hashes two nonces at once. Benchmark methodology and the
> (honestly caveated) cross-miner numbers are in [BENCHMARKS.md](BENCHMARKS.md); each miner is
> measured with a different tool, so treat sub-percent deltas as noise.

## Highlights

### v0.2.13

v0.2.13 widens the release platforms to match the field: a native **macOS Apple Silicon**
build (`macos-arm64`, the same ARMv8 hardware SHA-256 path the Android builds use) and a
**HiveOS/mmpOS farm package** (`hiveos_mmpos.amd64`) wrapping the Linux amd64 binary with
the agent hook scripts. Supporting both, the miner gains `--api-bind-address` — an opt-in
localhost stats endpoint serving one plain-text line (hashrate, uptime, version,
accepted, rejected) that the farm scripts poll. No hash-path changes.

### v0.2.12

v0.2.12 replaces the materialized path's per-run general `memcpy` call with a fixed
eight-word pure-Rust copy for its common short runs. On the deterministic 2,500-pair
production-x2 corpus, alternating runs cut mean time by 2.19% and p95 by 2.14% with the
same checksum. Five-second sustained gates improved 3.71% at one thread and 1.76% at 20
threads. Two-way SHA remains enabled; the x86 hash path still links no C/C++ backend.

### v0.2.11

v0.2.11 speeds up the pure-Rust materialized `v114` path while keeping 2-way SHA-NI
enabled. On the deterministic 2,500-pair production-x2 corpus, alternating runs cut mean
time by 20.1% and p95 by 19.4% versus v0.2.10 with the same checksum. Short 1-thread and
20-thread sustained regression gates improved about 5% on the same host. Stable sorting is
retained because it also beat the otherwise identical unstable-sort control. The normal
stable `release` build remains the fastest measured configuration; the x86 hash path links
no C/C++ backend.

- **Fast.** +8.9% @20T / +14.3% @24T vs the Rust competitor; parity with the canonical PGO
  C miner, edging it +0.5% at 24T peak (6 wins / 0 losses / 2 ties over 8 rounds). See
  [BENCHMARKS.md](BENCHMARKS.md) — including the caveats (the C margin is within cross-tool
  measurement noise; the Rust-vs-Rust margin is not).
- **Correct.** Byte-exact AstroBWTv3: the pure-Rust descriptor SA, the C++ it was ported
  from, and libsais agree element-for-element over 20,000 differential-fuzz cases and a
  committed 532-case golden fixture, with identical *refusal* behaviour. Plus
  **verify-on-submit**: any target-clearing share is re-checked with the canonical
  (SA-IS/libsais) PoW before it is sent, so a bug or hardware glitch costs a share rather
  than submitting garbage.
- **100% Rust hash, no C toolchain (x86).** The whole AstroBWTv3 hash path is pure Rust:
  `astrobwt/src/v114.rs` uses narrowly audited unsafe fixed-width loads/copies, its rare
  refusal fallback is the pure-Rust `sais32` (not C libsais), and `--features v114` compiles
  with **no C compiler at all** — no clang-cl, no cc/libsais. The C++ descriptor SA and C
  libsais are opt-in differential-fuzz oracles behind the dev-only `v114-cpp` feature. The
  pool TLS is pure Rust too (`rustls` + `rustls-rustcrypto`, replacing `ring`'s C/assembly),
  so building needs no C compiler and the shipped binary links no C dependency. **arm64
  exception (v0.2.8+):** ARM's
  hardware SHA-256 comes from `sha2`'s `asm` feature, which also drags in a C-assembled
  `sha256_aarch64.S` that nothing on aarch64 ever calls — that backend is Rust `asm!` plus NEON
  intrinsics — but which still has to compile, so arm64 builds need a C compiler for the target.
  Declining it would cost roughly 3x the hashrate on ARM, so it is the right trade.
- **Honest benchmarking built in.** `--sustained` is a counter-summed, fixed-window scoreboard
  (the per-thread `--bench` table understates hybrid-CPU throughput); see
  [BENCHMARKS.md](BENCHMARKS.md) for the head-to-head methodology.

## Build

**No C toolchain required on x86 — at all.** The descriptor suffix array AND its refusal fallback
are pure Rust (`sais32`), so a plain stable `cargo build --release -p dero-miner --features
v114` is the whole story — no `clang-cl`, no `cc`/C compiler, no libsais, no matched-LLVM
nightly, no `.cargo/config.toml`. Use the plain `release` profile: fat LTO (`--profile
release-lto`) is a ~6% *pessimization* for the Rust backend, see [BENCHMARKS.md](BENCHMARKS.md).

**arm64 needs a C compiler for the target (v0.2.8+).** Not for the hash code — that stays
Rust — but because enabling `sha2`'s ARMv8 SHA-256 backend also pulls in `sha2-asm`, whose
build script assembles a `sha256_aarch64.S` that only x86 ever calls. Cross-compiling from
this repo's CI supplies one automatically: `cargo zigbuild` for the musl arm64 tarball, the
NDK's `aarch64-linux-android24-clang` for the Android artifact (`.github/workflows/release.yml`).
Building on an arm64 host, any working `cc` will do. Without the hardware backend, `sha2`
falls back to software rounds and an ARM device gives up the bulk of its hashrate —
`scripts/verify-arm64-elf.sh` fails the build rather than shipping that silently.

The vendored C++ descriptor SA and the C `libsais` are retained only as differential-fuzz
oracles behind the dev-only `v114-cpp` feature, which *does* need `clang-cl` on `PATH`.
See [BUILDING-LTO.md](BUILDING-LTO.md).

```sh
cargo build --release -p dero-miner --features v114      # stable; ~parity with C
```

## Testing

```sh
cargo test -p dero-astrobwt              # all suites, pure Rust, no toolchain beyond cargo
cargo test -p dero-astrobwt --features v114   # + the v114 golden fixture
```

Everything passes on a fresh clone. Two independent oracle sets guard correctness:

- **`vectors/*.json`** — golden vectors from the **canonical DERO Go reference**, checked by
  `astrobwt/tests/{prologue,full,pow16,sais}_vectors.rs`: the prologue (sha256→salsa20→rc4→
  fnv1a), the op-loop intermediates, the suffix arrays (`sais_8_32` / `sais_8_16` over 26 edge
  and boundary inputs), and legacy POW16. Regenerate with `go-harness/run.sh` (needs Go); see
  [go-harness/README.md](go-harness/README.md).
- **`astrobwt/tests/fixtures/v114_golden.json`** — 532 cases (PoW hash, fused hash, SA digest,
  and *refusal* behaviour) frozen from the descriptor SA, guarding the pure-Rust `v114` path.

To also diff the Rust SA against the C++ it was ported from, see §3 of
[BUILDING-LTO.md](BUILDING-LTO.md) (needs `clang-cl`).

## Usage

Prebuilt binaries and their checksums are available from
[GitHub Releases](https://github.com/Dirtybird99/Dirtybird-Rust-Miner/releases):

| Asset | Platform |
|---|---|
| `…-amd64-v*.tar.gz` | Linux x86_64 (static musl — any distro) |
| `…-arm64-v*.tar.gz` | Linux aarch64 (static musl — SBCs, arm64 VMs; **not Android**) |
| `…-android-arm64-v*.tar.gz` | Android aarch64 (Termux — see below) |
| `…-macos-arm64-v*.tar.gz` | macOS Apple Silicon |
| `…-win64-v*.zip` | Windows x86_64 |
| `…hiveos_mmpos.amd64.tar.gz` | HiveOS / mmpOS farm package (see below) |

```sh
dero-miner -w <dero-address> -d <daemon:port> -t <threads>
# offline diagnostics:
dero-miner --bench                      # AstroBWTv3 throughput table
dero-miner --sustained -t 24 --secs 30  # honest fixed-window hashrate
```

`-w` is the reward address (a public DERO address), `-d` the daemon/pool getwork endpoint
(default `dero-node.mysrv.cloud:10100`), `-t` the thread count (default: all logical CPUs).

Progress and events go to **stderr**: the status line is repainted in place once a second and
shrinks to fit narrow terminals, keeping as many fields as the width allows. Redirecting
(`dero-miner … 2> miner.log`) switches it to complete, newline-terminated records with no colour
and no cursor control, so the log stays greppable. `NO_COLOR=1` turns colour off while keeping the
in-place repaint.

`--api-bind-address <ip:port>` serves a one-line plain-text stats endpoint over HTTP
(`<hashrate_hs> <uptime_secs> <version> <accepted> <rejected>`) for farm managers and
scripts; it is off unless the flag is given. The HiveOS/mmpOS package below wires it up
automatically.

## macOS (Apple Silicon)

Download `Dirtybird-Rust-Miner-macos-arm64-v*.tar.gz`, extract, and run `./dero-miner`.
The binary is not notarized, so the first run trips Gatekeeper ("cannot be opened because
the developer cannot be verified"); clear the quarantine attribute once:

```sh
xattr -d com.apple.quarantine ./dero-miner
```

The ARMv8 hardware SHA-256 path is the same one the Android/arm64 builds use, so M-series
chips get the hardware hash backend out of the box.

## HiveOS / mmpOS

The `dirtybird-rust-miner-v*.hiveos_mmpos.amd64.tar.gz` asset is a farm package: the Linux
amd64 binary plus the agent hook scripts both platforms expect (`h-config.sh`, `h-run.sh`,
`h-stats.sh` for HiveOS; `mmp-stats.sh` for mmpOS).

**HiveOS:** create a Flight Sheet with miner "Custom", set the installation URL to the
release asset URL, miner name `dirtybird-rust-miner`, wallet template `%WAL%`, and the
pool/daemon getwork endpoint as the URL (e.g. `dero-node.mysrv.cloud:10100` — a scheme
prefix is stripped automatically). Extra CLI flags can go in the "Extra config arguments"
box; they are appended to the generated command line.

**mmpOS:** add a custom miner profile pointing at the same asset URL; `mmp-stats.sh` is the
stats hook.

Both platforms read hashrate from the miner's stats endpoint on `127.0.0.1:44011`, which
the package's launch script enables via `--api-bind-address`.

## Android (Termux)

Requires a 64-bit ARM (aarch64) Android device, [Termux](https://termux.dev/), and release
v0.2.7 or newer (earlier releases have no Android-native binary — Termux execs through
Android's own linker, which a musl static-PIE does not survive, and musl DNS cannot
resolve on Android):

```sh
curl -fsSL https://raw.githubusercontent.com/Dirtybird99/Dirtybird-Rust-Miner/main/scripts/termux-setup.sh | bash
```

The installer downloads `Dirtybird-Rust-Miner-android-arm64-v*.tar.gz` from the latest
release, verifies it against `SHA256SUMS.txt`, prompts for daemon/wallet/threads (persisted;
re-run with `--reconfigure` to change, `--update` to upgrade, `--uninstall` to remove), takes
a wake-lock so Android Doze doesn't pause mining, and auto-restarts the miner if it exits.

Note the arm64 artifact split: `arm64` = static-musl for generic arm64 Linux (SBCs, arm64
VMs) and **will not run on Android**; `android-arm64` = bionic-native, the only one Termux
can exec and the only one that can resolve DNS on Android.

v0.2.9 adds a second ARM hashrate change: a two-stream SHA-256 kernel on the ARMv8 crypto
extensions, measured 8.8% faster on a native Neoverse-N2 runner. Two independent hashes are
interleaved so the pipeline stays fed — SHA256H is multi-cycle and one stream cannot fill it.
The instruction count is identical; only the scheduling changes, and the hashes are byte-for-byte
the same. It does hold two suffix arrays in flight, which trades cache footprint for that
scheduling, so on a device with small caches it may be the wrong trade: `--no-2way` (or
`MINER_2WAY=0`) turns it off, and it is worth comparing on your own hardware.

v0.2.10 reworks the console for small screens. The status line now shrinks a field at a time
instead of collapsing, so a phone-width terminal keeps the height, counters and uptime
(`[DB] 5.04 KH/s | H:7386579 MB:0 B:0 R:0 | 00:01:17`) rather than dropping to a bare rate, and
startup is a set of timestamped records that report the connection and how long it took.

Use v0.2.8 or newer for phone hashrate. v0.2.7 hashed with `sha2`'s software rounds, and
since every AstroBWTv3 hash SHA-256s ~270 KB of suffix-array output (~4,200 compressions),
that stage dominated everything else on ARM. v0.2.8 enables the ARMv8 crypto extensions
(SHA256H/SHA256SU) — the same hashes, byte for byte, with that stage no longer the
bottleneck. Expect a large multiple of v0.2.7's rate on any device whose `AT_HWCAP`
advertises `sha2`, which every modern phone does. Devices without the extensions
still work; `sha2` detects that at runtime and uses the software path.

Take the pool (option 1, the default) on a phone. The solo nodes pay out at network
difficulty, which at phone hashrates means hours between rewards — the counters sit at
zero long enough to look broken, even though nothing is wrong. Install `termux-api`
(plus the Termux:API app) for wake-lock and battery-status support.

## Layout

- `src/` — miner: getwork over TLS-WebSocket (`tls.rs`/`ws.rs`), worker loop (`worker.rs`),
  submit, CLI (`main.rs`), `--bench`/`--sustained` harnesses.
- `astrobwt/` — the AstroBWTv3 hash crate + vendored v114 descriptor-SA C++ + `build.rs`
  (PGO/LTO/large-page build knobs).
- `block/`, `cryptography/` — the DERO protocol types and crypto the miner depends on.
- `_pgo/dual.profdata` — the committed PGO profile for the LTO build.

## Caveats

Throughput numbers are **n=1** (one i7-13700HX, Windows 11). The peak-win binary requires the
nightly LTO build; the stable build is ~−1% vs the C miner (still ahead of the Rust competitor).
This branch is a single-host research/performance build — `main` remains the productized,
cross-platform release.
