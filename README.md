# DERO AstroBWTv3 CPU Miner — Rust (fused + cross-language-LTO build)

A Rust CPU miner for **DERO**'s AstroBWTv3 proof-of-work — a port of the Go reference
`cmd/dero-miner`, with the hot **v114 descriptor suffix-array** stage vendored as C++
(`astrobwt/vendor/v114/`) and compiled by clang-cl. ONE CPU, ONE VOTE.

> This is the **`fused-lto-win`** branch: a *different, faster* codebase from `main`. It
> trades `main`'s cross-platform packaging for a single fused hashing path plus a
> dual-PGO + cross-language-LTO build that, on an i7-13700HX, runs **+9–14% faster than
> [Dirtybird-Rust-Miner](https://github.com/Dirtybird99/Dirtybird-Rust-Miner) `main`** and
> **edges the Dirtybird C miner at peak**. Full, honestly-calibrated numbers in
> [BENCHMARKS.md](BENCHMARKS.md).

## Highlights

- **Fast.** +8.9% @20T / +14.3% @24T vs the Rust competitor; parity with the canonical PGO
  C miner, edging it +0.5% at 24T peak (6 wins / 0 losses / 2 ties over 8 rounds). See
  [BENCHMARKS.md](BENCHMARKS.md) — including the caveats (the C margin is within cross-tool
  measurement noise; the Rust-vs-Rust margin is not).
- **Correct.** Byte-exact AstroBWTv3 (`fused_v114_matches_reference_fuzz`, 0/20000 fuzzed
  divergences), plus **verify-on-submit**: any target-clearing share is re-checked with the
  canonical PoW before it is sent, so a hardware/miscompile glitch can never submit garbage.
- **Honest benchmarking built in.** `--sustained` is a counter-summed, fixed-window scoreboard
  (the per-thread `--bench` table understates hybrid-CPU throughput). [`headtohead.ps1`](headtohead.ps1)
  reproduces the head-to-head vs the C miner.

## Build

**Requirement:** LLVM's **`clang-cl` must be on `PATH`** (e.g. `C:\Program Files\LLVM\bin`).
`build.rs` compiles the vendored v114 C++ with clang-cl and `-fno-vectorize`/`-fno-slp-vectorize`
— a deliberate workaround for an MSVC `cl.exe` auto-vectorization miscompile of the descriptor
suffix array. This applies to **every** build, stable included; without clang-cl the build fails
with `failed to find tool "clang-cl"`.

```sh
cargo build --release -p dero-miner --features v114      # stable; ~parity with C
```

The peak build additionally needs a nightly toolchain + cross-language LTO — see
[BUILDING-LTO.md](BUILDING-LTO.md).

## Usage

```sh
dero-miner -w <dero-address> -d <daemon:port> -t <threads>
# offline diagnostics:
dero-miner --bench                      # AstroBWTv3 throughput table
dero-miner --sustained -t 24 --secs 30  # honest fixed-window hashrate
```

`-w` is the reward address (a public DERO address), `-d` the daemon/pool getwork endpoint
(default `minernode1.dero.live:10100`), `-t` the thread count (default: all logical CPUs).

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
