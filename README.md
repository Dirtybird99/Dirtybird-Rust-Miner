# DERO AstroBWTv3 CPU Miner — Rust (fused, pure-Rust suffix array)

A Rust CPU miner for **DERO**'s AstroBWTv3 proof-of-work — a port of the Go reference
`cmd/dero-miner`. The hot **v114 descriptor suffix-array** stage (~74–88% of every hash) is
**pure Rust** (`astrobwt/src/v114.rs`, `#![forbid(unsafe_code)]`), ported from the C++ that
used to be vendored under `astrobwt/vendor/v114/`. ONE CPU, ONE VOTE.

> This is the **`fused-lto-win`** branch: a *different, faster* codebase from `main`. It
> trades `main`'s cross-platform packaging for a single fused hashing path that, on an
> i7-13700HX, runs **+9–14% faster than
> [Dirtybird-Rust-Miner](https://github.com/Dirtybird99/Dirtybird-Rust-Miner) `main`** and
> **matches the Dirtybird C miner at peak**. Full, honestly-calibrated numbers in
> [BENCHMARKS.md](BENCHMARKS.md).
>
> Note the historical peak (22.3 KH/s) came from a nightly dual-PGO + cross-language-LTO
> build. That build is obsolete: there is no C++ left to LTO across. The `+9–14%` and C-miner
> figures above predate the pure-Rust suffix array and have **not** been re-measured against
> those competitors since; what *has* been re-measured, head-to-head on one binary, is the
> Rust SA vs the C++ SA it replaced (~+1%, see BENCHMARKS.md).

## Highlights

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
- **100% Rust hash, no C toolchain.** The whole AstroBWTv3 hash path is pure Rust:
  `astrobwt/src/v114.rs` is `#![forbid(unsafe_code)]`, its rare refusal fallback is the
  pure-Rust `sais32` (not C libsais), and `--features v114` compiles with **no C compiler at
  all** — no clang-cl, no cc/libsais. The C++ descriptor SA and the C libsais are opt-in
  differential-fuzz oracles behind the dev-only `v114-cpp` feature. (The pool TLS still links
  `ring`, which contains C/assembly — that's the one remaining non-Rust dependency.)
- **Honest benchmarking built in.** `--sustained` is a counter-summed, fixed-window scoreboard
  (the per-thread `--bench` table understates hybrid-CPU throughput). [`headtohead.ps1`](headtohead.ps1)
  reproduces the head-to-head vs the C miner.

## Build

**No C toolchain required — at all.** The descriptor suffix array AND its refusal fallback
are pure Rust (`sais32`), so a plain stable `cargo build --release -p dero-miner --features
v114` is the whole story — no `clang-cl`, no `cc`/C compiler, no libsais, no matched-LLVM
nightly, no `.cargo/config.toml`. Use the plain `release` profile: fat LTO (`--profile
release-lto`) is a ~6% *pessimization* for the Rust backend, see [BENCHMARKS.md](BENCHMARKS.md).

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
