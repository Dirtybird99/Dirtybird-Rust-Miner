# Benchmarks

Measured 2026-06-20 on an **Intel i7-13700HX** (8 P-cores / 8 E-cores, 24 threads),
Windows 11. All numbers are KH/s (thousands of AstroBWTv3 hashes/sec), higher is better.

## TL;DR

| Comparison | 20 threads | 24 threads (peak) | verdict |
|---|---|---|---|
| **vs Dirtybird-Rust-Miner** (author's own Rust miner) | **+8.9%** | **+14.3%** | **clear, robust win** |
| **vs Dirtybird-C-Miner** (canonical PGO build) | −0.6% | **+0.5%** | **parity — edges ahead at peak** |

- The headline result is **+9–14% over the Rust competitor** — large enough to survive any
  reasonable measurement noise.
- Against the **C** miner it's a **dead heat**: this miner edges it by ~0.5% at peak (24T) and
  trails by ~0.6% at 20T. That margin is *inside* cross-tool measurement uncertainty (each miner
  is measured with its own benchmark tool), so the honest reading is **parity, leaning ahead at
  peak** — see the round-win count, not just the average.
- **Correctness: byte-exact.** `fused_v114_matches_reference_fuzz` passes, 0 / 20000 fuzzed
  descriptor divergences, `canon_mismatch = 0`.
- The peak result requires the **nightly cross-language-LTO build** ([BUILDING-LTO.md](BUILDING-LTO.md));
  the plain **stable** build is ~−1% vs C (still ahead of the Rust competitor).

## Methodology

- **One miner at a time** (never concurrent) — no cross-miner cache/bandwidth contention.
- **Alternating run-order** each round, so neither side always runs on the hotter chip.
- Both processes forced to **HIGH** priority; 20s warmup to reach thermal steady-state.
- **This miner**: the nightly dual-PGO + cross-language-LTO binary, `--sustained`, **unpinned**.
- **Dirtybird-C-Miner**: the **canonical `build-pgo-use` PGO binary**, unpinned (its `set_affinity`
  is a no-op on Windows).
- **Dirtybird-Rust-Miner**: its own `bench` tool at `affinity=1` (its best config) + 2-way SHA.
- Reproduce with [`headtohead.ps1`](headtohead.ps1) (mine vs C) — same harness that produced these.

> Caveat: the three miners are each measured with a *different* tool (`--sustained`, C's
> `pgo-train`, DBR's `bench`). A sub-1% delta is below that cross-tool uncertainty; a +14% delta
> is well above it.

## vs Dirtybird-C-Miner — 24T peak, 8 rounds (the close one)

Mine vs the canonical PGO C binary, alternating order:

| round | MINE | C | delta | winner |
|---|---|---|---|---|
| 1 | 22.74 | 22.70 | +0.18% | tie |
| 2 | 22.55 | 22.45 | +0.47% | MINE |
| 3 | 22.51 | 22.32 | +0.87% | MINE |
| 4 | 22.30 | 22.21 | +0.39% | MINE |
| 5 | 22.31 | 22.23 | +0.33% | MINE |
| 6 | 22.24 | 22.27 | −0.13% | tie |
| 7 | 22.19 | 21.96 | +1.03% | MINE |
| 8 | 21.86 | 21.59 | +1.28% | MINE |
| **avg** | **22.34** | **22.22** | **+0.54%** | **6 wins / 0 losses / 2 ties** |

Never lost a round; sign test on the decided rounds p ≈ 0.016. Real, reproducible, but **narrow**.
At **20T** the same canonical C is slightly *ahead* (mine 19.99 vs C 20.11, −0.6%) because this
miner's 20T lever — P-core pinning, which the C miner can't do on Windows — was **not** applied in
these runs.

## vs Dirtybird-Rust-Miner — the robust win

Same serial harness, mine unpinned vs DBR-Rust at its `affinity=1` peak:

| threads | MINE | DBR-Rust | delta |
|---|---|---|---|
| 20 | 19.99 | 18.36 | **+8.9%** |
| 24 | 22.51 | 19.70 | **+14.3%** |

Why: DBR-Rust's 2-way batched pipeline is a latency win at low thread counts but a working-set /
memory-bandwidth liability at saturation (two in-flight nonces double the per-thread suffix-array
footprint on a bandwidth-bound box). This miner's single fused path + cross-language LTO scales
better at peak.

## Pure-Rust descriptor SA vs the vendored C++ (2026-07-10)

The v1.14 descriptor suffix array — ~88% of a hash — was ported from the vendored C++
(`astrobwt/vendor/v114/v114_stubs.cpp`, 2,400 lines) to pure Rust
(`astrobwt/src/v114.rs`, `#![forbid(unsafe_code)]`). Both backends ship in one binary;
`DERO_V114_CPP=1` selects the C++.

Measured with [`v114_ab.ps1`](v114_ab.ps1) — same binary, one backend per run, alternating
order, HIGH priority, 30 s sustained window, 24 threads, unpinned. **Plain `release` build**
(not the dual-PGO + cross-language-LTO build that produces the 22.3 KH/s figure above), so
the absolute numbers are lower; only the *delta* is meaningful here.

| round | RUST | CPP | delta | winner |
|---|---|---|---|---|
| 1 | 18.66 | 18.42 | +1.30% | RUST |
| 2 | 18.18 | 18.21 | −0.16% | CPP |
| 3 | 18.38 | 18.00 | +2.11% | RUST |
| 4 | 18.50 | 18.41 | +0.49% | RUST |
| 5 | 18.46 | 18.43 | +0.16% | RUST |
| 6 | 18.62 | 18.33 | +1.58% | RUST |
| **avg** | **18.47** | **18.30** | **+0.91%** | **5 W / 1 L / 0 T** |

**Verdict: parity, leaning ahead.** The sign test over the 6 decided rounds gives
p ≈ 0.22 — *not* significant, so this is **not** a claimed win. The honest reading is that
the Rust backend is indistinguishable from the C++ at saturation, on the right side of the
line. Single-thread `sa_bench` is a dead heat (1458 vs 1457 H/s).

Correctness is byte-exact, not merely "passes tests": the Rust SA, the C++ SA, and libsais
agree element-for-element; the fused hash equals `sha256(materialized SA)`; and both
backends **refuse the same inputs** (refusal drift would silently change how often the
libsais fallback runs). Verified over the 532-case `v114_golden.json` fixture (frozen from
the C++ before the port), 20,000 differential fuzz cases, and miner-sized 255-byte inputs.

### Two regressions the port introduced, and what they cost

A first, naively faithful cut was **+4.6% single-thread but −3.4% at 24 threads** — the
signature of extra memory traffic, not a worse algorithm:

- `radix_sort_runs_by_stored_key` and `merge_equal_key_runs_after_key` called `clear()`
  before `resize()`, re-zeroing the whole reused scratch buffer every hash. The C++ resizes
  only, because every slot is written before it is read.
- `keys` was a `[0u32; 512]` stack array — 2 KiB zeroed per group-run call. The C++ leaves
  that array uninitialized; Rust cannot without `unsafe`, so it moved into the reused
  thread-local scratch.

Both are *faithfulness* bugs as much as perf bugs: the C++ did neither. Removing them
restored parity. Worth remembering — "port it literally" and "port its memory behavior"
are not the same thing.

## Not claimed here

- A previously-measured **+6% at 16T** (via P-core pinning) is **not** re-verified against the
  canonical C binary in these runs, so it is intentionally **not** stated as a result. Re-run
  `headtohead.ps1 30 8 16` with mine pinned before citing it.
- DBR-Rust is the more **productized** project (cross-platform musl/aarch64 builds, pool defaults,
  release packaging). This comparison is throughput-only on one box.
