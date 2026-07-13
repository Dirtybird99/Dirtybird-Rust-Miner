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
- Reproduced with a local A/B harness (this miner's `--sustained` vs the C binary) on the same box.

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

Sign test on that run: p ≈ 0.22 — not significant on its own. A second, independent 6-round
run on a clean rebuild of the same tree:

| run | RUST | CPP | delta | rounds | sign test |
|---|---|---|---|---|---|
| 1 | 18.47 | 18.30 | +0.91% | 5 W / 1 L | p ≈ 0.22 (n.s.) |
| 2 | 18.57 | 18.36 | **+1.14%** | **6 W / 0 L** | **p = 0.031** |

**Verdict: the Rust backend is at least at parity, and probably ~1% ahead.** Run 2 is
significant and every round in both runs but one favors Rust; but ~1% is close enough to the
cross-run spread that "a small real win" is the strongest honest claim, not a headline
number. Single-thread `sa_bench` is a dead heat (1458 vs 1457 H/s), which is what you would
expect if the win comes from allocation/memory behaviour at saturation rather than from the
scalar inner loops.

### `release-lto` is a pessimization for the Rust backend — use `release`

The same A/B on the `release-lto` profile (`lto = "fat"`, `codegen-units = 1`) reverses
the result, and this one *is* significant:

| profile | RUSTFLAGS | RUST | CPP | delta | sign test |
|---|---|---|---|---|---|
| `release` | (none) | **18.47 / 18.57** | 18.30 / 18.36 | **+0.91% / +1.14%** | p ≈ 0.22 / p = 0.031 |
| `release-lto` | (none) | 17.46 | 18.22 | −4.20% | p = 0.031, 0 W / 6 L |
| `release-lto` | `-C target-cpu=x86-64-v3` | 17.27 | 18.16 | −4.87% | p = 0.031, 0 W / 6 L |

Read the **columns**, not just the deltas. The C++ scores ~18.2 KH/s under *both* profiles —
it is a separate translation unit compiled by clang either way, so the Rust profile cannot
touch it. The Rust backend drops from 18.47 to ~17.3–17.5 when fat LTO + `codegen-units=1`
is switched on. **Fat LTO makes the Rust descriptor SA ~6% slower than plain `release`.**
The apparent "C++ wins under LTO" is really "LTO hurts Rust here."

`-C target-cpu=x86-64-v3` does **not** explain it. The natural hypothesis was an unfair
comparison — `build.rs` hands the C++ `-march=x86-64-v3 -mtune=raptorlake -mavx2`
unconditionally, while rustc defaults to the x86-64 baseline. Matching the ISA made Rust
*slightly worse*, so the gap is inlining/register-allocation under `codegen-units = 1`, not
the instruction set. Hypothesis raised, tested, refuted.

**Recommendation: build the pure-Rust `v114` backend with the plain `release` profile.**
`release-lto` existed to LTO the Rust and the C++ *together*; with no C++ in the build there
is nothing to link across, and fat LTO's remaining effect here is negative.

Untried lever: single-language rustc PGO (`-Cprofile-generate` / `-Cprofile-use`). The C++
path historically gained ~12.5% from clang PGO on the descriptor TU, so this is the obvious
next experiment — and it is now a one-toolchain operation instead of the dual rustc+clang
profile dance in [BUILDING-LTO.md](BUILDING-LTO.md).

> Absolute numbers here are **not** comparable to the 22.3 KH/s headline at the top of this
> file: that build used nightly dual-PGO + cross-language LTO + `target-cpu=native`. None of
> the runs in this section use PGO. Only the RUST-vs-CPP delta *within* a row is meaningful.

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

### Dropping the C libsais fallback (2026-07-10) — no throughput cost

Commit `ea3c9f4` removed the C `libsais` dependency entirely from `--features v114`: the
descriptor SA's rare refusal fallback was rerouted from C `libsais` to the pure-Rust `sais32`,
so the mining build now links **no C at all**. The hot path is byte-identical Rust in both
builds and the fallback ~never fires (0 refusals across the 532-case golden fixture + 20k
fuzz), so the expectation was zero throughput change. Measured HEAD `ea3c9f4` (no libsais) vs
parent `909dd8b` (libsais linked), plain `release`, `--sustained -t 24 --secs 30`, HIGH
priority, 2 MB large pages (identical `sustained:` header on both), alternating order, 3 pairs
after a discarded 20 s warmup:

| pair | NEW (no libsais) | OLD (libsais) | delta |
|---|---|---|---|
| 1 | 19.62 | 19.22 | +2.1% |
| 2 | 19.40 | 19.19 | +1.1% |
| 3 | 19.32 | 18.98 | +1.8% |
| **mean** | **19.44** | **19.13** | **+1.6%** |

NEW won all three pairs, but the honest read is **"no regression, possibly a hair faster — not
a certified speedup."** Two reasons not to bank the +1.6%: (1) n = 3, so the 3 W / 0 L sweep is
only p ≈ 0.25 (an all-wins result needs ≥ 6 pairs for p < 0.05); and (2) the order was NEW-first
in every pair, and both binaries drift down ~1.5% first-to-last from thermal settling, biasing
NEW up by ~0.4%. Corrected for drift the gain is ~+1.3% and still uncertain. **The load-bearing
conclusion — dropping libsais did not cost throughput — holds regardless.** A proper 6-pair
ABBA run would be needed to certify the small gain; it is not needed for the "safe to ship"
decision. (Correctness across the two binaries is byte-identical — same `v114_golden.json`
fixture — so this is a pure throughput comparison.)

## Not claimed here

- A previously-measured **+6% at 16T** (via P-core pinning) is **not** re-verified against the
  canonical C binary in these runs, so it is intentionally **not** stated as a result. Re-run a
  pinned 16-thread A/B against the C binary before citing it.
- DBR-Rust is the more **productized** project (cross-platform musl/aarch64 builds, pool defaults,
  release packaging). This comparison is throughput-only on one box.
