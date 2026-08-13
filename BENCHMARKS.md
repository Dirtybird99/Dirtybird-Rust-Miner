# Benchmarks

## Stage-5 PR-25-class techniques (2026-08-12, branch `kata1-pr25-port`)

Four techniques ported from the C miner's post-PR-#24/#25 `v114_stubs.cpp` into the
materialized x2 path, landed together and measured as a stack:

1. Equal-key buckets **merge** their per-run sorted segments (the existing two-run
   linear merge and bottom-up k-way merge) instead of re-sorting the gathered
   positions from scratch.
2. The two-run merge caches each cursor's **eight-byte big-endian prefix** and
   reloads only the advanced side; the byte-walk comparator runs only on prefix ties.
3. Four adjacent **unique-key runs** copy straight out of the arena under one check.
4. The emitter builds a per-group-run **256-bit column-equality mask** (scalar):
   a fully-equal column triplet (`rel <= 253`) emits the whole group as one run with
   no scan, and a fully-equal next column skips the stable reorder.

Alternating paired runs on the deterministic 2,500-pair production-x2 corpus; every
arm produced checksum `4bd773cf950c05ae`; lower is better. Five B-C rounds:

| arm | mean µs/hash (5 rounds) | p95 µs/hash |
|---|---:|---:|
| v0.2.16 HEAD | 440.1–460.7 | 473.0–496.5 |
| **stack** | **390.6–404.7** | **415.5–433.3** |
| **paired change** | **−11.3% mean (range −8.5%…−12.6%, 5/5 rounds)** | **≈ −12%** |

120-second sustained B-C-C-B at 20 threads (`--sustained --secs 120 -t 20 --pin`),
v0.2.16 release binary vs the branch build:

| build | KH/s |
|---|---:|
| v0.2.16 release | 22.95 / 22.36 |
| **stack** | **25.73 / 25.57** |
| **change** | **+13.2%** |

`release-lto` on the same stack measured −0.78% µs/hash (3/3 rounds, at the
attribution floor) — consistent with the standing "plain stable `release`
recommended" verdict; rustc PGO was not re-attempted (previously measured as not
beating plain release). Gates: `cargo test --locked -p dero-astrobwt --features
v114` (including `fused_v114_matches_reference_fuzz`, 0/20,000 divergences) and the
release `"v114 shani2"` suites pass on every step; these are regression gates from
one Windows x86-64 host (i7-13700HX), not universal hardware claims.

## v0.2.12 fixed short-run copy (2026-08-02)

The materialized descriptor path emits runs averaging only a few positions. On the measured
Windows release, v0.2.11 sent every run through the general CRT `memcpy`; v0.2.12 uses four
fixed 16-byte moves for runs of eight positions or fewer and retains `memcpy` for longer
runs. Release assembly was checked to confirm the short path no longer calls the CRT.

Alternating runs used the same deterministic 2,500-pair production-x2 corpus. Every arm
produced checksum `4bd773cf950c05ae`; lower time is better.

| build | mean µs/hash | p95 µs/hash |
|---|---:|---:|
| v0.2.11 baseline | 474.71 | 506.98 |
| **v0.2.12** | **464.29** | **496.13** |
| **change** | **−2.19%** | **−2.14%** |

Five-second sustained B-C-C-B gates improved from 2.001 to 2.075 KH/s at one thread
(+3.71%) and from 21.259 to 21.633 KH/s at 20 threads (+1.76%). These are regression
gates from one Windows x86-64 host, not universal hardware claims.

## v0.2.11 pure-Rust materializer (2026-08-02)

The release gate used alternating runs of the same deterministic 2,500-pair production-x2
corpus. Every build produced checksum `4bd773cf950c05ae`; lower time is better.

| build | mean µs/hash | p95 µs/hash |
|---|---:|---:|
| v0.2.10 baseline | 611.80 | 649.38 |
| **v0.2.11** | **488.98** | **523.25** |
| **change** | **−20.1%** | **−19.4%** |

The retained stable slice sorts were also compared with an otherwise identical
`sort_unstable_by` control:

| sort control | mean µs/hash | p95 µs/hash |
|---|---:|---:|
| unstable | 522.31 | 561.78 |
| **stable (retained)** | **514.76** | **550.70** |
| **change** | **−1.45%** | **−1.97%** |

Short sustained ABBA regression gates improved from 1.547 to 1.628 KH/s at one thread
(+5.2%) and from 16.006 to 16.815 KH/s at 20 threads (+5.1%). These five-second gates and
the fixed-corpus results are from one Windows x86-64 host, not universal hardware or
cross-miner claims. Plain stable `release` remains the recommended build; rustc PGO and
additional compiler/code-shape experiments did not beat it.

The comparisons below are retained as historical results from earlier binaries and
harnesses.

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
(`astrobwt/vendor/v114/v114_stubs.cpp`, 2,400 lines) to pure Rust with narrowly audited
unsafe fixed-width loads/copies (`astrobwt/src/v114.rs`). Both backends ship in one binary;
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

### 2026-08-09 retest: LTO now wins on the Windows i7-13700HX

The materialized Rust backend changed substantially after the historical test below.
A fresh A/B used saved binaries, 20 threads, smart affinity, HIGH priority, 2 MiB large
pages, two-way SHA-NI, and six alternating 10-second pairs:

| build | mean | paired median | pair wins | fixed-work mean |
|---|---:|---:|---:|---:|
| plain `release` | 25.243 KH/s | — | — | 430,639 ns/hash |
| `release-lto` | **25.611 KH/s** | **+2.01%** | **5/6** | **422,398 ns/hash** |

Fat LTO improved sustained throughput **1.46%** and deterministic fixed-work latency
**1.91%**. Both builds produced checksum `4bd773cf950c05ae`. Two reversed-order
30-second Zig/Rust pairs then averaged 25.37 KH/s Rust and 26.24 KH/s Zig: **96.69%
parity**, with 3.31% remaining on this host.

This does not erase the target dependence demonstrated below. Plain `release` remains
the portable default; use `release-lto` on this workstation and anywhere an on-target A/B
confirms it.

### Historical: `release-lto` was a pessimization for the earlier Rust backend

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

**Historical recommendation:** this backend version favored plain `release`. Re-test the
current backend on the deployment CPU; the dated result above shows that the direction can
reverse after code-generation-sensitive changes.

Single-language rustc PGO (`-Cprofile-generate` / `-Cprofile-use`) was tested after these
historical runs and did not beat plain `release`, so it is not used for v0.2.11.

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
