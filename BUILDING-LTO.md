# Building this miner

The performance feature flag is `v114` — the descriptor suffix array, ~74–88% of each
hash. It is now a **pure-Rust** implementation (`astrobwt/src/v114.rs`, with narrowly
audited unsafe fixed-width loads/copies), ported from the C++ that used to be vendored
under `astrobwt/vendor/v114`. All real builds use `--features v114`.

**There is one build.** `cargo build --release -p dero-miner --features v114` — stable
toolchain, no C++ compiler, no `.cargo/config.toml`, no PGO profile. That is the
recommended production build and the fastest one measured
(see [BENCHMARKS.md](BENCHMARKS.md)).

---

## 1. The build

```sh
# from the repo root
cargo build --release -p dero-miner --features v114
# binary: target/release/dero-miner.exe
```

No `clang-cl` needed: nothing under `vendor/v114` is compiled unless you opt into the
dev-only `v114-cpp` feature (§3). This removes the old `-fno-vectorize` /
`-fno-slp-vectorize` flag discipline and the whole matched-LLVM toolchain requirement.

Make sure `.cargo/config.toml` does **not** exist (only `.cargo/config.toml.example`
is committed). A stray live config with the `[unstable]` table breaks stable builds.

Sanity-check correctness + speed:

```sh
target/release/dero-miner.exe --bench                        # offline AstroBWTv3 table
target/release/dero-miner.exe --sustained -t 24 --secs 30    # honest scoreboard
cargo test -p dero-astrobwt --features v114                  # incl. the golden fixture
```

### Do NOT use `--profile release-lto` for the Rust backend

Measured: fat LTO + `codegen-units = 1` makes the pure-Rust descriptor SA **~6% slower**
than plain `release` (18.5 → 17.3 KH/s @24T; see BENCHMARKS.md). `release-lto` existed to
LTO the Rust and the C++ *together* — with no C++ in the build there is nothing to link
across, and its remaining effect here is negative.

Single-language rustc PGO (`-Cprofile-generate` / `-Cprofile-use`) was tested and did not
beat plain `release`, so the release does not carry a profile.

---

## 2. Nightly cross-language-LTO build — OBSOLETE

This section described LTO-linking the Rust crates and the vendored v114 C++ to LLVM
bitcode together, with a dual rustc+clang PGO profile applied across the inlined boundary.
It required a nightly `rustc` whose bundled LLVM major matched `clang-cl`, plus `lld-link`,
`.cargo/config.toml`, `-Z target-applies-to-host`, and `-Clinker-plugin-lto`.

**There is no longer a C++ boundary to inline across.** The descriptor SA is Rust. The
recipe is preserved in git history (see `.cargo/config.toml.example` and the
`DERO_CC_PGO` / `DERO_CC_LTO` handling in `astrobwt/build.rs`) and still applies if you
build with `--features v114-cpp`, but it buys nothing for the production build — and fat
LTO on its own actively *costs* ~6% (see §1).

---

## 3. Verifying against the C++ (dev only)

The C++ the Rust was ported from is retained as a differential oracle. Compile both
backends into one binary and compare them:

```sh
# requires clang-cl on PATH
cargo test -p dero-astrobwt --features v114-cpp --release v114_diff_tests
DERO_DIFF_FUZZ_N=20000 cargo test -p dero-astrobwt --features v114-cpp --release \
  rust_v114_matches_cpp_fuzz
```

These assert that the Rust SA, the C++ SA, and libsais agree element-for-element, that the
fused hash equals `sha256(materialized SA)`, and that both backends **refuse the same
inputs**. Also run the debug build occasionally — it arms Rust's integer-overflow panics:

```sh
DERO_DIFF_FUZZ_N=500 cargo test -p dero-astrobwt --features v114-cpp rust_v114_matches_cpp_fuzz
```

Head-to-head throughput (`DERO_V114_CPP=1` selects the C++ at runtime; only meaningful in a
`v114-cpp` build):

```powershell
cargo build -p dero-miner --release --features v114-cpp
.\v114_ab.ps1 -Seconds 30 -Threads 24 -Rounds 6 -Profile release
```

---

## 4. Regenerating the legacy dual PGO profile (obsolete)

`_pgo/dual.profdata` is a **dual rustc+clang** profile and only applies to `v114-cpp`
builds. For the pure-Rust backend, use plain single-language rustc PGO instead
(`-Cprofile-generate` / `-Cprofile-use`) — no `DERO_CC_PGO`, no profile-runtime juggling.

The legacy recipe, for reference:

```sh
# instrument (no LTO, no --target needed)
RUSTFLAGS="-Ctarget-cpu=native -Cprofile-generate=$PWD/_pgo/raw" \
  DERO_CC_PGO=gen DERO_CC_PGO_NO_RT=1 \
  cargo +nightly build -p astrobwt --example pgo_train --features v114 --release

# train (returns from main so the LLVM atexit profile writer runs)
target/release/examples/pgo_train.exe 90000

# merge the rustc + clang raw profiles into the committed file
llvm-profdata merge -o _pgo/dual.profdata _pgo/raw/*.profraw <clang .profraw dir>/*.profraw
```

`DERO_CC_PGO_NO_RT=1` skips linking `clang_rt.profile` so rustc's profile runtime serves
clang's instrumented object (one runtime, one merged profile). See `astrobwt/build.rs`
for the `DERO_CC_PGO` / `DERO_CC_PGO_NO_RT` / `DERO_CC_LTO` env handling.
