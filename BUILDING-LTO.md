# Building this miner

There are two builds. The **stable** build is the normal one and works out of the
box. The **nightly cross-language-LTO** build is ~1.5% faster at peak (it is the one
that edges the Dirtybird C miner — see [BENCHMARKS.md](BENCHMARKS.md)) but needs a
nightly toolchain whose LLVM version matches the clang that compiles the vendored
v114 descriptor-SA C++.

The performance feature flag is `v114` (the vendored descriptor suffix array, ~75–88%
of each hash). All real builds use `--features v114`.

---

## 1. Stable build (recommended for normal use)

**Requires `clang-cl` on `PATH`** (LLVM, e.g. `C:\Program Files\LLVM\bin`) — `build.rs` forces
clang-cl with `-fno-vectorize`/`-fno-slp-vectorize` to dodge an MSVC `cl.exe` miscompile of the
v114 descriptor SA. Without it the build fails with `failed to find tool "clang-cl"`.

```sh
# from the repo root
cargo build --release -p dero-miner --features v114
# binary: target/release/dero-miner.exe
```

Make sure `.cargo/config.toml` does **not** exist (only `.cargo/config.toml.example`
is committed). A stray live config with the `[unstable]` table breaks stable builds.

Sanity-check correctness + speed:

```sh
target/release/dero-miner.exe --bench                 # offline AstroBWTv3 table
target/release/dero-miner.exe --sustained -t 24 --secs 30   # honest scoreboard
cargo test -p astrobwt --features v114 fused_v114_matches_reference_fuzz   # byte-exact
```

The stable build is roughly a **−1% tie** with the canonical PGO C miner at peak.

---

## 2. Nightly cross-language-LTO build (peak performance)

This compiles the Rust crates **and** the vendored v114 C++ to LLVM bitcode and LTO-links
them together, with a dual rustc+clang PGO profile applied across the inlined boundary.
That is what flips the peak result from a tie to a narrow win vs the C miner.

### Prerequisites
- A nightly `rustc` whose bundled LLVM matches your `clang-cl` major version
  (this win was built with nightly LLVM 22.1.x ≈ clang 22.1.x). Mismatched LLVM
  versions produce incompatible LTO bitcode and the link fails.
- `lld-link` and `clang-cl` on PATH (LLVM toolchain).

### Build (the committed profile is used as-is)
```sh
cp .cargo/config.toml.example .cargo/config.toml      # enable the LTO config
DERO_CC_PGO=_pgo/dual.profdata DERO_CC_LTO=1 \
  cargo +nightly build \
    --target x86_64-pc-windows-msvc \
    -Z target-applies-to-host \
    -p dero-miner --profile release-lto --features v114
# binary: target/x86_64-pc-windows-msvc/release-lto/dero-miner.exe
rm .cargo/config.toml                                  # restore stable builds
```

- `--target x86_64-pc-windows-msvc` is **required** — it excludes host proc-macros from
  the linker-plugin-lto flags (otherwise the proc-macro `prefer-dynamic` build conflicts
  with LTO on Windows).
- Benign `SHA256_*` shim hash-mismatch warnings from the PGO profile are expected and
  discarded.

Verify byte-exactness under LTO before trusting any speed number:
```sh
cargo +nightly test --target x86_64-pc-windows-msvc -p astrobwt --features v114 \
  fused_v114_matches_reference_fuzz
```

---

## 3. Regenerating the PGO profile (optional)

`_pgo/dual.profdata` is committed, so you normally don't need this. To regenerate it
(e.g. for a different CPU), instrument **without** LTO, run the training workload, and
merge:

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
