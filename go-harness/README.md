# go-harness — canonical test-vector generator

Regenerates the golden vectors the Rust suites in
`astrobwt/tests/{prologue,full,pow16,sais}_vectors.rs` load from `../vectors/*.json`.
These come from the **canonical DERO Go reference**, so they cross-check the Rust
port against an implementation it was NOT derived from.

```sh
./run.sh            # writes ../vectors/{astrobwt,pow16,sais}.json
```

Requires Go 1.21+. `run.sh` first runs a known-answer self-check
(`AstroBWTv3("a") == 54e2324d…`, the 10 vectors from derohe's own `pow_test.go`)
and aborts before writing if it fails — a mis-copied reference cannot emit vectors.

## Layout

- `deroref/` — a **verbatim copy** of `github.com/deroproject/derohe/astrobwt`
  (and its `astrobwtv3` subpackage), **BSD-3-Clause** (© DERO Foundation / The Go
  Authors — the retained `deroref/*/LICENSE.txt`; note this is the package license,
  distinct from derohe's repo-root research license). The only additions are:
  - `deroref/astrobwtv3/harness_hooks.go` — exported `Hx*` globals + `Sais832`.
  - `deroref/harness_sais.go` — exported `Sais816`.
  - ~10 lines in `deroref/astrobwtv3/pow.go` (each marked `// harness:`) that copy
    intermediates into the `Hx*` globals as a side effect. The hash return value is
    untouched, which is what the KAT self-check verifies.
- `main.go` — the dumper. `go run . <astrobwt|pow16|sais|selfcheck>`.

## Why a copy instead of importing derohe

The op-loop intermediates the `full_vectors` suite checks (tries, prev_lhash,
step3, the stream fingerprint) are locals inside `AstroBWTv3`; pristine derohe
exposes no hook for them. Rather than duplicate the 256-case op switch (transcription
risk), the reference is copied verbatim and instrumented with side-effect writes,
then proven faithful by the KAT gate.

## Which SA-IS engine

`sa32` uses the **astrobwtv3** package's unrestricted `sais_8_32` (handles the full
98303-byte range — the fixed-9973 `astrobwt` variant panics above 32767). `sa16` uses
the `astrobwt` package's `sais_8_16`. The dumper cross-checks the two agree
element-for-element (the suffix array is unique) before trusting either.
