# Dirtybird Rust Miner

A fast, cross-platform **DERO** (AstroBWTv3) CPU miner written in Rust. Connects to a DERO
daemon or pool over TLS-WebSocket getwork and mines with a 2-way batched AstroBWTv3 pipeline.

- **Zero dev fee.** Every hash is yours.
- **Byte-exact.** The hash is consensus-correct — gated on the `pow("a")` KAT and per-stage
  golden vectors on every build (including an emulated aarch64 run in CI).
- **Cross-platform.** Windows x86-64, Linux x86-64 and aarch64 (static musl — runs anywhere).
- **Fast on x86-64.** Hardware SHA-NI + AVX2 fast paths and a profile-guided (PGO) build;
  on aarch64 it transparently falls back to a portable soft-SHA + scalar path (same hash).

> The suffix-array core (~85% of the work) is the same vendored C/C++ the reference DERO
> miners use; the rest is native Rust. See `THIRD-PARTY-LICENSES` for attribution.

## Download

Grab a prebuilt archive for your platform from the
[**Releases**](https://github.com/Dirtybird99/Dirtybird-Rust-Miner/releases) page:

| Platform            | Asset                                              |
| ------------------- | -------------------------------------------------- |
| Windows x64         | `Dirtybird-Rust-Miner-win64-vX.Y.Z.zip`            |
| Linux x86-64        | `Dirtybird-Rust-Miner-amd64-vX.Y.Z.tar.gz`         |
| Linux aarch64 (ARM) | `Dirtybird-Rust-Miner-arm64-vX.Y.Z.tar.gz`         |
| HiveOS / MMPOS      | `dirtybird-rust-miner-vX.Y.Z.hiveos_mmpos.amd64.tar.gz` |

Verify your download against `SHA256SUMS.txt`.

## Quick start

Unpack the archive and run the miner. It defaults to a public DERO community pool; pass your
own wallet to get paid:

```sh
# Linux/macOS
./dero-miner -w dero1yourwalletaddress...

# Windows (or double-click start.bat)
dero-miner.exe -w dero1yourwalletaddress...
```

Common flags (`--help` for all):

| Flag                | Meaning                                                | Default                             |
| ------------------- | ------------------------------------------------------ | ----------------------------------- |
| `-d, --daemon`      | Daemon/pool `host:port` (TLS-WebSocket getwork)        | `community-pools.mysrv.cloud:10300` |
| `-w, --wallet`      | DERO wallet address (rewards paid here)                | project pool wallet                 |
| `-t, --threads`     | Worker threads (`0` = auto-detect physical cores)      | `0`                                 |
| `--affinity`        | Pin threads to P-cores first + raise priority          | on                                  |

## Build from source

Requires the [Rust toolchain](https://rustup.rs). On x86-64, the vendored C/C++ is built
with `clang` (set `CC`/`CXX` to clang if `cc.exe`/`gcc` is picked up).

```sh
cargo build --release          # native build
./target/release/dero-miner --help
```

### Cross-compile (every platform from one host)

Uses [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) + [Zig](https://ziglang.org)
as the C cross-compiler — the same way the release artifacts are built:

```sh
cargo install cargo-zigbuild
rustup target add x86_64-pc-windows-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

`scripts/release.sh <version>` builds and packages all platforms into `dist/`.

## Performance

On x86-64 the release binaries use SHA-NI + AVX2 and are PGO-optimized from the committed
`_pgo/merged.profdata`. aarch64 builds use the portable suffix array + soft SHA — correct,
just not hand-accelerated. CI runs a synthetic throughput smoke on each push; it is **not**
a representative benchmark (shared runners).

## License

MIT — see [`LICENSE`](LICENSE). Third-party components (the libsais and v1.14 descriptor
suffix arrays, etc.) retain their own licenses and copyright notices — see
[`THIRD-PARTY-LICENSES`](THIRD-PARTY-LICENSES).
