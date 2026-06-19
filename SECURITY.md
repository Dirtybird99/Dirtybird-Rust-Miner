# Security Policy

This policy covers **Dirtybird Rust Miner** (https://github.com/Dirtybird99/Dirtybird-Rust-Miner).

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use:

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the Security
   tab of the [Dirtybird99/Dirtybird-Rust-Miner](https://github.com/Dirtybird99/Dirtybird-Rust-Miner/security)
   repository.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix/release**: Depends on severity

## Scope

This policy applies to the latest version on the `main` branch, built from source with the
Rust toolchain (`cargo build --release`, or `cargo zigbuild` for cross-targets).

Please note:

- On x86-64 the miner uses SHA-NI + AVX2 fast paths (runtime-detected, with portable
  fallbacks); on aarch64 it uses the portable suffix array + soft SHA. Reports about
  unrelated hardware or toolchain versions are out of scope.
- This is a CPU miner that connects to a DERO daemon/pool over TLS-WebSocket. When
  reporting, please describe the configuration (daemon address, threads) so the issue can
  be reproduced.
- Do not include real wallet addresses or private network details in public reports.
