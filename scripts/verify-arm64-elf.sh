#!/usr/bin/env bash
# Assert the arm64 miner binary is a static-PIE, i.e. loadable by Android 10+.
#
# Android's loader rejects ET_EXEC binaries ("has unexpected e_type: 2"), and a
# QEMU smoke test cannot catch that regression -- qemu-user happily executes
# ET_EXEC -- so the release and CI dry-run both gate on these byte-level checks.
# The e_type probe is byte-identical to the one scripts/termux-setup.sh runs
# before first exec on a phone.
#
# Usage: verify-arm64-elf.sh <path-to-binary>
set -euo pipefail
BIN="${1:?usage: verify-arm64-elf.sh <path-to-binary>}"

# ELF magic, then e_machine (aarch64 = 0xB7 little-endian at offset 18).
magic="$(od -An -tx1 -N4 "$BIN" | tr -d ' \n')"
if [ "$magic" != "7f454c46" ]; then
  echo "FAIL: not an ELF binary (magic $magic)" >&2
  exit 1
fi
machine="$(od -An -tx1 -j18 -N2 "$BIN" | tr -d ' \n')"
if [ "$machine" != "b700" ]; then
  echo "FAIL: e_machine bytes are $machine, want b700 (aarch64)" >&2
  exit 1
fi

# e_type: 2 bytes LE at offset 16. 03 00 = ET_DYN (PIE); 02 00 = ET_EXEC.
etype="$(od -An -tx1 -j16 -N2 "$BIN" | tr -d ' \n')"
if [ "$etype" != "0300" ]; then
  echo "FAIL: e_type bytes are $etype, want 0300 (ET_DYN/PIE)" >&2
  exit 1
fi

# A static-PIE must not request a dynamic loader. Plain grep (not -q): -q
# exits at first match, and under pipefail a SIGPIPE'd readelf would flip
# this gate's answer in exactly the direction it exists to catch.
if readelf -lW "$BIN" | grep 'INTERP' >/dev/null; then
  echo "FAIL: binary has PT_INTERP (dynamic PIE, not static-PIE)" >&2
  exit 1
fi

# PT_TLS alignment: informational. Static musl initializes TLS from its own
# program headers (no Android loader involvement once PT_INTERP is absent), so
# a small p_align is not a known failure mode for this toolchain's artifact;
# the sibling Zig miner hard-fails < 0x40 against a different toolchain. Flip
# this to a hard fail only if an on-device crash is ever traced to TLS align.
tls_align="$(readelf -lW "$BIN" | awk '$1 == "TLS" {print $NF}')"
echo "PT_TLS p_align = ${tls_align:-<no PT_TLS>}"
if [ -n "$tls_align" ] && [ "$((tls_align))" -lt 64 ]; then
  echo "WARN: PT_TLS p_align $tls_align < 0x40 (Zig-miner guard threshold)" >&2
fi
