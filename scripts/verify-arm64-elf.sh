#!/usr/bin/env bash
# Assert an arm64 miner binary matches its artifact policy.
#
# Two arm64 artifact flavors exist since v0.2.7:
#
#   static-pie (default) -- aarch64-unknown-linux-musl, generic arm64 Linux.
#     ET_DYN, NO PT_INTERP, PT_TLS present with p_align >= 0x40.
#   bionic               -- aarch64-linux-android, the Termux/Android artifact.
#     ET_DYN, PT_INTERP = /system/bin/linker64, DT_NEEDED in an allowlist,
#     every PT_LOAD >= 16 KB-aligned, PT_TLS (if present) p_align >= 0x40.
#
# Android's loader rejects ET_EXEC ("has unexpected e_type: 2"), and a QEMU
# smoke test cannot catch loader-policy regressions (qemu-user has no bionic),
# so release and CI dry-run both gate on these byte/ELF-level checks. The
# magic/e_machine/e_type probes are byte-identical to scripts/termux-setup.sh.
#
# Usage: verify-arm64-elf.sh <path-to-binary> [static-pie|bionic]
set -euo pipefail
BIN="${1:?usage: verify-arm64-elf.sh <path-to-binary> [static-pie|bionic]}"
MODE="${2:-static-pie}"
case "$MODE" in
  static-pie|bionic) ;;
  *) echo "FAIL: unknown mode '$MODE' (want static-pie or bionic)" >&2; exit 2 ;;
esac

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

# e_type: 2 bytes LE at offset 16. 03 00 = ET_DYN; BOTH flavors are PIEs, so
# e_type cannot discriminate them -- PT_INTERP below does.
etype="$(od -An -tx1 -j16 -N2 "$BIN" | tr -d ' \n')"
if [ "$etype" != "0300" ]; then
  echo "FAIL: e_type bytes are $etype, want 0300 (ET_DYN/PIE)" >&2
  exit 1
fi

# Extract via sed/awk over full readelf output (never grep -q): -q exits at
# first match, and under pipefail a SIGPIPE'd readelf would flip a gate's
# answer in exactly the direction it exists to catch.
interp="$(readelf -lW "$BIN" |
  sed -n 's/.*\[Requesting program interpreter: \(.*\)\]/\1/p')"
tls_align="$(readelf -lW "$BIN" | awk '$1 == "TLS" {print $NF}')"

if [ "$MODE" = static-pie ]; then
  # A static-PIE must not request a dynamic loader.
  if [ -n "$interp" ]; then
    echo "FAIL: PT_INTERP=$interp (dynamic PIE, not static-PIE)" >&2
    exit 1
  fi
  # PT_TLS alignment: hard gate. "No Android loader involvement once
  # PT_INTERP is absent" turned out to be false: Termux cannot exec() from
  # app data (Android 10+ W^X) and routes every binary through bionic's
  # linker64, which aborts any executable whose PT_TLS p_align is < 64
  # ("executable's TLS segment is underaligned: ... needs to be at least 64
  # for ARM64 Bionic"). Traced on-device: v0.2.5 shipped p_align 0x8 and
  # SIGABRTed on SM-S938B / Android 16. src/main.rs (bionic_tls_align) is
  # what makes the linker emit 0x40; a missing PT_TLS would mean that pad
  # was dropped from the build, so it fails too. (Termux is served by the
  # separate bionic artifact since v0.2.7; this binary stays for generic
  # arm64 Linux and anyone who fetches it by hand.)
  echo "PT_TLS p_align = ${tls_align:-<no PT_TLS>}"
  if [ -z "$tls_align" ] || [ "$((tls_align))" -lt 64 ]; then
    echo "FAIL: PT_TLS p_align ${tls_align:-<missing>} < 0x40 -- bionic's linker64 aborts this on Android" >&2
    exit 1
  fi
  exit 0
fi

# ---- bionic mode (aarch64-linux-android artifact) ----
if [ "$interp" != "/system/bin/linker64" ]; then
  echo "FAIL: PT_INTERP is '${interp:-<none>}', want /system/bin/linker64" >&2
  echo "      (a musl static-PIE is also ET_DYN -- wrong artifact packaged?)" >&2
  exit 1
fi
echo "PT_INTERP = $interp"

# PT_TLS-if-present. rustc 1.97's aarch64-linux-android has no
# target_thread_local, so std lowers thread_local! to pthread keys and this
# build emits NO PT_TLS -- nothing for bionic's
# StaticTlsLayout::reserve_exe_segment_and_tcb to reject, which is why the
# musl TLS anchor in src/main.rs is deliberately NOT extended to android. If
# a toolchain bump ever flips native TLS on, this gate catches a p_align-8
# segment before it reaches a phone; echoing which branch held makes that
# flip a visible log diff instead of a silent pass.
if [ -z "$tls_align" ]; then
  echo "PT_TLS: absent (expected -- no target_thread_local on this target)"
else
  echo "PT_TLS p_align = $tls_align"
  if [ "$((tls_align))" -lt 64 ]; then
    echo "FAIL: PT_TLS p_align $tls_align < 0x40 -- bionic's linker64 aborts this" >&2
    exit 1
  fi
fi

# 16 KB-page devices (Android 15+): every PT_LOAD must be >= 0x4000-aligned
# (0x10000 from a future toolchain would be fine too). Turns the
# -Wl,-z,max-page-size=16384 link-arg from an invisible flag into a checked
# property, so NDK drift on the runner image cannot silently regress it.
load_fail=0
for la in $(readelf -lW "$BIN" | awk '$1 == "LOAD" {print $NF}'); do
  if [ "$((la))" -lt 16384 ]; then
    echo "FAIL: PT_LOAD p_align $la < 0x4000 (16 KB pages)" >&2
    load_fail=1
  fi
done
[ "$load_fail" -eq 0 ] || exit 1
echo "PT_LOAD p_align >= 0x4000 (16 KB-page safe)"

# DT_NEEDED: record what the binary links against. TODO(observe-then-gate):
# the allowlist below goes live only after reading the real list from the CI
# dry-run log -- guessing it risks the release job rejecting a legitimate
# entry at tag time.
mapfile -t needed < <(readelf -dW "$BIN" |
  sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
echo "DT_NEEDED: ${needed[*]:-<none>}"
# for so in "${needed[@]}"; do
#   case "$so" in
#     libc.so|libm.so|libdl.so) ;;
#     *) echo "FAIL: unexpected DT_NEEDED '$so' -- not on a stock device or not shipped" >&2; exit 1 ;;
#   esac
# done
