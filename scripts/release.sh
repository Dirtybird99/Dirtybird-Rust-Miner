#!/usr/bin/env bash
#
# Dirtybird Rust Miner -- build all release binaries + packages into dist/.
#
# Usage:  scripts/release.sh [version]
#   version defaults to the latest git tag, else v0.0.0-dev.
#
# Cross-compiles every target from one host via cargo-zigbuild (zig cc compiles the
# vendored C suffix array for each target). Produces, per platform, an archive with the
# binary plus README, LICENSE, THIRD-PARTY-LICENSES, the launcher, and (Linux) the HiveOS
# config/. Plus a HiveOS/MMPOS package and a SHA256SUMS.txt.
#
# x86-64 builds use the SHA-NI + AVX2 (x86_64_v3+sha) baseline and are PGO-optimized from
# the committed _pgo/merged.profdata (zig cc is clang-19, matching the profile). PGO and
# the CPU baseline are applied automatically by build.rs per target; ARM builds skip them.
# Hash output is byte-identical on every target.
set -euo pipefail
cd "$(dirname "$0")/.."

VER="${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0-dev)}"
DIST="dist"
NAME="Dirtybird-Rust-Miner"
BIN="dero-miner"

rm -rf "$DIST"
mkdir -p "$DIST"

stage_common() { cp README.md LICENSE THIRD-PARTY-LICENSES script.sh "$1"/; }

zb() { cargo zigbuild --release --target "$1" --bin "$BIN"; }

PY="$(command -v python3 || command -v python)"
zipdir() { # $1 = folder name under $DIST (also the archive stem)
  "$PY" - "$DIST" "$1" <<'PY'
import sys, shutil, os
dist, name = sys.argv[1], sys.argv[2]
shutil.make_archive(os.path.join(dist, name), "zip", root_dir=dist, base_dir=name)
PY
}

mk_tar() { # $1=archive-name  $2=rust-target
  local name="$1" target="$2" d="$DIST/$1"
  mkdir -p "$d"
  zb "$target"
  cp "target/$target/release/$BIN" "$d/$BIN"
  chmod +x "$d/$BIN"
  stage_common "$d"
  cp -r config "$d/config"
  tar -C "$DIST" --mode='u+rwx,go+rx' -czf "$DIST/$name.tar.gz" "$name"
  rm -rf "$d"
}

# ---- Linux tarballs (static musl = runs on any Linux) ------------------------
mk_tar "${NAME}-amd64-${VER}" x86_64-unknown-linux-musl
mk_tar "${NAME}-arm64-${VER}" aarch64-unknown-linux-musl

# ---- Windows zip -------------------------------------------------------------
zb x86_64-pc-windows-gnu
wd="$DIST/${NAME}-win64-${VER}"
mkdir -p "$wd"
cp "target/x86_64-pc-windows-gnu/release/$BIN.exe" "$wd/"
stage_common "$wd"
cp start.bat "$wd/"
zipdir "${NAME}-win64-${VER}"
rm -rf "$wd"

# ---- HiveOS / MMPOS package (static amd64 binary + h-scripts) ----------------
hd="$DIST/hive/$BIN"
mkdir -p "$hd"
cp config/h-manifest.conf config/h-run.sh config/h-config.sh config/h-stats.sh README.md LICENSE "$hd/"
zb x86_64-unknown-linux-musl
cp "target/x86_64-unknown-linux-musl/release/$BIN" "$hd/$BIN"
chmod +x "$hd/$BIN" "$hd"/*.sh
tar -C "$DIST/hive" --mode='u+rwx,go+rx' -czf "$DIST/dirtybird-rust-miner-${VER}.hiveos_mmpos.amd64.tar.gz" "$BIN"
rm -rf "$DIST/hive"

# ---- checksums ---------------------------------------------------------------
( cd "$DIST" && sha256sum *.zip *.tar.gz > SHA256SUMS.txt )

# ---- mirror archives into the repo tree (browsable releases/<version>/) -------
REL="releases/$VER"
mkdir -p "$REL"
cp "$DIST"/*.zip "$DIST"/*.tar.gz "$DIST/SHA256SUMS.txt" "$REL"/
echo "mirrored archives into $REL/"

echo "=== built into $DIST/ ==="
ls -1 "$DIST"
