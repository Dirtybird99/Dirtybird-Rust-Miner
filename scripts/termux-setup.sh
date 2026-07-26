#!/usr/bin/env bash
#
# DIRTYBIRD Rust Miner -- Termux (Android) setup & launcher.
#
# Download-only installer: fetches the pre-built aarch64 static-PIE release
# from GitHub, verifies it against the published SHA256SUMS.txt, prompts for
# daemon/wallet/threads, acquires a wake-lock so Android Doze doesn't kill the
# miner, and runs it with auto-restart.
#
# Ported from Dirtybird-C-Miner scripts/termux-setup.sh (PR #2 by moralpriest,
# as reworked on that repo's master). Key divergence: this miner has NO config
# file -- every setting is a CLI flag -- so choices persist in settings.env
# here and are re-validated on every read before landing on the command line.
#
# The shebang is env-bash on purpose: Termux has no /bin/bash.
#
# Usage:
#   bash scripts/termux-setup.sh                # install (if needed) + run
#   bash scripts/termux-setup.sh --update       # re-download the latest release
#   bash scripts/termux-setup.sh --reconfigure  # re-prompt for daemon/wallet/threads
#   bash scripts/termux-setup.sh --uninstall    # remove installed files
#   bash scripts/termux-setup.sh --help         # this message
#
set -euo pipefail

REPO="Dirtybird99/Dirtybird-Rust-Miner"
NAME="Dirtybird-Rust-Miner"
DEFAULT_WALLET="dero1qyvuemd6z0uzsx5ufc99f0jhyzvvpysmrd2t3526ht7a9dfh7jve2qqt0vu5y"
INSTALL_DIR="$HOME/dirtybird-rust-miner"
BINARY_NAME="dero-miner"
VERSION_FILE=".installed_version"
SETTINGS_FILE="settings.env"
# First release whose arm64 binary is a static-PIE. Older releases ship ET_EXEC
# binaries that Android 10+ refuses to exec ("has unexpected e_type: 2"), so
# they are refused up front rather than failing cryptically after download.
MIN_TAG="v0.2.5"

# ── daemon / pool menu ────────────────────────────────────────────────────────
# The two pools hand out low-difficulty shares, so a phone sees progress every
# few seconds; the solo daemons hand out real network work, which is the same
# expected earnings for a given hashrate but can leave a phone sitting for
# hours between rewards -- and that reads as a broken miner. Hence the labels.
#
# Port matters as much as host: dero.rabidmining.com serves solo daemon work on
# :10100 and pool shares on :10300. The pool port is the one worth offering.
#
# No scheme prefix: the miner hands the address straight to the socket resolver
# and takes the SNI name from everything before the LAST ':' (src/tls.rs), so a
# "ws://" prefix becomes part of the hostname and resolution fails.
#
# Verified 2026-07-25 -- all four completed this miner's own TLS handshake and
# 'GET /ws/<wallet>' WebSocket upgrade and served a job. A plain TCP probe is
# not enough to re-check them: the miner only ever speaks TLS. To re-check one
# with the miner itself, watch for the first job to arrive:
#   ./dero-miner -w WALLET -d HOST:PORT -t 1 --debug   # expect: recv: {"jobid":...
declare -a DAEMON_NAMES=(
    "Community Pools"
    "Rabid Mining"
    "dero-node.net"
    "DERO Foundation"
    "Custom address"
)
declare -a DAEMON_ADDRS=(
    "community-pools.mysrv.cloud:10300"
    "dero.rabidmining.com:10300"
    "dero-node.net:10100"
    "node.derofoundation.org:10100"
    ""
)
declare -a DAEMON_KINDS=(
    "pool -- rewards every few seconds, best for phones"
    "pool -- rewards every few seconds, best for phones"
    "solo node -- a phone may wait hours between rewards"
    "solo node -- full blocks only, 9x the work per reward"
    ""
)

# ── colours (safe for Termux) ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { printf "${GREEN}[*]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()   { printf "${RED}[x]${NC} %s\n" "$*" >&2; }
note()  { printf "${CYAN}[i]${NC} %s\n" "$*"; }

# ── validators ────────────────────────────────────────────────────────────────
# Every value that reaches the miner's command line or settings.env passes one
# of these, on write AND on read-back.
valid_daemon()  { printf '%s' "$1" | grep -qE '^[A-Za-z0-9._-]+:[0-9]{1,5}$'; }
valid_wallet()  { printf '%s' "$1" | grep -qE '^(dero1|deto1)[a-z0-9]{60,}$'; }
valid_threads() { printf '%s' "$1" | grep -qE '^[1-9][0-9]*$' && [ "$1" -le 2048 ]; }

# ── flags ─────────────────────────────────────────────────────────────────────
FORCE_UPDATE=false
RECONFIGURE=false
UNINSTALL=false

usage() {
    cat <<'USAGE'
DIRTYBIRD Rust Miner -- Termux (Android) setup & launcher.

Downloads the pre-built aarch64 static-PIE release, verifies its checksum,
prompts for daemon/wallet/threads (persisted in settings.env), acquires a
wake-lock so Android Doze doesn't pause mining, and runs with auto-restart.

Usage:
  bash scripts/termux-setup.sh                # install (if needed) + run
  bash scripts/termux-setup.sh --update       # re-download the latest release
  bash scripts/termux-setup.sh --reconfigure  # re-prompt for daemon/wallet/threads
  bash scripts/termux-setup.sh --uninstall    # remove installed files
  bash scripts/termux-setup.sh --help         # this message

Requires aarch64 (64-bit ARM) Android and release v0.2.5 or newer. Install
termux-api ("pkg install termux-api" plus the Termux:API app) for wake-lock
and battery-status support.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --update)       FORCE_UPDATE=true; shift ;;
        --reconfigure)  RECONFIGURE=true; shift ;;
        --uninstall)    UNINSTALL=true; shift ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) err "Unknown option: $1"; exit 2 ;;
    esac
done

# ── step 1: handle --uninstall (needs no dependencies, so it comes first) ─────
if [ "$UNINSTALL" = true ]; then
    info "Removing $INSTALL_DIR ..."
    rm -rf "$INSTALL_DIR"
    info "Done. (Settings and binaries removed.)"
    exit 0
fi

# ── step 2: detect platform ───────────────────────────────────────────────────
ARCH="$(uname -m)"
if [ "$(uname -o 2>/dev/null)" != "Android" ]; then
    err "This script is for Android/Termux only."
    err "On other platforms, download the matching release manually:"
    err "  https://github.com/$REPO/releases  (${NAME}-{amd64,arm64,win64}-v*)"
    exit 1
fi
if [ "$ARCH" != "aarch64" ]; then
    err "Android on $ARCH is not supported by this script."
    err "Only aarch64 (64-bit ARM) Android is supported."
    err "Other platforms can download a release manually:"
    err "  https://github.com/$REPO/releases"
    exit 1
fi

# ── step 3: install deps ──────────────────────────────────────────────────────
info "Checking dependencies..."
need_install=()
for cmd in tar jq; do
    command -v "$cmd" &>/dev/null || need_install+=("$cmd")
done
# prefer curl, fall back to wget
if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    need_install+=(curl)
fi

if [ "${#need_install[@]}" -gt 0 ]; then
    info "Installing: ${need_install[*]}"
    pkg update -y >/dev/null 2>&1 || true
    pkg install -y "${need_install[@]}" >/dev/null 2>&1 || {
        err "Failed to install: ${need_install[*]}"
        err "Run: pkg install -y ${need_install[*]}"
        exit 1
    }
fi
info "Dependencies OK."

# ── step 4: get the binary ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# HTTP fetcher (stdout): curl preferred, wget fallback. -f matters: without it
# a GitHub error page would flow onward as if it were the payload.
fetch() {
    if command -v curl &>/dev/null; then
        curl -fsSL "$1"
    else
        wget -qO- "$1"
    fi
}
# HTTP fetcher (to file $2).
fetch_to() {
    if command -v curl &>/dev/null; then
        curl -fsSL "$1" -o "$2"
    else
        wget -q -O "$2" "$1"
    fi
}

# The binary existence check matters: an update interrupted between the
# old-binary clear and the relocation would leave a stale version stamp with
# no binary, and a stamp-only fast path would then loop forever on exec 127.
if [ "$FORCE_UPDATE" = false ] && [ -f "$VERSION_FILE" ] && [ -x "./$BINARY_NAME" ]; then
    info "Already installed ($(cat "$VERSION_FILE")). Use --update to upgrade."
else
    info "Fetching latest release info..."
    # Latest RELEASE, never latest tag: tags can exist with no published
    # release (failed release runs burn the version number).
    LATEST_TAG="$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
        | jq -r '.tag_name // empty' 2>/dev/null || true)"

    if [ -z "$LATEST_TAG" ]; then
        err "Could not determine latest release. Check network connection."
        exit 1
    fi
    # The tag flows into URLs, filenames, and a grep pattern below -- hold it
    # to the same strict form the release workflow enforces.
    if ! printf '%s' "$LATEST_TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
        err "Unexpected release tag format: $LATEST_TAG"
        exit 1
    fi
    info "Latest release: $LATEST_TAG"

    # Releases are immutable, so the tag alone is trustworthy evidence of
    # whether the arm64 binary is Android-runnable (static-PIE since MIN_TAG).
    if [ "$LATEST_TAG" != "$MIN_TAG" ] &&
       [ "$(printf '%s\n' "$MIN_TAG" "$LATEST_TAG" | sort -V | head -n1)" != "$MIN_TAG" ]; then
        err "Release $LATEST_TAG predates Android support."
        err "Releases before $MIN_TAG ship a non-PIE arm64 binary that Android refuses to run."
        err "Wait for $MIN_TAG or newer: https://github.com/$REPO/releases"
        exit 1
    fi

    ARCHIVE="${NAME}-arm64-${LATEST_TAG}.tar.gz"
    BASE_URL="https://github.com/$REPO/releases/download/${LATEST_TAG}"

    info "Downloading $ARCHIVE ..."
    fetch_to "$BASE_URL/$ARCHIVE" "$ARCHIVE" || { err "Download failed."; exit 1; }

    # Same-origin defense-in-depth against corrupted/truncated downloads, not
    # compromise resistance: the sums come from the same release the tarball
    # does. The release pipeline generates and self-verifies this file.
    info "Verifying checksum..."
    fetch_to "$BASE_URL/SHA256SUMS.txt" "SHA256SUMS.txt" || {
        err "Could not download SHA256SUMS.txt from the release."; exit 1; }
    # Anchored so a future sibling asset (e.g. "$ARCHIVE.sig") can never add a
    # second line to the sum file. The tag was format-checked above, so '.' is
    # the only regex-special character in the name.
    grep -E "^[0-9a-f]{64}  ${ARCHIVE//./\\.}\$" SHA256SUMS.txt > "$ARCHIVE.sum" || {
        err "SHA256SUMS.txt has no entry for $ARCHIVE."; exit 1; }
    sha256sum -c "$ARCHIVE.sum" || { err "Checksum mismatch for $ARCHIVE."; exit 1; }
    rm -f "$ARCHIVE.sum" SHA256SUMS.txt

    info "Extracting..."
    # Clear the previous install FIRST, unconditionally. Guarding the relocate
    # on "is the binary missing?" is how the C-miner ancestor silently pinned
    # users to their first-installed version: the tarball always nests the
    # binary one directory deep, so after the first install the guard never
    # fired while the version stamp advanced. Also sweep any package directory
    # an interrupted earlier run left behind.
    rm -f "./$BINARY_NAME"
    find . -maxdepth 1 -type d -name "${NAME}-*" -exec rm -rf {} + 2>/dev/null || true

    tar xzf "$ARCHIVE"
    rm -f "$ARCHIVE"

    # The tarball nests everything under ${NAME}-arm64-vX.Y.Z/; lift the
    # binary out to $INSTALL_DIR.
    NESTED="$(find . -maxdepth 2 -name "$BINARY_NAME" -type f | head -1)"
    if [ -z "$NESTED" ]; then
        err "Extraction succeeded but $BINARY_NAME binary not found."
        exit 1
    fi
    mv -f "$NESTED" "./$BINARY_NAME"
    # dirname is never "." here: the binary was cleared above, so find can
    # only have matched inside the freshly extracted package directory.
    rm -rf "$(dirname "$NESTED")" 2>/dev/null || true
    chmod +x "./$BINARY_NAME"

    # Backstop behind the version floor: byte-check that the binary really is
    # an aarch64 static-PIE before first exec, so a hypothetical regressed
    # release fails with an actionable message instead of a cryptic exec
    # error. Same probes the release CI asserts (scripts/verify-arm64-elf.sh).
    if [ "$(od -An -tx1 -N4 "./$BINARY_NAME" | tr -d ' \n')" != "7f454c46" ]; then
        err "$BINARY_NAME is not an ELF binary (corrupt download?)."
        exit 1
    fi
    if [ "$(od -An -tx1 -j18 -N2 "./$BINARY_NAME" | tr -d ' \n')" != "b700" ]; then
        err "$BINARY_NAME is not an aarch64 binary (wrong tarball?)."
        exit 1
    fi
    ETYPE="$(od -An -tx1 -j16 -N2 "./$BINARY_NAME" | tr -d ' \n')"
    if [ "$ETYPE" != "0300" ]; then
        err "This $BINARY_NAME build is not position-independent (e_type=$ETYPE);"
        err "Android cannot run it. Use release $MIN_TAG or newer:"
        err "  https://github.com/$REPO/releases"
        exit 1
    fi

    # Exec probe: catches a corrupt or incompatible download before mining.
    if ! "./$BINARY_NAME" --version >/dev/null 2>&1; then
        err "$BINARY_NAME failed to execute on this device."
        err "Re-run with --update; if it persists, open an issue with your"
        err "Android version and device model."
        exit 1
    fi
    info "Installed $LATEST_TAG ($("./$BINARY_NAME" --version))."
    echo "$LATEST_TAG" > "$VERSION_FILE"
fi

# ── step 5: configure (daemon / wallet / threads) ─────────────────────────────
# Rejected input re-prompts instead of exiting: these are the interactive steps
# a phone user is likely to fat-finger, and the download has already succeeded
# by now -- throwing the whole install away over a typo is a poor trade. Every
# read comes from /dev/tty (stdin is the script body under curl | bash) and
# treats EOF as "accept the default", so a non-interactive run terminates.
if [ "$RECONFIGURE" = true ] || [ ! -f "$SETTINGS_FILE" ]; then
    printf "\n"
    printf "${CYAN}Select a daemon/pool:${NC}\n\n"
    for i in "${!DAEMON_NAMES[@]}"; do
        if [ -n "${DAEMON_ADDRS[$i]}" ]; then
            printf "  ${GREEN}[%d]${NC} %-16s %s\n" \
                "$((i + 1))" "${DAEMON_NAMES[$i]}" "${DAEMON_ADDRS[$i]}"
            printf "      %-16s ${YELLOW}%s${NC}\n" "" "${DAEMON_KINDS[$i]}"
        else
            printf "  ${GREEN}[%d]${NC} %s\n" "$((i + 1))" "${DAEMON_NAMES[$i]}"
        fi
    done
    printf "\n"

    DAEMON=""
    while [ -z "$DAEMON" ]; do
        read -rp "  Choice [1]: " CHOICE </dev/tty || CHOICE=""
        CHOICE="${CHOICE:-1}"

        if ! printf '%s' "$CHOICE" | grep -qE '^[0-9]+$' ||
           [ "$CHOICE" -lt 1 ] || [ "$CHOICE" -gt "${#DAEMON_NAMES[@]}" ]; then
            warn "Enter a number from 1 to ${#DAEMON_NAMES[@]}."
            continue
        fi

        DAEMON="${DAEMON_ADDRS[$((CHOICE - 1))]}"
        if [ -z "$DAEMON" ]; then
            printf "\n"
            printf "${CYAN}Daemon/pool address (host:port, no scheme prefix)${NC}\n"
            read -rp "  Address: " DAEMON </dev/tty || DAEMON=""
            # Validated, not just non-empty: this string lands on the miner's
            # command line and in settings.env, and the miner resolves it
            # verbatim -- see the menu comment above for the no-scheme rule.
            if ! valid_daemon "$DAEMON"; then
                warn "Expected host:port (e.g. dero-node.net:10100)."
                DAEMON=""
            fi
        fi
    done
    info "Using: $DAEMON"

    # Wallet. The default mines to the project wallet -- deliberate, printed
    # loudly, and Enter accepts it; paste your own address to mine to yours.
    printf "\n"
    printf "${CYAN}DERO wallet address${NC}\n"
    printf "  Press Enter to mine to the ${YELLOW}project wallet${NC}:\n"
    printf "  ${GREEN}%s${NC}\n" "$DEFAULT_WALLET"
    WALLET=""
    while [ -z "$WALLET" ]; do
        read -rp "  Wallet: " INPUT_WALLET </dev/tty || INPUT_WALLET=""
        WALLET="${INPUT_WALLET:-$DEFAULT_WALLET}"
        # Prefix + length floor; the miner then bech32-validates for real and
        # refuses typos on startup, but this catches truncated pastes here,
        # while re-prompting is still cheap.
        if ! valid_wallet "$WALLET"; then
            warn "Must start with dero1 (mainnet) and be a full address."
            WALLET=""
        fi
    done

    # Threads: default max(1, cores-1); on big.LITTLE phones all-cores tends
    # to thermally throttle, so the cap is exposed rather than silent.
    CORES="$(nproc 2>/dev/null || echo 4)"
    DEFAULT_THREADS=$((CORES - 1))
    [ "$DEFAULT_THREADS" -lt 1 ] && DEFAULT_THREADS=1
    printf "\n"
    printf "${CYAN}Mining threads${NC}\n"
    THREADS=""
    while [ -z "$THREADS" ]; do
        read -rp "  Threads [${DEFAULT_THREADS}] (1-${CORES}): " INPUT_THREADS </dev/tty || INPUT_THREADS=""
        THREADS="${INPUT_THREADS:-$DEFAULT_THREADS}"
        if ! printf '%s' "$THREADS" | grep -qE '^[1-9][0-9]*$' ||
           [ "$THREADS" -gt "$CORES" ]; then
            warn "Enter a number from 1 to $CORES."
            THREADS=""
        fi
    done

    # All three values passed their validators above; settings.env is plain
    # KEY=value, never sourced, and re-validated on every read below.
    {
        printf '%s\n' "# Written by termux-setup.sh; edit via --reconfigure."
        printf 'DAEMON=%s\n' "$DAEMON"
        printf 'WALLET=%s\n' "$WALLET"
        printf 'THREADS=%s\n' "$THREADS"
    } > "$SETTINGS_FILE"
    info "Settings written to $INSTALL_DIR/$SETTINGS_FILE"
else
    info "Using existing settings (use --reconfigure to change)."
fi

# Read-back with re-validation: settings.env is user-editable, and anything
# that reaches the command line must satisfy the same rules as the prompts.
DAEMON="$(grep -E '^DAEMON=' "$SETTINGS_FILE" | head -1 | cut -d= -f2- || true)"
WALLET="$(grep -E '^WALLET=' "$SETTINGS_FILE" | head -1 | cut -d= -f2- || true)"
THREADS="$(grep -E '^THREADS=' "$SETTINGS_FILE" | head -1 | cut -d= -f2- || true)"
if ! valid_daemon "$DAEMON" || ! valid_wallet "$WALLET" || ! valid_threads "$THREADS"; then
    err "Invalid or incomplete $SETTINGS_FILE. Re-run with --reconfigure."
    exit 1
fi

# ── step 6: battery / thermal advisory ────────────────────────────────────────
# termux-* commands hang indefinitely when the termux-api package is installed
# without the Termux:API companion app, hence the timeouts.
if command -v termux-battery-status &>/dev/null; then
    BAT_JSON="$(timeout 5 termux-battery-status 2>/dev/null || true)"
    BAT_PCT="$(printf '%s' "$BAT_JSON" | jq -r '.percentage // empty' 2>/dev/null || true)"
    BAT_PLUGGED="$(printf '%s' "$BAT_JSON" | jq -r '.plugged // empty' 2>/dev/null || true)"
    if printf '%s' "$BAT_PCT" | grep -qE '^[0-9]+$' && [ "$BAT_PCT" -lt 40 ]; then
        warn "Battery is ${BAT_PCT}%. Mining drains battery fast; consider charging."
    fi
    # termux-api reports "UNPLUGGED" / "PLUGGED_AC" / "PLUGGED_USB" /
    # "PLUGGED_WIRELESS" / "PLUGGED_DOCK" (BatteryStatusAPI.java). Matching
    # UNPLUGGED alone avoids false warnings on every charging phone (the
    # C-miner script tests nonexistent PLUGGED_TYPE_* values) and treats
    # wireless/dock charging as charging.
    if [ "$BAT_PLUGGED" = "UNPLUGGED" ]; then
        warn "Device is not charging. Thermal throttling may reduce hashrate."
    fi
fi

# ── step 7: acquire wake-lock ─────────────────────────────────────────────────
# Traps are registered BEFORE the lock is acquired so a Ctrl-C landing between
# the two can never leak it (release_lock is a no-op while WAKE_LOCK=false).
# Separate INT/TERM trap: with only an EXIT trap, Ctrl-C during the backoff
# sleep would resume the loop and restart the miner instead of quitting.
WAKE_LOCK=false
release_lock() {
    if [ "$WAKE_LOCK" = true ]; then
        timeout 5 termux-wake-unlock 2>/dev/null || true
        WAKE_LOCK=false
        info "Wake-lock released."
    fi
}
trap release_lock EXIT
trap 'release_lock; exit 130' INT TERM

if command -v termux-wake-lock &>/dev/null; then
    timeout 5 termux-wake-lock 2>/dev/null && WAKE_LOCK=true || true
    if [ "$WAKE_LOCK" = true ]; then
        info "Wake-lock acquired (Android Doze will not suspend the miner)."
    fi
else
    note "Install termux-api + the Termux:API app for wake-lock support."
    note "Without it, Android Doze may pause the miner in background."
fi

# ── step 8: run with auto-restart ─────────────────────────────────────────────
printf "\n"
printf "  Daemon:   ${GREEN}%s${NC}\n" "$DAEMON"
printf "  Wallet:   ${GREEN}%s${NC}\n" "$WALLET"
printf "  Threads:  ${GREEN}%s${NC}\n" "$THREADS"
printf "\n"
info "Starting: ./$BINARY_NAME -w $WALLET -d $DAEMON -t $THREADS"
info "(Ctrl-C to stop)"
printf "\n"

BACKOFF=5
MAX_BACKOFF=30
while true; do
    START="$SECONDS"
    set +e
    "./$BINARY_NAME" -w "$WALLET" -d "$DAEMON" -t "$THREADS"
    EXIT_CODE=$?
    set -e
    if [ "$EXIT_CODE" -eq 0 ]; then
        info "Miner exited cleanly."
        break
    fi
    # A run that survived a while was healthy; start the backoff ladder over.
    if [ $((SECONDS - START)) -ge 60 ]; then
        BACKOFF=5
    fi
    warn "Miner exited with code $EXIT_CODE. Restarting in ${BACKOFF}s..."
    sleep "$BACKOFF"
    BACKOFF=$((BACKOFF * 2))
    [ "$BACKOFF" -gt "$MAX_BACKOFF" ] && BACKOFF="$MAX_BACKOFF"
done
