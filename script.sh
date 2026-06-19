#!/usr/bin/env bash
#
# Dirtybird Rust Miner -- launcher.
#
# Runs the miner with the default pool. To mine to YOUR wallet, pass flags:
#   ./script.sh -w dero1yourwalletaddress... -t <threads> -d host:port
# On Windows, run from Git Bash:  bash script.sh
set -euo pipefail
cd "$(dirname "$0")"

if   [ -f "./dero-miner" ];     then BIN="./dero-miner"
elif [ -f "./dero-miner.exe" ]; then BIN="./dero-miner.exe"
else
    echo "error: dero-miner not found; run this from a release folder." >&2
    exit 1
fi

echo "Starting miner (Ctrl-C to stop)..."
echo
exec "$BIN" "$@"
