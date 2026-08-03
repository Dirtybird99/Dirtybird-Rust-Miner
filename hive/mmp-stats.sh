#!/usr/bin/env bash
# mmpOS stats hook: executed (not sourced) by the agent, prints one JSON
# object. Args are part of the mmpOS interface even though a CPU miner
# ignores the device count.
# shellcheck disable=SC2034
DEVICE_COUNT=$1
LOG_FILE=$2

cd "$(dirname "$0")" || exit 1
# shellcheck source=hive/h-manifest.conf disable=SC1091
source ./h-manifest.conf

stats_raw=$(curl -s --max-time 5 "http://127.0.0.1:${MINER_API_PORT}/stats")

if [[ -z ${stats_raw} ]]; then
  echo "Miner API connection failed"
  exit 1
fi

read -r hs _uptime ver acc rej <<< "${stats_raw}"

jq -nc \
  --argjson hash "[${hs}]" \
  --argjson busid '["cpu"]' \
  --arg units "hs" \
  --arg ac "${acc}" --arg inv "0" --arg rj "${rej}" \
  --arg miner_version "${ver}" \
  --arg miner_name "dirtybird-rust-miner" \
  '{$busid, $hash, $units, air: [$ac, $inv, $rj], miner_name: $miner_name, miner_version: $miner_version}'
