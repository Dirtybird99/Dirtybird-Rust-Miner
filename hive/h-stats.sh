#!/usr/bin/env bash
# Sourced by the HiveOS agent inside a function; its contract is to set the
# variables `khs` (hashrate in kH/s) and `stats` (JSON). The endpoint returns
# one plain-text line: "<hs> <uptime_secs> <version> <accepted> <rejected>".

# Resolve the manifest next to this script rather than at a fixed
# /hive/miners/custom/<name> path: mmpOS installs elsewhere, and the absolute
# form silently stops working the moment CUSTOM_NAME or the install root moves.
# BASH_SOURCE, not $0 -- the agent sources this file, so $0 is the agent.
# HIVE_MANIFEST is the override hook for tests.
# shellcheck source=hive/h-manifest.conf disable=SC1091
source "${HIVE_MANIFEST:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/h-manifest.conf}"

stats_raw=$(curl -s --max-time 5 "http://127.0.0.1:${MINER_API_PORT}/stats")

if [[ -z ${stats_raw} ]]; then
  khs=0
  stats="null"
else
  read -r hs uptime ver acc rej <<< "${stats_raw}"
  khs=$(printf "%.3f" "${hs}e-3")
  temp=$(/hive/sbin/cpu-temp 2> /dev/null)
  [[ -z ${temp} ]] && temp=0
  stats=$(printf '{"hs": [%s], "hs_units": "hs", "temp": [%s], "uptime": %s, "ver": "%s", "ar": [%s, %s], "algo": "astrobwt"}' \
    "${hs}" "${temp}" "${uptime}" "${ver}" "${acc}" "${rej}")
fi

# Consumed by the sourcing agent, not here.
# shellcheck disable=SC2034
: "${khs}" "${stats}"
