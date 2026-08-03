#!/usr/bin/env bash
# HiveOS launch wrapper: run the miner with the args h-config.sh generated,
# teeing output to the agent-readable log.

cd "$(dirname "$0")" || exit 1
# shellcheck source=hive/h-manifest.conf disable=SC1091
source ./h-manifest.conf

[[ ! -d ${CUSTOM_LOG_BASEDIR} ]] && mkdir -p "${CUSTOM_LOG_BASEDIR}"

pkill -9 -x dero-miner > /dev/null 2>&1

# Word-splitting the config line is intentional: it IS the argv.
# shellcheck disable=SC2046
./dero-miner $(< "${CUSTOM_CONFIG_FILENAME}") "$@" 2>&1 | tee -a "${CUSTOM_LOG_BASENAME}.log"
