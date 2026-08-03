#!/usr/bin/env bash
# Translates the HiveOS Flight Sheet into one line of dero-miner arguments.
# The agent execs this after writing CUSTOM_URL / CUSTOM_TEMPLATE /
# CUSTOM_USER_CONFIG into the environment.

# shellcheck source=hive/h-manifest.conf disable=SC1091
source /hive/miners/custom/dirtybird-rust-miner/h-manifest.conf

[[ -z ${CUSTOM_CONFIG_FILENAME} ]] && echo "CUSTOM_CONFIG_FILENAME is empty" && exit 1

# DERO addresses contain no dots, so anything after one is a worker-name
# suffix pasted by pool-style templates — the daemon getwork protocol has no
# worker concept, drop it.
WALLET=${CUSTOM_TEMPLATE%%.*}

# Flight Sheets often carry a scheme (wss://host:port); the miner dials the
# getwork websocket itself and wants bare host:port.
DAEMON=${CUSTOM_URL#*://}

{
  printf -- "-d %s -w %s --api-bind-address 127.0.0.1:%s" \
    "${DAEMON}" "${WALLET}" "${MINER_API_PORT}"
  [[ -n ${CUSTOM_USER_CONFIG} ]] && printf -- " %s" "${CUSTOM_USER_CONFIG}"
  printf "\n"
} > "${CUSTOM_CONFIG_FILENAME}"
