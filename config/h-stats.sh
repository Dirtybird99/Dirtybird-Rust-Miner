#!/usr/bin/env bash
. /hive/miners/custom/dero-miner/h-manifest.conf

# dero-miner has no HTTP stats API; it prints a live status line to the log of the form:
#   [dero-rs]   8.25 KH/s (  8.20 avg) | H:<n> | MB:<accepted> | Blk:<n> | REJ:<rejected> | Diff:<n> | net:up
# Read the tail of the log and scrape the freshest values for the HiveOS dashboard.

LOG="${CUSTOM_LOG_BASENAME}.log"

khs=0
uptime=0
acc=0
rej=0

if [[ -f $LOG ]]; then
    line=$(tail -c 8192 "$LOG" 2>/dev/null | tr '\r' '\n' | grep 'KH/s' | tail -n1)
    if [[ -n $line ]]; then
        # hashrate: the token followed by "KH/s" (the avg field has no unit)
        khs=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+ KH/s' | head -n1 | grep -oE '[0-9]+\.[0-9]+')
        # MB: = accepted miniblocks, REJ: = rejected
        acc=$(echo "$line" | grep -oE 'MB:[0-9]+' | grep -oE '[0-9]+')
        rej=$(echo "$line" | grep -oE 'REJ:[0-9]+' | grep -oE '[0-9]+')
    fi
    # best-effort uptime from the log's age
    now=$(date +%s); started=$(stat -c %Y "$LOG" 2>/dev/null || echo "$now")
    uptime=$(( now - started ))
fi

[[ -z $khs ]] && khs=0
[[ -z $acc ]] && acc=0
[[ -z $rej ]] && rej=0
[[ -z $uptime || $uptime -lt 0 ]] && uptime=0

stats=$(cat <<-END
{
    "hs": [$khs],
    "hs_units": "khs",
    "uptime": $uptime,
    "ar": [$acc, $rej],
    "algo": "ASTROBWT"
}
END
)
