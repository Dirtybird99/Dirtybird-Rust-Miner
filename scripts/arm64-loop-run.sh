#!/usr/bin/env bash
# Driver for the arm64 optimize-loop: turns "the working tree as it stands" into
# a byte-exactness verdict and a ns/hash number measured on real ARM silicon.
#
#   arm64-loop-run.sh gate     commit + push the tree, run the arm64 workflow,
#                              cache its result, exit 0 iff the gate passed
#   arm64-loop-run.sh metric   print median ns/hash for the frozen SA arm
#
# Both read ONE CI run. The gate dispatches it; the metric only reads what the
# gate cached, so an iteration costs a single round trip and the two verdicts
# can never come from different builds.
#
# THIS SCRIPT IS PART OF THE MEASURING INSTRUMENT. The loop may not edit it.
#
# Why the result cache is keyed by commit SHA: a metric read that silently
# returns the previous iteration's number would produce a confident, wrong
# keep -- the worst failure this loop can have, because it is invisible. A
# mismatch is therefore a hard error, never a re-dispatch and never a guess.
set -euo pipefail

BRANCH="perf/arm64-loop"
WORKFLOW="arm64-bench.yml"
SANDBOX="${SANDBOX:-sandbox}"
RESULT="$SANDBOX/last-run.json"
FROZEN_ENV="$SANDBOX/frozen.env"
ITERS="${ARM64_ITERS:-2000}"
REPEATS="${ARM64_REPEATS:-7}"

die() { echo "arm64-loop-run: $*" >&2; exit 1; }

# The SA arm to report as THE metric. Frozen by phase 0 (fused vs materialized
# is a definition of what is being measured, not something a candidate may
# change mid-loop). Absent = refuse to measure rather than pick a default and
# quietly optimize a path the phone does not run.
frozen_arm() {
  [ -f "$FROZEN_ENV" ] || die "$FROZEN_ENV missing -- freeze the SA arm (phase 0) before looping"
  # shellcheck source=/dev/null
  . "$FROZEN_ENV"
  case "${FROZEN_ARM:-}" in
    fused|materialized) printf '%s' "$FROZEN_ARM" ;;
    *) die "FROZEN_ARM must be 'fused' or 'materialized', got '${FROZEN_ARM:-}'" ;;
  esac
}

cmd_gate() {
  mkdir -p "$SANDBOX"
  command -v gh >/dev/null || die "gh CLI not found"
  command -v jq >/dev/null || die "jq not found"

  git add -A
  # --allow-empty: an iteration that reverts to best legitimately has no diff,
  # and it still needs its own measurement.
  git commit -q --allow-empty -m "arm64-loop candidate $(date -u +%Y%m%dT%H%M%SZ)"
  local sha
  sha="$(git rev-parse HEAD)"
  git push -q -f origin "HEAD:$BRANCH"
  echo "arm64-loop: dispatching $WORKFLOW on $BRANCH @ ${sha:0:12}" >&2

  gh workflow run "$WORKFLOW" --ref "$BRANCH" \
    -f mode=bench -f iters="$ITERS" -f repeats="$REPEATS" >/dev/null

  # Correlate the dispatch to a run by HEAD SHA rather than by "most recent":
  # concurrent or queued runs otherwise attach the wrong result to this tree.
  local run_id="" tries=0
  while [ -z "$run_id" ] && [ "$tries" -lt 30 ]; do
    sleep 5
    run_id="$(gh run list --workflow "$WORKFLOW" --limit 20 \
      --json databaseId,headSha --jq \
      "[.[] | select(.headSha == \"$sha\")] | .[0].databaseId // empty")"
    tries=$((tries + 1))
  done
  [ -n "$run_id" ] || die "no workflow run appeared for ${sha:0:12}"
  echo "arm64-loop: run $run_id" >&2

  # A failed run is a failed gate, not a script error -- the loop must be free
  # to revert and continue.
  local conclusion="failure"
  if gh run watch "$run_id" --interval 20 --exit-status >/dev/null 2>&1; then
    conclusion="success"
  fi

  rm -f "$SANDBOX/bench-result.json"
  gh run download "$run_id" -n "arm64-bench-bench" -D "$SANDBOX" >/dev/null 2>&1 || true
  if [ ! -f "$SANDBOX/bench-result.json" ]; then
    echo "GATE=fail (run $conclusion, no result artifact)" >&2
    return 1
  fi
  mv "$SANDBOX/bench-result.json" "$RESULT"

  local got_sha gate
  got_sha="$(jq -r .commit "$RESULT")"
  gate="$(jq -r .gate "$RESULT")"
  [ "$got_sha" = "$sha" ] || die "result is for $got_sha, tree is $sha"
  [ "$gate" = "pass" ] || { echo "GATE=fail ($gate)" >&2; return 1; }

  echo "GATE=pass  fused=$(jq -r .fused.ns_per_hash_median "$RESULT") ns/hash" \
       " materialized=$(jq -r .materialized.ns_per_hash_median "$RESULT") ns/hash" >&2
}

cmd_metric() {
  [ -f "$RESULT" ] || die "$RESULT missing -- run 'gate' first"
  local arm sha got
  arm="$(frozen_arm)"
  sha="$(git rev-parse HEAD)"
  got="$(jq -r .commit "$RESULT")"
  # The gate commits, so HEAD is the measured commit. Any drift means the tree
  # moved after measurement and the cached number describes different code.
  [ "$got" = "$sha" ] || die "cached result is for $got but HEAD is $sha -- stale metric"
  jq -r ".${arm}.ns_per_hash_median" "$RESULT"
}

case "${1:-}" in
  gate)   cmd_gate ;;
  metric) cmd_metric ;;
  *) die "usage: arm64-loop-run.sh {gate|metric}" ;;
esac
