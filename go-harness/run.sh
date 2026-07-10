#!/usr/bin/env bash
# Regenerate the Rust miner's golden test vectors from the canonical DERO Go
# reference.
#
# Two generators, two Go modules:
#   * this dir (module deroharness) — the AstroBWTv3 hash vectors, from a
#     vendored+instrumented copy of derohe/astrobwt (deroref/). KAT-gated.
#     Feeds astrobwt/tests/{prologue,full,pow16,sais}_vectors.rs.
#   * block/  (module deroharness-block) — the dero-protocol vectors, from a
#     PRISTINE import of derohe (rpc/block/transaction/crypto) via a replace to
#     a sibling ../../../derohe-main. Feeds block/tests/*.rs.
#
# All vectors ARE committed, so a fresh clone's `cargo test` is green without
# running this; regeneration is a dev-only op (needs Go 1.21+, and for the block
# targets a derohe-main checkout beside "Rust miner").
#
#   ./run.sh            # regenerate everything (astrobwt + block)
#   ./run.sh sais       # just one astrobwt suite
#   ./run.sh block      # just one block suite (delegates to block/)
set -euo pipefail
cd "$(dirname "$0")"
OUT="../vectors"
mkdir -p "$OUT"

ASTRO="astrobwt pow16 sais"
# block/ module targets: dero-protocol + dero-crypto vectors.
# (proof, proofrings are NOT here yet — they need a vendored+patched derohe with a
#  deterministic RNG; see go-harness/block/README.md.)
BLOCK="address iaddress scdata scdataft block miniblockhash proofnonce argdecode \
bn256 crypto algebra polynomial nonbalance statement innerproduct"

gen_astro() { echo "  vectors/$1.json"; go run . "$1" > "$OUT/$1.json"; }
gen_block() { echo "  vectors/$1.json"; ( cd block && go run . "$1" ) > "$OUT/$1.json"; }

run_all() {
  go run . selfcheck            # astrobwt KAT gate: pow("a")==54e2324d…
  ( cd block && go run . selfcheck )   # block gate: address round-trip + args
  for s in $ASTRO; do gen_astro "$s"; done
  for s in $BLOCK; do gen_block "$s"; done
}

arg="${1:-all}"
case " $arg " in
  " all ")                       run_all ;;
  *" $arg "*|" $arg ") ;;         # fallthrough handled below
esac
if [ "$arg" != all ]; then
  if printf '%s\n' $ASTRO | grep -qx "$arg"; then gen_astro "$arg"
  elif printf '%s\n' $BLOCK | grep -qx "$arg"; then gen_block "$arg"
  else echo "usage: run.sh [all|$ASTRO|$BLOCK]" >&2; exit 2
  fi
fi
echo "done."
