#!/usr/bin/env bash
# Materialize proofgen/crypto/ — a LOCAL, PATCHED copy of derohe's
# cryptography/crypto — from your derohe checkout.
#
# This copy is NOT committed: derohe's crypto package is under the DERO RESEARCH
# LICENSE (non-commercial), so it must not be redistributed inside this MIT repo.
# You regenerate it locally (Research Use) from your own derohe checkout, and this
# script applies the one deterministic-RNG patch the proof vectors need.
#
#   DEROHE=../../../derohe-main ./setup.sh     # or set DEROHE to your checkout
#
# The patch: RandomScalar()/RandomScalarFixed() become deterministic —
#   nonce_k = reducedhash(ConvertBigIntToByte(k)), k = 1,2,3,...
# exactly the sequence the Rust DeterministicRng (dero_crypto proof.rs) consumes,
# so Go's GenerateProof and the Rust port produce byte-identical transfer proofs.
set -euo pipefail
cd "$(dirname "$0")"
DEROHE="${DEROHE:-../../../derohe-main}"
SRC="$DEROHE/cryptography/crypto"
[ -d "$SRC" ] || { echo "derohe crypto not found at $SRC — set DEROHE=<your derohe checkout>" >&2; exit 1; }

rm -rf crypto && mkdir crypto
cp "$SRC"/*.go crypto/
rm -f crypto/*_test.go

# Overwrite random.go with the deterministic-RNG variant.
cat > crypto/random.go <<'PATCH'
// HARNESS-PATCHED copy of derohe cryptography/crypto/random.go (DERO RESEARCH
// LICENSE — NOT redistributed; regenerated locally by proofgen/setup.sh).
//
// RandomScalar is made DETERMINISTIC so a Go transfer proof reproduces byte-for-
// byte in the Rust dero_crypto port. Matches the Rust DeterministicRng (proof.rs):
//   nonce_k = reducedhash(ConvertBigIntToByte(k)), k = 1,2,3,...
package crypto

import "math/big"
import "github.com/deroproject/derohe/cryptography/bn256"

var deterministicCounter int64

// ResetDeterministicRNG rewinds the counter so the next RandomScalar() returns the
// k=1 value — call immediately before GenerateProof (== DeterministicRng::new()).
func ResetDeterministicRNG() { deterministicCounter = 0 }

func RandomScalar() *big.Int {
	deterministicCounter++
	return reducedhash(ConvertBigIntToByte(big.NewInt(deterministicCounter)))
}

func RandomScalarFixed() *big.Int { return RandomScalar() }

type KeyPair struct {
	x *big.Int
	y *bn256.G1
}
PATCH

echo "proofgen/crypto/ ready ($(ls crypto/*.go | wc -l) files, random.go patched)"
