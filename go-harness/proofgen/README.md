# go-harness/proofgen — Zether transfer-proof vector generator

Generates `vectors/proof.json` and `vectors/proofrings.json` — the byte-exact
Zether/Bulletproof transfer proofs that `cryptography/crypto/tests/proof_vectors.rs`
and `proof_rings.rs` check the Rust `dero_crypto` port against.

```sh
cd go-harness/proofgen
DEROHE=../../../derohe-main ./setup.sh   # materialize the local patched crypto copy
go run . selfcheck                       # Go verifies its own synthetic proof
go run . proof       > ../../vectors/proof.json        # N=2
go run . proofrings  > ../../vectors/proofrings.json   # N=2,4,8
# …or just ../run.sh, which bootstraps setup.sh automatically.
```

## Why this module is different from the others

The other two generators reference or vendor derohe's **BSD-3** packages. This one
needs to patch derohe's `RandomScalar`, so it works differently on two axes:

1. **It patches derohe's crypto.** Go's `GenerateProof` draws randomness from
   `crypto/rand` internally; the Rust `generate_proof` takes a `DeterministicRng`.
   For the proofs to match byte-for-byte, the Go side must consume the *same*
   scalars in the *same* order. `setup.sh` copies derohe's `cryptography/crypto`
   locally and overwrites `random.go` so `RandomScalar()` returns the deterministic
   sequence the Rust `DeterministicRng` (`dero_crypto` `proof.rs`) documents:
   `nonce_k = reducedhash(ConvertBigIntToByte(k))`, k = 1,2,3,…. The consumption
   order already matches — the Rust prover was ported from this patched Go.

2. **The crypto copy is NOT committed.** derohe's `cryptography/crypto` is under the
   **DERO RESEARCH LICENSE** (non-commercial), not BSD-3, so it must not be
   redistributed in this MIT repo. `proofgen/crypto/` is `.gitignore`d; you
   regenerate it locally from your own derohe checkout (Research Use) via `setup.sh`.
   Only the *vectors* (data) and this original harness code are committed.

## The synthetic statement

`main.go` builds a valid N-member ring transfer directly (no wallet, no chain):
sender at index 0, receiver at 1, the rest an anonymity set. Each member i gets a
secret `s_i` and balance `v_i`, with encrypted balance
`ElGamal{Left:(s_i+v_i)·G, Right:G}` (decrypts to `v_i` under `s_i`). Then, mirroring
`walletapi/transaction_build.go`: `r = ReducedHash((HashToPoint(…roothash…pubkeys…))^sk)`,
`C[i]` = ±value·G (sender/receiver) + r·pub[i], `D = r·G`, `CLn/CRn = ebalance ± C/D`,
and `u = (HashToPoint(…roothash…scid…))^sk`. `GenerateProof` runs under the reset
deterministic RNG; `Proof.Verify` confirms the statement is sound before it's dumped.
