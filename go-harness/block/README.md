# go-harness/block — dero-protocol test-vector generator

Regenerates the golden vectors the Rust `dero-protocol` (block) suites in
`block/tests/*.rs` load from `../../vectors/*.json`, computed from the **canonical
DERO Go reference** — so they cross-check the Rust port against an implementation
it was *not* derived from.

```sh
cd go-harness/block
go run . selfcheck        # gate: address round-trip + args marshal/unmarshal
go run . address          # -> ../../vectors/address.json
# … or use ../run.sh which drives every target
```

## What it produces

| target | vector | derohe API used |
|---|---|---|
| `address` | address.json | `secret·G`, `rpc.Address.String()` |
| `iaddress` | iaddress.json | integrated/proof addresses + `Arguments` CBOR |
| `scdata` | scdata.json | `rpc.Arguments.MarshalBinary` (SC fields) |
| `scdataft` | scdataft.json | float/time args, zero-time, RPC_EXPIRY |
| `block` | block.json | coinbase tx, `MiniBlock`, `Block.Serialize`, BLID |
| `miniblockhash` | miniblockhash.json | `SerializeWithoutLastMiniBlock` + keyhash binding |
| `proofnonce` | proofnonce.json | a real tx blob → `Fees`, per-payload `Proof.Nonce` |
| `argdecode` | argdecode.json | adversarial CBOR vs `Arguments.UnmarshalBinary` |

## Design

- **Pristine derohe, no vendored copy, no instrumentation.** Every value is a public
  derohe function's output. `go.mod` has `replace github.com/deroproject/derohe =>
  ../../../derohe-main` — a **relative** path assuming `derohe-main` is a sibling of
  `Rust miner` on disk. Adjust the replace if your layout differs. (The astrobwt
  generator one level up is the opposite: it *vendors* a copy because it needs
  instrumentation hooks for op-loop intermediates.)
- **All vectors are committed**, so `cargo test` is green on a fresh clone without Go.
  This generator only needs to run when the vectors are (re)built.
- **proofnonce** reuses the real transaction blob shipped in derohe's own
  `transaction/transaction_test.go` (`proofnonce_tx.hex`).

### The argdecode corpus, and one intentional exclusion

`argdecode` systematically generates a corpus (positives + truncations + semantic
malformations: wrong value type per tag, bad key length, wrong H/A byte length,
non-map top-levels) and dumps whatever Go's `UnmarshalBinary` decides; the faithful
Rust port must reproduce every outcome, error strings included.

It deliberately does **not** probe the *trailing-data* class (a valid CBOR item
followed by extra bytes). Go's `dec.Unmarshal` rejects those (`cbor: N bytes of
extraneous data`); the Rust port **intentionally** validates only the first item and
ignores trailing bytes (documented at `block/src/arguments.rs:28,546`). That is a
known, deliberate design difference — not a decoder bug — so testing it would only
assert a divergence both sides already agree to disagree on.
