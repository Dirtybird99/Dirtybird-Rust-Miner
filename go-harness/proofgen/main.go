// Zether/Bulletproof transfer-proof vector generator.
//
// Builds a SYNTHETIC N-member ring transfer directly (no wallet, no chain), runs
// the DETERMINISTIC-RNG patched GenerateProof (crypto/random.go), verifies it, and
// dumps the statement + witness + byte-exact proof for the Rust dero_crypto port to
// reproduce. The Rust rebuilds the proof from these same inputs + DeterministicRng
// and must serialize identically.
//
//	go run . proof       > ../../vectors/proof.json        # N=2
//	go run . proofrings  > ../../vectors/proofrings.json   # N=2,4,8
//	go run . selfcheck                                     # verify a proof, no output
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/deroproject/derohe/cryptography/bn256"

	"proofgen/crypto"
)

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

func emit(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		die("marshal: %v", err)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

func comp(g *bn256.G1) string { return hex.EncodeToString(g.EncodeCompressed()) }
func compList(gs []*bn256.G1) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = comp(g)
	}
	return out
}
func gmul(n *big.Int) *bn256.G1 { return new(bn256.G1).ScalarMult(crypto.G, n) }
func add(a, b *bn256.G1) *bn256.G1 { return new(bn256.G1).Add(a, b) }

// buildCase constructs a synthetic n-member ring transfer (sender at index 0,
// receiver at 1), generates the deterministic proof, and returns the vector.
func buildCase(n int) map[string]any {
	// distinct member secrets; index 0 = sender, 1 = receiver, 2.. = anonymity set.
	secrets := make([]*big.Int, n)
	balances := make([]uint64, n)
	for i := 0; i < n; i++ {
		secrets[i] = big.NewInt(int64(1001 + i*37)) // distinct, small
		balances[i] = uint64(5000 + i*111)
	}
	senderSecret := secrets[0]
	value := uint64(1234) // transfer amount, < sender balance

	pub := make([]*bn256.G1, n)
	for i := 0; i < n; i++ {
		pub[i] = gmul(secrets[i])
	}
	// ebalance[i] = ConstructElGamal(pub[i], G).Plus(balance[i]) = {Left:(s+v)G, Right:G};
	// decrypts to balance[i] under secret[i].
	ebal := make([]*crypto.ElGamal, n)
	for i := 0; i < n; i++ {
		ebal[i] = crypto.ConstructElGamal(pub[i], crypto.ElGamal_BASE_G).Plus(new(big.Int).SetUint64(balances[i]))
	}

	var roothash [32]byte
	for i := range roothash {
		roothash[i] = byte(0x40 + i)
	}
	var scid crypto.Hash // zero = DERO asset
	scidIndex := 0
	var txid crypto.Hash
	for i := range txid {
		txid[i] = byte(0x90 + i)
	}

	// r = ReducedHash( (HashToPoint(HashtoNumber("DERO"++roothash++Σpub)))^senderSecret )
	rinputs := append([]byte{}, roothash[:]...)
	for i := range pub {
		rinputs = append(rinputs, pub[i].EncodeCompressed()...)
	}
	rencrypted := new(bn256.G1).ScalarMult(
		crypto.HashToPoint(crypto.HashtoNumber(append([]byte(crypto.PROTOCOL_CONSTANT), rinputs...))),
		senderSecret)
	r := crypto.ReducedHash(rencrypted.EncodeCompressed())

	// C[i]: sender -value, receiver +value, else 0; then hidden behind r·pub[i].
	C := make([]*bn256.G1, n)
	for i := 0; i < n; i++ {
		var x bn256.G1
		switch i {
		case 0:
			x.ScalarMult(crypto.G, big.NewInt(0-int64(value)))
		case 1:
			x.ScalarMult(crypto.G, big.NewInt(int64(value)))
		default:
			x.ScalarMult(crypto.G, big.NewInt(0))
		}
		x.Add(new(bn256.G1).Set(&x), new(bn256.G1).ScalarMult(pub[i], r))
		C[i] = &x
	}
	D := new(bn256.G1).ScalarMult(crypto.G, r)

	CLn := make([]*bn256.G1, n)
	CRn := make([]*bn256.G1, n)
	for i := 0; i < n; i++ {
		CLn[i] = add(ebal[i].Left, C[i])
		CRn[i] = add(ebal[i].Right, D)
	}

	statement := crypto.Statement{
		CLn: CLn, CRn: CRn, Publickeylist: pub, C: C, D: D, Fees: 0,
	}
	copy(statement.Roothash[:], roothash[:])
	statement.Bytes_per_publickey = 8

	witness := crypto.Witness{
		SecretKey:      senderSecret,
		R:              r,
		TransferAmount: value,
		Balance:        balances[0] - value,
		Index:          []int{0, 1},
	}

	// u = (HashToPoint(HashtoNumber("DERO"++roothash++scid++scid_index)))^senderSecret
	uinput := append([]byte(crypto.PROTOCOL_CONSTANT), roothash[:]...)
	uinput = append(uinput, scid[:]...)
	uinput = append(uinput, []byte(strconv.Itoa(scidIndex))...)
	u := new(bn256.G1).ScalarMult(crypto.HashToPoint(crypto.HashtoNumber(uinput)), senderSecret)

	crypto.ResetDeterministicRNG()
	proof := crypto.GenerateProof(scid, scidIndex, &statement, &witness, u, txid, 0)
	verifyGo := proof.Verify(scid, scidIndex, &statement, txid, 0)

	var buf bytes.Buffer
	proof.Serialize(&buf)

	return map[string]any{
		"n":             n,
		"publickeylist": compList(pub),
		"cln":           compList(CLn),
		"crn":           compList(CRn),
		"c":             compList(C),
		"d":             comp(D),
		"fees":          statement.Fees,
		"roothash":      hex.EncodeToString(roothash[:]),
		"sender_secret": senderSecret.String(),
		"r":             r.String(),
		"transfer":      value,
		"balance":       balances[0] - value,
		"index":         []int{0, 1},
		"u":             comp(u),
		"scid":          hex.EncodeToString(scid[:]),
		"scid_index":    scidIndex,
		"txid":          hex.EncodeToString(txid[:]),
		"proof_hex":     hex.EncodeToString(buf.Bytes()),
		"verify_go":     verifyGo,
	}
}

func main() {
	if len(os.Args) < 2 {
		die("usage: proofgen <proof|proofrings|selfcheck>")
	}
	switch os.Args[1] {
	case "proof":
		emit(buildCase(2))
	case "proofrings":
		var cases []map[string]any
		for _, n := range []int{2, 4, 8} {
			cases = append(cases, buildCase(n))
		}
		emit(cases)
	case "selfcheck":
		c := buildCase(2)
		if c["verify_go"].(bool) {
			fmt.Fprintf(os.Stderr, "selfcheck ok: N=2 proof verifies (%d proof bytes)\n", len(c["proof_hex"].(string))/2)
		} else {
			die("selfcheck FAIL: Go rejected its own proof")
		}
	default:
		die("unknown %q", os.Args[1])
	}
}
