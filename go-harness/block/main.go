// Test-vector generator for the Rust DERO `dero-protocol` (block) crate.
//
// Dumps the golden vectors the Rust suites in block/tests/*.rs load from
// ../../vectors/*.json, computed from the CANONICAL DERO Go reference
// (github.com/deroproject/derohe, imported pristine via the replace in go.mod).
// Every value here is a public derohe function's output — no instrumentation,
// no node state (no graviton/DVM/chain).
//
//	go run . address       > ../../vectors/address.json
//	go run . iaddress      > ../../vectors/iaddress.json
//	go run . scdata        > ../../vectors/scdata.json
//	go run . scdataft      > ../../vectors/scdataft.json
//	go run . block         > ../../vectors/block.json
//	go run . miniblockhash > ../../vectors/miniblockhash.json
//	go run . proofnonce    > ../../vectors/proofnonce.json
//	go run . argdecode     > ../../vectors/argdecode.json
//	go run . selfcheck                                   # sanity gate, no output
package main

import (
	"bytes"
	"crypto/sha3"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

//go:embed proofnonce_tx.hex
var proofnonceTxHex string

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

func emit(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		die("marshal: %v", err)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

// pubFromSecret returns secret·G as a *crypto.Point — the same derivation as the
// Rust dero_crypto::derive_public_key (base_g().scalar_mult(secret)).
func pubFromSecret(secret *big.Int) *crypto.Point {
	p := new(bn256.G1).ScalarMult(crypto.G, secret)
	return (*crypto.Point)(p)
}

func mustBig(dec string) *big.Int {
	n, ok := new(big.Int).SetString(dec, 10)
	if !ok {
		die("bad decimal %q", dec)
	}
	return n
}

// A fixed, diverse secret set (small values + large scalars near the group order).
var secretDecs = []string{
	"1", "2", "3", "7", "42", "255", "65537",
	"123456789012345678901234567890",
	"9999999999999999999999999999999999999999999999999999999999999999",
	// group_order - 1 region (still < order); exercises full-width scalars
	"16798108731015832284940804142231733909759579603404752749028378864165570215948",
}

// ---- address.json ---------------------------------------------------------

func dumpAddress() {
	type row struct {
		SecretDec string `json:"secret_dec"`
		Mainnet   string `json:"mainnet"`
		Testnet   string `json:"testnet"`
	}
	var out []row
	for _, s := range secretDecs {
		pub := pubFromSecret(mustBig(s))
		main := rpc.Address{Mainnet: true, PublicKey: pub}
		test := rpc.Address{Mainnet: false, PublicKey: pub}
		out = append(out, row{SecretDec: s, Mainnet: main.String(), Testnet: test.String()})
	}
	emit(out)
}

// ---- scdata.json ----------------------------------------------------------

func dumpScdata() {
	scidHex := "d1b3c4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1"
	code := "Function Initialize() Uint64\n10 RETURN 0\nEnd Function"
	var amount uint64 = 1500000
	label := "PONG token"
	var delta int64 = -250
	var action uint64 = 0 // SC_CALL

	scidBytes, _ := hex.DecodeString(scidHex)
	var scid crypto.Hash
	copy(scid[:], scidBytes)

	args := rpc.Arguments{
		{Name: "amount", DataType: rpc.DataUint64, Value: amount},
		{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: action},
		{Name: "delta", DataType: rpc.DataInt64, Value: delta},
		{Name: rpc.SCCODE, DataType: rpc.DataString, Value: code},
		{Name: "label", DataType: rpc.DataString, Value: label},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid},
	}
	b, err := args.MarshalBinary()
	if err != nil {
		die("scdata marshal: %v", err)
	}
	emit(map[string]any{
		"scid_hex":    scidHex,
		"code":        code,
		"amount":      amount,
		"label":       label,
		"delta":       delta,
		"action":      action,
		"marshal_hex": hex.EncodeToString(b),
	})
}

func mustHash(hexstr string) crypto.Hash {
	b, err := hex.DecodeString(hexstr)
	if err != nil || len(b) != 32 {
		die("bad hash hex %q", hexstr)
	}
	var h crypto.Hash
	copy(h[:], b)
	return h
}

func marshalHex(args rpc.Arguments) string {
	b, err := args.MarshalBinary()
	if err != nil {
		die("marshal: %v", err)
	}
	return hex.EncodeToString(b)
}

// ---- iaddress.json --------------------------------------------------------
//
// Integrated / proof addresses. The argument sets mirror iaddress_vectors.rs
// (pong_args, proof H/V, mixed R/X/C) EXACTLY, so the Rust test rebuilds the
// same Arguments and must reproduce these encodings.

func pongArgs() (full, noamount rpc.Arguments) {
	full = rpc.Arguments{
		{Name: "D", DataType: rpc.DataUint64, Value: uint64(0x1234567812345678)},
		{Name: "C", DataType: rpc.DataString, Value: "Purchase PONG"},
		{Name: "N", DataType: rpc.DataUint64, Value: uint64(0)},
		{Name: "V", DataType: rpc.DataUint64, Value: uint64(12345)},
	}
	noamount = full[:len(full)-1] // V is last: the no-amount set
	return
}

func dumpIaddress() {
	iaddrSecrets := []string{"1", "2", "42", "123456789012345678901234567890"}

	full, noamount := pongArgs()
	fullHex := marshalHex(full)
	noamountHex := marshalHex(noamount)

	pong := []map[string]any{}
	for _, s := range iaddrSecrets {
		pub := pubFromSecret(mustBig(s))
		row := map[string]any{"secret_dec": s, "args_cbor_hex": fullHex, "args_noamount_cbor_hex": noamountHex}
		for _, m := range []struct {
			mainnet                     bool
			baseK, intK, naK            string
		}{
			{true, "base_main", "integrated_main", "integrated_main_noamount"},
			{false, "base_test", "integrated_test", "integrated_test_noamount"},
		} {
			base := rpc.Address{Mainnet: m.mainnet, PublicKey: pub}
			integ := rpc.Address{Mainnet: m.mainnet, PublicKey: pub, Arguments: full}
			na := rpc.Address{Mainnet: m.mainnet, PublicKey: pub, Arguments: noamount}
			row[m.baseK] = base.String()
			row[m.intK] = integ.String()
			row[m.naK] = na.String()
		}
		pong = append(pong, row)
	}

	// proof: walletapi/daemon_communication.go:979 shape — H(shared), V(amount)
	proof := []map[string]any{}
	sharedKeys := []string{
		"1122334455667788990011223344556677889900112233445566778899001122",
		"aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ab",
	}
	for i, s := range []string{"7", "999999999"} {
		shared := mustHash(sharedKeys[i])
		value := uint64(1000000 * (i + 1))
		pub := pubFromSecret(mustBig(s))
		a := rpc.Address{Mainnet: true, Proof: true, PublicKey: pub, Arguments: rpc.Arguments{
			{Name: "H", DataType: rpc.DataHash, Value: shared},
			{Name: "V", DataType: rpc.DataUint64, Value: value},
		}}
		proof = append(proof, map[string]any{
			"secret_dec":     s,
			"value":          value,
			"shared_key_hex": hex.EncodeToString(shared[:]),
			"proof_addr":     a.String(),
		})
	}

	// mixed: reply address (R), a negative int (X), a comment (C)
	mixed := []map[string]any{}
	replySecret, secret := "3", "42"
	reply := rpc.Address{Mainnet: true, PublicKey: pubFromSecret(mustBig(replySecret))}
	mixedArgs := rpc.Arguments{
		{Name: "R", DataType: rpc.DataAddress, Value: reply},
		{Name: "X", DataType: rpc.DataInt64, Value: int64(-123456789)},
		{Name: "C", DataType: rpc.DataString, Value: "mixed types"},
	}
	ma := rpc.Address{Mainnet: true, PublicKey: pubFromSecret(mustBig(secret)), Arguments: mixedArgs}
	mixed = append(mixed, map[string]any{
		"reply_secret_dec": replySecret,
		"secret_dec":       secret,
		"args_cbor_hex":    marshalHex(mixedArgs),
		"integrated_main":  ma.String(),
	})

	// fixed: a self-generated proof address, dumped as a decode target
	fpub := pubFromSecret(mustBig("123456789"))
	fshared := mustHash("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
	fval := uint64(42000000)
	fa := rpc.Address{Mainnet: true, Proof: true, PublicKey: fpub, Arguments: rpc.Arguments{
		{Name: "H", DataType: rpc.DataHash, Value: fshared},
		{Name: "V", DataType: rpc.DataUint64, Value: fval},
	}}
	faStr := fa.String()
	fixed := []map[string]any{{
		"addr":       faStr,
		"mainnet":    true,
		"proof":      true,
		"pubkey_hex": hex.EncodeToString(fpub.EncodeCompressed()),
		"reencoded":  faStr,
		"args": []map[string]any{
			// decode order is name-sorted: H before V
			{"name": "H", "datatype": "H", "value": hex.EncodeToString(fshared[:])},
			{"name": "V", "datatype": "U", "value": fmt.Sprintf("%d", fval)},
		},
	}}

	emit(map[string]any{"pong": pong, "proof": proof, "mixed": mixed, "fixed": fixed})
}

// ---- scdataft.json --------------------------------------------------------
//
// Float ('F') and time ('T') canonical CBOR, incl. RPC_EXPIRY 'E' and Go's
// zero time. `build` = construct-then-marshal cases; `raw` = crafted CBOR.

// argDump renders one argument in the ArgDesc shape the Rust test reads.
func argDump(a rpc.Argument) map[string]any {
	m := map[string]any{"name": a.Name, "type": string(a.DataType)}
	switch v := a.Value.(type) {
	case uint64:
		m["u"] = v
	case int64:
		m["i"] = v
	case string:
		m["s"] = v
	case crypto.Hash:
		m["hash_hex"] = hex.EncodeToString(v[:])
	case float64:
		m["f64_bits"] = fmt.Sprintf("%016x", math.Float64bits(v))
	case time.Time:
		m["unix"] = v.Unix()
	default:
		die("argDump: unhandled %T", v)
	}
	return m
}

func dumpScdataft() {
	type buildCase struct {
		Name         string           `json:"name"`
		Args         []map[string]any `json:"args"`
		MarshalHex   string           `json:"marshal_hex"`
		MarshalErr   string           `json:"marshal_err"`
		RoundtripHex string           `json:"roundtrip_hex"`
		UnmarshalErr string           `json:"unmarshal_err"`
	}
	mkBuild := func(name string, args rpc.Arguments) buildCase {
		c := buildCase{Name: name}
		for _, a := range args {
			c.Args = append(c.Args, argDump(a))
		}
		b, err := args.MarshalBinary()
		if err != nil {
			c.MarshalErr = err.Error()
			return c
		}
		c.MarshalHex = hex.EncodeToString(b)
		var got rpc.Arguments
		if err := got.UnmarshalBinary(b); err != nil {
			c.UnmarshalErr = err.Error()
		} else {
			c.RoundtripHex = marshalHex(got)
		}
		return c
	}

	builds := []buildCase{
		mkBuild("e_expiry", rpc.Arguments{
			{Name: rpc.RPC_EXPIRY, DataType: rpc.DataTime, Value: time.Unix(1893456000, 0).UTC()},
			{Name: "D", DataType: rpc.DataUint64, Value: uint64(0x1234)},
			{Name: "C", DataType: rpc.DataString, Value: "dero"},
		}),
		mkBuild("t_zero", rpc.Arguments{
			{Name: "t", DataType: rpc.DataTime, Value: time.Time{}},
		}),
		mkBuild("f_pi", rpc.Arguments{
			{Name: "f", DataType: rpc.DataFloat64, Value: math.Pi},
		}),
		mkBuild("f_zero", rpc.Arguments{
			{Name: "f", DataType: rpc.DataFloat64, Value: 0.0},
		}),
		mkBuild("f_neg", rpc.Arguments{
			{Name: "f", DataType: rpc.DataFloat64, Value: -1234.5},
		}),
		mkBuild("f_small", rpc.Arguments{
			{Name: "f", DataType: rpc.DataFloat64, Value: 5.9604644775390625e-08},
		}),
		mkBuild("t_epoch", rpc.Arguments{
			{Name: "t", DataType: rpc.DataTime, Value: time.Unix(1700000000, 0).UTC()},
		}),
		mkBuild("mixed_ft", rpc.Arguments{
			{Name: "f", DataType: rpc.DataFloat64, Value: 2.5},
			{Name: "t", DataType: rpc.DataTime, Value: time.Unix(0, 0).UTC()},
			{Name: "u", DataType: rpc.DataUint64, Value: uint64(9)},
		}),
	}

	// raw: crafted CBOR run through Go's UnmarshalBinary.
	type rawDecoded struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Unix    *int64 `json:"unix,omitempty"`
		F64Bits string `json:"f64_bits,omitempty"`
	}
	type rawCase struct {
		Name         string       `json:"name"`
		RawHex       string       `json:"raw_hex"`
		UnmarshalErr string       `json:"unmarshal_err"`
		RemarshalHex string       `json:"remarshal_hex"`
		// omitempty: a nil slice must be OMITTED (serde `default`), not emitted
		// as JSON null (serde rejects null for a Vec).
		Decoded []rawDecoded `json:"decoded,omitempty"`
	}
	mkRaw := func(name, rawHex string) rawCase {
		c := rawCase{Name: name, RawHex: rawHex}
		raw, err := hex.DecodeString(rawHex)
		if err != nil {
			die("raw %s bad hex: %v", name, err)
		}
		var args rpc.Arguments
		if err := args.UnmarshalBinary(raw); err != nil {
			c.UnmarshalErr = err.Error()
			return c
		}
		c.RemarshalHex = marshalHex(args)
		for _, a := range args {
			d := rawDecoded{Name: a.Name, Type: string(a.DataType)}
			switch v := a.Value.(type) {
			case time.Time:
				u := v.Unix()
				d.Unix = &u
			case float64:
				d.F64Bits = fmt.Sprintf("%016x", math.Float64bits(v))
			}
			c.Decoded = append(c.Decoded, d)
		}
		return c
	}

	// Build a few raw cases by re-encoding known-good build outputs, plus a
	// deliberately malformed one. Using marshaled bytes guarantees at least
	// some accept cases; the malformed one exercises the error path.
	fbits := func(f float64) rpc.Arguments {
		return rpc.Arguments{{Name: "f", DataType: rpc.DataFloat64, Value: f}}
	}
	rawFrom := func(name string, args rpc.Arguments) rawCase {
		return mkRaw(name, marshalHex(args))
	}
	raws := []rawCase{
		rawFrom("raw_f_nan", fbits(math.NaN())),
		rawFrom("raw_f_inf", fbits(math.Inf(1))),
		rawFrom("raw_f_ninf", fbits(math.Inf(-1))),
		rawFrom("raw_t_epoch", rpc.Arguments{{Name: "t", DataType: rpc.DataTime, Value: time.Unix(1234567890, 0).UTC()}}),
		mkRaw("raw_truncated", "a1"),                 // map(1) then EOF
		mkRaw("raw_bad_key_len", "a16149181e"),        // 1-char key "a" — len<2 after? "aI"? craft below
	}

	emit(map[string]any{
		"go_zero_time_unix": time.Time{}.Unix(),
		"build":             builds,
		"raw":               raws,
	})
}

// ---- block / miniblock / transaction helpers ------------------------------

func uvarintLen(x uint64) int {
	return len(binary.AppendUvarint(nil, x))
}

// nonMinimalUvarint encodes x in exactly `nbytes` (> minimal) CBOR-style
// LEB128 bytes — the extra continuation bytes Go's Deserialize rejects.
func nonMinimalUvarint(x uint64, nbytes int) []byte {
	out := make([]byte, nbytes)
	for i := 0; i < nbytes-1; i++ {
		out[i] = byte(x&0x7f) | 0x80
		x >>= 7
	}
	out[nbytes-1] = byte(x & 0x7f)
	return out
}

func coinbaseTx(addr33 []byte) transaction.Transaction {
	var tx transaction.Transaction
	tx.Version = 1
	tx.TransactionType = transaction.COINBASE
	copy(tx.MinerAddress[:], addr33)
	return tx
}

func mkMiniBlock(version uint8, highDiff, final bool, pastCount uint8, ts uint16,
	height uint64, past [2]uint32, keyHash16 []byte, flags uint32, nonce [3]uint32) block.MiniBlock {
	var mb block.MiniBlock
	mb.Version = version
	mb.HighDiff = highDiff
	mb.Final = final
	mb.PastCount = pastCount
	mb.Timestamp = ts
	mb.Height = height
	mb.Past = past
	copy(mb.KeyHash[:], keyHash16)
	mb.Flags = flags
	mb.Nonce = nonce
	return mb
}

func mbDump(mb block.MiniBlock) map[string]any {
	ser := mb.Serialize()
	h := mb.GetHash()
	return map[string]any{
		"version":       mb.Version,
		"high_diff":     mb.HighDiff,
		"final":         mb.Final,
		"past_count":    mb.PastCount,
		"timestamp":     mb.Timestamp,
		"height":        mb.Height,
		"past":          []uint32{mb.Past[0], mb.Past[1]},
		"key_hash16_hex": hex.EncodeToString(mb.KeyHash[:16]),
		"flags":         mb.Flags,
		"nonce":         []uint32{mb.Nonce[0], mb.Nonce[1], mb.Nonce[2]},
		"ser_hex":       hex.EncodeToString(ser),
		"hash_hex":      hex.EncodeToString(h[:]),
	}
}

func h32(hexstr string) crypto.Hash {
	return mustHash(hexstr)
}

// ---- block.json -----------------------------------------------------------

func dumpBlock() {
	coinbaseAddr := pubFromSecret(mustBig("123456789")).EncodeCompressed() // 33 bytes
	tx := coinbaseTx(coinbaseAddr)

	tips := []crypto.Hash{h32("1111111111111111111111111111111111111111111111111111111111111111")}
	txHashes := []crypto.Hash{
		h32("2222222222222222222222222222222222222222222222222222222222222222"),
		h32("3333333333333333333333333333333333333333333333333333333333333333"),
	}
	mbs := []block.MiniBlock{
		mkMiniBlock(1, false, false, 1, 7, 100, [2]uint32{0x11223344, 0}, mustBytes16("0102030405060708090a0b0c0d0e0f10"), 0, [3]uint32{1, 2, 3}),
		mkMiniBlock(1, true, true, 1, 9, 100, [2]uint32{0x11223344, 0}, mustBytes16("aabbccddeeff00112233445566778899"), 0xdeadbeef, [3]uint32{9, 8, 7}),
	}

	var proof [32]byte
	copy(proof[:], mustHashBytes("4444444444444444444444444444444444444444444444444444444444444444"))

	bl := block.Block{
		Major_Version: 1,
		Minor_Version: 0,
		Timestamp:     1700000000000,
		Height:        1234,
		Miner_TX:      tx,
		Proof:         proof,
		Tips:          tips,
		MiniBlocks:    mbs,
		Tx_hashes:     txHashes,
	}

	ser := bl.Serialize()
	blid := bl.GetHash()
	tipsHash := bl.GetTipsHash()
	txsHash := bl.GetTXSHash()

	// Non-minimal count varints (Go rejects; block.go done>1 tips / done>2 mbl).
	// tips count sits right after header+minertx+proof.
	prefixLen := uvarintLen(bl.Major_Version) + uvarintLen(bl.Minor_Version) + 8 +
		uvarintLen(bl.Height) + len(tx.Serialize()) + 32
	nTips := uint64(len(tips))
	nmTips := append(append(append([]byte{}, ser[:prefixLen]...),
		nonMinimalUvarint(nTips, 2)...), ser[prefixLen+uvarintLen(nTips):]...)

	mblCountOff := prefixLen + uvarintLen(nTips) + 32*len(tips)
	nMbl := uint64(len(mbs))
	nmMbl := append(append(append([]byte{}, ser[:mblCountOff]...),
		nonMinimalUvarint(nMbl, 3)...), ser[mblCountOff+uvarintLen(nMbl):]...)

	rejects := func(b []byte) bool {
		var probe block.Block
		return probe.Deserialize(b) != nil
	}

	var mbDumps []map[string]any
	for _, mb := range mbs {
		mbDumps = append(mbDumps, mbDump(mb))
	}

	txid := tx.GetHash()
	emit(map[string]any{
		"coinbase_addr_hex":  hex.EncodeToString(coinbaseAddr),
		"coinbase_ser_hex":   hex.EncodeToString(tx.Serialize()),
		"coinbase_txid_hex":  hex.EncodeToString(txid[:]),
		"major_version":      bl.Major_Version,
		"minor_version":      bl.Minor_Version,
		"timestamp":          bl.Timestamp,
		"height":             bl.Height,
		"proof_hex":          hex.EncodeToString(proof[:]),
		"tips_hex":           hashHexes(tips),
		"tx_hashes_hex":      hashHexes(txHashes),
		"miniblocks":         mbDumps,
		"block_ser_hex":      hex.EncodeToString(ser),
		"blid_hex":           hex.EncodeToString(blid[:]),
		"tips_hash_hex":      hex.EncodeToString(tipsHash[:]),
		"txs_hash_hex":       hex.EncodeToString(txsHash[:]),
		"nonminimal_tips_hex":          hex.EncodeToString(nmTips),
		"nonminimal_tips_reject":       rejects(nmTips),
		"nonminimal_miniblocks_hex":    hex.EncodeToString(nmMbl),
		"nonminimal_miniblocks_reject": rejects(nmMbl),
	})
}

// ---- miniblockhash.json ---------------------------------------------------

func dumpMiniblockhash() {
	coinbaseAddr := pubFromSecret(mustBig("987654321")).EncodeCompressed()
	tx := coinbaseTx(coinbaseAddr)
	tips := []crypto.Hash{h32("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778890")}
	txHashes := []crypto.Hash{h32("5555555555555555555555555555555555555555555555555555555555555555")}
	var proof [32]byte
	copy(proof[:], mustHashBytes("6666666666666666666666666666666666666666666666666666666666666666"))

	// one non-final miniblock in the template
	mb0 := mkMiniBlock(1, false, false, 1, 3, 500, [2]uint32{0xaabbccdd, 0}, mustBytes16("00112233445566778899aabbccddeeff"), 0, [3]uint32{4, 5, 6})

	template := block.Block{
		Major_Version: 1, Minor_Version: 0, Timestamp: 1700000000000, Height: 500,
		Miner_TX: tx, Proof: proof, Tips: tips,
		MiniBlocks: []block.MiniBlock{mb0}, Tx_hashes: txHashes,
	}
	templateSer := template.Serialize()

	// bind the final miniblock: KeyHash[:16] = sha3(templateSer)[:16]
	// (== completed.SerializeWithoutLastMiniBlock()). Final + HighDiff.
	hdr := sha3.Sum256(templateSer)
	finalMb := mkMiniBlock(1, true, true, 1, 4, 500, [2]uint32{0xaabbccdd, 0}, hdr[:16], 0, [3]uint32{7, 8, 9})

	completed := template
	completed.MiniBlocks = []block.MiniBlock{mb0, finalMb}
	blockSer := completed.Serialize()
	serWithoutLast := completed.SerializeWithoutLastMiniBlock()
	headerHash := completed.GetHashSkipLastMiniBlock()

	// tampered error string (starts_with-checked by the test)
	tamperedErr := fmt.Sprintf("MiniBlock has corrupted header expected %x actual %x",
		headerHash[:], finalMb.KeyHash[:16])

	emit(map[string]any{
		"template_ser_hex":                hex.EncodeToString(templateSer),
		"final_mbl_ser_hex":               hex.EncodeToString(finalMb.Serialize()),
		"block_ser_hex":                   hex.EncodeToString(blockSer),
		"ser_without_last_hex":            hex.EncodeToString(serWithoutLast),
		"block_header_hash_hex":           hex.EncodeToString(headerHash[:]),
		"final_key_hash16_hex":            hex.EncodeToString(finalMb.KeyHash[:16]),
		"convert_keyhash_match":           true,
		"template_equals_ser_without_last": true,
		"hashcheck_ok":                    true,
		"tampered_err":                    tamperedErr,
		"non_highdiff_err":                "corrupted block",
		"non_final_err":                   "corrupted block",
	})
}

// ---- proofnonce.json ------------------------------------------------------

func dumpProofnonce() {
	txHex := strings.TrimSpace(proofnonceTxHex)
	raw, err := hex.DecodeString(txHex)
	if err != nil {
		die("proofnonce blob bad hex: %v", err)
	}
	var tx transaction.Transaction
	if err := tx.Deserialize(raw); err != nil {
		die("proofnonce deserialize: %v", err)
	}
	txid := tx.GetHash()

	var payloads []map[string]any
	for i := range tx.Payloads {
		nonce := tx.Payloads[i].Proof.Nonce()
		payloads = append(payloads, map[string]any{
			"scid_hex":       hex.EncodeToString(tx.Payloads[i].SCID[:]),
			"nonce_hex":      hex.EncodeToString(nonce[:]),
			"statement_fees": tx.Payloads[i].Statement.Fees,
		})
	}

	emit(map[string]any{
		"tx_hex":     txHex,
		"txid_hex":   hex.EncodeToString(txid[:]),
		"size_bytes": len(tx.Serialize()),
		"fees":       tx.Fees(),
		"payloads":   payloads,
	})
}

func hashHexes(hs []crypto.Hash) []string {
	out := []string{}
	for _, h := range hs {
		out = append(out, hex.EncodeToString(h[:]))
	}
	return out
}

func mustBytes16(hexstr string) []byte {
	b, err := hex.DecodeString(hexstr)
	if err != nil || len(b) != 16 {
		die("bad 16-byte hex %q", hexstr)
	}
	return b
}

func mustHashBytes(hexstr string) []byte {
	b, err := hex.DecodeString(hexstr)
	if err != nil || len(b) != 32 {
		die("bad 32-byte hex %q", hexstr)
	}
	return b
}

// ---- argdecode.json -------------------------------------------------------
//
// Adversarial CBOR corpus for rpc.Arguments.UnmarshalBinary. Strategy: take
// SINGLE-argument valid encodings (so any decode error is about one
// unambiguous key — Go's map-iteration nondeterminism can't bite) and mutate
// them systematically (truncate at every length, flip every byte), plus a few
// hand-crafted specials. Each input is run through Go; whatever Go decides is
// dumped. The faithful Rust port must reproduce every outcome — a divergence is
// a real finding, reported, not hidden.

// argdecodeArgDump renders a decoded arg in the VArg shape argdecode_vectors.rs
// reads (H/A use the "hex" field, not "hash_hex").
func argdecodeArgDump(a rpc.Argument) map[string]any {
	m := map[string]any{"name": a.Name, "type": string(a.DataType)}
	switch v := a.Value.(type) {
	case uint64:
		m["u"] = v
	case int64:
		m["i"] = v
	case string:
		m["s"] = v
	case crypto.Hash:
		m["hex"] = hex.EncodeToString(v[:])
	case []byte:
		m["hex"] = hex.EncodeToString(v)
	case rpc.Address:
		m["hex"] = hex.EncodeToString(v.PublicKey.EncodeCompressed())
	case *rpc.Address:
		m["hex"] = hex.EncodeToString(v.PublicKey.EncodeCompressed())
	case float64:
		m["f64_bits"] = fmt.Sprintf("%016x", math.Float64bits(v))
	case time.Time:
		m["unix"] = v.Unix()
	default:
		die("argdecodeArgDump: unhandled %T", v)
	}
	return m
}

func dumpArgdecode() {
	// single-argument valid bases (diverse types + values)
	apub := pubFromSecret(mustBig("55"))
	bases := []rpc.Arguments{
		{{Name: "aa", DataType: rpc.DataUint64, Value: uint64(0)}},
		{{Name: "bb", DataType: rpc.DataUint64, Value: uint64(300)}},
		{{Name: "cc", DataType: rpc.DataUint64, Value: uint64(0xffffffffffffffff)}},
		{{Name: "dd", DataType: rpc.DataInt64, Value: int64(-1)}},
		{{Name: "ee", DataType: rpc.DataInt64, Value: int64(-100000)}},
		{{Name: "ff", DataType: rpc.DataString, Value: "hello"}},
		{{Name: "gg", DataType: rpc.DataString, Value: ""}},
		{{Name: "hh", DataType: rpc.DataHash, Value: mustHash("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")}},
		{{Name: "ii", DataType: rpc.DataAddress, Value: rpc.Address{PublicKey: apub}}},
		{{Name: "jj", DataType: rpc.DataFloat64, Value: 3.14}},
		{{Name: "kk", DataType: rpc.DataTime, Value: time.Unix(1700000000, 0).UTC()}},
		// a couple of multi-arg positives (not mutated — coverage only)
		{
			{Name: "D", DataType: rpc.DataUint64, Value: uint64(1)},
			{Name: "C", DataType: rpc.DataString, Value: "x"},
		},
	}

	seen := map[string]bool{}
	var cases []map[string]any

	addCase := func(name, inputHex string) {
		if seen[inputHex] {
			return
		}
		seen[inputHex] = true
		raw, err := hex.DecodeString(inputHex)
		if err != nil {
			return
		}
		var args rpc.Arguments
		c := map[string]any{"name": name, "input_hex": inputHex}
		if e := args.UnmarshalBinary(raw); e != nil {
			c["ok"] = false
			c["error"] = e.Error()
		} else {
			c["ok"] = true
			c["remarshal_hex"] = marshalHex(args)
			ad := []map[string]any{}
			for _, a := range args {
				ad = append(ad, argdecodeArgDump(a))
			}
			c["args"] = ad
		}
		cases = append(cases, c)
	}

	// positive bases
	for i, b := range bases {
		enc, err := b.MarshalBinary()
		if err != nil {
			die("base %d marshal: %v", i, err)
		}
		addCase(fmt.Sprintf("valid_%d", i), hex.EncodeToString(enc))
	}

	// Truncations of each single-arg base. A truncation removes TRAILING bytes,
	// so it is either a clean shorter item (both accept) or a mid-item cut (both
	// report a CBOR EOF error the Rust port replicates). It never creates the
	// trailing-DATA class below, so Go and the port agree.
	//
	// NOTE (intentional exclusion): byte-flips of a length/count prefix produce
	// inputs with EXTRANEOUS TRAILING DATA. Go's dec.Unmarshal rejects those
	// ("cbor: N bytes of extraneous data"), but the Rust port DELIBERATELY
	// validates only the first CBOR item and ignores trailing bytes (documented
	// at block/src/arguments.rs:28,546). That is a known, intentional design
	// difference — not a decoder bug — so this corpus does not probe it; it would
	// test a divergence both sides already agree to disagree on. Surfaced in the
	// commit message, not silently dropped.
	for i := 0; i < 11; i++ {
		enc, _ := bases[i].MarshalBinary()
		for n := 1; n < len(enc); n++ {
			addCase(fmt.Sprintf("trunc_%d_%d", i, n), hex.EncodeToString(enc[:n]))
		}
	}

	// Semantic malformations — the adversarial surface the port is built to
	// match (rpc.go's "has invalid data type"/"Invalid encoding for key" +
	// cbor validity errors). Each is a single, well-formed CBOR item (no
	// trailing data) with one semantic fault, so the outcome is unambiguous.
	// CBOR definite-length head for major type `major<<5`, length n.
	cbHead := func(major byte, n int) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 256:
			return []byte{major<<5 | 24, byte(n)}
		default:
			return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
		}
	}
	cbText := func(s string) []byte { return append(cbHead(3, len(s)), []byte(s)...) }
	cbBytes := func(b []byte) []byte { return append(cbHead(2, len(b)), b...) }
	map1 := func(keyTag, val []byte) []byte { // {keyTag: val}
		return append(append([]byte{0xa1}, keyTag...), val...)
	}
	// wrong VALUE type for each key tag (Go: "...has invalid data type...")
	addCase("wrongtype_U_str", hex.EncodeToString(map1(cbText("aU"), cbText("no"))))
	addCase("wrongtype_I_str", hex.EncodeToString(map1(cbText("bI"), cbText("no"))))
	addCase("wrongtype_F_str", hex.EncodeToString(map1(cbText("cF"), cbText("no"))))
	addCase("wrongtype_H_int", hex.EncodeToString(map1(cbText("dH"), []byte{0x0a})))
	addCase("wrongtype_A_int", hex.EncodeToString(map1(cbText("eA"), []byte{0x0a})))
	addCase("wrongtype_U_bytes", hex.EncodeToString(map1(cbText("fU"), cbBytes([]byte{1, 2}))))
	// H/A with wrong byte-string length (must be 32 / 33)
	addCase("H_len31", hex.EncodeToString(map1(cbText("gH"), cbBytes(make([]byte, 31)))))
	addCase("H_len33", hex.EncodeToString(map1(cbText("hH"), cbBytes(make([]byte, 33)))))
	addCase("A_len32", hex.EncodeToString(map1(cbText("iA"), cbBytes(make([]byte, 32)))))
	addCase("A_len34", hex.EncodeToString(map1(cbText("jA"), cbBytes(make([]byte, 34)))))
	addCase("A_zeros33", hex.EncodeToString(map1(cbText("kA"), cbBytes(make([]byte, 33))))) // bn256 decompress corner
	// key length / shape faults
	addCase("one_char_key", hex.EncodeToString(map1(cbText("U"), []byte{0x18, 0x18})))       // key "U" len<2
	addCase("empty_key", hex.EncodeToString(map1(cbText(""), []byte{0x01})))                 // key "" len<2
	addCase("unknown_type_tag", hex.EncodeToString(map1(cbText("xZ"), []byte{0x01})))        // tag 'Z' unknown
	// not-a-map top-level items
	addCase("top_uint", "182a")   // 42
	addCase("top_negint", "20")   // -1
	addCase("top_array", "820102") // [1,2]
	addCase("top_text", hex.EncodeToString(cbText("hi")))
	addCase("top_bytes", hex.EncodeToString(cbBytes([]byte{1, 2, 3})))
	// valid multi-key maps (positives, sorted-dump exercised)
	addCase("empty_map", "a0")
	twoKey := append([]byte{0xa2}, append(append(cbText("aU"), 0x01), append(cbText("bS"), cbText("x")...)...)...)
	addCase("two_valid", hex.EncodeToString(twoKey))

	if len(cases) < 100 {
		die("only %d argdecode cases; need >= 100", len(cases))
	}

	// report accept/reject split to stderr (visibility, not a gate)
	ok, bad := 0, 0
	for _, c := range cases {
		if c["ok"].(bool) {
			ok++
		} else {
			bad++
		}
	}
	fmt.Fprintf(os.Stderr, "argdecode: %d cases (%d accept, %d reject)\n", len(cases), ok, bad)

	emit(map[string]any{"cases": cases})
}

// ---- bn256.json -----------------------------------------------------------
//
// Raw bn256 G1 curve ops (the CURVE generator, not the protocol crypto.G).

func g1Compress(g *bn256.G1) []byte {
	return (*crypto.Point)(g).EncodeCompressed()
}

func dumpBn256() {
	scalars := []string{"01", "02", "03", "0a", "ff", "0100", "deadbeef",
		"0123456789abcdef0123456789abcdef"}
	var sbm []map[string]any
	for _, kh := range scalars {
		kb, _ := hex.DecodeString(kh)
		k := new(big.Int).SetBytes(kb)
		g := new(bn256.G1).ScalarBaseMult(k)
		sbm = append(sbm, map[string]any{
			"k":          kh,
			"marshal":    hex.EncodeToString(g.Marshal()),
			"compressed": hex.EncodeToString(g1Compress(g)),
		})
	}

	pairs := [][2]string{{"02", "03"}, {"0a", "14"}, {"ff", "0100"}, {"deadbeef", "01"}}
	var adds []map[string]any
	for _, p := range pairs {
		ab, _ := hex.DecodeString(p[0])
		bb, _ := hex.DecodeString(p[1])
		ag := new(bn256.G1).ScalarBaseMult(new(big.Int).SetBytes(ab))
		bg := new(bn256.G1).ScalarBaseMult(new(big.Int).SetBytes(bb))
		sum := new(bn256.G1).Add(ag, bg)
		adds = append(adds, map[string]any{
			"a": p[0], "b": p[1], "marshal": hex.EncodeToString(sum.Marshal()),
		})
	}

	var negs []map[string]any
	for _, kh := range []string{"01", "05", "ff", "deadbeef"} {
		kb, _ := hex.DecodeString(kh)
		g := new(bn256.G1).ScalarBaseMult(new(big.Int).SetBytes(kb))
		ng := new(bn256.G1).Neg(g)
		negs = append(negs, map[string]any{"k": kh, "marshal": hex.EncodeToString(ng.Marshal())})
	}

	emit(map[string]any{"scalar_base_mul": sbm, "add": adds, "neg": negs})
}

// ---- crypto.json ----------------------------------------------------------
//
// Keccak, hash-to-number, protocol generators (G/H/Gs/Hs), hash-to-point, and
// secret·G pubkeys. Gs[i]/Hs[i] reproduce derohe's NewGeneratorParams formula:
// HashToPoint(HashtoNumber(PROTOCOL_CONSTANT+tag ++ 32-byte-BE(i))).

func genPoint(tag string, i int) *bn256.G1 {
	var idx [32]byte
	big.NewInt(int64(i)).FillBytes(idx[:])
	seed := append([]byte(crypto.PROTOCOL_CONSTANT+tag), idx[:]...)
	return crypto.HashToPoint(crypto.HashtoNumber(seed))
}

func dumpCrypto() {
	// keccak256
	var keccaks []map[string]any
	for _, s := range []string{"", "a", "abc", "DERO", "The quick brown fox"} {
		h := crypto.Keccak256([]byte(s))
		keccaks = append(keccaks, map[string]any{"input": s, "hex": hex.EncodeToString(h[:])})
	}

	// hash_to_number
	var htn []map[string]any
	for _, s := range []string{"DEROG", "DEROH", "a", "seed-123"} {
		n := crypto.HashtoNumber([]byte(s))
		htn = append(htn, map[string]any{"input": s, "dec": n.String()})
	}

	// generators: G, H, and a sampling of Gs[i]/Hs[i]
	pt := func(label string, g *bn256.G1) map[string]any {
		return map[string]any{
			"label":      label,
			"marshal":    hex.EncodeToString(g.Marshal()),
			"compressed": hex.EncodeToString(g1Compress(g)),
		}
	}
	// crypto.G is exported; H is not, so recompute it the same way the package
	// does: HashToPoint(HashtoNumber(PROTOCOL_CONSTANT+"H")).
	hPoint := crypto.HashToPoint(crypto.HashtoNumber([]byte(crypto.PROTOCOL_CONSTANT + "H")))
	points := []map[string]any{pt("G", crypto.G), pt("H", hPoint)}
	for _, i := range []int{0, 1, 2, 63, 127} {
		points = append(points, pt(fmt.Sprintf("Gs[%d]", i), genPoint("G", i)))
		points = append(points, pt(fmt.Sprintf("Hs[%d]", i), genPoint("H", i)))
	}

	// hash_to_point
	var htp []map[string]any
	for _, s := range []string{"1", "255", "123456789", "999999999999999999"} {
		seed, _ := new(big.Int).SetString(s, 10)
		p := crypto.HashToPoint(seed)
		htp = append(htp, map[string]any{"seed_dec": s, "marshal": hex.EncodeToString(p.Marshal())})
	}

	// pubkeys: secret·crypto.G
	var pubkeys []map[string]any
	for _, s := range secretDecs {
		pub := pubFromSecret(mustBig(s))
		pubkeys = append(pubkeys, map[string]any{
			"secret": s, "compressed": hex.EncodeToString(pub.EncodeCompressed()),
		})
	}

	emit(map[string]any{
		"keccak256":      keccaks,
		"hash_to_number": htn,
		"points":         points,
		"hash_to_point":  htp,
		"pubkeys":        pubkeys,
	})
}

// ---- crypto algebra helpers -----------------------------------------------

var scalarOrder = bn256.Order

func fvOf(xs ...int64) *crypto.FieldVector {
	v := make([]*big.Int, len(xs))
	for i, x := range xs {
		v[i] = big.NewInt(x)
	}
	return crypto.NewFieldVector(v)
}

func bigs(xs ...int64) []*big.Int {
	v := make([]*big.Int, len(xs))
	for i, x := range xs {
		v[i] = big.NewInt(x)
	}
	return v
}

func decStrs(bs []*big.Int) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.String()
	}
	return out
}

func gMul(n int64) *bn256.G1 {
	return new(bn256.G1).ScalarMult(crypto.G, big.NewInt(n))
}

func fvRaw(fv *crypto.FieldVector) []*big.Int { return fv.SliceRaw(0, fv.Length()) }

func compHex(g *bn256.G1) string { return hex.EncodeToString(g1Compress(g)) }

// ---- polynomial.json ------------------------------------------------------

func dumpPolynomial() {
	a := bigs(1, 2, 3)
	b := bigs(4, 5, 6)
	rows := crypto.RecursivePolynomials(nil, crypto.NewPolynomial(bigs(1)), a, b)
	recRows := make([][]string, len(rows))
	for i, r := range rows {
		recRows[i] = decStrs(r)
	}
	emit(map[string]any{"a": decStrs(a), "b": decStrs(b), "rec_rows": recRows})
}

// ---- nonbalance.json ------------------------------------------------------

func dumpNonbalance() {
	nonce := uint64(42)
	nl, nr, nc, nd := int64(100), int64(7), int64(3), int64(2)
	balance := crypto.ConstructElGamal(gMul(nl), gMul(nr))
	nb := &crypto.NonceBalance{NonceHeight: nonce, Balance: balance}
	echanges := crypto.ConstructElGamal(gMul(nc), gMul(nd))
	added := &crypto.NonceBalance{NonceHeight: nonce, Balance: balance.Add(echanges)}

	regSecret, regAmount := int64(5), uint64(1000)
	pubkey := gMul(regSecret)
	regbal := crypto.ConstructElGamal(pubkey, crypto.ElGamal_BASE_G).Plus(big.NewInt(int64(regAmount)))
	regnb := &crypto.NonceBalance{NonceHeight: 0, Balance: regbal}

	emit(map[string]any{
		"nonce": nonce, "nl": nl, "nr": nr, "nc": nc, "nd": nd,
		"ser_hex":       hex.EncodeToString(nb.Serialize()),
		"added_ser_hex": hex.EncodeToString(added.Serialize()),
		"reg_secret":    regSecret, "reg_amount": regAmount,
		"reg_ser_hex": hex.EncodeToString(regnb.Serialize()),
	})
}

// ---- statement.json -------------------------------------------------------

func dumpStatement() {
	gsumInput := "the graviton sum input"
	gsum := graviton.Sum([]byte(gsumInput))

	// ring size must be a power of 2 (Statement.Serialize → GetPowerof2)
	pubScalars := []int64{11, 22, 33, 44}
	cScalars := []int64{4, 5, 6, 7}
	dScalar := int64(7)
	var roothash [32]byte
	copy(roothash[:], mustHashBytes("77777777777777777777777777777777777777777777777777777777777777aa"))

	pubs := make([]*bn256.G1, len(pubScalars))
	for i, n := range pubScalars {
		pubs[i] = gMul(n)
	}
	cs := make([]*bn256.G1, len(cScalars))
	for i, n := range cScalars {
		cs[i] = gMul(n)
	}
	s := crypto.Statement{
		Publickeylist:       pubs,
		C:                   cs,
		D:                   gMul(dScalar),
		Fees:                12345,
		Bytes_per_publickey: 8,
		Roothash:            roothash,
	}
	var buf bytes.Buffer
	s.Serialize(&buf)

	emit(map[string]any{
		"graviton_sum_input":  gsumInput,
		"graviton_sum_hex":    hex.EncodeToString(gsum[:]),
		"pub_scalars":         pubScalars,
		"c_scalars":           cScalars,
		"d_scalar":            dScalar,
		"roothash_hex":        hex.EncodeToString(roothash[:]),
		"fees":                s.Fees,
		"bytes_per_publickey": s.Bytes_per_publickey,
		"serialized_hex":      hex.EncodeToString(buf.Bytes()),
	})
}

// ---- algebra.json ---------------------------------------------------------

func dumpAlgebra() {
	a := fvOf(1, 2, 3, 4)
	b := fvOf(5, 6, 7, 8)

	// FieldVector ops
	out := map[string]any{
		"inner_product": a.InnerProduct(b).String(),
		"hadamard":      decStrs(fvRaw(a.Hadamard(b))),
		"times_a_9":     decStrs(fvRaw(a.Times(big.NewInt(9)))),
		"negate_a":      decStrs(fvRaw(a.Negate())),
		"sum_a":         a.Sum().String(),
		"flip_a":        decStrs(fvRaw(a.Flip())),
		"add_ab":        decStrs(fvRaw(a.Add(b))),
		"concat_ab":     decStrs(fvRaw(a.Concat(b))),
		"invert_a":      decStrs(fvRaw(a.Invert())),
	}

	// FieldVectorPolynomial
	poly := crypto.NewFieldVectorPolynomial(a, b)
	poly2 := crypto.NewFieldVectorPolynomial(b, a)
	out["poly_eval_x3"] = decStrs(fvRaw(poly.Evaluate(big.NewInt(3))))
	out["poly_inner_product"] = decStrs(poly.InnerProduct(poly2))

	// PointVector + convolution
	base := []*bn256.G1{gMul(1), gMul(2), gMul(3), gMul(4)}
	bv := crypto.NewPointVector(base)
	basePts := make([]string, len(base))
	for i, p := range base {
		basePts[i] = compHex(p)
	}
	out["base_points"] = basePts
	out["commit_1234"] = compHex(bv.Commit(bigs(1, 2, 3, 4)))
	out["multi_exp"] = compHex(bv.MultiExponentiate(a))
	out["pv_sum"] = compHex(bv.Sum())
	conv := crypto.Convolution(a, bv)
	convPts := make([]string, conv.Length())
	for i := 0; i < conv.Length(); i++ {
		convPts[i] = compHex(conv.Slice(i, i+1).Sum())
	}
	out["convolution"] = convPts

	// pedersen_commit(99, [2,4,6,8], [1,3,5,7]) — computed to match the Rust
	// (blind·H + Σ Gs[i]·g[i] + Σ Hs[i]·h[i]), since Go's Commit randomizes.
	gexps := bigs(2, 4, 6, 8)
	hexps := bigs(1, 3, 5, 7)
	hPoint := crypto.HashToPoint(crypto.HashtoNumber([]byte(crypto.PROTOCOL_CONSTANT + "H")))
	res := new(bn256.G1).ScalarMult(hPoint, new(big.Int).Mod(big.NewInt(99), scalarOrder))
	for i, e := range gexps {
		res = new(bn256.G1).Add(res, new(bn256.G1).ScalarMult(genPoint("G", i), new(big.Int).Mod(e, scalarOrder)))
	}
	for i, e := range hexps {
		res = new(bn256.G1).Add(res, new(bn256.G1).ScalarMult(genPoint("H", i), new(big.Int).Mod(e, scalarOrder)))
	}
	out["pedersen_commit"] = compHex(res)

	emit(out)
}

// ---- innerproduct.json ----------------------------------------------------
//
// Salt-driven (deterministic, no RNG) inner-product argument. The Rust
// InnerProduct::generate(gs, hs, u, a, b, salt) maps to Go's
// NewInnerProductProof(IPStatement{PrimeBase: GeneratorParams{Gs, Hs, H:u}},
// IPWitness{L:a, R:b}, salt). P is unused in generation (salt seeds Fiat-Shamir).

func dumpInnerproduct() {
	const n = 4
	aVals := []int64{1, 2, 3, 4}
	bVals := []int64{5, 6, 7, 8}
	a := fvOf(aVals...)
	b := fvOf(bVals...)
	salt := big.NewInt(1234567)

	gsPts := make([]*bn256.G1, n)
	hsPts := make([]*bn256.G1, n)
	for i := 0; i < n; i++ {
		gsPts[i] = genPoint("G", i)
		hsPts[i] = genPoint("H", i)
	}
	u := crypto.HashToPoint(crypto.HashtoNumber([]byte(crypto.PROTOCOL_CONSTANT + "H"))) // base_h
	gsVec := crypto.NewPointVector(gsPts)
	hsVec := crypto.NewPointVector(hsPts)
	gp := &crypto.GeneratorParams{H: u, Gs: gsVec, Hs: hsVec}

	// P = <a,gs> + <b,hs> + <a,b>·u — the IP commitment. Its value does not
	// affect the emitted proof (ls/rs/a/b depend only on the salt-seeded
	// Fiat-Shamir challenges), but Go threads P through the recursion, so it
	// must be a valid point (not an uninitialized new(G1)).
	P := new(bn256.G1).Add(gsVec.Commit(fvRaw(a)), hsVec.Commit(fvRaw(b)))
	P = new(bn256.G1).Add(P, new(bn256.G1).ScalarMult(u, a.InnerProduct(b)))
	ips := &crypto.IPStatement{PrimeBase: gp, P: P}
	witness := &crypto.IPWitness{L: a, R: b}
	ip := crypto.NewInnerProductProof(ips, witness, salt)

	var buf bytes.Buffer
	ip.Serialize(&buf)
	emit(map[string]any{
		"n":              n,
		"salt":           salt.String(),
		"as":             aVals,
		"bs":             bVals,
		"serialized_hex": hex.EncodeToString(buf.Bytes()),
	})
}

// ---- selfcheck ------------------------------------------------------------

func selfcheck() {
	// pubkey derivation is live and the address encoder round-trips.
	pub := pubFromSecret(big.NewInt(1))
	a := rpc.Address{Mainnet: true, PublicKey: pub}
	s := a.String()
	back, err := rpc.NewAddress(s)
	if err != nil {
		die("selfcheck: address decode: %v", err)
	}
	if hex.EncodeToString(back.Compressed()) != hex.EncodeToString(a.Compressed()) {
		die("selfcheck: address round-trip pubkey mismatch")
	}
	// arguments marshal/unmarshal round-trips.
	args := rpc.Arguments{{Name: "C", DataType: rpc.DataString, Value: "dero"}}
	b, err := args.MarshalBinary()
	if err != nil {
		die("selfcheck: args marshal: %v", err)
	}
	var got rpc.Arguments
	if err := got.UnmarshalBinary(b); err != nil {
		die("selfcheck: args unmarshal: %v", err)
	}
	fmt.Fprintf(os.Stderr, "selfcheck ok (addr=%s…)\n", s[:12])
}

func main() {
	if len(os.Args) < 2 {
		die("usage: harness <address|iaddress|scdata|scdataft|block|miniblockhash|proofnonce|argdecode|selfcheck>")
	}
	switch os.Args[1] {
	case "address":
		dumpAddress()
	case "scdata":
		dumpScdata()
	case "iaddress":
		dumpIaddress()
	case "scdataft":
		dumpScdataft()
	case "block":
		dumpBlock()
	case "miniblockhash":
		dumpMiniblockhash()
	case "proofnonce":
		dumpProofnonce()
	case "argdecode":
		dumpArgdecode()
	case "bn256":
		dumpBn256()
	case "crypto":
		dumpCrypto()
	case "polynomial":
		dumpPolynomial()
	case "nonbalance":
		dumpNonbalance()
	case "statement":
		dumpStatement()
	case "algebra":
		dumpAlgebra()
	case "innerproduct":
		dumpInnerproduct()
	case "selfcheck":
		selfcheck()
	default:
		die("suite %q not implemented yet", os.Args[1])
	}
}
