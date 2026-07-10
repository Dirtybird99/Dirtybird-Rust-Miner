// Test-vector generator for the Rust DERO AstroBWTv3 miner.
//
// Dumps the golden vectors the Rust tests load from ../vectors/*.json, computed
// from the CANONICAL DERO Go reference (deroref/, a verbatim copy of
// github.com/deroproject/derohe/astrobwt with a few side-effect instrumentation
// hooks — see deroref/astrobwtv3/harness_hooks.go). The reference's hash output
// is untouched, so the shipped known-answer vectors still prove it faithful;
// `run.sh` self-checks pow("a") before writing anything.
//
//	go run . astrobwt   > ../vectors/astrobwt.json   # prologue + full pipeline
//	go run . pow16      > ../vectors/pow16.json       # legacy POW16
//	go run . sais       > ../vectors/sais.json        # SA-IS edge + boundary arrays
//	go run . selfcheck                                # KAT gate, no output
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/crypto/sha3"

	deroref "deroharness/deroref"
	v3 "deroharness/deroref/astrobwtv3"
)

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

// The 10 canonical known-answer vectors shipped in derohe's pow_test.go.
var kat = []struct{ in, out string }{
	{"a", "54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea"},
	{"ab", "faeaff767be60134f0bcc5661b5f25413791b4df8ad22ff6732024d35ec4e7d0"},
	{"abc", "715c3d8c61a967b7664b1413f8af5a2a9ba0005922cb0ba4fac8a2d502b92cd6"},
	{"abcd", "74cc16efc1aac4768eb8124e23865da4c51ae134e29fa4773d80099c8bd39ab8"},
	{"abcde", "d080d0484272d4498bba33530c809a02a4785368560c5c3eac17b5dacd357c4b"},
	{"abcdef", "813e89e0484cbd3fbb3ee059083af53ed761b770d9c245be142c676f669e4607"},
	{"abcdefg", "3972fe8fe2c9480e9d4eff383b160e2f05cc855dc47604af37bc61fdf20f21ee"},
	{"abcdefgh", "f96191b7e39568301449d75d42d05090e41e3f79a462819473a62b1fcc2d0997"},
	{"abcdefghi", "8c76af6a57dfed744d5b7467fa822d9eb8536a851884aa7d8e3657028d511322"},
	{"abcdefghij", "f838568c38f83034b2ff679d5abf65245bd2be1b27c197ab5fbac285061cf0a7"},
}

// selfcheck aborts unless the instrumented reference reproduces the shipped KAT.
// This is what makes the dumped intermediates trustworthy: if the op switch were
// mis-copied, the final hash would drift and this would fail.
func selfcheck() {
	for _, k := range kat {
		got := fmt.Sprintf("%x", v3.AstroBWTv3([]byte(k.in)))
		if got != k.out {
			die("KAT FAIL: pow(%q) = %s want %s", k.in, got, k.out)
		}
	}
	fmt.Fprintf(os.Stderr, "KAT ok (%d vectors)\n", len(kat))
}

func emit(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		die("marshal: %v", err)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

// ---- astrobwt.json (prologue + full) -------------------------------------

type fullCase struct {
	InputHex        string `json:"input_hex"`
	ShaKeyHex       string `json:"sha_key_hex"`
	PostSalsaHex    string `json:"post_salsa_hex"`
	PostRc4Hex      string `json:"post_rc4_hex"`
	Lhash           uint64 `json:"lhash"`
	FinalHashHex    string `json:"final_hash_hex"`
	Tries           uint64 `json:"tries"`
	DataLen         uint32 `json:"data_len"`
	LhashFinal      uint64 `json:"lhash_final"`
	PrevLhashFinal  uint64 `json:"prev_lhash_final"`
	Step3FinalHex   string `json:"step3_final_hex"`
	DataHashHex     string `json:"data_hash_hex"`
}

func dumpAstrobwt() {
	selfcheck()
	var inputs [][]byte
	for _, k := range kat {
		inputs = append(inputs, []byte(k.in))
	}
	// The empty input and a spread of miniblock-sized (48-byte) blobs.
	inputs = append(inputs, []byte{})
	inputs = append(inputs, mustHex("419ebb000000001bbdc9bf2200000000635d6e4e24829b4249fe0e67878ad4350000000043f53e5436cf610000086b00"))
	for seed := 1; seed <= 4; seed++ {
		inputs = append(inputs, deterministic(48, uint64(seed)*0x1234567))
	}

	var cases []fullCase
	for _, in := range inputs {
		hash := v3.AstroBWTv3(in) // populates the Hx* hooks as a side effect
		cases = append(cases, fullCase{
			InputHex:       hex.EncodeToString(in),
			ShaKeyHex:      hex.EncodeToString(v3.HxShaKey[:]),
			PostSalsaHex:   hex.EncodeToString(v3.HxPostSalsa[:]),
			PostRc4Hex:     hex.EncodeToString(v3.HxPostRc4[:]),
			Lhash:          v3.HxLhashInitial,
			FinalHashHex:   hex.EncodeToString(hash[:]),
			Tries:          v3.HxTries,
			DataLen:        v3.HxDataLen,
			LhashFinal:     v3.HxLhashFinal,
			PrevLhashFinal: v3.HxPrevLhash,
			Step3FinalHex:  hex.EncodeToString(v3.HxStep3Final[:]),
			DataHashHex:    hex.EncodeToString(v3.HxDataHash[:]),
		})
	}
	emit(cases)
}

// ---- pow16.json (legacy) --------------------------------------------------

func dumpPow16() {
	const stage1Len = 9973
	type pcase struct {
		InputHex  string `json:"input_hex"`
		KeyHex    string `json:"key_hex"`
		Stage1Hex string `json:"stage1_hex"`
		FinalHex  string `json:"final_hex"`
	}
	inputs := [][]byte{
		[]byte("a"), []byte("dero"), []byte("AstroBWT POW16 legacy"),
		mustHex("419ebb000000001bbdc9bf2200000000635d6e4e24829b4249fe0e67878ad4350000000043f53e5436cf610000086b00"),
		deterministic(48, 0xC0FFEE), deterministic(48, 0xBADF00D),
	}
	var cases []pcase
	for _, in := range inputs {
		key := sha3.Sum256(in)
		var counter [16]byte
		stage1 := make([]byte, stage1Len)
		salsa.XORKeyStream(stage1, stage1, &counter, &key)
		final := deroref.POW16(in)
		cases = append(cases, pcase{
			InputHex:  hex.EncodeToString(in),
			KeyHex:    hex.EncodeToString(key[:]),
			Stage1Hex: hex.EncodeToString(stage1),
			FinalHex:  hex.EncodeToString(final[:]),
		})
	}
	emit(map[string]any{"stage1_length": stage1Len, "cases": cases})
}

// ---- sais.json (SA-IS edge + boundary) ------------------------------------

func dumpSais() {
	type scase struct {
		Name     string  `json:"name"`
		InputHex string  `json:"input_hex"`
		Sa32     []int32 `json:"sa32"`
		HasSa16  bool    `json:"has_sa16"`
		Sa16     []int16 `json:"sa16,omitempty"`
	}
	add := func(cases *[]scase, name string, in []byte) {
		// sa32 from the v3 (unrestricted) sais_8_32 the Rust sais32 ports.
		sa32 := v3.Sais832(in)
		c := scase{Name: name, InputHex: hex.EncodeToString(in), Sa32: sa32}
		if len(in) < 32768 {
			c.HasSa16 = true
			c.Sa16 = deroref.Sais816(in)
			// Cross-check the two independent Go SA-IS engines agree (the SA is
			// unique): sais_8_16 cast to i32 must equal sais_8_32. Catches any
			// package mismatch before the vector is trusted.
			for i, v := range c.Sa16 {
				if int32(v) != sa32[i] {
					die("sais mismatch on %q at %d: sa16=%d sa32=%d", name, i, v, sa32[i])
				}
			}
		}
		*cases = append(*cases, c)
	}

	var cases []scase
	// trivial lengths
	add(&cases, "trivial_empty", []byte{})
	add(&cases, "trivial_1", []byte{7})
	add(&cases, "trivial_2_eq", []byte{9, 9})
	add(&cases, "trivial_2_ne", []byte{9, 3})
	// all-equal (recursion base cases)
	add(&cases, "all_equal_16", bytesOf(0x41, 16))
	add(&cases, "all_equal_255", bytesOf(0x41, 255))
	add(&cases, "all_equal_256", bytesOf(0x41, 256))
	add(&cases, "all_equal_257", bytesOf(0x41, 257))
	// monotone
	add(&cases, "monotone_inc_256", monotone(256, true))
	add(&cases, "monotone_dec_256", monotone(256, false))
	// SLSL alternation and short-period (force the recursion)
	add(&cases, "slsl_256", repeatPat([]byte{0, 1}, 256))
	add(&cases, "period3_258", repeatPat([]byte{'a', 'b', 'c'}, 258))
	add(&cases, "period7_259", repeatPat([]byte{1, 2, 3, 4, 5, 6, 7}, 259))
	// boundary lengths, pseudo-random content
	for _, n := range []int{255, 256, 257, 512, 1000, 9973} {
		add(&cases, fmt.Sprintf("rand_a256_%d", n), deterministic(n, uint64(n)*0x9E3779B1))
	}
	// small alphabets (stress the SA-IS induced-sort)
	add(&cases, "rand_a2_600", detAlpha(600, 2, 0xAA))
	add(&cases, "rand_a3_600", detAlpha(600, 3, 0xBB))
	add(&cases, "rand_a4_777", detAlpha(777, 4, 0xCC))
	add(&cases, "rand_a16_888", detAlpha(888, 16, 0xDD))
	// zero-tail and mixed (mirrors AstroBWT stream shapes)
	add(&cases, "zeros_300", bytesOf(0, 300))
	add(&cases, "half_zero_400", halfZero(400))
	// large boundary: sa32 only (len > i16::MAX)
	add(&cases, "max_98303", deterministic(98303, 0xDEADBEEF))

	if len(cases) < 20 {
		die("only %d sais cases; test needs >= 20", len(cases))
	}
	emit(map[string]any{"cases": cases})
}

// ---- deterministic content helpers (no rand: reproducible dumps) ----------

func splitmix(seed uint64) func() uint64 {
	s := seed
	return func() uint64 {
		s += 0x9E3779B97F4A7C15
		z := s
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
}
func deterministic(n int, seed uint64) []byte {
	next := splitmix(seed)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(next())
	}
	return b
}
func detAlpha(n int, alphabet uint64, seed uint64) []byte {
	next := splitmix(seed)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(next() % alphabet)
	}
	return b
}
func bytesOf(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}
func monotone(n int, inc bool) []byte {
	b := make([]byte, n)
	for i := range b {
		if inc {
			b[i] = byte(i)
		} else {
			b[i] = byte(255 - i)
		}
	}
	return b
}
func repeatPat(pat []byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = pat[i%len(pat)]
	}
	return b
}
func halfZero(n int) []byte {
	next := splitmix(0x5151)
	b := make([]byte, n)
	for i := range b {
		if i%2 == 0 {
			b[i] = 0
		} else {
			b[i] = byte(next())
		}
	}
	return b
}
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		die("bad hex %q: %v", s, err)
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		die("usage: harness <astrobwt|pow16|sais|selfcheck>")
	}
	switch os.Args[1] {
	case "astrobwt":
		dumpAstrobwt()
	case "pow16":
		dumpPow16()
	case "sais":
		dumpSais()
	case "selfcheck":
		selfcheck()
	default:
		die("unknown suite %q", os.Args[1])
	}
}
