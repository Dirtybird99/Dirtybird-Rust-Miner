package astrobwtv3

// Instrumentation hooks for the Rust miner's test-vector harness.
//
// AstroBWTv3 (in pow.go) writes each intermediate it computes into these
// package globals as a side effect, so the harness can dump the exact
// prologue and op-loop state the Rust `Debug` struct records — WITHOUT
// duplicating the 256-case op switch. The hash return value is unchanged, so
// the shipped known-answer vectors (pow("a") = 54e2324d…) still prove the
// instrumented function is faithful.
//
// Single-threaded use only (the harness runs one hash at a time).

var (
	HxShaKey       [32]byte // sha256(input)  — prologue step 1
	HxPostSalsa    [256]byte // salsa20 keystream — prologue step 2
	HxPostRc4      [256]byte // modified RC4 — prologue step 3
	HxLhashInitial uint64    // fnv1a-64 of post-rc4 — prologue step 4 (lhash)
	HxTries        uint64    // op-loop iteration count
	HxDataLen      uint32    // accumulated stream length fed to the suffix array
	HxLhashFinal   uint64    // lhash after the op loop
	HxPrevLhash    uint64    // prev_lhash after the op loop
	HxStep3Final   [256]byte // 256-byte working buffer after the op loop
	HxDataHash     [32]byte  // sha256(stream[:data_len]) — op-loop fingerprint
)

// Sais832 returns the suffix array of text using this package's sais_8_32, the
// UNRESTRICTED 32-bit SA-IS the AstroBWTv3 v3 pipeline uses (handles the full
// MAX_LENGTH=98303 range, unlike the fixed-9973 astrobwt package variant). This
// is the exact engine the Rust `sais32` module was ported from.
func Sais832(text []byte) []int32 {
	sa := make([]int32, len(text))
	text_32(text, sa)
	return sa
}
