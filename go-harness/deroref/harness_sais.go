package astrobwt

// Exported wrappers so the Rust miner's test-vector harness can call the
// canonical Go SA-IS engines. These are the exact functions the Rust
// `sais32` / `sais16` modules were ported from (astrobwt/sais.go's
// sais_8_32 and astrobwt/sais16.go's sais_8_16), reached through the
// package-local text_32_0alloc / text_16_0alloc entry points.

// Sais832 returns the suffix array of text using Go's sais_8_32 (int32 indices).
func Sais832(text []byte) []int32 {
	sa := make([]int32, len(text))
	text_32_0alloc(text, sa)
	return sa
}

// Sais816 returns the suffix array of text using Go's sais_8_16 (int16 indices).
// Only valid for len(text) < 32768.
func Sais816(text []byte) []int16 {
	sa := make([]int16, len(text))
	text_16_0alloc(text, sa)
	return sa
}
