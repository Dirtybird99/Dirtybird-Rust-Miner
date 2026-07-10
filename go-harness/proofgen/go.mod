module proofgen

go 1.25.0

require (
	github.com/deroproject/derohe v0.0.0
	github.com/deroproject/graviton v0.0.0-20220130070622-2c248a53b2e1
	github.com/go-logr/logr v1.4.3
	golang.org/x/crypto v0.54.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// bn256 + graviton resolve via pristine derohe; only the copied crypto package
// (proofgen/crypto) is patched for the deterministic RNG.
replace github.com/deroproject/derohe => ../../../derohe-main
