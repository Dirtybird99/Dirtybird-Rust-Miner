//! aarch64: assert the SHA-256 backend is the *hardware* one when it must be.
//!
//! Every AstroBWTv3 hash finishes by SHA-256-ing the suffix-array output —
//! ~263-284 KB, ~4,200 compression calls — so on ARM the gap between sha2's
//! software rounds and the ARMv8 crypto extensions is most of the hashrate (a
//! Snapdragon 8 Elite measured 2.41 KH/s on the software path). astrobwt's
//! Cargo.toml enables sha2's `asm` feature for aarch64 to get the hardware
//! backend, but that backend still consults AT_HWCAP at runtime (via
//! cpufeatures) and silently falls back to software when the bit is clear.
//!
//! That leaves two ways to ship a hollow win, neither visible in a build log:
//!   1. the binary carries SHA256H/SHA256SU yet the process never executes them
//!      because hwcap says no, and
//!   2. a CI correctness run "proves" the hardware backend under an emulator
//!      that reports no crypto extensions, so only software rounds ever ran —
//!      a green tick that verified nothing about the code that changed.
//!
//! So: always report what detection found, and *assert* it whenever the caller
//! declares this environment is meant to have it — CI sets
//! DERO_REQUIRE_AARCH64_SHA2=1, including for the qemu run, which turns "the
//! emulator lacks crypto extensions" into a failure instead of a hollow pass.
//! Deliberately unset by default: contributors on ARM boards without the
//! extensions (Cortex-A72 / Raspberry Pi 4) still get a passing suite, and the
//! software fallback is correct there — just slow.
#![cfg(target_arch = "aarch64")]

#[test]
fn reports_aarch64_sha2_hwcap() {
    // The same AT_HWCAP bit cpufeatures reads inside sha2's aarch64 backend.
    let detected = std::arch::is_aarch64_feature_detected!("sha2");
    eprintln!("aarch64 sha2 (ARMv8 crypto extensions) hwcap detected = {detected}");

    if std::env::var_os("DERO_REQUIRE_AARCH64_SHA2").is_some() {
        assert!(
            detected,
            "DERO_REQUIRE_AARCH64_SHA2 is set, but AT_HWCAP reports no ARMv8 \
             SHA-256 support: sha2 is running software rounds here, so any \
             hashrate or correctness claim about the hardware backend made in \
             this environment is void"
        );
    }
}
