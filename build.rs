// Build the AstroBWTv3 suffix-array hot path (portable C/C++) plus the x86-only SHA-NI and
// AVX2-wolf accelerators, via the `cc` crate so the same vendored sources cross-compile to
// every target (Windows/Linux x86_64, Linux/macOS aarch64) through whatever C toolchain
// cargo selects — system clang, or `zig cc` under cargo-zigbuild.
//
// The suffix array (libsais + the v1.14 descriptor SA) is portable C/C++ and is built on
// every target. `vendor/sha_ni/sha_ni.c` (SHA-NI) and `vendor/wolf/wolf_avx2.cpp` (AVX2)
// are x86-only and are skipped elsewhere — the Rust side falls back to the `sha2` crate's
// soft SHA-256 and the scalar `wolf_branch` (byte-identical output).
//
// Optional clang PGO on x86 (DERO_SA_PGO=use + a committed _pgo/merged.profdata), and
// optional `-flto` (DERO_LTO=on) which only helps when the linker is zig's lld (release
// cross-builds) — rustc's MSVC linker can't LTO discrete objects, so it is off by default.
use std::path::PathBuf;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendor = manifest.join("vendor");
    let inc_sais = vendor.join("libsais");
    let inc_v114 = vendor.join("v114");

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_x86 = target_arch == "x86_64";
    let is_windows = target_os == "windows";

    // Detect whether the C toolchain is `zig cc` (cargo-zigbuild cross-builds) — it wants
    // `-mcpu=x86_64_v3+sha`, whereas plain clang wants `-march=x86-64-v3 -msha`.
    let target_us = std::env::var("TARGET").unwrap_or_default().replace('-', "_");
    let probe = |k: &str| std::env::var(k).unwrap_or_default().to_lowercase();
    let cc_is_zig = probe("CC").contains("zig")
        || probe(&format!("CC_{target_us}")).contains("zig")
        || probe("TARGET_CC").contains("zig");

    // PGO: x86-only, opt-in via a committed profile (default "use", mirroring the Zig
    // miner). Skipped automatically when the target isn't x86 or the profile is absent.
    let pgo = env_or("DERO_SA_PGO", "use");
    let default_profile = manifest.join("_pgo").join("merged.profdata");
    let profile = env_or("DERO_SA_PROFDATA", &default_profile.to_string_lossy());
    let use_pgo = is_x86 && pgo == "use" && std::path::Path::new(&profile).exists();
    // LTO only when the linker is zig's lld (the release cross-builds set DERO_LTO=on);
    // rustc's MSVC linker can't LTO the discrete objects, so default off.
    let use_lto = is_x86 && env_or("DERO_LTO", "off") == "on";

    // Force clang only for a bare native Windows (MSVC) build — cl.exe can't compile the
    // vendored C++ (GCC/Clang builtins). When zig drives (cargo-zigbuild) or CC/CXX are set
    // (incl. the target-specific CC_<target> cargo-zigbuild exports), honor that toolchain.
    let has_cc = std::env::var("CC").is_ok() || std::env::var(format!("CC_{target_us}")).is_ok();
    let has_cxx = std::env::var("CXX").is_ok() || std::env::var(format!("CXX_{target_us}")).is_ok();
    let force_clang_c = is_windows && !cc_is_zig && !has_cc;
    let force_clang_cpp = is_windows && !cc_is_zig && !has_cxx;

    let common: &[&str] =
        &["-DNDEBUG", "-fomit-frame-pointer", "-finline-functions", "-funroll-loops", "-fno-sanitize=all"];

    let apply_common = |b: &mut cc::Build| {
        b.include(&inc_sais).include(&inc_v114).opt_level(3).warnings(false);
        for f in common {
            b.flag(f);
        }
        if is_x86 {
            if cc_is_zig {
                b.flag("-mcpu=x86_64_v3+sha");
            } else {
                b.flag("-march=x86-64-v3").flag("-msha");
            }
        }
        if use_pgo {
            b.flag(&format!("-fprofile-use={profile}"));
            // wolf_avx2/sha_ni carry no profile data; don't fail on that.
            b.flag_if_supported("-Wno-profile-instr-unprofiled");
            b.flag_if_supported("-Wno-profile-instr-out-of-date");
        }
        if use_lto {
            b.flag("-flto");
        }
    };

    // --- C: portable suffix array (+ x86 SHA-NI) ---
    let mut c = cc::Build::new();
    c.cpp(false);
    if force_clang_c {
        c.compiler("clang");
    }
    apply_common(&mut c);
    c.file(vendor.join("libsais").join("libsais.c"));
    c.file(vendor.join("v114").join("sha_stub.c"));
    if is_x86 {
        c.file(vendor.join("sha_ni").join("sha_ni.c"));
    }
    c.compile("dero_sa_c");

    // --- C++: v1.14 descriptor SA (+ x86 AVX2 wolf) ---
    let mut cpp = cc::Build::new();
    cpp.cpp(true);
    if force_clang_cpp {
        cpp.compiler("clang");
    }
    apply_common(&mut cpp);
    cpp.flag("-std=c++17").flag("-fno-vectorize").flag("-fno-slp-vectorize");
    cpp.file(vendor.join("v114").join("v114_stubs.cpp"));
    cpp.file(vendor.join("v114").join("v114_wrapper.cpp"));
    if is_x86 {
        cpp.file(vendor.join("wolf").join("wolf_avx2.cpp"));
    }
    cpp.compile("dero_sa_cpp");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor");
    println!("cargo:rerun-if-env-changed=DERO_SA_PGO");
    println!("cargo:rerun-if-env-changed=DERO_SA_PROFDATA");
    println!("cargo:rerun-if-env-changed=DERO_LTO");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CXX");
}
