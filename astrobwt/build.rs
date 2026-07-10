fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DERO_CC_PGO");
    println!("cargo:rerun-if-env-changed=DERO_CC_PGO_NO_RT");
    println!("cargo:rerun-if-env-changed=DERO_CC_LTO");
    println!("cargo:rerun-if-env-changed=DERO_CC_PROFILE_RT_DIR");
    println!("cargo:rerun-if-changed=vendor/v114/v114_stubs.cpp");
    println!("cargo:rerun-if-changed=vendor/v114/v114_wrapper.cpp");
    println!("cargo:rerun-if-changed=vendor/v114/sha_stub.c");
    println!("cargo:rerun-if-changed=vendor/v114/dluna_v114.h");
    println!("cargo:rerun-if-changed=vendor/v114/libsais.h");
    println!("cargo:rerun-if-changed=vendor/v114/openssl/sha.h");

    // Only the `v114-cpp` (dev/verification) feature compiles the vendored C++.
    // The production `v114` feature is the pure-Rust port in src/v114.rs and
    // needs no C++ toolchain — no clang-cl, no cross-language LTO.
    if std::env::var_os("CARGO_FEATURE_V114_CPP").is_none() {
        return;
    }

    let mut cpp = cc::Build::new();
    cpp.cpp(true)
        .include("vendor/v114")
        .define("NDEBUG", None)
        .file("vendor/v114/v114_stubs.cpp")
        .file("vendor/v114/v114_wrapper.cpp");

    // CORRECTION (2026-07-10): this file used to claim MSVC `cl.exe` miscompiles
    // the descriptor SA, producing a valid-but-mis-ordered suffix array for
    // "~1.4% of inputs". That was a MISATTRIBUTION of a Rust-side bug.
    //
    // The real cause: the descriptor reads 3 bytes past `data_len` (a `load24`)
    // and those bytes must be zero. The caller's tail zero-fill used
    // `Vec::resize`, which zeroes only NEWLY-APPENDED bytes — leaving live
    // op-loop bytes in the tail whenever the buffer was already long enough.
    // That fires on exactly 15/1024 = 1.46% of inputs, matching the observed
    // rate. Fixing the fill (see `astrobwtv3_with_scratch` in src/lib.rs) took
    // the descriptor-vs-libsais fuzz from 284/20000 divergences to 0/20000.
    // Independently: the C++ verified byte-exact under its own upstream
    // DLUNA_VERIFY_STAGE5_DESCRIPTOR oracle, and building the descriptor with
    // clang-cl, clang++ and MinGW-g++ at both O0 and O3 gave identical correct
    // results given a zero tail. It was a PORT bug, not a miscompile.
    //
    // Whether MSVC `cl.exe` *also* miscompiles this TU was never tested in
    // isolation, so clang-cl and the no-vectorize flags are retained out of
    // caution rather than demonstrated necessity. This whole path now builds
    // only under the dev-only `v114-cpp` feature; production uses the pure-Rust
    // port (src/v114.rs), which needs no C++ toolchain and no flag discipline.
    let compiler = cpp.get_compiler();
    if compiler.is_like_msvc() {
        let is_clang_cl = compiler
            .path()
            .to_string_lossy()
            .to_lowercase()
            .contains("clang-cl");
        if !is_clang_cl {
            // Force clang-cl (must be on PATH). cc treats it as MSVC-like.
            cpp.compiler("clang-cl");
        }
        cpp.flag("/std:c++17")
            .flag("/EHsc")
            // clang front-end flags MUST be passed through clang-cl via /clang:
            // (bare `-fno-vectorize` is silently ignored by the cl-style driver).
            // -fno-vectorize/-fno-slp-vectorize are the CORRECTNESS-CRITICAL
            // flags: the descriptor SA miscompiles when the vectorizer touches it
            // (the reference miner disables it for the same reason).
            .flag("/clang:-march=x86-64-v3")
            .flag("/clang:-mtune=raptorlake")
            .flag("/clang:-mavx2")
            .flag("/clang:-fno-vectorize")
            .flag("/clang:-fno-slp-vectorize");
    } else {
        // Non-MSVC (gcc/clang) hosts: the reference miner's verified flags.
        cpp.flag("-std=c++17")
            .flag("-O3")
            .flag("-march=x86-64-v3")
            .flag("-mtune=native")
            .flag("-mavx2")
            .flag("-fno-vectorize")
            .flag("-fno-slp-vectorize");
    }

    // PGO of the descriptor SA TU (the ~88%-of-hash hot path). Opt-in via env:
    //   DERO_CC_PGO=gen           -> instrument (write profile at runtime)
    //   DERO_CC_PGO=<merged.profdata> -> use the profile to guide optimization
    // The C miner PGOs its whole pipeline (measured +~15% at 24T); this gives the
    // Rust miner the same lever on the shared descriptor SA.
    let cc_pgo = std::env::var("DERO_CC_PGO").ok();
    if let Some(ref mode) = cc_pgo {
        if compiler.is_like_msvc() {
            if mode == "gen" {
                cpp.flag("/clang:-fprofile-generate");
            } else {
                cpp.flag(&format!("/clang:-fprofile-use={mode}"));
            }
        } else if mode == "gen" {
            cpp.flag("-fprofile-generate");
        } else {
            cpp.flag(&format!("-fprofile-use={mode}"));
        }
    }

    // Cross-language LTO: emit LLVM bitcode for the descriptor TU so lld-link can
    // optimize it together with the Rust bitcode (rustc -Clinker-plugin-lto). This
    // replicates the C miner's whole-program PGO+LTO across the Rust<->C++ boundary.
    // Requires rustc and clang on the SAME LLVM major (nightly LLVM22 + clang22).
    if std::env::var_os("DERO_CC_LTO").is_some() {
        if compiler.is_like_msvc() {
            cpp.flag("/clang:-flto");
        } else {
            cpp.flag("-flto");
        }
    }

    cpp.compile("dero_v114");

    // Instrumented objects reference the LLVM profile runtime (__llvm_profile_*);
    // link clang_rt.profile so the mixed clang-cl + MSVC-rustc binary resolves it.
    // Skip when DERO_CC_PGO_NO_RT=1 — used for DUAL PGO (rustc -Cprofile-generate +
    // clang -fprofile-generate), where rustc already links the LLVM profile runtime
    // and a second clang_rt.profile would collide.
    if cc_pgo.as_deref() == Some("gen") && std::env::var_os("DERO_CC_PGO_NO_RT").is_none() {
        if let Ok(rt_dir) = std::env::var("DERO_CC_PROFILE_RT_DIR") {
            println!("cargo:rustc-link-search=native={rt_dir}");
        } else {
            println!(
                "cargo:rustc-link-search=native=C:/Program Files/LLVM/lib/clang/22/lib/windows"
            );
        }
        println!("cargo:rustc-link-lib=static=clang_rt.profile-x86_64");
    }

    // NOTE: vendor/v114/sha_stub.c (no-op SHA256_Init/Update/Final) is
    // intentionally NOT compiled. The fused-hash path's streaming SHA sink calls
    // SHA256_Init/Update/Final, which the Rust crate now supplies for real,
    // backed by hardware SHA-NI (sha_ni_shim in src/sais32.rs). Compiling the
    // no-op stub here would collide with those #[no_mangle] symbols.
}
