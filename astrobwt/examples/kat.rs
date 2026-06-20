//! Cross-implementation known-answer test (KAT).
//!
//! The Dirtybird C miner asserts at startup that `pow("a")` equals
//! `54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea`
//! (see its README "Correctness"). Reproducing that hex proves the Rust
//! pipeline is byte-identical to the competitor across ALL seven stages,
//! including whichever suffix-array backend this build selected
//! (pure-Rust sais32 / libsais / v114 descriptor SA).
//!
//! Run: cargo run -p dero-astrobwt --example kat --release [--features v114]

use dero_astrobwt::{astrobwtv3, AstroBwtScratch};

const KAT_A: &str = "54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea";

fn main() {
    // Path 1: the one-shot public API.
    let h = astrobwtv3(b"a");
    let got = hex::encode(h);
    println!("astrobwtv3(\"a\")            = {got}");
    println!("expected (Dirtybird C KAT) = {KAT_A}");
    let oneshot_ok = got == KAT_A;

    // Path 2: the mining fast path (scratch reuse) — this is what the bench
    // and worker actually call, and what the feature flags route.
    let mut scratch = AstroBwtScratch::new();
    let h2 = dero_astrobwt::astrobwtv3_with_scratch(b"a", &mut scratch);
    let got2 = hex::encode(h2);
    let scratch_ok = got2 == KAT_A;
    println!("astrobwtv3_with_scratch    = {got2}");

    // A couple more inputs hashed both ways must agree (one-shot is the oracle).
    let mut all_agree = true;
    for inp in [b"".as_slice(), b"DERO", b"\x00\xff\x10abc", &[0u8; 80]] {
        let a = astrobwtv3(inp);
        let b = dero_astrobwt::astrobwtv3_with_scratch(inp, &mut scratch);
        if a != b {
            all_agree = false;
            println!("MISMATCH oneshot vs scratch on {inp:?}");
        }
    }

    println!(
        "\nKAT one-shot:  {}\nKAT scratch:   {}\nself-consistency: {}",
        if oneshot_ok { "PASS" } else { "FAIL" },
        if scratch_ok { "PASS" } else { "FAIL" },
        if all_agree { "PASS" } else { "FAIL" },
    );

    if oneshot_ok && scratch_ok && all_agree {
        println!("\nALL CORRECTNESS CHECKS PASS");
    } else {
        eprintln!("\nCORRECTNESS FAILURE");
        std::process::exit(1);
    }
}
