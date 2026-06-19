//! Correctness gate: KAT + golden vectors. Exit 0 = PASS, 1 = FAIL. Mines nothing.
use dero_miner::hash_once;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn check(name: &str, input: &[u8], expect: &str) -> bool {
    let got = hex(&hash_once(input));
    let ok = got == expect;
    println!("{:8} {}  {}", name, if ok { "PASS" } else { "FAIL" }, got);
    ok
}

fn main() {
    let pat48: [u8; 48] = std::array::from_fn(|i| i as u8);
    let mut ok = true;
    ok &= check("a", b"a", "54e2324ddacc3f0383501a9e5760f85d63e9bc6705e9124ca7aef89016ab81ea");
    ok &= check("zero48", &[0u8; 48], "e511c6a69ffcc8a28cf410ad47b2d9d032d436f9280b887ac20044c3f040314e");
    ok &= check("pat48", &pat48, "4474513fdacd0dd4840e923ecf0c4a14861849dcde87e2935bf4f9ef2233ad10");
    if ok {
        println!("SELFTEST_OK");
    } else {
        eprintln!("SELFTEST_FAILED");
        std::process::exit(1);
    }
}
