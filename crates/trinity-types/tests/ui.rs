//! Compile-fail UI tests for `SecretBytes` invariants (WP-10 acceptance).

#[test]
fn secret_bytes_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
