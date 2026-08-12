//! Fuzz target: feed arbitrary bytes to the Trinity descriptor parser.
//!
//! The parser must never panic; every input is either `Ok` or a `ParseError`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use trinity_verify::parse;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse(s);
    }
    // Also exercise non-UTF8 rejection path implicitly by skipping;
    // the public API is `&str`, so only UTF-8 is in scope.
});
