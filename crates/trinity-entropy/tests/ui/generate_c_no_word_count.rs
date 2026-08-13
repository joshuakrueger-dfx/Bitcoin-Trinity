//! S15b: `generate_c` does not take a `WordCount` — a 12-word C cannot be expressed.
use trinity_entropy::{generate_c, AdditionalEntropy};
use trinity_types::WordCount;

fn main() {
    let extra = AdditionalEntropy::new();
    // This line must fail to compile: generate_c hardcodes Words24.
    let _ = generate_c(WordCount::Words12, &extra);
}
