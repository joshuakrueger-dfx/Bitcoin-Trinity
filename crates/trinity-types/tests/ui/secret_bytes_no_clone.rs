//! WP-10: `SecretBytes` must not implement `Clone`.
use trinity_types::SecretBytes;

fn main() {
    let secret = SecretBytes::new(vec![1, 2, 3, 4]);
    // This line must fail to compile — no Clone, no second live copy.
    let _copy = secret.clone();
}
