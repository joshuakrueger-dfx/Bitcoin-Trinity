//! Compile-time proof that every secret-holding type in this crate
//! implements [`ZeroizeOnDrop`].
//!
//! Rust cannot enumerate "all types in the crate". The list below *is* the
//! inventory: adding a secret type without listing it here is a review miss;
//! listing it here without the bound is a compile error. Removing
//! `ZeroizeOnDrop` from any listed type breaks `cargo test`.

use zeroize::ZeroizeOnDrop;

use crate::blob::DecodedBlob;
use crate::fake::FakePlatformKeyStore;

const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn secret_types_impl_zeroize_on_drop() {
    assert_zeroize_on_drop::<DecodedBlob>();
    assert_zeroize_on_drop::<FakePlatformKeyStore>();
    assert_zeroize_on_drop::<trinity_types::SecretBytes>();
}
