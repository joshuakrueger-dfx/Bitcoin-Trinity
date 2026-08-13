//! Compile-time inventory: secret-holding types implement [`ZeroizeOnDrop`].
//!
//! Rust cannot enumerate "all types in the crate". The list below *is* the
//! inventory: adding a secret type without listing it here is a review miss;
//! listing it here without the bound is a compile error. Removing
//! `ZeroizeOnDrop` from any listed type breaks `cargo test`.
//!
//! # Types this inventory cannot name
//!
//! Transient signing material is `bitcoin::bip32::Xpriv` (master in
//! [`crate::local::LocalSigner::sign`] / `unlock_master`, intermediate
//! child in `derive_child`) and `bitcoin::secp256k1::SecretKey` (the
//! `derived` vec in `sign_with_master` / [`crate::sign::sign_inputs`]).
//! Both are `Copy`. `Copy` and `Drop` cannot coexist, so neither type
//! can implement [`ZeroizeOnDrop`], and `secp256k1 0.29.1::SecretKey`
//! does not implement [`zeroize::Zeroize`] either — `Zeroizing<SecretKey>`
//! does not compile. They are therefore **not** listed below. They are
//! wiped best-effort with [`SecretKey::non_secure_erase`] (fill `0x01`)
//! via [`crate::sign::erase_xpriv`] / [`crate::sign::erase_secret_key`]
//! after each use. That is the only hook the pinned crates expose; it
//! is not a guarantee (compiler copies, BIP-32 intermediates inside
//! `Xpriv::derive_priv`).

use zeroize::ZeroizeOnDrop;

use crate::LocalSigner;

const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn secret_types_impl_zeroize_on_drop() {
    assert_zeroize_on_drop::<LocalSigner>();
    assert_zeroize_on_drop::<trinity_types::SecretBytes>();
}
