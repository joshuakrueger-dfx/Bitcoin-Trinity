//! Compile-time inventory: secret-holding types implement [`ZeroizeOnDrop`].

use zeroize::ZeroizeOnDrop;

use crate::{Bip39Material, GeneratedKey};

const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn secret_types_impl_zeroize_on_drop() {
    assert_zeroize_on_drop::<GeneratedKey>();
    assert_zeroize_on_drop::<Bip39Material>();
    assert_zeroize_on_drop::<trinity_types::SecretBytes>();
}
