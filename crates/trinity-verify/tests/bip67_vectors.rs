//! Official BIP-67 test vectors — pubkey sort + multisig script encoding.
//!
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki>
//! (Test vectors). Scripts use OP_k / OP_n / OP_CHECKMULTISIG with k=2.

use trinity_verify::{build_checkmultisig_script, sort_pubkeys};

fn hex_pk(s: &str) -> [u8; 33] {
    assert_eq!(s.len(), 66, "compressed pubkey hex");
    let mut out = [0u8; 33];
    for i in 0..33 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn hex_bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn assert_sorted(input: &[&str], expected: &[&str]) {
    let mut keys: Vec<[u8; 33]> = input.iter().map(|s| hex_pk(s)).collect();
    sort_pubkeys(&mut keys);
    let got: Vec<String> = keys.iter().map(hex_encode).collect();
    let want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want);
}

fn hex_encode(b: &[u8; 33]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn assert_script(k: u32, sorted_hex: &[&str], script_hex: &str) {
    let keys: Vec<[u8; 33]> = sorted_hex.iter().map(|s| hex_pk(s)).collect();
    let script = build_checkmultisig_script(k, &keys).expect("script");
    assert_eq!(script.as_bytes(), hex_bytes(script_hex).as_slice());
}

#[test]
fn vector1_two_keys() {
    // BIP-67 Vector 1 (2-of-2)
    let list = [
        "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
        "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
    ];
    let sorted = [
        "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
        "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
    ];
    assert_sorted(&list, &sorted);
    assert_script(
        2,
        &sorted,
        "522102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f\
         2102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f852ae",
    );
}

#[test]
fn vector2_already_sorted() {
    let list = [
        "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
        "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
        "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
    ];
    assert_sorted(&list, &list);
    assert_script(
        2,
        &list,
        "522102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0\
         21027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77\
         2102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b40453ae",
    );
}

#[test]
fn vector3_four_keys_edge_bytes() {
    let list = [
        "030000000000000000000000000000000000004141414141414141414141414141",
        "020000000000000000000000000000000000004141414141414141414141414141",
        "020000000000000000000000000000000000004141414141414141414141414140",
        "030000000000000000000000000000000000004141414141414141414141414140",
    ];
    let sorted = [
        "020000000000000000000000000000000000004141414141414141414141414140",
        "020000000000000000000000000000000000004141414141414141414141414141",
        "030000000000000000000000000000000000004141414141414141414141414140",
        "030000000000000000000000000000000000004141414141414141414141414141",
    ];
    assert_sorted(&list, &sorted);
    assert_script(
        2,
        &sorted,
        "5221020000000000000000000000000000000000004141414141414141414141414140\
         21020000000000000000000000000000000000004141414141414141414141414141\
         21030000000000000000000000000000000000004141414141414141414141414140\
         2103000000000000000000000000000000000000414141414141414141414141414154ae",
    );
}

#[test]
fn vector4_from_bitcore() {
    let list = [
        "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
        "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
        "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
    ];
    let sorted = [
        "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
        "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
        "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
    ];
    assert_sorted(&list, &sorted);
    assert_script(
        2,
        &sorted,
        "5221021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18\
         21022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da\
         2103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e953ae",
    );
}

/// Mutation probe: reversed (descending) sort must fail the vector comparison.
#[test]
fn mutation_reversed_sort_fails_vector() {
    let list = [
        hex_pk("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da"),
        hex_pk("03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9"),
        hex_pk("021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18"),
    ];
    let mut reversed = list;
    reversed.sort_unstable_by(|a, b| b.cmp(a));
    let mut correct = list;
    sort_pubkeys(&mut correct);
    assert_ne!(reversed, correct);
    // Reversed order also produces a different script encoding.
    let bad = build_checkmultisig_script(2, &reversed).unwrap();
    let good = build_checkmultisig_script(2, &correct).unwrap();
    assert_ne!(bad.as_bytes(), good.as_bytes());
}

/// Mutation probe: off-by-one swap of two adjacent sorted keys fails vector script.
#[test]
fn mutation_adjacent_swap_fails_vector_script() {
    let sorted = [
        hex_pk("021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18"),
        hex_pk("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da"),
        hex_pk("03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9"),
    ];
    let mut swapped = sorted;
    swapped.swap(0, 1);
    let expected = hex_bytes(
        "5221021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18\
         21022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da\
         2103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e953ae",
    );
    let bad = build_checkmultisig_script(2, &swapped).unwrap();
    assert_ne!(bad.as_bytes(), expected.as_slice());
    let good = build_checkmultisig_script(2, &sorted).unwrap();
    assert_eq!(good.as_bytes(), expected.as_slice());
}
