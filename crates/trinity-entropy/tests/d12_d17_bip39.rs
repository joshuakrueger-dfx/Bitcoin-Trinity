//! Official BIP-39 test vectors (D12, D17) plus 1,000 random round-trips.
//!
//! Source: <https://github.com/trezor/python-mnemonic/blob/master/vectors.json>
//! (the canonical English vectors also used by the `bip39` crate's own test
//! suite). Entropy → mnemonic is compared to the published words. Seed is
//! compared against an independent PBKDF2-HMAC-SHA512 (empty passphrase,
//! salt `"mnemonic"`, 2048 rounds) via Python's `hashlib` — the official
//! JSON seeds use passphrase `"TREZOR"`, which this crate never applies
//! (Spec §2.2: `seed := PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64)`).

use trinity_entropy::bip39_from_entropy;
use trinity_types::WordCount;

/// (entropy_hex, official English mnemonic).
///
/// Source: trezor/python-mnemonic `vectors.json`, English list, entries
/// whose entropy is 16 bytes (12 words) or 32 bytes (24 words). 18-word
/// vectors are out of scope (Trinity only allows 12 or 24, Spec §2.2.3).
const OFFICIAL: &[(&str, &str)] = &[
    // --- 12-word / L=16 (D17) ---
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ),
    (
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
    ),
    (
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
    ),
    (
        "23db8160a31d3e0dca3688ed941adbf3",
        "cat swing flag economy stadium alone churn speed unique patch report train",
    ),
    (
        "f30f8c1da665478f49b001d94c5fc452",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
    ),
    // --- 24-word / L=32 (D12) ---
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
    ),
    (
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    ),
    (
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
    ),
    (
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
    ),
    (
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
    ),
    (
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
    ),
];

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn independent_seed(mnemonic: &str) -> Vec<u8> {
    let out = std::process::Command::new("python3")
        .args([
            "-c",
            "import hashlib, sys; m=sys.argv[1].encode(); print(hashlib.pbkdf2_hmac('sha512', m, b'mnemonic', 2048, 64).hex())",
            mnemonic,
        ])
        .output()
        .expect("python3 hashlib.pbkdf2_hmac");
    assert!(
        out.status.success(),
        "python3 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hex = String::from_utf8(out.stdout).unwrap();
    decode_hex(hex.trim())
}

fn assert_vector(entropy_hex: &str, expected_mnemonic: &str) {
    let entropy = decode_hex(entropy_hex);
    let got = bip39_from_entropy(&entropy).expect("bip39_from_entropy");
    let phrase = core::str::from_utf8(got.mnemonic.as_slice()).unwrap();
    assert_eq!(
        phrase, expected_mnemonic,
        "mnemonic mismatch for {entropy_hex}"
    );
    let expected_seed = independent_seed(expected_mnemonic);
    assert_eq!(
        got.seed.as_slice(),
        expected_seed.as_slice(),
        "empty-passphrase seed mismatch for {entropy_hex}"
    );
}

#[test]
fn d12_official_24_word_bip39_vectors() {
    let mut n = 0;
    for (entropy, mnemonic) in OFFICIAL {
        if decode_hex(entropy).len() == usize::from(WordCount::Words24.entropy_bytes()) {
            assert_vector(entropy, mnemonic);
            n += 1;
        }
    }
    assert_eq!(n, 8, "expected eight official 24-word vectors");
}

#[test]
fn d17_official_12_word_bip39_vectors() {
    let mut n = 0;
    for (entropy, mnemonic) in OFFICIAL {
        if decode_hex(entropy).len() == usize::from(WordCount::Words12.entropy_bytes()) {
            assert_vector(entropy, mnemonic);
            n += 1;
        }
    }
    assert_eq!(n, 8, "expected eight official 12-word vectors");
}

#[test]
fn d12_1000_random_24_word_roundtrip() {
    random_roundtrip(32, 1000);
}

#[test]
fn d17_1000_random_12_word_roundtrip() {
    random_roundtrip(16, 1000);
}

/// Random entropy → production `bip39_from_entropy` → parse words → entropy.
///
/// Shape chosen from the auftrag: "random entropy → mnemonic → back".
/// Seed identity against Python is locked on the official vectors above
/// (8+8 invocations); 1,000 extra PBKDF2-2048 shells would dominate the
/// test runtime without tightening the mnemonic mapping.
fn random_roundtrip(entropy_len: usize, cases: usize) {
    for i in 0..cases {
        let mut entropy = vec![0u8; entropy_len];
        getrandom::fill(&mut entropy).expect("getrandom");
        let got = bip39_from_entropy(&entropy).unwrap_or_else(|e| {
            panic!("case {i}: {e}");
        });
        let phrase = core::str::from_utf8(got.mnemonic.as_slice()).unwrap();
        let parsed = bip39::Mnemonic::parse(phrase).expect("parse own mnemonic");
        assert_eq!(
            parsed.to_entropy(),
            entropy,
            "round-trip entropy mismatch at case {i}"
        );
        assert_eq!(parsed.word_count(), entropy_len * 3 / 4);
    }
}
