//! D13 / S20 — external re-computability via `scripts/recompute_entropy.sh`.
//!
//! A real `openssl dgst -sha512 -mac HMAC` process reproduces `extract`
//! from `raw_csprng` + `extra_bytes`. Not mocked.

use std::path::PathBuf;
use std::process::Command;

use trinity_entropy::{extract, generate_from_raw, AdditionalEntropy, GeneratedKey};
use trinity_types::WordCount;

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/recompute_entropy.sh")
}

fn openssl_entropy(raw_hex: &str, extra_hex: &str, l: u8) -> String {
    let out = Command::new(script())
        .args([raw_hex, extra_hex, &l.to_string()])
        .output()
        .expect("spawn recompute_entropy.sh");
    assert!(
        out.status.success(),
        "script failed: status={} stderr={} stdout={}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .to_ascii_lowercase()
}

fn assert_matches_openssl(key: &GeneratedKey) {
    let got = openssl_entropy(
        &key.raw_csprng_hex(),
        &key.extra_bytes_hex(),
        key.word_count().entropy_bytes(),
    );
    assert_eq!(got, key.entropy_hex(), "openssl digest != crate extract");
}

fn raw_from_seed(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn s20_openssl_dice_coins_cards_and_mixtures() {
    let raw = raw_from_seed(0x42);

    let dice = AdditionalEntropy::new().with_dice("31662").unwrap();
    let coins = AdditionalEntropy::new().with_coins("010101").unwrap();
    let cards = AdditionalEntropy::new().with_cards("AS10HKD").unwrap();
    let mix = AdditionalEntropy::new()
        .with_dice("123456")
        .unwrap()
        .with_coins("01")
        .unwrap()
        .with_cards("AS")
        .unwrap();
    let dice_cards = AdditionalEntropy::new()
        .with_dice("12")
        .unwrap()
        .with_cards("KH")
        .unwrap();
    let empty = AdditionalEntropy::new();
    let with_sensor = mix.clone().with_sensor(&[0xde, 0xad, 0x1e, 0x00]);

    for extra in [dice, coins, cards, mix, dice_cards, empty, with_sensor] {
        for wc in [WordCount::Words12, WordCount::Words24] {
            let key = generate_from_raw(wc, &raw, &extra).unwrap();
            assert_matches_openssl(&key);
        }
    }
}

/// D13: 1,000 openssl cases (Spec §5.1 stated scope).
///
/// Each case forks `openssl` + `xxd` against production [`extract`]. Measured
/// locally at ~17 s for 1,000 — acceptable for this crate.
#[test]
fn d13_openssl_recomputes_extract() {
    const CASES: usize = 1000;
    for i in 0..CASES {
        let mut raw = [0u8; 32];
        raw[0] = i as u8;
        raw[31] = (i >> 8) as u8;
        raw[15] = raw[15].wrapping_add(i as u8);

        let extra = match i % 6 {
            0 => AdditionalEntropy::new(),
            1 => AdditionalEntropy::new()
                .with_dice(&format!("{}", 1 + (i % 6)))
                .unwrap(),
            2 => AdditionalEntropy::new()
                .with_coins(if i % 2 == 0 { "0" } else { "1" })
                .unwrap(),
            3 => AdditionalEntropy::new().with_cards("AS").unwrap(),
            4 => AdditionalEntropy::new()
                .with_dice("654321")
                .unwrap()
                .with_coins("10")
                .unwrap()
                .with_cards("KD")
                .unwrap(),
            _ => AdditionalEntropy::new()
                .with_dice("1")
                .unwrap()
                .with_sensor(&[i as u8, 0x1e, 0xff]),
        };
        let wc = if i % 2 == 0 {
            WordCount::Words24
        } else {
            WordCount::Words12
        };
        let key = generate_from_raw(wc, &raw, &extra).unwrap();
        assert_matches_openssl(&key);
        // Sanity: the crate path used above is `extract` itself.
        let direct = extract(&raw, &extra.canonical_bytes(), wc);
        assert_eq!(direct.as_slice(), key.entropy().as_slice());
    }
}

#[test]
fn script_rejects_bad_input() {
    let s = script();
    let bad = Command::new(&s).args(["zz", "", "32"]).output().unwrap();
    assert!(!bad.status.success());
    let bad_l = Command::new(&s)
        .args([
            "0000000000000000000000000000000000000000000000000000000000000000",
            "",
            "15",
        ])
        .output()
        .unwrap();
    assert!(!bad_l.status.success());
    let bad_extra = Command::new(&s)
        .args([
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abc",
            "32",
        ])
        .output()
        .unwrap();
    assert!(!bad_extra.status.success());
    let usage = Command::new(&s).output().unwrap();
    assert!(!usage.status.success());
}
