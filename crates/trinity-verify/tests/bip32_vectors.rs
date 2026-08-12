//! Official BIP-32 test vectors — public (non-hardened) derivation only.
//!
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
//! (Test Vectors). Parent nodes may sit after hardened steps; only the
//! **child** step exercised here is non-hardened. Parent chain code +
//! compressed pubkey are taken from the published extended public key at
//! that node; the child must match the next published xpub bit-for-bit.

use std::str::FromStr;

use bitcoin::bip32::Xpub;
use trinity_verify::{ckd_pub, decode_xpub, DeriveError, MAX_NON_HARDENED_INDEX};

/// Decode published xpub → (chain_code, compressed_pubkey).
fn fields(xpub: &str) -> ([u8; 32], [u8; 33]) {
    decode_xpub(xpub).expect("published xpub decodes")
}

fn assert_ckd(parent_xpub: &str, index: u32, child_xpub: &str) {
    let (p_cc, p_pk) = fields(parent_xpub);
    let child = ckd_pub(&p_cc, &p_pk, index).expect("ckd_pub");
    let (e_cc, e_pk) = fields(child_xpub);
    assert_eq!(
        child.chain_code, e_cc,
        "chain code mismatch at index {index}"
    );
    assert_eq!(child.public_key, e_pk, "pubkey mismatch at index {index}");
    // Sanity: re-decode via Xpub for display identity of the child fields only.
    let xp = Xpub::from_str(child_xpub).unwrap();
    assert_eq!(child.public_key, xp.public_key.serialize());
}

// --- Test Vector 1 ---------------------------------------------------------
// seed (hex): 000102030405060708090a0b0c0d0e0f

const TV1_M: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const TV1_M_0H: &str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
const TV1_M_0H_1: &str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
const TV1_M_0H_1_2H: &str = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
const TV1_M_0H_1_2H_2: &str = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";
const TV1_M_0H_1_2H_2_1E9: &str = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";

// --- Test Vector 2 ---------------------------------------------------------
// seed (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542

const TV2_M: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
const TV2_M_0: &str = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
const TV2_M_0_MAXH: &str = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a";
const TV2_M_0_MAXH_1: &str = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon";
const TV2_M_0_MAXH_1_MAXH1: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
const TV2_M_0_MAXH_1_MAXH1_2: &str = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";

#[test]
fn vector1_m0h_to_m0h_1() {
    // m/0H → m/0H/1  (index 1, non-hardened)
    assert_ckd(TV1_M_0H, 1, TV1_M_0H_1);
}

#[test]
fn vector1_m0h_1_2h_to_m0h_1_2h_2() {
    // m/0H/1/2H → m/0H/1/2H/2  (index 2)
    assert_ckd(TV1_M_0H_1_2H, 2, TV1_M_0H_1_2H_2);
}

#[test]
fn vector1_m0h_1_2h_2_to_1e9() {
    // m/0H/1/2H/2 → m/0H/1/2H/2/1000000000
    assert_ckd(TV1_M_0H_1_2H_2, 1_000_000_000, TV1_M_0H_1_2H_2_1E9);
}

#[test]
fn vector2_m_to_m0() {
    // m → m/0  (index 0)
    assert_ckd(TV2_M, 0, TV2_M_0);
}

#[test]
fn vector2_after_hardened_to_1() {
    // m/0/2147483647H → m/0/2147483647H/1
    assert_ckd(TV2_M_0_MAXH, 1, TV2_M_0_MAXH_1);
}

#[test]
fn vector2_final_to_2() {
    // m/0/2147483647H/1/2147483646H → …/2
    assert_ckd(TV2_M_0_MAXH_1_MAXH1, 2, TV2_M_0_MAXH_1_MAXH1_2);
}

#[test]
fn vector1_master_fields_decode() {
    // Sanity: master xpub fields are stable (no CKD, just decode path).
    let (cc, pk) = fields(TV1_M);
    assert_eq!(cc.len(), 32);
    assert!(pk[0] == 0x02 || pk[0] == 0x03);
}

/// Mutation probe: wrong child index must not silently match the vector child.
/// Calls the real `ckd_pub` (unlike a standalone HMAC reimplementation).
#[test]
fn mutation_off_by_one_index_fails_vector() {
    let (p_cc, p_pk) = fields(TV1_M_0H);
    let wrong = ckd_pub(&p_cc, &p_pk, 2 /* should be 1 */).unwrap();
    let (e_cc, e_pk) = fields(TV1_M_0H_1);
    assert_ne!(wrong.chain_code, e_cc);
    assert_ne!(wrong.public_key, e_pk);
}

#[test]
fn hardened_index_rejected_on_public_vectors() {
    let (p_cc, p_pk) = fields(TV1_M);
    assert_eq!(
        ckd_pub(&p_cc, &p_pk, 0x8000_0000),
        Err(DeriveError::HardenedIndex(0x8000_0000))
    );
    // Max non-hardened is still accepted by the gate (may or may not be a
    // valid child for this parent — only the hardened bit is checked first).
    let _ = ckd_pub(&p_cc, &p_pk, MAX_NON_HARDENED_INDEX);
}
