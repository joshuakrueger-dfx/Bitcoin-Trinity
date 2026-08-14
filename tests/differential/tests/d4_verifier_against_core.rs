//! D4 — verifier against Bitcoin Core `deriveaddresses` (Spec §5.1).
//!
//! 500 deterministic 2-of-3 setups × 1_000 receive addresses. Comparison is
//! one `deriveaddresses(desc, [0, 999])` per setup (utility RPC, no wallet).
//! A single descriptor wallet is created and the first setup is imported so
//! the `createwallet`/`importdescriptors` path is exercised without 500
//! wallet files (that exhausted Docker Desktop's bitcoind on this host).

use std::time::{Duration, Instant};

use trinity_differential::rpc::{
    connect, create_descriptor_wallet, derive_receive_addresses, import_receive_descriptor,
    unload_wallet,
};
use trinity_differential::{all_setups, verify_receive_addresses, ADDRS, SETUPS};

#[test]
fn d4_verifier_against_core() {
    let node = connect();
    let (wallet_name, wallet) = create_descriptor_wallet(&node, "shared");

    let started = Instant::now();
    let mut compared = 0u32;

    for setup in all_setups() {
        if setup.index > 0 && setup.index % 50 == 0 {
            eprintln!(
                "D4 progress: {}/{} setups, {} addresses so far, {:?}",
                setup.index,
                SETUPS,
                compared,
                started.elapsed()
            );
        }
        let desc = setup.receive();
        if setup.index == 0 {
            let imported = import_receive_descriptor(&wallet, desc);
            assert!(
                imported.len() == 1 && imported[0].success,
                "D4 importdescriptors unsuccessful setup=0\ninput={desc}\nresult={imported:?}"
            );
        }

        let core = derive_receive_addresses(&node, desc);
        assert_eq!(
            core.len() as u32,
            ADDRS,
            "D4 setup={}: Core returned {} addresses, expected {ADDRS}\ninput={desc}",
            setup.index,
            core.len()
        );

        let ours = verify_receive_addresses(desc);
        assert_eq!(
            ours.len() as u32,
            ADDRS,
            "D4 setup={}: trinity-verify returned {} addresses, expected {ADDRS}\ninput={desc}",
            setup.index,
            ours.len()
        );

        for idx in 0..ADDRS as usize {
            assert_eq!(
                ours[idx], core[idx],
                "D4 mismatch setup={} index={idx}\ninput={desc}\nexpected (core)={}\nactual (trinity-verify)={}",
                setup.index, core[idx], ours[idx]
            );
            compared += 1;
        }
    }
    unload_wallet(&node, &wallet_name);

    let elapsed = started.elapsed();
    eprintln!(
        "D4: {compared} addresses (={SETUPS} setups × {ADDRS} indices) \
         matched Core deriveaddresses in {elapsed:?}"
    );
    assert_eq!(compared, SETUPS * ADDRS);
    assert!(
        elapsed < Duration::from_secs(20 * 60),
        "D4 runtime {elapsed:?} exceeded the 20-minute acceptance cap"
    );
}
