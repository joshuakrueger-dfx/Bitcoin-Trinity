//! D5 — verifier against the builder (`trinity-watch`). Spec §5.1.
//!
//! Same 500 setups as D4 (shared generator). A divergence is an independence
//! alarm: the two stacks must not silently disagree.

use std::time::{Duration, Instant};

use trinity_differential::{
    all_setups, verify_receive_addresses, watch_receive_addresses, ADDRS, SETUPS,
};

#[test]
fn d5_verifier_against_watch() {
    let started = Instant::now();
    let mut compared = 0u32;

    for setup in all_setups() {
        if setup.index > 0 && setup.index % 50 == 0 {
            eprintln!(
                "D5 progress: {}/{} setups, {} addresses so far, {:?}",
                setup.index,
                SETUPS,
                compared,
                started.elapsed()
            );
        }
        let desc = setup.receive();
        let verify = verify_receive_addresses(desc);
        let watch = watch_receive_addresses(&setup.descriptors);

        assert_eq!(
            verify.len() as u32,
            ADDRS,
            "D5 setup={}: trinity-verify returned {} addresses, expected {ADDRS}\ninput={desc}",
            setup.index,
            verify.len()
        );
        assert_eq!(
            watch.len() as u32,
            ADDRS,
            "D5 setup={}: trinity-watch returned {} addresses, expected {ADDRS}\ninput={desc}",
            setup.index,
            watch.len()
        );

        for idx in 0..ADDRS as usize {
            assert_eq!(
                verify[idx], watch[idx],
                "D5 mismatch setup={} index={idx}\ninput={desc}\nexpected (trinity-watch)={}\nactual (trinity-verify)={}",
                setup.index, watch[idx], verify[idx]
            );
            compared += 1;
        }
    }

    let elapsed = started.elapsed();
    eprintln!(
        "D5: {compared} addresses (={SETUPS} setups × {ADDRS} indices) \
         matched trinity-watch in {elapsed:?}"
    );
    assert_eq!(compared, SETUPS * ADDRS);
    assert!(
        elapsed < Duration::from_secs(20 * 60),
        "D5 runtime {elapsed:?} exceeded the 20-minute acceptance cap"
    );
}
