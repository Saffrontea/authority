//! The durable nonce/tombstone primitive is exercised against an independent
//! in-memory history, including dispatcher/adapter reopen, duplicates and expiry.
use std::collections::BTreeMap;

use authority_replay_ledger::ReplayLedger;
use proptest::prelude::*;

proptest! {
    #[test]
    fn durable_records_refine_history_across_restart_and_reordering(
        actions in prop::collection::vec((0_u8..4, 0_u8..6, 0_i64..40), 1..60),
    ) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("revocations");
        let mut now = 0_i64;
        let mut ledger = ReplayLedger::open(&path, now).unwrap();
        let mut history = BTreeMap::<String, i64>::new();
        for (action, id, horizon) in actions {
            let adapter = if id < 3 { "wg" } else { "tcp" };
            let nonce = format!("{adapter}_decision{}", id % 3);
            match action {
                0 | 1 => {
                    let expected = horizon > now
                        && history.get(&nonce).is_none_or(|expires_at| *expires_at <= now);
                    let result = ledger.consume(&nonce, horizon, now);
                    if horizon <= now {
                        prop_assert!(result.is_err());
                    } else {
                        prop_assert_eq!(result.unwrap(), expected);
                        if expected { history.insert(nonce, horizon); }
                    }
                }
                2 => { now += horizon % 4; }
                _ => { ledger = ReplayLedger::open(&path, now).unwrap(); }
            }
            // Compare every decision and adapter, including the unrelated ones.
            for id in 0..6 {
                let adapter = if id < 3 { "wg" } else { "tcp" };
                let nonce = format!("{adapter}_decision{}", id % 3);
                prop_assert_eq!(ledger.contains(&nonce, now),
                    history.get(&nonce).is_some_and(|expiry| *expiry > now));
            }
        }
        let reopened = ReplayLedger::open(&path, now).unwrap();
        for (nonce, expiry) in history {
            prop_assert_eq!(reopened.contains(&nonce, now), expiry > now);
        }
    }
}
