//! Correspondence for the canonical ID/ability views used by the Verus BFS
//! model. Real signed IDs and structured abilities must preserve all results.
use authority_planning_core::{Derivation, Mechanism, Model, Plan, Request, solve};
use proptest::prelude::*;
use std::collections::BTreeSet;

fn bits(mask: u8) -> BTreeSet<u8> {
    (0..6).filter(|bit| mask & (1 << bit) != 0).collect()
}

proptest! {
    #[test]
    fn canonical_views_preserve_results_budgets_and_execution_order(
        ids in prop::collection::btree_set(any::<i64>(), 0..=6),
        labels in prop::collection::btree_set(any::<u64>(), 6),
        ports in prop::array::uniform6(any::<u16>()),
        mechanisms in prop::array::uniform6((0_u8..64, 0_u8..64)),
        derivations in prop::collection::vec((0_u8..64, 0_u8..64), 0..7),
        (available, permitted, goals) in (0_u8..64, prop_oneof![Just(63_u8), 0_u8..64], 0_u8..64),
        (forbidden, required) in (0_u8..64, prop_oneof![Just(0_u8), 0_u8..64]),
        max_mechanisms in 0_usize..=6, budget in 0_usize..=64,
    ) {
        let ids = ids.into_iter().collect::<Vec<_>>();
        let labels = labels.into_iter().zip(ports).collect::<Vec<_>>();
        let actual_abilities = |mask| bits(mask).into_iter().map(|id| labels[usize::from(id)]).collect::<BTreeSet<_>>();
        let actual_ids = |mask| bits(mask).into_iter().filter_map(|id| ids.get(usize::from(id)).copied()).collect::<BTreeSet<_>>();
        let canonical = Model {
            mechanisms: mechanisms.iter().take(ids.len()).enumerate().map(|(id, (requires, provides))| Mechanism {
                id: u8::try_from(id).unwrap(), requires: bits(*requires), provides: bits(*provides),
            }).collect(),
            derivations: derivations.iter().map(|(requires, provides)| Derivation {
                requires: bits(*requires), provides: bits(*provides),
            }).collect(),
        };
        let mut actual = Model {
            mechanisms: mechanisms.iter().take(ids.len()).enumerate().map(|(index, (requires, provides))| Mechanism {
                id: ids[index], requires: actual_abilities(*requires), provides: actual_abilities(*provides),
            }).collect(),
            derivations: derivations.iter().map(|(requires, provides)| Derivation {
                requires: actual_abilities(*requires), provides: actual_abilities(*provides),
            }).collect(),
        };
        actual.mechanisms.reverse();
        actual.derivations.reverse();
        let accept = |plan: &Plan<u8, u8>| bits(required).iter().all(|id| plan.mechanisms.contains(id));
        let accept_actual = |plan: &Plan<(u64, u16), i64>| bits(required).iter().all(|id|
            ids.get(usize::from(*id)).is_some_and(|real| plan.mechanisms.contains(real)));
        let mut request = Request { goals: bits(goals), available: bits(available), permitted: bits(permitted),
            forbidden_mechanisms: bits(forbidden), max_mechanisms, max_states: budget };
        let mut actual_request = Request { goals: actual_abilities(goals), available: actual_abilities(available),
            permitted: actual_abilities(permitted), forbidden_mechanisms: actual_ids(forbidden), max_mechanisms, max_states: budget };
        for selected_budget in [budget, 1_usize << ids.len()] {
            request.max_states = selected_budget;
            actual_request.max_states = selected_budget;
            let expected = solve(&canonical, &request, accept);
            let observed = solve(&actual, &actual_request, accept_actual).map(|plan| Plan {
                mechanisms: plan.mechanisms.iter().map(|id| u8::try_from(ids.binary_search(id).unwrap()).unwrap()).collect(),
                abilities: plan.abilities.iter().map(|ability| u8::try_from(labels.binary_search(ability).unwrap()).unwrap()).collect(),
            });
            prop_assert_eq!(observed, expected);
        }
    }
}
