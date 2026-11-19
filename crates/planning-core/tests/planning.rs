use std::collections::BTreeSet;

use authority_planning_core::{Derivation, Mechanism, Model, PlanningError, Request, solve};
use proptest::prelude::*;

fn mechanism(id: u8, requires: &[u8], provides: &[u8]) -> Mechanism<u8, u8> {
    Mechanism {
        id,
        requires: requires.iter().copied().collect(),
        provides: provides.iter().copied().collect(),
    }
}

fn request(goals: &[u8], permitted: &[u8]) -> Request<u8, u8> {
    Request {
        goals: goals.iter().copied().collect(),
        available: BTreeSet::new(),
        permitted: permitted.iter().copied().collect(),
        forbidden_mechanisms: BTreeSet::new(),
        max_mechanisms: 8,
        max_states: 256,
    }
}

#[test]
fn finds_an_authorized_alternative_instead_of_rejecting_the_intent() {
    let model = Model {
        mechanisms: vec![
            mechanism(0, &[], &[1, 9]), // Broad route has an unauthorized side effect.
            mechanism(1, &[], &[2]),
            mechanism(2, &[2], &[1]),
        ],
        derivations: vec![],
    };
    let plan = solve(&model, &request(&[1], &[1, 2]), |_| true).unwrap();
    assert_eq!(plan.mechanisms, vec![1, 2]);
    assert_eq!(plan.abilities, BTreeSet::from([1, 2]));
}

#[test]
fn hyperedges_require_all_inputs_and_cycles_do_not_bootstrap_authority() {
    let mut model = Model {
        mechanisms: vec![mechanism(0, &[1, 2], &[3]), mechanism(1, &[3], &[2])],
        derivations: vec![],
    };
    let mut query = request(&[3], &[1, 2, 3]);
    query.available.insert(1);
    assert_eq!(
        solve(&model, &query, |_| true),
        Err(PlanningError::NoSolution)
    );
    model.mechanisms.push(mechanism(2, &[], &[2]));
    assert_eq!(
        solve(&model, &query, |_| true).unwrap().mechanisms,
        vec![2, 0]
    );
}

#[test]
fn composition_effects_cannot_be_omitted_to_evade_policy() {
    let model = Model {
        mechanisms: vec![mechanism(0, &[], &[1]), mechanism(1, &[], &[2])],
        derivations: vec![
            Derivation {
                requires: BTreeSet::from([1, 2]),
                provides: BTreeSet::from([3]),
            },
            Derivation {
                requires: BTreeSet::from([3]),
                provides: BTreeSet::from([4]),
            },
            Derivation {
                requires: BTreeSet::from([4]),
                provides: BTreeSet::from([3]),
            },
        ],
    };
    assert_eq!(
        solve(&model, &request(&[1, 2], &[1, 2, 3]), |_| true),
        Err(PlanningError::NoSolution)
    );
    let plan = solve(&model, &request(&[4], &[1, 2, 3, 4]), |_| true).unwrap();
    assert_eq!(plan.abilities, BTreeSet::from([1, 2, 3, 4]));
}

#[test]
fn constraints_apply_even_after_the_goal_is_reached() {
    let model = Model {
        mechanisms: vec![mechanism(0, &[], &[1]), mechanism(1, &[], &[2])],
        derivations: vec![],
    };
    let mut query = request(&[1], &[1, 2]);
    let plan = solve(&model, &query, |plan| plan.abilities.contains(&2)).unwrap();
    assert_eq!(plan.mechanisms, vec![0, 1]);
    query.forbidden_mechanisms.insert(1);
    assert_eq!(
        solve(&model, &query, |plan| plan.abilities.contains(&2)),
        Err(PlanningError::NoSolution)
    );
    query.forbidden_mechanisms.clear();
    query.max_mechanisms = 1;
    assert_eq!(
        solve(&model, &query, |plan| plan.abilities.contains(&2)),
        Err(PlanningError::NoSolution)
    );
}

#[test]
fn duplicate_ids_and_budget_exhaustion_fail_closed() {
    let mut model = Model {
        mechanisms: vec![mechanism(0, &[], &[1]), mechanism(0, &[], &[2])],
        derivations: vec![],
    };
    let mut query = request(&[1], &[1, 2]);
    assert_eq!(
        solve(&model, &query, |_| true),
        Err(PlanningError::DuplicateMechanism)
    );
    model.mechanisms.pop();
    query.max_states = 1;
    assert_eq!(
        solve(&model, &query, |_| true),
        Err(PlanningError::SearchLimit)
    );
    query.max_states = 0;
    assert_eq!(
        solve(&model, &query, |_| true),
        Err(PlanningError::SearchLimit)
    );
}

#[test]
fn ability_scopes_are_not_interchangeable() {
    let model = Model {
        mechanisms: vec![Mechanism {
            id: "connect",
            requires: BTreeSet::new(),
            provides: BTreeSet::from([("alice", "server-a", 443)]),
        }],
        derivations: vec![],
    };
    let query = Request {
        goals: BTreeSet::from([("alice", "server-a", 443)]),
        available: BTreeSet::new(),
        permitted: BTreeSet::from([("alice", "server-b", 443)]),
        forbidden_mechanisms: BTreeSet::new(),
        max_mechanisms: 1,
        max_states: 2,
    };
    assert_eq!(
        solve(&model, &query, |_| true),
        Err(PlanningError::NoSolution)
    );
}

fn bits(mask: u8) -> BTreeSet<u8> {
    (0..4).filter(|bit| mask & (1 << bit) != 0).collect()
}

proptest! {
    #[test]
    fn solver_matches_exhaustive_executable_subsets(
        specs in prop::collection::vec((0_u8..16, 0_u8..16), 0..7),
        goal in 0_u8..16,
        permit in 0_u8..16,
    ) {
        let model = Model {
            mechanisms: specs.iter().enumerate().map(|(id, (requires, provides))| Mechanism {
                id: u8::try_from(id).unwrap(), requires: bits(*requires), provides: bits(*provides),
            }).collect::<Vec<_>>(),
            derivations: vec![],
        };
        let query = Request { goals: bits(goal), permitted: bits(permit), ..request(&[], &[]) };
        let mut best = None;
        // Independent reference: enumerate subsets, then run each to a fixed point.
        for mask in 0_usize..(1 << specs.len()) {
            let mut abilities = BTreeSet::new();
            let mut executed = BTreeSet::new();
            loop {
                let count = executed.len();
                for m in &model.mechanisms {
                    if mask & (1 << m.id) != 0 && m.requires.is_subset(&abilities) {
                        executed.insert(m.id);
                        abilities.extend(m.provides.iter().copied());
                    }
                }
                if executed.len() == count { break; }
            }
            if executed.len() == mask.count_ones() as usize
                && query.goals.is_subset(&abilities) && abilities.is_subset(&query.permitted)
            {
                best = Some(best.map_or(executed.len(), |n: usize| n.min(executed.len())));
            }
        }
        let result = solve(&model, &query, |_| true);
        prop_assert_eq!(result.as_ref().ok().map(|plan| plan.mechanisms.len()), best);
        if let Ok(plan) = &result {
            prop_assert!(query.goals.is_subset(&plan.abilities));
            prop_assert!(plan.abilities.is_subset(&query.permitted));
            let mut available = query.available.clone();
            for id in &plan.mechanisms {
                let m = model.mechanisms.iter().find(|m| m.id == *id).unwrap();
                prop_assert!(m.requires.is_subset(&available));
                available.extend(m.provides.iter().copied());
            }
        }
        let mut reversed = model.clone();
        reversed.mechanisms.reverse();
        prop_assert_eq!(result, solve(&reversed, &query, |_| true));
    }
}

#[test]
fn facts_gate_composition_without_granting_authority_and_explanations_are_grounded() {
    use authority_planning_core::{Conditional, ConditionalModel, explain};
    let model = ConditionalModel {
        mechanisms: vec![Conditional {
            value: mechanism(0, &[], &[1]),
            requires_facts: BTreeSet::new(),
        }],
        derivations: vec![Conditional {
            value: Derivation {
                requires: BTreeSet::from([1]),
                provides: BTreeSet::from([2]),
            },
            requires_facts: BTreeSet::from([9]),
        }],
    };
    let without = model.instantiate(&BTreeSet::new());
    assert_eq!(
        solve(&without, &request(&[2], &[1, 2]), |_| true),
        Err(PlanningError::NoSolution)
    );
    let compiled = model.instantiate(&BTreeSet::from([9]));
    let plan = solve(&compiled, &request(&[2], &[1, 2]), |_| true).unwrap();
    assert!(!plan.abilities.contains(&9));
    let trace = explain(&compiled, &BTreeSet::new(), &plan).unwrap();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].after_mechanisms, 1);
    let mut omitted = plan.clone();
    omitted.abilities.remove(&2);
    assert!(explain(&compiled, &BTreeSet::new(), &omitted).is_err());
    assert_eq!(
        solve(&compiled, &request(&[1], &[1]), |_| true),
        Err(PlanningError::NoSolution)
    );
}
