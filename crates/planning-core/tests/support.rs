use std::collections::{BTreeMap, BTreeSet};

use authority_planning_core::support::{Observation, recompute};
use authority_planning_core::{
    Conditional, ConditionalModel, Derivation, Mechanism, Request, solve,
};

fn observation(value: u8, source: u8) -> Observation<u8, u8, u8> {
    Observation {
        value,
        source,
        owner: 7,
        revision: 1,
        not_before: 10,
        expires_at: 20,
        revoked: false,
    }
}

fn model() -> ConditionalModel<u8, u8, u8> {
    ConditionalModel {
        mechanisms: vec![Conditional {
            value: Mechanism {
                id: 0,
                requires: BTreeSet::new(),
                provides: BTreeSet::from([9]),
            },
            requires_facts: BTreeSet::new(),
        }],
        derivations: vec![
            Conditional {
                value: Derivation {
                    requires: BTreeSet::from([1]),
                    provides: BTreeSet::from([2]),
                },
                requires_facts: BTreeSet::from([5]),
            },
            Conditional {
                value: Derivation {
                    requires: BTreeSet::from([2]),
                    provides: BTreeSet::from([1]),
                },
                requires_facts: BTreeSet::new(),
            },
        ],
    }
}

#[test]
fn independent_support_survives_but_cycles_cannot_support_themselves() {
    let revisions = BTreeMap::from([(1, 1), (2, 1), (3, 1)]);
    let mut roots = vec![observation(1, 1), observation(1, 2)];
    let facts = vec![observation(5, 3)];
    roots[0].revoked = true;
    let live = recompute(&model(), &roots, &facts, &7, 15, &revisions);
    assert_eq!(live.abilities, BTreeSet::from([1, 2]));
    roots[1].revoked = true;
    assert!(
        recompute(&model(), &roots, &facts, &7, 15, &revisions)
            .abilities
            .is_empty()
    );
}

#[test]
fn environment_revision_or_expiry_removes_dependent_ability() {
    let revisions = BTreeMap::from([(1, 1), (3, 2)]);
    let roots = vec![observation(1, 1)];
    let mut facts = vec![observation(5, 3)];
    assert_eq!(
        recompute(&model(), &roots, &facts, &7, 15, &revisions).abilities,
        BTreeSet::from([1])
    );
    facts[0].revision = 2;
    assert_eq!(
        recompute(&model(), &roots, &facts, &7, 15, &revisions).abilities,
        BTreeSet::from([1, 2])
    );
    assert!(
        recompute(&model(), &roots, &facts, &7, 20, &revisions)
            .abilities
            .is_empty()
    );
}

#[test]
fn observations_require_owner_current_revision_and_valid_interval() {
    let revisions = BTreeMap::from([(1, 1)]);
    let mut root = observation(1, 1);
    assert!(root.active(&7, 10, &revisions));
    assert!(!root.active(&8, 15, &revisions));
    assert!(!root.active(&7, 9, &revisions));
    assert!(!root.active(&7, 20, &revisions));
    root.revision = 0;
    assert!(!root.active(&7, 15, &revisions));
    root.revision = 1;
    root.not_before = -1;
    assert!(!root.active(&7, 15, &revisions));
}

#[test]
fn reuse_avoids_issuance_and_mandatory_effects_still_require_permission() {
    let model = model();
    let revisions = BTreeMap::from([(1, 1), (3, 1)]);
    let live = recompute(
        &model,
        &[observation(1, 1)],
        &[observation(5, 3)],
        &7,
        15,
        &revisions,
    );
    let compiled = model.instantiate(&live.facts);
    let mut request = Request {
        goals: BTreeSet::from([2]),
        available: live.roots,
        permitted: BTreeSet::from([1, 2]),
        forbidden_mechanisms: BTreeSet::new(),
        max_mechanisms: 1,
        max_states: 2,
    };
    assert!(
        solve(&compiled, &request, |_| true)
            .unwrap()
            .mechanisms
            .is_empty()
    );
    request.permitted.remove(&2);
    assert!(solve(&compiled, &request, |_| true).is_err());
    assert!(!live.abilities.contains(&9));
}
