//! Finite, monotone ability planning, independent of policy storage and protocols.
//!
//! `A` is a caller-defined, fully scoped ability (including subject, resource,
//! operation and validity where applicable). Equality must mean the same authority;
//! layer labels alone are not abilities. All prerequisites of a hyperedge must hold.
//! Derivations are mandatory effects of composition, never optional grants.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mechanism<A, M> {
    pub id: M,
    pub requires: BTreeSet<A>,
    pub provides: BTreeSet<A>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation<A> {
    pub requires: BTreeSet<A>,
    pub provides: BTreeSet<A>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model<A, M> {
    pub mechanisms: Vec<Mechanism<A, M>>,
    pub derivations: Vec<Derivation<A>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<A, M> {
    pub goals: BTreeSet<A>,
    /// Existing abilities usable by this plan, not unauthenticated identity facts.
    pub available: BTreeSet<A>,
    pub permitted: BTreeSet<A>,
    pub forbidden_mechanisms: BTreeSet<M>,
    pub max_mechanisms: usize,
    /// Bounds the number of distinct executable plans admitted to the search.
    pub max_states: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan<A, M> {
    /// A valid execution order: prerequisites precede their consumers.
    pub mechanisms: Vec<M>,
    /// Includes existing abilities and all mandatory derived effects.
    pub abilities: BTreeSet<A>,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PlanningError {
    #[error("mechanism ids must be unique")]
    DuplicateMechanism,
    #[error("no authorized plan satisfies the intent and constraints")]
    NoSolution,
    #[error("planning search budget exhausted; authorization was not established")]
    SearchLimit,
}

fn closure<A: Ord + Clone>(abilities: &mut BTreeSet<A>, derivations: &[Derivation<A>]) {
    loop {
        let count = abilities.len();
        for rule in derivations {
            if rule.requires.is_subset(abilities) {
                abilities.extend(rule.provides.iter().cloned());
            }
        }
        if abilities.len() == count {
            return;
        }
    }
}

/// Finds a plan with the fewest mechanisms, with stable id order breaking ties.
///
/// `satisfies` checks final constraints and may reject a goal-reaching plan while
/// allowing a larger plan. It must be pure and depend only on the selected set
/// and abilities, not execution order. Effects must be monotone and complete:
/// deletions, mutable external facts and undeclared side effects are not modeled.
///
/// # Errors
/// Returns an error for an invalid catalog, unsatisfied constraints, or exhausted
/// search budget. A budget failure must never be interpreted as authorization.
pub fn solve<A: Ord + Clone, M: Ord + Clone>(
    model: &Model<A, M>,
    request: &Request<A, M>,
    satisfies: impl Fn(&Plan<A, M>) -> bool,
) -> Result<Plan<A, M>, PlanningError> {
    let catalog: BTreeMap<_, _> = model
        .mechanisms
        .iter()
        .map(|mechanism| (mechanism.id.clone(), mechanism))
        .collect();
    if catalog.len() != model.mechanisms.len() {
        return Err(PlanningError::DuplicateMechanism);
    }
    if request.max_states == 0 {
        return Err(PlanningError::SearchLimit);
    }
    let mut initial = request.available.clone();
    closure(&mut initial, &model.derivations);
    if !initial.is_subset(&request.permitted) {
        return Err(PlanningError::NoSolution);
    }
    let mut queue = VecDeque::from([Plan {
        mechanisms: Vec::new(),
        abilities: initial,
    }]);
    let mut visited = BTreeSet::from([BTreeSet::<M>::new()]);
    while let Some(plan) = queue.pop_front() {
        if request.goals.is_subset(&plan.abilities) && satisfies(&plan) {
            return Ok(plan);
        }
        if plan.mechanisms.len() >= request.max_mechanisms {
            continue;
        }
        let selected: BTreeSet<_> = plan.mechanisms.iter().cloned().collect();
        for (id, mechanism) in &catalog {
            if selected.contains(id)
                || request.forbidden_mechanisms.contains(id)
                || !mechanism.requires.is_subset(&plan.abilities)
            {
                continue;
            }
            let mut next_selected = selected.clone();
            next_selected.insert(id.clone());
            if visited.contains(&next_selected) {
                continue;
            }
            let mut next = plan.clone();
            next.mechanisms.push(id.clone());
            next.abilities.extend(mechanism.provides.iter().cloned());
            closure(&mut next.abilities, &model.derivations);
            if !next.abilities.is_subset(&request.permitted) {
                continue;
            }
            if visited.len() >= request.max_states {
                return Err(PlanningError::SearchLimit);
            }
            visited.insert(next_selected);
            queue.push_back(next);
        }
    }
    Err(PlanningError::NoSolution)
}

#[cfg(test)]
mod closure_properties {
    use super::{Derivation, closure};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn bits(mask: u8) -> BTreeSet<u8> {
        (0..6).filter(|bit| mask & (1 << bit) != 0).collect()
    }

    proptest! {
        #[test]
        fn concrete_closure_matches_synchronous_horn_fixed_point(
            seed in 0_u8..64,
            specs in prop::collection::vec((0_u8..64, 0_u8..64), 0..10),
        ) {
            let mut expected = seed;
            // At most six new labels can enter this independent bitset oracle.
            // All rules inspect the PREVIOUS round; production is sequential.
            for _ in 0..6 {
                let previous = expected;
                for &(requires, provides) in &specs {
                    if requires & previous == requires { expected |= provides; }
                }
            }
            let mut rules = specs.iter().map(|(requires, provides)| Derivation {
                requires: bits(*requires), provides: bits(*provides),
            }).collect::<Vec<_>>();
            let mut actual = bits(seed);
            closure(&mut actual, &rules);
            prop_assert_eq!(&actual, &bits(expected));
            let mut idempotent = actual.clone();
            closure(&mut idempotent, &rules);
            prop_assert_eq!(&idempotent, &actual);
            rules.reverse();
            let mut reordered = bits(seed);
            closure(&mut reordered, &rules);
            prop_assert_eq!(reordered, actual);
        }
    }
}
