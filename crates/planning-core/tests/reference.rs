//! An independent bounded reference: enumerate execution orders, not BFS states
//! or selected-set deduplication. Bitsets intentionally differ from production.
use std::collections::BTreeSet;

use authority_planning_core::{Conditional, ConditionalModel, explain};
use authority_planning_core::{Derivation, Mechanism, PlanningError, Request, solve};
use proptest::prelude::*;

#[derive(Debug)]
struct Reference<'a> {
    mechanisms: &'a [(u8, u8)],
    derivations: &'a [(u8, u8)],
    goals: u8,
    permitted: u8,
    forbidden: u8,
    enabled: u8,
    required: u8,
    even: bool,
    max_mechanisms: usize,
}

impl Reference<'_> {
    fn closure(&self, mut abilities: u8) -> u8 {
        loop {
            let previous = abilities;
            // Synchronous rounds; production applies rules sequentially.
            for &(requires, provides) in self.derivations {
                if requires & previous == requires {
                    abilities |= provides;
                }
            }
            if previous == abilities {
                return abilities;
            }
        }
    }

    fn accepts(&self, selected: u8, abilities: u8) -> bool {
        abilities & self.goals == self.goals
            && selected & self.required == self.required
            && (!self.even || selected.count_ones().is_multiple_of(2))
    }

    fn enumerate(
        &self,
        prefix: &mut Vec<u8>,
        selected: u8,
        abilities: u8,
        best: &mut Option<Vec<u8>>,
    ) {
        let abilities = self.closure(abilities);
        if abilities & !self.permitted != 0 {
            return;
        }
        if self.accepts(selected, abilities)
            && best
                .as_ref()
                .is_none_or(|old| (prefix.len(), &*prefix) < (old.len(), old))
        {
            *best = Some(prefix.clone());
        }
        if prefix.len() >= self.max_mechanisms {
            return;
        }
        for (index, &(requires, provides)) in self.mechanisms.iter().enumerate() {
            let id = u8::try_from(index).unwrap();
            if self.enabled & (1 << id) != 0
                && (selected | self.forbidden) & (1 << id) == 0
                && abilities & requires == requires
            {
                prefix.push(id);
                self.enumerate(prefix, selected | (1 << id), abilities | provides, best);
                prefix.pop();
            }
        }
    }
}

fn bits(mask: u8) -> BTreeSet<u8> {
    (0..6).filter(|bit| mask & (1 << bit) != 0).collect()
}

proptest! {
    #[test]
    fn sound_complete_minimal_with_composition_and_constraints(
        mechanisms in prop::collection::vec((0_u8..64, 0_u8..64), 0..=6),
        derivations in prop::collection::vec((0_u8..64, 0_u8..64), 0..=6),
        mechanism_facts in prop::collection::vec(0_u8..64,6),
        derivation_facts in prop::collection::vec(0_u8..64,6),
        environment in 0_u8..64,
        available in 0_u8..64, goals in 0_u8..64,
        permitted in prop_oneof![Just(63_u8), 0_u8..64],
        forbidden in prop_oneof![Just(0_u8), 0_u8..64],
        required in prop_oneof![Just(0_u8), 0_u8..64],
        even in any::<bool>(), max_mechanisms in 0_usize..=6,
        budget in 0_usize..=64,
    ) {
        let enabled = mechanisms.iter().enumerate().fold(0u8,|mask,(i,_)|if mechanism_facts[i] & environment == mechanism_facts[i] {mask | (1 << i)}else{mask});
        let active_derivations:Vec<_> = derivations.iter().enumerate().filter(|(i,_)|derivation_facts[*i] & environment == derivation_facts[*i]).map(|(_,rule)|*rule).collect();
        let reference = Reference {
            mechanisms: &mechanisms, derivations: &active_derivations,
            goals, permitted, forbidden, enabled, required, even, max_mechanisms,
        };
        let mut expected = None;
        reference.enumerate(&mut vec![], 0, available, &mut expected);

        let conditional = ConditionalModel {
            mechanisms:mechanisms.iter().enumerate().map(|(id,&(requires,provides))|Conditional {value:Mechanism {id:u8::try_from(id).unwrap(),requires:bits(requires),provides:bits(provides)},requires_facts:bits(mechanism_facts[id])}).collect(),
            derivations:derivations.iter().enumerate().map(|(id,&(requires,provides))|Conditional {value:Derivation {requires:bits(requires),provides:bits(provides)},requires_facts:bits(derivation_facts[id])}).collect(),
        };
        let mut model=conditional.instantiate(&bits(environment));
        let mut request = Request {
            goals: bits(goals), available: bits(available), permitted: bits(permitted),
            forbidden_mechanisms: bits(forbidden), max_mechanisms,
            // Every selected set fits; SearchLimit cannot hide incompleteness.
            max_states: 1 << mechanisms.len(),
        };
        let accepts = |plan: &authority_planning_core::Plan<u8, u8>| {
            let selected = plan.mechanisms.iter().fold(0_u8, |mask, id| mask | (1 << id));
            selected & required == required && (!even || plan.mechanisms.len().is_multiple_of(2))
        };
        let actual = solve(&model, &request, accepts);
        match &expected {
            None => prop_assert_eq!(&actual, &Err(PlanningError::NoSolution)),
            Some(order) => {
                let plan = actual.as_ref().unwrap();
                prop_assert!(explain(&model,&request.available,plan).is_ok());
                prop_assert_eq!(&plan.mechanisms, order);
                let mut observed = reference.closure(available);
                let mut selected = 0_u8;
                for &id in &plan.mechanisms {
                    let (requires, provides) = mechanisms[usize::from(id)];
                    prop_assert_eq!(observed & requires, requires);
                    prop_assert_eq!((selected | forbidden) & (1 << id), 0);
                    selected |= 1 << id;
                    observed = reference.closure(observed | provides);
                    prop_assert_eq!(observed & !permitted, 0);
                }
                prop_assert_eq!(&plan.abilities, &bits(observed));
                prop_assert!(reference.accepts(selected, observed));
            }
        }
        model.mechanisms.reverse();
        model.derivations.reverse();
        prop_assert_eq!(&actual, &solve(&model, &request, accepts));
        request.max_states = budget;
        // Exhaustion is distinct from a proof of absence. Any returned plan must
        // still be the same globally minimal plan, even under a smaller budget.
        match solve(&model, &request, accepts) {
            Ok(plan) => prop_assert_eq!(Some(plan), actual.ok()),
            Err(PlanningError::NoSolution) => prop_assert!(expected.is_none()),
            Err(error) => prop_assert_eq!(error, PlanningError::SearchLimit),
        }
    }
}
