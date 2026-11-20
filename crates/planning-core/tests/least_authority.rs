use authority_planning_core::{
    Derivation, Mechanism, Model, Plan, PlanningError, Request, minimal_indices, solve_frontier,
    solve_minimal_authority,
};
use proptest::prelude::*;
use std::collections::BTreeSet;
fn bits(mask: u8) -> BTreeSet<u8> {
    (0..6).filter(|bit| mask & (1 << bit) != 0).collect()
}
fn request() -> Request<u8, u8> {
    Request {
        goals: bits(1),
        available: BTreeSet::new(),
        permitted: bits(63),
        forbidden_mechanisms: BTreeSet::new(),
        max_mechanisms: 6,
        max_states: 64,
    }
}
#[test]
fn two_step_narrow_plan_beats_one_step_broad_plan_including_derived_effects() {
    let model = Model {
        mechanisms: vec![
            Mechanism {
                id: 0,
                requires: bits(0),
                provides: bits(7),
            },
            Mechanism {
                id: 1,
                requires: bits(0),
                provides: bits(2),
            },
            Mechanism {
                id: 2,
                requires: bits(2),
                provides: bits(1),
            },
        ],
        derivations: vec![Derivation {
            requires: bits(4),
            provides: bits(8),
        }],
    };
    let plan = solve_minimal_authority(&model, &request(), |_| true, BTreeSet::is_subset).unwrap();
    assert_eq!(plan.mechanisms, vec![1, 2]);
    assert_eq!(plan.abilities, bits(3));
    let mut bounded = request();
    // With four states the broad goal has already been visited before exhaustion.
    bounded.max_states = 4;
    assert_eq!(
        solve_frontier(&model, &bounded, |_| true, BTreeSet::is_subset),
        Err(PlanningError::SearchLimit)
    );
}
#[test]
fn equivalent_and_incomparable_elements_survive_the_partial_order() {
    let sets = vec![bits(3), bits(5), bits(3), bits(7)];
    assert_eq!(minimal_indices(&sets, BTreeSet::is_subset), vec![0, 1, 2]);
}
// Independent exhaustive selected-subset oracle with synchronous closure rounds.
proptest! {
 #[test]
 fn frontier_matches_exhaustive_feasible_authorities(
 specs in prop::collection::vec((0_u8..64,0_u8..64),0..=6),
 derivations in prop::collection::vec((0_u8..64,0_u8..64),0..=5),
 goal in 0_u8..64, available in 0_u8..64, permitted in 0_u8..64,
 required in 0_u8..64,
 ){
 let model=Model{mechanisms:specs.iter().enumerate().map(|(i,&(r,p))|Mechanism{id:u8::try_from(i).unwrap(),requires:bits(r),provides:bits(p)}).collect(),derivations:derivations.iter().map(|&(r,p)|Derivation{requires:bits(r),provides:bits(p)}).collect()};
 let mut req=request();req.goals=bits(goal);req.available=bits(available);req.permitted=bits(permitted);
 let closure=|mut state:u8|{for _ in 0..6{let previous=state;for &(r,p) in &derivations{if previous&r==r{state|=p;}}}state};
 let mut feasible=Vec::new();
 for chosen in 0_u8..(1<<specs.len()){
  if chosen&required!=required{continue;}
  let mut state=closure(available);let mut executed=0_u8;
  if state&!permitted!=0{continue;}
  for _ in 0..specs.len(){
   let previous=state;
   for (i,&(r,p)) in specs.iter().enumerate(){if chosen&(1<<i)!=0 && previous&r==r{state|=p;executed|=1<<i;}}
   state=closure(state);
  }
  if executed==chosen && state&goal==goal && state&!permitted==0{feasible.push((chosen,state));}
 }
 let expected:BTreeSet<_>=feasible.iter().filter(|(_,state)|!feasible.iter().any(|(_,other)|other!=state && other&state==*other)).map(|(m,a)|(*m,*a)).collect();
 let actual=solve_frontier(&model,&req,|p:&Plan<u8,u8>|p.mechanisms.iter().fold(0_u8,|mask,id|mask|(1<<id))&required==required,BTreeSet::is_subset);
 if expected.is_empty(){prop_assert_eq!(actual,Err(PlanningError::NoSolution));}else{
  let plans=actual.unwrap();let observed:BTreeSet<_>=plans.iter().map(|p|(p.mechanisms.iter().fold(0_u8,|mask,id|mask|(1<<id)),p.abilities.iter().fold(0_u8,|mask,a|mask|(1<<a)))).collect();prop_assert_eq!(observed,expected);
  let mut reversed=model.clone();reversed.mechanisms.reverse();reversed.derivations.reverse();
  prop_assert_eq!(plans,solve_frontier(&reversed,&req,|p|p.mechanisms.iter().fold(0_u8,|mask,id|mask|(1<<id))&required==required,BTreeSet::is_subset).unwrap());
 }
 }
}
