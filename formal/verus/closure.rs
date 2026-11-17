verus! {
/* PRODUCTION_DERIVATION_TYPE */

pub open spec fn lift_rules(rules: Seq<NativeRule>) -> Seq<Rule> {
    rules.map_values(|rule: NativeRule| Rule { requires: rule.requires.to_iset(), provides: rule.provides.to_iset() })
}
pub open spec fn provides_in(rules: Seq<NativeRule>, universe: Set<nat>) -> bool {
    forall|i: int| 0 <= i < rules.len() ==> rules[i].provides.subset_of(universe)
}
pub open spec fn effect_universe(seed: Set<nat>, rules: Seq<NativeRule>, length: nat) -> Set<nat>
    recommends length <= rules.len(),
    decreases length,
{
    if length == 0 { seed }
    else { effect_universe(seed, rules, (length - 1) as nat).union(rules[(length - 1) as int].provides) }
}
pub proof fn universe_covers_effects(seed: Set<nat>, rules: Seq<NativeRule>, length: nat)
    requires length <= rules.len(),
    ensures seed.subset_of(effect_universe(seed, rules, length)),
        forall|i: int| 0 <= i < length ==> rules[i].provides.subset_of(effect_universe(seed, rules, length)),
    decreases length,
{
    if length > 0 {
        universe_covers_effects(seed, rules, (length - 1) as nat);
        assert forall|i: int| 0 <= i < length implies rules[i].provides.subset_of(effect_universe(seed, rules, length)) by {
            if i < length - 1 { assert(rules[i].provides.subset_of(effect_universe(seed, rules, (length - 1) as nat))); }
        };
    }
}

// One production rule application, with independently stated monotonicity,
// declared-effect bound and least-closure preservation obligations.
pub proof fn apply_native_rule(rules: Seq<NativeRule>, seed: Set<nat>, previous: Set<nat>,
    universe: Set<nat>, index: int) -> (result: Set<nat>)
    requires 0 <= index < rules.len(), previous.subset_of(universe), provides_in(rules, universe),
        previous.to_iset().subset_of(closure(lift_rules(rules), seed.to_iset())),
    ensures previous.subset_of(result), result.subset_of(universe),
        result.to_iset().subset_of(closure(lift_rules(rules), seed.to_iset())),
        rules[index].requires.subset_of(previous) ==> rules[index].provides.subset_of(result),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let rule = rules[index];
    closure_closed(lift_rules(rules), seed.to_iset());
    assert(lift_rules(rules)[index].requires == rule.requires.to_iset());
    assert(lift_rules(rules)[index].provides == rule.provides.to_iset());
    let mut abilities = previous;
    /* PRODUCTION_RULE_APPLICATION */
    abilities
}

pub proof fn native_round(rules: Seq<NativeRule>, seed: Set<nat>, universe: Set<nat>, length: nat)
    -> (result: Set<nat>)
    requires length <= rules.len(), seed.subset_of(universe), provides_in(rules, universe),
    ensures seed.subset_of(result), result.subset_of(universe),
        result.to_iset().subset_of(closure(lift_rules(rules), seed.to_iset())),
        forall|i: int| 0 <= i < length && rules[i].requires.subset_of(seed) ==> rules[i].provides.subset_of(result),
    decreases length,
{
    if length == 0 {
        closure_extensive(lift_rules(rules), seed.to_iset());
        seed
    } else {
        let previous = native_round(rules, seed, universe, (length - 1) as nat);
        let result = apply_native_rule(rules, seed, previous, universe, (length - 1) as int);
        assert forall|i: int| 0 <= i < length && rules[i].requires.subset_of(seed)
            implies rules[i].provides.subset_of(result) by {
            if i < length - 1 { assert(rules[i].provides.subset_of(previous)); }
            else { assert(rules[i].requires.subset_of(previous)); }
        };
        result
    }
}

// The outer production loop: every nonterminal round strictly increases the
// finite set, so remaining possible effects decrease. The universe is ghost-only.
pub proof fn native_closure_bounded(seed: Set<nat>, rules: Seq<NativeRule>, universe: Set<nat>)
    -> (result: Set<nat>)
    requires seed.subset_of(universe), provides_in(rules, universe),
    ensures seed.subset_of(result), result.subset_of(universe),
        result.to_iset() =~= closure(lift_rules(rules), seed.to_iset()),
    decreases universe.len() - seed.len(),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let count = seed.len();
    let abilities = native_round(rules, seed, universe, rules.len());
    if /* PRODUCTION_CLOSURE_STOP */ {
        vstd::set_lib::lemma_subset_equality(seed, abilities);
        assert forall|i: int| 0 <= i < rules.len()
            && lift_rules(rules)[i].requires.subset_of(abilities.to_iset())
            implies lift_rules(rules)[i].provides.subset_of(abilities.to_iset()) by {
            assert(rules[i].requires.subset_of(seed));
            assert(rules[i].provides.subset_of(abilities));
        };
        assert(closed(lift_rules(rules), abilities.to_iset()));
        closure_least(lift_rules(rules), seed.to_iset(), abilities.to_iset());
        abilities
    } else {
        vstd::set_lib::lemma_len_subset(seed, abilities);
        vstd::set_lib::lemma_len_subset(abilities, universe);
        let result = native_closure_bounded(abilities, rules, universe);
        closure_closed(lift_rules(rules), seed.to_iset());
        closure_monotone(lift_rules(rules), seed.to_iset(), abilities.to_iset());
        closure_least(lift_rules(rules), abilities.to_iset(), closure(lift_rules(rules), seed.to_iset()));
        result
    }
}

pub proof fn concrete_closure_is_least_fixed_point(seed: Set<nat>, rules: Seq<NativeRule>) -> (result: Set<nat>)
    ensures seed.subset_of(result),
        result.to_iset() =~= closure(lift_rules(rules), seed.to_iset()),
{
    let universe = effect_universe(seed, rules, rules.len());
    universe_covers_effects(seed, rules, rules.len());
    assert(provides_in(rules, universe));
    native_closure_bounded(seed, rules, universe)
}

} // verus!
