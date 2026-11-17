use vstd::prelude::*;

verus! {

pub struct Rule {
    pub requires: ISet<nat>,
    pub provides: ISet<nat>,
}

pub open spec fn closed(rules: Seq<Rule>, abilities: ISet<nat>) -> bool {
    forall|i: int| 0 <= i < rules.len() ==>
        rules[i].requires.subset_of(abilities) ==> rules[i].provides.subset_of(abilities)
}

// Intersection of all rule-closed supersets: the least Horn closure. The
// universe is arbitrary; no six-bit/PBT bound is imposed on these theorems.
pub open spec fn closure(rules: Seq<Rule>, seed: ISet<nat>) -> ISet<nat> {
    ISet::new(|a: nat| forall|candidate: ISet<nat>|
        closed(rules, candidate) && seed.subset_of(candidate) ==> candidate.contains(a))
}

pub proof fn closure_extensive(rules: Seq<Rule>, seed: ISet<nat>)
    ensures seed.subset_of(closure(rules, seed)),
{
    assert forall|a: nat| seed.contains(a) implies closure(rules, seed).contains(a) by {
        assert forall|candidate: ISet<nat>| closed(rules, candidate)
            && seed.subset_of(candidate) implies candidate.contains(a) by {};
    };
}

pub proof fn closure_least(rules: Seq<Rule>, seed: ISet<nat>, candidate: ISet<nat>)
    requires closed(rules, candidate), seed.subset_of(candidate),
    ensures closure(rules, seed).subset_of(candidate),
{
    assert forall|a: nat| closure(rules, seed).contains(a) implies candidate.contains(a) by {};
}

pub proof fn closure_closed(rules: Seq<Rule>, seed: ISet<nat>)
    ensures closed(rules, closure(rules, seed)),
{
    let result = closure(rules, seed);
    assert forall|i: int| 0 <= i < rules.len() && rules[i].requires.subset_of(result)
        implies rules[i].provides.subset_of(result) by {
        assert forall|a: nat| rules[i].provides.contains(a) implies result.contains(a) by {
            assert forall|candidate: ISet<nat>| closed(rules, candidate)
                && seed.subset_of(candidate) implies candidate.contains(a) by {
                closure_least(rules, seed, candidate);
                assert(rules[i].requires.subset_of(candidate));
                assert(rules[i].provides.subset_of(candidate));
            };
        };
    };
}

pub proof fn closure_monotone(rules: Seq<Rule>, smaller: ISet<nat>, larger: ISet<nat>)
    requires smaller.subset_of(larger),
    ensures closure(rules, smaller).subset_of(closure(rules, larger)),
{
    closure_extensive(rules, larger);
    closure_closed(rules, larger);
    closure_least(rules, smaller, closure(rules, larger));
}

// This equality is the basis of selected-set deduplication: mandatory effects
// depend on the accumulated effects, not on the order used to compose them.
pub proof fn closure_incremental(rules: Seq<Rule>, seed: ISet<nat>, effects: ISet<nat>)
    ensures closure(rules, closure(rules, seed).union(effects))
        =~= closure(rules, seed.union(effects)),
{
    let joined = seed.union(effects);
    let accumulated = closure(rules, seed).union(effects);
    closure_extensive(rules, seed);
    assert(joined.subset_of(accumulated));
    closure_monotone(rules, joined, accumulated);
    closure_extensive(rules, joined);
    closure_monotone(rules, seed, joined);
    assert(accumulated.subset_of(closure(rules, joined)));
    closure_closed(rules, joined);
    closure_least(rules, accumulated, closure(rules, joined));
}


// Catalog IDs are unique positions; the production duplicate-ID check is the
// adapter from caller IDs to these positions. Abilities include their scope.
pub struct Catalog {
    pub mechanisms: Seq<Rule>,
    pub derivations: Seq<Rule>,
    pub available: ISet<nat>,
    pub permitted: ISet<nat>,
    pub forbidden: ISet<nat>,
    pub goals: ISet<nat>,
    pub accepts: spec_fn(Set<nat>, ISet<nat>) -> bool,
}

pub open spec fn effects(c: Catalog, selected: Set<nat>) -> ISet<nat> {
    ISet::new(|a: nat| exists|i: int| 0 <= i < c.mechanisms.len()
        && selected.contains(i as nat) && c.mechanisms[i].provides.contains(a))
}

pub open spec fn abilities(c: Catalog, selected: Set<nat>) -> ISet<nat> {
    closure(c.derivations, c.available.union(effects(c, selected)))
}

pub open spec fn step(c: Catalog, before: Set<nat>, after: Set<nat>) -> bool {
    exists|i: int| 0 <= i < c.mechanisms.len()
        && !before.contains(i as nat) && !c.forbidden.contains(i as nat)
        && c.mechanisms[i].requires.subset_of(abilities(c, before))
        && after == before.insert(i as nat)
        && abilities(c, after).subset_of(c.permitted)
}

pub open spec fn reachable(c: Catalog, length: nat, selected: Set<nat>) -> bool
    decreases length,
{
    if length == 0 {
        selected == Set::<nat>::empty() && abilities(c, selected).subset_of(c.permitted)
    } else {
        exists|previous: Set<nat>| reachable(c, (length - 1) as nat, previous)
            && step(c, previous, selected)
    }
}

pub open spec fn goal(c: Catalog, selected: Set<nat>) -> bool {
    c.goals.subset_of(abilities(c, selected)) && (c.accepts)(selected, abilities(c, selected))
}

pub open spec fn succeeds(c: Catalog, length: nat) -> bool {
    exists|selected: Set<nat>| reachable(c, length, selected) && goal(c, selected)
}


pub open spec fn ids_in_catalog(c: Catalog, order: Seq<nat>) -> bool {
    forall|i: int| 0 <= i < order.len() ==> order[i] < c.mechanisms.len()
}

pub open spec fn execute(c: Catalog, order: Seq<nat>) -> ISet<nat>
    decreases order.len(),
{
    if order.len() == 0 {
        closure(c.derivations, c.available)
    } else {
        closure(c.derivations, execute(c, order.drop_last()).union(
            c.mechanisms[order.last() as int].provides))
    }
}

pub open spec fn valid_execution(c: Catalog, order: Seq<nat>) -> bool
    decreases order.len(),
{
    if order.len() == 0 {
        execute(c, order).subset_of(c.permitted)
    } else {
        let prefix = order.drop_last();
        let id = order.last();
        valid_execution(c, prefix)
            && id < c.mechanisms.len()
            && !prefix.to_set().contains(id)
            && !c.forbidden.contains(id)
            && c.mechanisms[id as int].requires.subset_of(execute(c, prefix))
            && execute(c, order).subset_of(c.permitted)
    }
}

pub proof fn effects_empty(c: Catalog)
    ensures effects(c, Set::empty()) =~= ISet::<nat>::empty(),
{}

pub proof fn effects_insert(c: Catalog, selected: Set<nat>, id: nat)
    requires id < c.mechanisms.len(),
    ensures effects(c, selected.insert(id)) =~=
        effects(c, selected).union(c.mechanisms[id as int].provides),
{
    assert forall|a: nat| effects(c, selected.insert(id)).contains(a) ==
        effects(c, selected).union(c.mechanisms[id as int].provides).contains(a) by {
        if effects(c, selected.insert(id)).contains(a) {
            let i = choose|i: int| 0 <= i < c.mechanisms.len()
                && selected.insert(id).contains(i as nat) && c.mechanisms[i].provides.contains(a);
            if i != id as int {
                assert(selected.contains(i as nat));
                assert(effects(c, selected).contains(a));
            }
        } else {
            if c.mechanisms[id as int].provides.contains(a) {
                assert(selected.insert(id).contains(id));
                assert(effects(c, selected.insert(id)).contains(a));
            }
            if effects(c, selected).contains(a) {
                let i = choose|i: int| 0 <= i < c.mechanisms.len()
                    && selected.contains(i as nat) && c.mechanisms[i].provides.contains(a);
                assert(selected.insert(id).contains(i as nat));
                assert(effects(c, selected.insert(id)).contains(a));
            }
        }
    };
}

pub proof fn execution_depends_only_on_selected_set(c: Catalog, order: Seq<nat>)
    requires ids_in_catalog(c, order),
    ensures execute(c, order) =~= abilities(c, order.to_set()),
    decreases order.len(),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    if order.len() == 0 {
        assert(order.to_set() =~= Set::<nat>::empty());
        effects_empty(c);
        assert(c.available.union(effects(c, order.to_set())) =~= c.available);
    } else {
        let prefix = order.drop_last();
        let id = order.last();
        assert(order =~= prefix.push(id));
        assert(ids_in_catalog(c, prefix));
        execution_depends_only_on_selected_set(c, prefix);
        Seq::<nat>::lemma_push_to_set_commute(prefix, id);
        effects_insert(c, prefix.to_set(), id);
        let seed = c.available.union(effects(c, prefix.to_set()));
        let extra = c.mechanisms[id as int].provides;
        closure_incremental(c.derivations, seed, extra);
        assert(seed.union(extra) =~= c.available.union(effects(c, order.to_set())));
    }
}

pub proof fn valid_execution_ids(c: Catalog, order: Seq<nat>)
    requires valid_execution(c, order),
    ensures ids_in_catalog(c, order),
    decreases order.len(),
{
    if order.len() > 0 {
        valid_execution_ids(c, order.drop_last());
        assert forall|i: int| 0 <= i < order.len() implies order[i] < c.mechanisms.len() by {
            if i < order.len() - 1 { assert(order.drop_last()[i] == order[i]); }
            else { assert(order[i] == order.last()); }
        };
    }
}

pub proof fn execution_reaches_layer(c: Catalog, order: Seq<nat>)
    requires valid_execution(c, order),
    ensures reachable(c, order.len(), order.to_set()),
    decreases order.len(),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    valid_execution_ids(c, order);
    execution_depends_only_on_selected_set(c, order);
    if order.len() > 0 {
        let prefix = order.drop_last();
        let id = order.last();
        execution_reaches_layer(c, prefix);
        valid_execution_ids(c, prefix);
        execution_depends_only_on_selected_set(c, prefix);
        assert(order =~= prefix.push(id));
        Seq::<nat>::lemma_push_to_set_commute(prefix, id);
        assert(step(c, prefix.to_set(), order.to_set()));
        assert(reachable(c, (order.len() - 1) as nat, prefix.to_set()));
        assert(reachable(c, order.len(), order.to_set()));
    } else {
        assert(order.to_set() =~= Set::<nat>::empty());
        assert(reachable(c, 0, order.to_set()));
    }
}

pub proof fn layer_has_execution(c: Catalog, length: nat, selected: Set<nat>)
    requires reachable(c, length, selected),
    ensures exists|order: Seq<nat>| order.len() == length
        && order.to_set() == selected && valid_execution(c, order),
    decreases length,
{
    broadcast use vstd::seq_lib::group_seq_properties;
    if length == 0 {
        let empty = Seq::<nat>::empty();
        assert(empty.to_set() =~= Set::<nat>::empty());
        assert(ids_in_catalog(c, empty));
        execution_depends_only_on_selected_set(c, empty);
        assert(valid_execution(c, empty));
    } else {
        let previous = choose|previous: Set<nat>| reachable(c, (length - 1) as nat, previous)
            && step(c, previous, selected);
        layer_has_execution(c, (length - 1) as nat, previous);
        let prefix = choose|order: Seq<nat>| order.len() == length - 1
            && order.to_set() == previous && valid_execution(c, order);
        let i = choose|i: int| 0 <= i < c.mechanisms.len()
            && !previous.contains(i as nat) && !c.forbidden.contains(i as nat)
            && c.mechanisms[i].requires.subset_of(abilities(c, previous))
            && selected == previous.insert(i as nat)
            && abilities(c, selected).subset_of(c.permitted);
        let order = prefix.push(i as nat);
        Seq::<nat>::lemma_push_to_set_commute(prefix, i as nat);
        assert(order.drop_last() =~= prefix);
        valid_execution_ids(c, prefix);
        assert(ids_in_catalog(c, order));
        execution_depends_only_on_selected_set(c, prefix);
        execution_depends_only_on_selected_set(c, order);
        assert(valid_execution(c, order));
    }
}

// Breadth-first layer specification, independent of machine-size search bounds.
// The caller must treat an exhausted implementation budget as SearchLimit.
pub open spec fn shortest(c: Catalog, bound: nat) -> Option<nat>
    decreases bound,
{
    if bound == 0 {
        if succeeds(c, 0) { Some(0) } else { None }
    } else {
        match shortest(c, (bound - 1) as nat) {
            Some(length) => Some(length),
            None => if succeeds(c, bound) { Some(bound) } else { None },
        }
    }
}

pub proof fn layer_sound(c: Catalog, length: nat, selected: Set<nat>)
    requires reachable(c, length, selected),
    ensures
        abilities(c, selected).subset_of(c.permitted),
        selected.len() == length,
        forall|id: nat| selected.contains(id) ==>
            id < c.mechanisms.len() && !c.forbidden.contains(id),
    decreases length,
{
    if length > 0 {
        let previous = choose|previous: Set<nat>| reachable(c, (length - 1) as nat, previous)
            && step(c, previous, selected);
        layer_sound(c, (length - 1) as nat, previous);
        let i = choose|i: int| 0 <= i < c.mechanisms.len()
            && !previous.contains(i as nat) && !c.forbidden.contains(i as nat)
            && c.mechanisms[i].requires.subset_of(abilities(c, previous))
            && selected == previous.insert(i as nat)
            && abilities(c, selected).subset_of(c.permitted);
        assert(selected.len() == previous.len() + 1);
        assert forall|id: nat| selected.contains(id) implies
            id < c.mechanisms.len() && !c.forbidden.contains(id) by {
            if id != i as nat { assert(previous.contains(id)); }
        };
    }
}

// Completeness and minimality of the layer search, including the empty plan and
// final predicates that require extending an already goal-reaching state.
pub proof fn shortest_correct(c: Catalog, bound: nat)
    ensures
        match shortest(c, bound) {
            Some(length) => length <= bound && succeeds(c, length)
                && forall|earlier: nat| earlier < length ==> !succeeds(c, earlier),
            None => forall|length: nat| length <= bound ==> !succeeds(c, length),
        },
    decreases bound,
{
    if bound > 0 {
        shortest_correct(c, (bound - 1) as nat);
        if shortest(c, (bound - 1) as nat).is_none() {
            if succeeds(c, bound) {
                assert forall|earlier: nat| earlier < bound implies !succeeds(c, earlier) by {};
            } else {
                assert forall|length: nat| length <= bound implies !succeeds(c, length) by {};
            }
        }
    }
}

pub proof fn solution_sound_and_minimal(c: Catalog, bound: nat, length: nat, selected: Set<nat>)
    requires shortest(c, bound) == Some(length),
        reachable(c, length, selected), goal(c, selected),
    ensures
        length <= bound,
        selected.len() == length,
        abilities(c, selected).subset_of(c.permitted),
        c.goals.subset_of(abilities(c, selected)),
        (c.accepts)(selected, abilities(c, selected)),
        forall|other_length: nat, other: Set<nat>|
            reachable(c, other_length, other) && goal(c, other) ==> length <= other_length,
{
    shortest_correct(c, bound);
    layer_sound(c, length, selected);
    assert forall|other_length: nat, other: Set<nat>|
        reachable(c, other_length, other) && goal(c, other) implies length <= other_length by {
        assert(succeeds(c, other_length));
    };
}

pub proof fn no_solution_complete(c: Catalog, bound: nat, length: nat, selected: Set<nat>)
    requires shortest(c, bound).is_none(), length <= bound,
    ensures !(reachable(c, length, selected) && goal(c, selected)),
{
    shortest_correct(c, bound);
    if reachable(c, length, selected) && goal(c, selected) {
        assert(succeeds(c, length));
    }
}


// End-to-end theorem for the mathematical solver: a returned minimum length has
// an executable witness; every competing authorized execution is at least as long.
pub proof fn solver_sound_complete_minimal(c: Catalog, bound: nat)
    ensures
        match shortest(c, bound) {
            Some(length) => length <= bound
                && (exists|order: Seq<nat>| order.len() == length
                    && valid_execution(c, order)
                    && c.goals.subset_of(execute(c, order))
                    && (c.accepts)(order.to_set(), execute(c, order)))
                && (forall|other: Seq<nat>| valid_execution(c, other)
                    && c.goals.subset_of(execute(c, other))
                    && (c.accepts)(other.to_set(), execute(c, other))
                    ==> length <= other.len()),
            None => forall|order: Seq<nat>| order.len() <= bound ==>
                !(valid_execution(c, order)
                    && c.goals.subset_of(execute(c, order))
                    && (c.accepts)(order.to_set(), execute(c, order))),
        },
{
    shortest_correct(c, bound);
    match shortest(c, bound) {
        Some(length) => {
            let selected = choose|selected: Set<nat>| reachable(c, length, selected) && goal(c, selected);
            layer_has_execution(c, length, selected);
            let order = choose|order: Seq<nat>| order.len() == length
                && order.to_set() == selected && valid_execution(c, order);
            valid_execution_ids(c, order);
            execution_depends_only_on_selected_set(c, order);
            assert(c.goals.subset_of(execute(c, order)));
            assert((c.accepts)(order.to_set(), execute(c, order)));
            assert forall|other: Seq<nat>| valid_execution(c, other)
                && c.goals.subset_of(execute(c, other))
                && (c.accepts)(other.to_set(), execute(c, other))
                implies length <= other.len() by {
                valid_execution_ids(c, other);
                execution_depends_only_on_selected_set(c, other);
                execution_reaches_layer(c, other);
                assert(execute(c, other) == abilities(c, other.to_set()));
                assert(goal(c, other.to_set()));
                assert(succeeds(c, other.len()));
            };
        },
        None => {
            assert forall|order: Seq<nat>| order.len() <= bound
                implies !(valid_execution(c, order)
                    && c.goals.subset_of(execute(c, order))
                    && (c.accepts)(order.to_set(), execute(c, order))) by {
                if valid_execution(c, order)
                    && c.goals.subset_of(execute(c, order))
                    && (c.accepts)(order.to_set(), execute(c, order)) {
                    valid_execution_ids(c, order);
                    execution_depends_only_on_selected_set(c, order);
                    execution_reaches_layer(c, order);
                    assert(execute(c, order) == abilities(c, order.to_set()));
                    assert(goal(c, order.to_set()));
                    assert(succeeds(c, order.len()));
                }
            };
        },
    }
}

} // verus!
