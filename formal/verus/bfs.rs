verus! {
pub struct SearchNode { pub mechanisms: Seq<nat>, pub abilities: ISet<nat> }
pub struct SearchState {
    pub queue: Seq<SearchNode>, pub visited: Set<Set<nat>>, pub done: Set<Set<nat>>,
}
pub enum SearchFailure { NoSolution, SearchLimit }

pub open spec fn key(node: SearchNode) -> Set<nat> { node.mechanisms.to_set() }
pub open spec fn node_valid(c: Catalog, node: SearchNode) -> bool {
    valid_execution(c, node.mechanisms) && node.abilities == execute(c, node.mechanisms)
}
pub open spec fn queue_keys(queue: Seq<SearchNode>) -> Set<Set<nat>> {
    queue.map_values(|node: SearchNode| key(node)).to_set()
}
pub open spec fn node_goal(c: Catalog, node: SearchNode) -> bool {
    c.goals.subset_of(node.abilities) && (c.accepts)(key(node), node.abilities)
}
pub open spec fn ordered(queue: Seq<SearchNode>) -> bool {
    forall|i: int, j: int| 0 <= i < j < queue.len() ==> queue[i].mechanisms.len() <= queue[j].mechanisms.len()
}
pub open spec fn edge_at(c: Catalog, selected: Set<nat>, id: int) -> bool {
    0 <= id < c.mechanisms.len() && !selected.contains(id as nat) && !c.forbidden.contains(id as nat)
        && c.mechanisms[id].requires.subset_of(abilities(c, selected))
        && abilities(c, selected.insert(id as nat)).subset_of(c.permitted)
}
pub open spec fn expanded(c: Catalog, bound: nat, done: Set<Set<nat>>, visited: Set<Set<nat>>) -> bool {
    forall|parent: Set<nat>, child: Set<nat>| done.contains(parent) && parent.len() < bound
        && step(c, parent, child) ==> visited.contains(child)
}
pub open spec fn common_inv(c: Catalog, bound: nat, budget: nat, state: SearchState) -> bool {
    state.visited.len() <= budget
        && state.visited.contains(Set::<nat>::empty())
        && state.visited == state.done.union(queue_keys(state.queue))
        && (forall|selected: Set<nat>| state.visited.contains(selected) ==>
            reachable(c, selected.len(), selected) && selected.len() <= bound)
        && (forall|selected: Set<nat>| state.done.contains(selected) ==> !goal(c, selected))
        && expanded(c, bound, state.done, state.visited)
        && (forall|i: int| 0 <= i < state.queue.len() ==> node_valid(c, state.queue[i])
            && state.queue[i].mechanisms.len() <= bound)
        && ordered(state.queue)
        && (forall|i: int| 0 <= i < state.queue.len() ==>
            (#[trigger] state.queue[i]).mechanisms.len() <= state.queue[0].mechanisms.len() + 1)
}

pub proof fn node_representation(c: Catalog, node: SearchNode)
    requires node_valid(c, node),
    ensures node.abilities == abilities(c, key(node)), key(node).len() == node.mechanisms.len(),
        reachable(c, node.mechanisms.len(), key(node)),
        node_goal(c, node) == goal(c, key(node)),
{
    valid_execution_ids(c, node.mechanisms);
    execution_depends_only_on_selected_set(c, node.mechanisms);
    execution_reaches_layer(c, node.mechanisms);
    layer_sound(c, node.mechanisms.len(), key(node));
}

pub proof fn queue_key_witness(queue: Seq<SearchNode>, selected: Set<nat>)
    requires queue_keys(queue).contains(selected),
    ensures exists|i: int| 0 <= i < queue.len() && key(queue[i]) == selected,
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let keys = queue.map_values(|node: SearchNode| key(node));
    assert(keys.contains(selected));
    let i = choose|i: int| 0 <= i < keys.len() && keys[i] == selected;
    assert(key(queue[i]) == selected);
}

pub proof fn queue_keys_push(queue: Seq<SearchNode>, node: SearchNode)
    ensures queue_keys(queue.push(node)) =~= queue_keys(queue).insert(key(node)),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let f = |n: SearchNode| key(n);
    assert(queue.push(node).map_values(f) =~= queue.map_values(f).push(key(node)));
    Seq::<Set<nat>>::lemma_push_to_set_commute(queue.map_values(f), key(node));
}

// If every pending node is at or beyond a cutoff, every shorter reachable
// bounded state has already been expanded. This is the BFS completeness link.
pub proof fn shorter_states_done(c: Catalog, bound: nat, budget: nat, state: SearchState,
    length: nat, selected: Set<nat>, cutoff: nat)
    requires common_inv(c, bound, budget, state), reachable(c, length, selected),
        length <= bound, length < cutoff,
        forall|i: int| 0 <= i < state.queue.len() ==> cutoff <= (#[trigger] state.queue[i]).mechanisms.len(),
    ensures state.done.contains(selected),
    decreases length,
{
    layer_sound(c, length, selected);
    if length > 0 {
        let previous = choose|previous: Set<nat>| reachable(c, (length - 1) as nat, previous) && step(c, previous, selected);
        shorter_states_done(c, bound, budget, state, (length - 1) as nat, previous, cutoff);
        layer_sound(c, (length - 1) as nat, previous);
        assert(state.visited.contains(selected));
    } else {
        assert(selected == Set::<nat>::empty());
        assert(state.visited.contains(selected));
    }
    if !state.done.contains(selected) {
        assert(queue_keys(state.queue).contains(selected));
        queue_key_witness(state.queue, selected);
        let i = choose|i: int| 0 <= i < state.queue.len() && key(state.queue[i]) == selected;
        node_representation(c, state.queue[i]);
        assert(state.queue[i].mechanisms.len() == length);
        assert(false);
    }
}

pub proof fn goal_at_head_is_minimum(c: Catalog, bound: nat, budget: nat, state: SearchState)
    requires common_inv(c, bound, budget, state), state.queue.len() > 0, node_goal(c, state.queue[0]),
    ensures node_valid(c, state.queue[0]), state.queue[0].mechanisms.len() <= bound,
        forall|length: nat, selected: Set<nat>| reachable(c, length, selected) && goal(c, selected)
            ==> state.queue[0].mechanisms.len() <= length,
{
    node_representation(c, state.queue[0]);
    assert forall|i: int| 0 <= i < state.queue.len() implies state.queue[0].mechanisms.len() <= (#[trigger] state.queue[i]).mechanisms.len() by {};
    assert forall|length: nat, selected: Set<nat>| reachable(c, length, selected) && goal(c, selected)
        implies state.queue[0].mechanisms.len() <= length by {
        if length < state.queue[0].mechanisms.len() {
            shorter_states_done(c, bound, budget, state, length, selected, state.queue[0].mechanisms.len());
        }
    };
}

pub proof fn empty_queue_proves_no_solution(c: Catalog, bound: nat, budget: nat, state: SearchState)
    requires common_inv(c, bound, budget, state), state.queue.len() == 0,
    ensures forall|length: nat, selected: Set<nat>| length <= bound ==>
        !(reachable(c, length, selected) && goal(c, selected)),
{
    assert forall|length: nat, selected: Set<nat>| length <= bound
        implies !(reachable(c, length, selected) && goal(c, selected)) by {
        if reachable(c, length, selected) && goal(c, selected) {
            assert forall|i: int| 0 <= i < state.queue.len() implies length + 1 <= (#[trigger] state.queue[i]).mechanisms.len() by {};
            shorter_states_done(c, bound, budget, state, length, selected, length + 1);
        }
    };
}


pub open spec fn edge_prefix(c: Catalog, parent: SearchNode, visited: Set<Set<nat>>, length: nat) -> bool {
    forall|id: int| 0 <= id < length && edge_at(c, key(parent), id) ==>
        visited.contains(key(parent).insert(id as nat))
}
pub open spec fn expansion_inv(c: Catalog, bound: nat, budget: nat, parent: SearchNode,
    state: SearchState, length: nat) -> bool {
    node_valid(c, parent) && !node_goal(c, parent) && parent.mechanisms.len() < bound
        && state.visited.len() <= budget && state.visited.contains(Set::<nat>::empty())
        && state.visited == state.done.union(queue_keys(state.queue)).insert(key(parent))
        && (forall|selected: Set<nat>| state.visited.contains(selected) ==>
            reachable(c, selected.len(), selected) && selected.len() <= bound)
        && (forall|selected: Set<nat>| state.done.contains(selected) ==> !goal(c, selected))
        && expanded(c, bound, state.done, state.visited)
        && (forall|i: int| 0 <= i < state.queue.len() ==> node_valid(c, state.queue[i])
            && parent.mechanisms.len() <= state.queue[i].mechanisms.len() <= parent.mechanisms.len() + 1
            && state.queue[i].mechanisms.len() <= bound)
        && ordered(state.queue)
        && edge_prefix(c, parent, state.visited, length)
}

pub proof fn extend_node(c: Catalog, plan: SearchNode, id: int) -> (next: SearchNode)
    requires node_valid(c, plan), 0 <= id < c.mechanisms.len(),
        !key(plan).contains(id as nat), !c.forbidden.contains(id as nat),
        c.mechanisms[id].requires.subset_of(plan.abilities),
    ensures next.mechanisms == plan.mechanisms.push(id as nat),
        key(next) == key(plan).insert(id as nat),
        next.abilities == abilities(c, key(next)),
        next.abilities.subset_of(c.permitted) ==> node_valid(c, next),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let mechanism = c.mechanisms[id];
    /* PRODUCTION_EXTEND_NODE */
    assert(next.mechanisms.drop_last() =~= plan.mechanisms);
    assert(next.mechanisms.last() == id as nat);
    assert(next.mechanisms.to_set() =~= plan.mechanisms.to_set().insert(id as nat));
    valid_execution_ids(c, plan.mechanisms);
    assert(ids_in_catalog(c, next.mechanisms));
    execution_depends_only_on_selected_set(c, next.mechanisms);
    next
}


pub open spec fn state_space(size: nat) -> Set<Set<nat>>
    decreases size,
{
    if size == 0 { Set::<Set<nat>>::empty().insert(Set::<nat>::empty()) }
    else {
        let previous = state_space((size - 1) as nat);
        previous.union(previous.map(|selected: Set<nat>| selected.insert((size - 1) as nat)))
    }
}
pub open spec fn bounded_ids(selected: Set<nat>, size: nat) -> bool {
    forall|id: nat| selected.contains(id) ==> id < size
}
pub proof fn state_space_covers(selected: Set<nat>, size: nat)
    requires bounded_ids(selected, size),
    ensures state_space(size).contains(selected),
    decreases size,
{
    broadcast use Set::lemma_map_contains;
    if size == 0 {
        assert(selected =~= Set::<nat>::empty());
    } else {
        let last = (size - 1) as nat;
        if selected.contains(last) {
            let rest = selected.remove(last);
            assert(bounded_ids(rest, last));
            state_space_covers(rest, last);
            assert(selected =~= rest.insert(last));
            assert(state_space(last).map(|s: Set<nat>| s.insert(last)).contains(selected));
        } else {
            assert(bounded_ids(selected, last));
            state_space_covers(selected, last);
        }
    }
}
pub proof fn state_space_only_bounded(selected: Set<nat>, size: nat)
    requires state_space(size).contains(selected),
    ensures bounded_ids(selected, size),
    decreases size,
{
    broadcast use Set::lemma_map_contains;
    if size == 0 {
        assert(selected == Set::<nat>::empty());
    } else {
        let last = (size - 1) as nat;
        let previous = state_space(last);
        if previous.contains(selected) { state_space_only_bounded(selected, last); }
        else {
            let old = choose|old: Set<nat>| previous.contains(old) && selected == old.insert(last);
            state_space_only_bounded(old, last);
        }
    }
}
pub open spec fn two_power(size: nat) -> nat
    decreases size,
{
    if size == 0 { 1 } else { 2 * two_power((size - 1) as nat) }
}
pub proof fn state_space_cardinality(size: nat)
    ensures state_space(size).len() == two_power(size),
    decreases size,
{
    broadcast use Set::lemma_map_contains;
    if size > 0 {
        let last = (size - 1) as nat;
        state_space_cardinality(last);
        let previous = state_space(last);
        let f = |s: Set<nat>| s.insert(last);
        let inserted = previous.map(f);
        assert forall|a: Set<nat>, b: Set<nat>| previous.contains(a) && previous.contains(b) && f(a) == f(b)
            implies a == b by {
            state_space_only_bounded(a, last);
            state_space_only_bounded(b, last);
            assert(a =~= f(a).remove(last));
            assert(b =~= f(b).remove(last));
        };
        assert(previous.injective_on(f));
        vstd::set_lib::lemma_map_size(previous, inserted, f);
        assert forall|s: Set<nat>| previous.contains(s) implies !inserted.contains(s) by {
            state_space_only_bounded(s, last);
            if inserted.contains(s) {
                let old = choose|old: Set<nat>| previous.contains(old) && s == f(old);
                assert(s.contains(last));
            }
        };
        assert(previous.disjoint(inserted));
        vstd::set_lib::lemma_set_disjoint_lens(previous, inserted);
    }
}

pub proof fn capacity_at_failure(c: Catalog, budget: nat, visited: Set<Set<nat>>, next: Set<nat>)
    requires visited.len() >= budget, !visited.contains(next), reachable(c, next.len(), next),
        forall|selected: Set<nat>| visited.contains(selected) ==> reachable(c, selected.len(), selected),
    ensures budget < state_space(c.mechanisms.len()).len(),
{
    let space = state_space(c.mechanisms.len());
    assert forall|selected: Set<nat>| visited.contains(selected) implies space.contains(selected) by {
        layer_sound(c, selected.len(), selected);
        state_space_covers(selected, c.mechanisms.len());
    };
    layer_sound(c, next.len(), next);
    state_space_covers(next, c.mechanisms.len());
    assert(visited.insert(next).subset_of(space));
    vstd::set_lib::lemma_len_subset(visited.insert(next), space);
    assert(visited.insert(next).len() == visited.len() + 1);
}

pub proof fn expand_one(c: Catalog, bound: nat, budget: nat, plan: SearchNode,
    before: SearchState, id: int) -> (r: Result<SearchState, SearchFailure>)
    requires 0 <= id < c.mechanisms.len(), expansion_inv(c, bound, budget, plan, before, id as nat),
    ensures match r {
        Ok(after) => expansion_inv(c, bound, budget, plan, after, (id + 1) as nat)
            && before.visited.subset_of(after.visited) && after.done == before.done
            && after.queue.len() + before.visited.len() == before.queue.len() + after.visited.len(),
        Err(cause) => cause == SearchFailure::SearchLimit && budget < state_space(c.mechanisms.len()).len(),
    },
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let selected = key(plan);
    let mechanism = c.mechanisms[id];
    let mut visited = before.visited;
    let mut queue = before.queue;
    node_representation(c, plan);
    /* PRODUCTION_EXPAND_ONE */
    node_representation(c, next);
    let after = SearchState { queue, visited, done: before.done };
    assert forall|child: Set<nat>| visited.contains(child) implies
        reachable(c, child.len(), child) && child.len() <= bound by {
        if before.visited.contains(child) {} else { assert(child == key(next)); }
    };
    assert forall|i: int| 0 <= i < queue.len() implies node_valid(c, queue[i])
        && plan.mechanisms.len() <= queue[i].mechanisms.len() <= plan.mechanisms.len() + 1
        && queue[i].mechanisms.len() <= bound by {
        if i < before.queue.len() { assert(queue[i] == before.queue[i]); } else { assert(queue[i] == next); }
    };
    assert forall|i: int, j: int| 0 <= i < j < queue.len()
        implies queue[i].mechanisms.len() <= queue[j].mechanisms.len() by {
        if j < before.queue.len() {} else { assert(queue[j] == next); }
    };
    assert(edge_prefix(c, plan, visited, (id + 1) as nat));
    queue_keys_push(before.queue, next);
    assert(visited =~= before.done.union(queue_keys(queue)).insert(key(plan)));
    assert(expanded(c, bound, before.done, visited));
    assert(visited.len() <= budget);
    assert(expansion_inv(c, bound, budget, plan, after, (id + 1) as nat));
    assert(after.queue.len() + before.visited.len() == before.queue.len() + after.visited.len());
    Ok(after)
}


pub proof fn expand_prefix(c: Catalog, bound: nat, budget: nat, plan: SearchNode,
    before: SearchState, length: nat) -> (r: Result<SearchState, SearchFailure>)
    requires length <= c.mechanisms.len(), expansion_inv(c, bound, budget, plan, before, 0),
    ensures match r {
        Ok(after) => expansion_inv(c, bound, budget, plan, after, length)
            && before.visited.subset_of(after.visited) && after.done == before.done
            && after.queue.len() + before.visited.len() == before.queue.len() + after.visited.len(),
        Err(cause) => cause == SearchFailure::SearchLimit && budget < state_space(c.mechanisms.len()).len(),
    },
    decreases length,
{
    if length == 0 { Ok(before) }
    else {
        let previous = match expand_prefix(c, bound, budget, plan, before, (length - 1) as nat) {
            Ok(previous) => previous, Err(cause) => return Err(cause),
        };
        expand_one(c, bound, budget, plan, previous, (length - 1) as int)
    }
}

pub proof fn queue_has_key_at(queue: Seq<SearchNode>, index: int)
    requires 0 <= index < queue.len(),
    ensures queue_keys(queue).contains(key(queue[index])),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let mapped = queue.map_values(|node: SearchNode| key(node));
    assert(mapped[index] == key(queue[index]));
    assert(mapped.contains(key(queue[index])));
}

pub proof fn queue_keys_pop(queue: Seq<SearchNode>)
    requires queue.len() > 0,
    ensures queue_keys(queue) =~= queue_keys(queue.drop_first()).insert(key(queue[0])),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let f = |n: SearchNode| key(n);
    queue_has_key_at(queue, 0);
    assert(queue.map_values(f) =~= seq![key(queue[0])] + queue.drop_first().map_values(f));
    assert forall|selected: Set<nat>| queue_keys(queue).contains(selected)
        == queue_keys(queue.drop_first()).insert(key(queue[0])).contains(selected) by {
        if queue_keys(queue).contains(selected) {
            queue_key_witness(queue, selected);
            let i = choose|i: int| 0 <= i < queue.len() && key(queue[i]) == selected;
            if i > 0 {
                assert(key(queue.drop_first()[i - 1]) == selected);
                queue_has_key_at(queue.drop_first(), i - 1);
                assert(queue_keys(queue.drop_first()).contains(selected));
            }
        } else if queue_keys(queue.drop_first()).contains(selected) {
            queue_key_witness(queue.drop_first(), selected);
            let i = choose|i: int| 0 <= i < queue.drop_first().len() && key(queue.drop_first()[i]) == selected;
            assert(key(queue[i + 1]) == selected);
            queue_has_key_at(queue, i + 1);
        }
    };
}

pub proof fn begin_expansion(c: Catalog, bound: nat, budget: nat, before: SearchState) -> (after: SearchState)
    requires common_inv(c, bound, budget, before), before.queue.len() > 0,
        !node_goal(c, before.queue[0]), before.queue[0].mechanisms.len() < bound,
    ensures expansion_inv(c, bound, budget, before.queue[0], after, 0),
        after.visited == before.visited, after.done == before.done,
        after.queue.len() + 1 == before.queue.len(),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    queue_keys_pop(before.queue);
    let queue = before.queue.drop_first();
    assert forall|i: int| 0 <= i < queue.len() implies node_valid(c, queue[i])
        && before.queue[0].mechanisms.len() <= queue[i].mechanisms.len() <= before.queue[0].mechanisms.len() + 1
        && queue[i].mechanisms.len() <= bound by {
        assert(queue[i] == before.queue[i + 1]);
    };
    assert(ordered(queue));
    assert(before.visited =~= before.done.union(queue_keys(queue)).insert(key(before.queue[0])));
    let after = SearchState { queue, visited: before.visited, done: before.done };
    assert(expansion_inv(c, bound, budget, before.queue[0], after, 0));
    after
}

pub proof fn finish_expansion(c: Catalog, bound: nat, budget: nat, plan: SearchNode, before: SearchState)
    -> (after: SearchState)
    requires expansion_inv(c, bound, budget, plan, before, c.mechanisms.len()),
    ensures common_inv(c, bound, budget, after), after.queue == before.queue,
        after.visited == before.visited, after.done == before.done.insert(key(plan)),
{
    node_representation(c, plan);
    let done = before.done.insert(key(plan));
    assert forall|parent: Set<nat>, child: Set<nat>| done.contains(parent) && parent.len() < bound
        && step(c, parent, child) implies before.visited.contains(child) by {
        if parent == key(plan) {
            let id = choose|id: int| 0 <= id < c.mechanisms.len()
                && !parent.contains(id as nat) && !c.forbidden.contains(id as nat)
                && c.mechanisms[id].requires.subset_of(abilities(c, parent))
                && child == parent.insert(id as nat) && abilities(c, child).subset_of(c.permitted);
            assert(edge_at(c, parent, id));
        }
    };
    assert forall|i: int| 0 <= i < before.queue.len() implies
        (#[trigger] before.queue[i]).mechanisms.len() <= before.queue[0].mechanisms.len() + 1 by {};
    assert forall|selected: Set<nat>| done.contains(selected) implies !goal(c, selected) by {
        if selected == key(plan) {} else { assert(before.done.contains(selected)); }
    };
    let after = SearchState { queue: before.queue, visited: before.visited, done };
    assert(after.visited =~= after.done.union(queue_keys(after.queue)));
    assert(common_inv(c, bound, budget, after));
    after
}

pub proof fn skip_at_mechanism_bound(c: Catalog, bound: nat, budget: nat, before: SearchState)
    -> (after: SearchState)
    requires common_inv(c, bound, budget, before), before.queue.len() > 0,
        !node_goal(c, before.queue[0]), before.queue[0].mechanisms.len() >= bound,
    ensures common_inv(c, bound, budget, after), after.visited == before.visited,
        after.queue.len() + 1 == before.queue.len(),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let plan = before.queue[0];
    node_representation(c, plan);
    queue_keys_pop(before.queue);
    let queue = before.queue.drop_first();
    let done = before.done.insert(key(plan));
    assert(plan.mechanisms.len() == bound);
    assert forall|parent: Set<nat>, child: Set<nat>| done.contains(parent) && parent.len() < bound
        && step(c, parent, child) implies before.visited.contains(child) by {
        assert(parent != key(plan));
    };
    assert forall|i: int| 0 <= i < queue.len() implies node_valid(c, queue[i]) && queue[i].mechanisms.len() <= bound by {
        assert(queue[i] == before.queue[i + 1]);
    };
    assert(ordered(queue));
    assert forall|i: int| 0 <= i < queue.len() implies
        (#[trigger] queue[i]).mechanisms.len() <= queue[0].mechanisms.len() + 1 by {
        assert(queue[0] == before.queue[1]);
    };
    assert forall|selected: Set<nat>| done.contains(selected) implies !goal(c, selected) by {
        if selected == key(plan) {} else { assert(before.done.contains(selected)); }
    };
    let after = SearchState { queue, visited: before.visited, done };
    assert(after.visited =~= done.union(queue_keys(queue)));
    assert(common_inv(c, bound, budget, after));
    after
}

pub open spec fn solution_spec(c: Catalog, bound: nat, plan: SearchNode) -> bool {
    node_valid(c, plan) && node_goal(c, plan) && plan.mechanisms.len() <= bound
        && forall|length: nat, selected: Set<nat>| reachable(c, length, selected) && goal(c, selected)
            ==> plan.mechanisms.len() <= length
}
pub open spec fn no_solution_spec(c: Catalog, bound: nat) -> bool {
    forall|length: nat, selected: Set<nat>| length <= bound ==> !(reachable(c, length, selected) && goal(c, selected))
}

// The outer queue loop, with the production goal/bound guards copied below.
// Each pop decreases queue length; an enqueue increases both visited and queue
// by one. 2*(budget - visited.len()) + queue.len() therefore strictly decreases.
pub proof fn search_queue(c: Catalog, bound: nat, budget: nat, state: SearchState)
    -> (r: Result<SearchNode, SearchFailure>)
    requires common_inv(c, bound, budget, state),
    ensures match r { Ok(plan) => solution_spec(c, bound, plan),
        Err(SearchFailure::NoSolution) => no_solution_spec(c, bound),
        Err(SearchFailure::SearchLimit) => budget < state_space(c.mechanisms.len()).len() },
    decreases 2 * (budget - state.visited.len()) + state.queue.len(),
{
    if state.queue.len() == 0 {
        empty_queue_proves_no_solution(c, bound, budget, state);
        return Err(SearchFailure::NoSolution);
    }
    let plan = state.queue[0];
    if /* PRODUCTION_GOAL_GUARD */ {
        goal_at_head_is_minimum(c, bound, budget, state);
        return Ok(plan);
    }
    if /* PRODUCTION_BOUND_GUARD */ {
        let after = skip_at_mechanism_bound(c, bound, budget, state);
        return search_queue(c, bound, budget, after);
    }
    let remainder = begin_expansion(c, bound, budget, state);
    let expanded = match expand_prefix(c, bound, budget, plan, remainder, c.mechanisms.len()) {
        Ok(expanded) => expanded, Err(cause) => return Err(cause),
    };
    let after = finish_expansion(c, bound, budget, plan, expanded);
    vstd::set_lib::lemma_len_subset(remainder.visited, expanded.visited);
    search_queue(c, bound, budget, after)
}


pub proof fn forbidden_initial_has_no_reachable_state(c: Catalog, length: nat, selected: Set<nat>)
    requires !closure(c.derivations, c.available).subset_of(c.permitted),
    ensures !reachable(c, length, selected),
    decreases length,
{
    if reachable(c, length, selected) {
        if length == 0 {
            effects_empty(c);
            assert(selected == Set::<nat>::empty());
            assert(c.available.union(effects(c, selected)) =~= c.available);
        } else {
            let previous = choose|previous: Set<nat>| reachable(c, (length - 1) as nat, previous)
                && step(c, previous, selected);
            forbidden_initial_has_no_reachable_state(c, (length - 1) as nat, previous);
        }
    }
}

pub proof fn initialize_queue(c: Catalog, bound: nat, budget: nat, initial: ISet<nat>) -> (state: SearchState)
    requires budget > 0, initial == closure(c.derivations, c.available), initial.subset_of(c.permitted),
    ensures common_inv(c, bound, budget, state),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let queue = /* PRODUCTION_INITIAL_QUEUE */;
    let visited = /* PRODUCTION_INITIAL_VISITED */;
    let done = Set::<Set<nat>>::empty();
    effects_empty(c);
    assert(key(queue[0]) == Set::<nat>::empty());
    assert(valid_execution(c, queue[0].mechanisms));
    node_representation(c, queue[0]);
    let empty = Seq::<SearchNode>::empty();
    assert(empty.push(queue[0]) =~= queue);
    assert(queue_keys(empty) =~= Set::<Set<nat>>::empty());
    queue_keys_push(empty, queue[0]);
    assert(queue_keys(queue) =~= visited);
    assert forall|selected: Set<nat>| visited.contains(selected) implies
        reachable(c, selected.len(), selected) && selected.len() <= bound by {
        assert(selected == key(queue[0]));
    };
    assert forall|i: int| 0 <= i < queue.len() implies node_valid(c, queue[i]) && queue[i].mechanisms.len() <= bound by {
        assert(i == 0);
    };
    assert(ordered(queue));
    assert(expanded(c, bound, done, visited));
    let state = SearchState { queue, visited, done };
    assert(visited.len() <= budget);
    assert(visited.contains(Set::<nat>::empty()));
    assert(visited =~= done.union(queue_keys(queue)));
    assert forall|selected: Set<nat>| done.contains(selected) implies !goal(c, selected) by {};
    assert forall|i: int| 0 <= i < queue.len() implies
        (#[trigger] queue[i]).mechanisms.len() <= queue[0].mechanisms.len() + 1 by {};
    assert(common_inv(c, bound, budget, state));
    state
}

// Catalog order is the BTreeMap order after injective ID relabeling to positions.
// Clone/collection views preserve values; the raw duplicate-ID guard is checked
// by the adapter and exercised independently by native tests.
pub proof fn solve_canonical(c: Catalog, bound: nat, budget: nat) -> (r: Result<SearchNode, SearchFailure>)
    ensures match r { Ok(plan) => solution_spec(c, bound, plan),
        Err(SearchFailure::NoSolution) => no_solution_spec(c, bound),
        Err(SearchFailure::SearchLimit) => budget < state_space(c.mechanisms.len()).len() },
{
    if /* PRODUCTION_ZERO_BUDGET_GUARD */ {
        state_space_covers(Set::<nat>::empty(), c.mechanisms.len());
        let singleton = Set::<Set<nat>>::empty().insert(Set::<nat>::empty());
        assert(singleton.subset_of(state_space(c.mechanisms.len())));
        vstd::set_lib::lemma_len_subset(singleton, state_space(c.mechanisms.len()));
        return Err(SearchFailure::SearchLimit);
    }
    let initial = closure(c.derivations, c.available);
    if /* PRODUCTION_INITIAL_PERMISSION_GUARD */ {
        assert forall|length: nat, selected: Set<nat>| length <= bound
            implies !(reachable(c, length, selected) && goal(c, selected)) by {
            forbidden_initial_has_no_reachable_state(c, length, selected);
        };
        return Err(SearchFailure::NoSolution);
    }
    let state = initialize_queue(c, bound, budget, initial);
    search_queue(c, bound, budget, state)
}

pub proof fn full_budget_completeness(c: Catalog, bound: nat, budget: nat)
    -> (r: Result<SearchNode, SearchFailure>)
    requires budget >= two_power(c.mechanisms.len()),
    ensures r.is_ok() == shortest(c, bound).is_some(),
        match r { Ok(plan) => solution_spec(c, bound, plan),
            Err(cause) => cause == SearchFailure::NoSolution && no_solution_spec(c, bound) },
{
    state_space_cardinality(c.mechanisms.len());
    shortest_correct(c, bound);
    let result = solve_canonical(c, bound, budget);
    match result {
        Ok(plan) => {
            node_representation(c, plan);
            assert(succeeds(c, plan.mechanisms.len()));
        },
        Err(SearchFailure::NoSolution) => {
            if let Some(length) = shortest(c, bound) {
                let selected = choose|selected: Set<nat>| reachable(c, length, selected) && goal(c, selected);
                assert(false);
            }
        },
        Err(SearchFailure::SearchLimit) => { assert(false); },
    }
    result
}

} // verus!
