// Uses the independent execution specification from solver.rs. This establishes
// the semantic replacement rule for selected-set memoization, not yet the
// concrete BFS invariant that the first admitted representative is canonical.
verus! {

pub open spec fn lex_less(left: Seq<nat>, right: Seq<nat>) -> bool {
    left.len() == right.len() && exists|at: int| 0 <= at < left.len()
        && left[at] < right[at]
        && forall|i: int| 0 <= i < at ==> left[i] == right[i]
}

pub proof fn lex_irreflexive(order: Seq<nat>)
    ensures !lex_less(order, order),
{}

pub proof fn lex_total(left: Seq<nat>, right: Seq<nat>)
    requires left.len() == right.len(),
    ensures left == right || lex_less(left, right) || lex_less(right, left),
    decreases left.len(),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    if left.len() > 0 {
        let lp = left.drop_last();
        let rp = right.drop_last();
        assert(left =~= lp.push(left.last()));
        assert(right =~= rp.push(right.last()));
        lex_total(lp, rp);
        if lex_less(lp, rp) {
            ordered_children(lp, rp, left.last(), right.last());
        } else if lex_less(rp, lp) {
            ordered_children(rp, lp, right.last(), left.last());
        } else if left.last() < right.last() {
            ordered_children(lp, rp, left.last(), right.last());
        } else if right.last() < left.last() {
            ordered_children(rp, lp, right.last(), left.last());
        } else {
            assert(left =~= right);
        }
    } else {
        assert(left =~= right);
    }
}

pub proof fn lex_transitive(a: Seq<nat>, b: Seq<nat>, c: Seq<nat>)
    requires lex_less(a, b), lex_less(b, c),
    ensures lex_less(a, c),
{
    let ab = choose|at: int| 0 <= at < a.len() && a[at] < b[at]
        && forall|i: int| 0 <= i < at ==> a[i] == b[i];
    let bc = choose|at: int| 0 <= at < b.len() && b[at] < c[at]
        && forall|i: int| 0 <= i < at ==> b[i] == c[i];
    let first = if ab <= bc { ab } else { bc };
    assert(a[first] < c[first]);
    assert(forall|i: int| 0 <= i < first ==> a[i] == c[i]);
}

pub proof fn lex_append(left: Seq<nat>, right: Seq<nat>, suffix: Seq<nat>)
    requires lex_less(left, right),
    ensures lex_less(left + suffix, right + suffix),
{
    let at = choose|at: int| 0 <= at < left.len() && left[at] < right[at]
        && forall|i: int| 0 <= i < at ==> left[i] == right[i];
    assert((left + suffix)[at] < (right + suffix)[at]);
    assert(forall|i: int| 0 <= i < at ==> (left + suffix)[i] == (right + suffix)[i]);
}

// Sorted catalog expansion preserves the order of equal-depth parents, even
// when their appended IDs differ. Equal parents use the catalog's ID order.
pub proof fn ordered_children(left: Seq<nat>, right: Seq<nat>, a: nat, b: nat)
    requires lex_less(left, right) || (left == right && a < b),
    ensures lex_less(left.push(a), right.push(b)),
{
    if lex_less(left, right) {
        let at = choose|at: int| 0 <= at < left.len() && left[at] < right[at]
            && forall|i: int| 0 <= i < at ==> left[i] == right[i];
        assert(left.push(a)[at] < right.push(b)[at]);
        assert(forall|i: int| 0 <= i < at ==> left.push(a)[i] == right.push(b)[i]);
    } else {
        assert(left.push(a)[left.len() as int] < right.push(b)[left.len() as int]);
        assert(forall|i: int| 0 <= i < left.len() ==> left.push(a)[i] == right.push(b)[i]);
    }
}

pub proof fn concatenated_selection(prefix: Seq<nat>, suffix: Seq<nat>)
    ensures (prefix + suffix).to_set() == prefix.to_set().union(suffix.to_set()),
    decreases suffix.len(),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    if suffix.len() == 0 {
        assert(prefix + suffix =~= prefix);
        assert(suffix.to_set() =~= Set::<nat>::empty());
    } else {
        let before = suffix.drop_last();
        let id = suffix.last();
        concatenated_selection(prefix, before);
        assert(suffix =~= before.push(id));
        assert(prefix + suffix =~= (prefix + before).push(id));
        Seq::<nat>::lemma_push_to_set_commute(before, id);
        Seq::<nat>::lemma_push_to_set_commute(prefix + before, id);
        assert(prefix.to_set().union(before.to_set()).insert(id)
            =~= prefix.to_set().union(before.to_set().insert(id)));
    }
}

// Any valid representative of the same selected set permits the same suffix.
// In particular, replacing a discarded path cannot change a prerequisite,
// forbidden-ID check, mandatory effect, or authority bound at a later step.
pub proof fn replace_execution_prefix(c: Catalog, original: Seq<nat>,
    replacement: Seq<nat>, suffix: Seq<nat>)
    requires valid_execution(c, original), valid_execution(c, replacement),
        original.to_set() == replacement.to_set(), valid_execution(c, original + suffix),
    ensures valid_execution(c, replacement + suffix),
        (original + suffix).to_set() == (replacement + suffix).to_set(),
        execute(c, original + suffix) == execute(c, replacement + suffix),
    decreases suffix.len(),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    valid_execution_ids(c, original + suffix);
    concatenated_selection(original, suffix);
    concatenated_selection(replacement, suffix);
    assert((original + suffix).to_set() =~= (replacement + suffix).to_set());
    if suffix.len() == 0 {
        assert(original + suffix =~= original);
        assert(replacement + suffix =~= replacement);
    } else {
        let prefix = suffix.drop_last();
        let old = original + prefix;
        let new = replacement + prefix;
        let id = suffix.last();
        assert((original + suffix).drop_last() =~= old);
        assert((replacement + suffix).drop_last() =~= new);
        assert((original + suffix).last() == id);
        assert((replacement + suffix).last() == id);
        replace_execution_prefix(c, original, replacement, prefix);
        valid_execution_ids(c, old);
        valid_execution_ids(c, new);
        assert forall|i: int| 0 <= i < (replacement + suffix).len()
            implies (replacement + suffix)[i] < c.mechanisms.len() by {
            if i < new.len() { assert((replacement + suffix)[i] == new[i]); }
            else { assert((replacement + suffix)[i] == id); }
        };
        execution_depends_only_on_selected_set(c, original + suffix);
        execution_depends_only_on_selected_set(c, replacement + suffix);
    }
    assert((original + suffix).to_set() =~= (replacement + suffix).to_set());
    valid_execution_ids(c, original + suffix);
    valid_execution_ids(c, replacement + suffix);
    execution_depends_only_on_selected_set(c, original + suffix);
    execution_depends_only_on_selected_set(c, replacement + suffix);
}

// A lexicographically smaller representative dominates every valid continuation
// of the discarded representative, including its arbitrary pure final predicate.
pub proof fn smaller_representative_dominates(c: Catalog, original: Seq<nat>,
    replacement: Seq<nat>, suffix: Seq<nat>)
    requires valid_execution(c, original), valid_execution(c, replacement),
        original.to_set() == replacement.to_set(), lex_less(replacement, original),
        valid_execution(c, original + suffix),
        c.goals.subset_of(execute(c, original + suffix)),
        (c.accepts)((original + suffix).to_set(), execute(c, original + suffix)),
    ensures valid_execution(c, replacement + suffix),
        lex_less(replacement + suffix, original + suffix),
        (replacement + suffix).len() == (original + suffix).len(),
        c.goals.subset_of(execute(c, replacement + suffix)),
        (c.accepts)((replacement + suffix).to_set(), execute(c, replacement + suffix)),
{
    replace_execution_prefix(c, original, replacement, suffix);
    lex_append(replacement, original, suffix);
}

} // verus!
