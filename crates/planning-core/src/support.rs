//! Recompute live authority from independent roots, never from yesterday's closure.
//!
//! The caller must authenticate observations and hold a consistent storage snapshot.
//! Issuing a credential alone does not establish an installed enforcement root.

use std::collections::{BTreeMap, BTreeSet};

use crate::{ConditionalModel, closure};

/// A revisioned, expiring observation owned by an authority subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation<T, S, O> {
    pub value: T,
    pub source: S,
    pub owner: O,
    pub revision: u64,
    pub not_before: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

impl<T, S: Ord, O: PartialEq> Observation<T, S, O> {
    /// A newer source revision invalidates old observations, even if unexpired.
    #[must_use]
    pub fn active(&self, owner: &O, now: i64, revisions: &BTreeMap<S, u64>) -> bool {
        self.owner == *owner
            && !self.revoked
            && self.not_before >= 0
            && self.not_before <= now
            && now < self.expires_at
            && self.revision > 0
            && revisions.get(&self.source) == Some(&self.revision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAuthority<A, F> {
    pub roots: BTreeSet<A>,
    pub facts: BTreeSet<F>,
    pub abilities: BTreeSet<A>,
}

/// Compute the least fixed point after expiration, revocation or revision changes.
/// Only derivations run: available issuance mechanisms are not evidence of authority.
/// Permission is deliberately not used to filter effects. The planner must reject a
/// closure outside `P(u)`, including effects derived from otherwise permitted roots.
#[must_use]
pub fn recompute<A, M, F, S, O>(
    model: &ConditionalModel<A, M, F>,
    roots: &[Observation<A, S, O>],
    facts: &[Observation<F, S, O>],
    owner: &O,
    now: i64,
    revisions: &BTreeMap<S, u64>,
) -> LiveAuthority<A, F>
where
    A: Ord + Clone,
    M: Clone,
    F: Ord + Clone,
    S: Ord,
    O: PartialEq,
{
    let roots: BTreeSet<_> = roots
        .iter()
        .filter(|root| root.active(owner, now, revisions))
        .map(|root| root.value.clone())
        .collect();
    let facts = facts
        .iter()
        .filter(|fact| fact.active(owner, now, revisions))
        .map(|fact| fact.value.clone())
        .collect();
    let compiled = model.instantiate(&facts);
    let mut abilities = roots.clone();
    closure(&mut abilities, &compiled.derivations);
    LiveAuthority {
        roots,
        facts,
        abilities,
    }
}
