//! Exact authority ordering and policy precedence over application-defined sets.
//! No resource axis, protocol, identifier format, or serialization is built in.

use std::collections::BTreeSet;

/// A non-enumerating set representation. Implementations must return exact,
/// disjoint differences and reject operations exceeding their own bounds.
pub trait Space: Clone {
    type Error;
    fn is_empty(&self) -> bool;
    /// # Errors
    /// Rejects incompatible representations or an exceeded algebra bound.
    fn intersection(&self, other: &Self) -> Result<Self, Self::Error>;
    /// # Errors
    /// Rejects incompatible representations or an exceeded algebra bound.
    fn difference(&self, other: &Self) -> Result<Vec<Self>, Self::Error>;
    fn operation_cost(&self, other: &Self) -> usize;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<P> {
    Invalid,
    Algebra,
    Budget,
    Denied(P),
    Uncovered,
}

/// Identity chooses which spaces are comparable; provenance does not participate
/// in precedence. `order` is an application-defined deterministic rule ID.
#[derive(Debug, Clone)]
pub struct Rule<I, S, O, P> {
    pub identity: I,
    pub space: S,
    pub priority: i32,
    pub deny: bool,
    pub order: O,
    pub provenance: P,
}

struct Budget {
    partitions: usize,
    work: usize,
}

impl Budget {
    fn new(partitions: usize) -> Self {
        Self {
            partitions,
            work: partitions.saturating_mul(64),
        }
    }

    fn subtract<S: Space, P>(&mut self, region: &S, cover: &S) -> Result<Vec<S>, Error<P>> {
        self.work = self
            .work
            .checked_sub(region.operation_cost(cover))
            .ok_or(Error::Budget)?;
        region.difference(cover).map_err(|_| Error::Algebra)
    }

    fn extend<S, P>(&self, next: &mut Vec<S>, pieces: Vec<S>) -> Result<(), Error<P>> {
        if next.len().saturating_add(pieces.len()) > self.partitions {
            return Err(Error::Budget);
        }
        next.extend(pieces);
        Ok(())
    }
}

/// Entire union inclusion, with one work budget across all requested spaces.
///
/// # Errors
/// Rejects empty inputs, invalid algebra operations, or budget exhaustion.
pub fn covered<I: Eq, S: Space>(
    requested: &[(I, S)],
    cover: &[(I, S)],
    limit: usize,
) -> Result<bool, Error<()>> {
    if limit == 0 || requested.len().saturating_add(cover.len()) > limit {
        return Err(Error::Budget);
    }
    if requested.iter().chain(cover).any(|(_, s)| s.is_empty()) {
        return Err(Error::Invalid);
    }
    let mut budget = Budget::new(limit);
    for (identity, space) in requested {
        let mut remaining = vec![space.clone()];
        for (_, covering) in cover.iter().filter(|(id, _)| id == identity) {
            let mut next = Vec::new();
            for region in remaining {
                let pieces = budget.subtract(&region, covering)?;
                budget.extend(&mut next, pieces)?;
            }
            remaining = next;
            if remaining.is_empty() {
                break;
            }
        }
        if !remaining.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Resolve a complete requested space by priority, deny, and deterministic ID.
/// Revisions must stay in provenance; they cannot rank independent policies.
///
/// # Errors
/// Rejects uncovered space, a winning deny, invalid sets and bounded-work failure.
pub fn authorize<I: Eq, S: Space, O: Ord, P: Clone + Ord>(
    identity: &I,
    requested: &S,
    rules: &[Rule<I, S, O, P>],
    limit: usize,
) -> Result<BTreeSet<P>, Error<P>> {
    if requested.is_empty() || rules.iter().any(|r| r.space.is_empty()) {
        return Err(Error::Invalid);
    }
    if limit == 0 || rules.len() > limit {
        return Err(Error::Budget);
    }
    let mut ranked: Vec<_> = rules.iter().filter(|r| &r.identity == identity).collect();
    ranked.sort_by(|a, b| (b.priority, b.deny, &b.order).cmp(&(a.priority, a.deny, &a.order)));
    let mut budget = Budget::new(limit);
    let mut remaining = vec![requested.clone()];
    let mut provenance = BTreeSet::new();
    for rule in ranked {
        let mut next = Vec::new();
        for region in remaining {
            // The same charge bounds intersection as well as subtraction.
            let pieces = budget.subtract(&region, &rule.space)?;
            if !region
                .intersection(&rule.space)
                .map_err(|_| Error::Algebra)?
                .is_empty()
            {
                if rule.deny {
                    return Err(Error::Denied(rule.provenance.clone()));
                }
                provenance.insert(rule.provenance.clone());
            }
            budget.extend(&mut next, pieces)?;
        }
        remaining = next;
        if remaining.is_empty() {
            return Ok(provenance);
        }
    }
    Err(Error::Uncovered)
}

/// A resource axis with exact set operations, independent of its value type.
pub trait Domain: Clone {
    type Error;
    fn is_empty(&self) -> bool;
    /// # Errors
    /// Rejects incompatible representations or an exceeded algebra bound.
    fn intersection(&self, other: &Self) -> Result<Self, Self::Error>;
    /// # Errors
    /// Rejects incompatible representations or an exceeded algebra bound.
    fn difference(&self, other: &Self) -> Result<Self, Self::Error>;
    fn complexity(&self) -> usize;
}

/// Ordered axes form a product. Axis meaning and compatible shapes belong to
/// the catalog's identity, rather than an implicit protocol switch in the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product<D>(pub Vec<D>);

impl<D: Domain> Space for Product<D> {
    type Error = ();
    fn is_empty(&self) -> bool {
        self.0.is_empty() || self.0.iter().any(Domain::is_empty)
    }
    fn intersection(&self, other: &Self) -> Result<Self, ()> {
        if self.0.len() != other.0.len() {
            return Err(());
        }
        self.0
            .iter()
            .zip(&other.0)
            .map(|(a, b)| a.intersection(b).map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
    fn difference(&self, other: &Self) -> Result<Vec<Self>, ()> {
        if self.is_empty() {
            return Ok(Vec::new());
        }
        let overlap = self.intersection(other)?;
        if overlap.is_empty() {
            return Ok(vec![self.clone()]);
        }
        let mut result = Vec::new();
        let mut remainder = self.clone();
        for axis in 0..self.0.len() {
            let mut outside = remainder.clone();
            outside.0[axis] = remainder.0[axis]
                .difference(&other.0[axis])
                .map_err(|_| ())?;
            if !outside.is_empty() {
                result.push(outside);
            }
            remainder.0[axis] = overlap.0[axis].clone();
        }
        Ok(result)
    }
    fn operation_cost(&self, other: &Self) -> usize {
        self.0
            .iter()
            .chain(&other.0)
            .fold(1_usize, |cost, axis| cost.saturating_add(axis.complexity()))
            .saturating_mul(self.0.len().max(other.0.len()))
            .saturating_mul(2)
    }
}
