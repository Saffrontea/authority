//! Exact finite unions of half-open integer intervals. Operations never enumerate
//! addresses or ports; IPv4 /0 and the entire port space each occupy one interval.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Inclusive lower and exclusive upper bound. IPv4 endpoints require 33 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    pub start: u64,
    pub end: u64,
}

/// Canonical, sorted, nonempty, disjoint and nonadjacent intervals. Invalid or
/// noncanonical wire representations are rejected rather than silently widened.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct IntervalSet(Vec<Interval>);

impl<'de> Deserialize<'de> for IntervalSet {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let intervals = Vec::<Interval>::deserialize(decoder)?;
        if intervals.len() > MAX_INTERVALS
            || intervals.iter().any(|i| i.start >= i.end)
            || intervals.windows(2).any(|w| w[0].end >= w[1].start)
        {
            return Err(serde::de::Error::custom("noncanonical resource intervals"));
        }
        Ok(Self(intervals))
    }
}

/// A bounded representation, independent of the number of represented points.
pub const MAX_INTERVALS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResourceError {
    #[error("invalid resource interval or CIDR")]
    Invalid,
    #[error("symbolic resource partition budget exhausted")]
    Budget,
}

impl IntervalSet {
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Normalize a bounded collection without enumerating its points.
    ///
    /// # Errors
    /// Rejects reversed/empty intervals and excessive input or fragmentation.
    pub fn new(mut intervals: Vec<Interval>) -> Result<Self, ResourceError> {
        if intervals.len() > MAX_INTERVALS {
            return Err(ResourceError::Budget);
        }
        if intervals.iter().any(|i| i.start >= i.end) {
            return Err(ResourceError::Invalid);
        }
        intervals.sort_unstable();
        let mut result: Vec<Interval> = Vec::new();
        for interval in intervals {
            if let Some(last) = result.last_mut()
                && interval.start <= last.end
            {
                last.end = last.end.max(interval.end);
            } else {
                result.push(interval);
            }
        }
        Ok(Self(result))
    }

    /// Canonical inclusive nonzero TCP port range.
    ///
    /// # Errors
    /// Rejects port zero and reversed bounds.
    pub fn ports(first: u16, last: u16) -> Result<Self, ResourceError> {
        if first == 0 || first > last {
            return Err(ResourceError::Invalid);
        }
        Self::new(vec![Interval {
            start: u64::from(first),
            end: u64::from(last) + 1,
        }])
    }

    /// CIDR requires a canonical network address; host bits must already be zero.
    ///
    /// # Errors
    /// Rejects invalid prefix lengths or noncanonical network addresses.
    pub fn cidr(network: Ipv4Addr, prefix: u8) -> Result<Self, ResourceError> {
        if prefix > 32 {
            return Err(ResourceError::Invalid);
        }
        let start = u64::from(u32::from(network));
        let width = 1_u64 << (32 - prefix);
        if !start.is_multiple_of(width) {
            return Err(ResourceError::Invalid);
        }
        Self::new(vec![Interval {
            start,
            end: start + width,
        }])
    }

    #[must_use]
    pub fn intervals(&self) -> &[Interval] {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn contains_point(&self, point: u64) -> bool {
        let index = self.0.partition_point(|i| i.end <= point);
        self.0.get(index).is_some_and(|i| i.start <= point)
    }

    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        let mut index = 0;
        self.0.iter().all(|interval| {
            while index < other.0.len() && other.0[index].end <= interval.start {
                index += 1;
            }
            other
                .0
                .get(index)
                .is_some_and(|cover| cover.start <= interval.start && interval.end <= cover.end)
        })
    }

    /// # Errors
    /// Rejects a result exceeding the symbolic fragmentation budget.
    pub fn union(&self, other: &Self) -> Result<Self, ResourceError> {
        let mut inputs = self.0.clone();
        inputs.extend_from_slice(&other.0);
        // At most twice the input budget; normalize before checking output size.
        inputs.sort_unstable();
        let mut result: Vec<Interval> = Vec::new();
        for interval in inputs {
            if let Some(last) = result.last_mut()
                && interval.start <= last.end
            {
                last.end = last.end.max(interval.end);
            } else {
                result.push(interval);
            }
        }
        Self::bounded(result)
    }

    /// # Errors
    /// Rejects a result exceeding the symbolic fragmentation budget.
    pub fn intersection(&self, other: &Self) -> Result<Self, ResourceError> {
        let (mut left, mut right) = (0, 0);
        let mut result = Vec::new();
        while left < self.0.len() && right < other.0.len() {
            let (a, b) = (self.0[left], other.0[right]);
            let overlap = Interval {
                start: a.start.max(b.start),
                end: a.end.min(b.end),
            };
            if overlap.start < overlap.end {
                result.push(overlap);
            }
            if a.end < b.end {
                left += 1;
            } else {
                right += 1;
            }
        }
        Self::bounded(result)
    }

    /// # Errors
    /// Rejects a result exceeding the symbolic fragmentation budget.
    pub fn difference(&self, other: &Self) -> Result<Self, ResourceError> {
        let mut result = Vec::new();
        let mut right = 0;
        for a in &self.0 {
            let mut start = a.start;
            while right < other.0.len() && other.0[right].end <= start {
                right += 1;
            }
            let mut cursor = right;
            while cursor < other.0.len() && other.0[cursor].start < a.end {
                let b = other.0[cursor];
                if start < b.start {
                    result.push(Interval {
                        start,
                        end: b.start.min(a.end),
                    });
                }
                start = start.max(b.end);
                if start >= a.end {
                    break;
                }
                cursor += 1;
            }
            if start < a.end {
                result.push(Interval { start, end: a.end });
            }
            if result.len() > MAX_INTERVALS {
                return Err(ResourceError::Budget);
            }
        }
        Self::bounded(result)
    }

    fn bounded(intervals: Vec<Interval>) -> Result<Self, ResourceError> {
        if intervals.len() > MAX_INTERVALS {
            Err(ResourceError::Budget)
        } else {
            Ok(Self(intervals))
        }
    }
}

/// A product of resource and time factors. The axes' meaning belongs to the
/// caller (e.g. source IP, destination IP, destination port, validity). Identity,
/// operation and key binding must be compared before entering this algebra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region<const N: usize>(pub [IntervalSet; N]);

impl<const N: usize> Region<N> {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.iter().any(IntervalSet::is_empty)
    }

    /// # Errors
    /// Rejects symbolic fragmentation beyond the budget.
    pub fn intersection(&self, other: &Self) -> Result<Self, ResourceError> {
        let mut result = self.clone();
        for (axis, other) in result.0.iter_mut().zip(&other.0) {
            *axis = axis.intersection(other)?;
        }
        Ok(result)
    }

    /// Exact disjoint product difference, at most N boxes, without point expansion.
    ///
    /// # Errors
    /// Rejects symbolic fragmentation beyond the budget.
    pub fn difference(&self, other: &Self) -> Result<Vec<Self>, ResourceError> {
        if self.is_empty() {
            return Ok(Vec::new());
        }
        let overlap = self.intersection(other)?;
        if overlap.is_empty() {
            return Ok(vec![self.clone()]);
        }
        let mut result = Vec::new();
        let mut remainder = self.clone();
        for axis in 0..N {
            let mut outside = remainder.clone();
            outside.0[axis] = remainder.0[axis].difference(&other.0[axis])?;
            if !outside.is_empty() {
                result.push(outside);
            }
            remainder.0[axis] = overlap.0[axis].clone();
        }
        Ok(result)
    }
}

/// Subtract a union, fail closed if its exact product decomposition is too large.
///
/// # Errors
/// Never returns a partial result on budget exhaustion.
pub fn uncovered<const N: usize>(
    requested: &Region<N>,
    cover: &[Region<N>],
    budget: usize,
) -> Result<Vec<Region<N>>, ResourceError> {
    if budget == 0 {
        return Err(ResourceError::Budget);
    }
    let mut remaining = if requested.is_empty() {
        Vec::new()
    } else {
        vec![requested.clone()]
    };
    for covering in cover {
        let mut next = Vec::new();
        for region in remaining {
            let pieces = region.difference(covering)?;
            if next.len().saturating_add(pieces.len()) > budget {
                return Err(ResourceError::Budget);
            }
            next.extend(pieces);
        }
        remaining = next;
        if remaining.is_empty() {
            break;
        }
    }
    Ok(remaining)
}

#[derive(Debug, Clone)]
pub struct RegionRule<const N: usize> {
    pub policy: crate::PolicyRef,
    pub priority: i32,
    pub effect: crate::Effect,
    pub region: Region<N>,
}

/// Resolve precedence by subtracting only winning regions. Lower priority rules
/// cannot fill a higher priority deny; revisions never rank distinct policies.
///
/// # Errors
/// Rejects uncovered regions, winning denies and any partition budget exhaustion.
pub fn authorize<const N: usize>(
    requested: &Region<N>,
    rules: &[RegionRule<N>],
    budget: usize,
) -> Result<std::collections::BTreeSet<crate::PolicyRef>, crate::ability_policy::PermissionError> {
    use crate::{Effect, ability_policy::PermissionError};
    if requested.is_empty() {
        return Err(PermissionError::InvalidRequest);
    }
    if rules
        .iter()
        .any(|r| r.policy.revision < 1 || r.region.is_empty())
    {
        return Err(PermissionError::InvalidRule);
    }
    if budget == 0 || rules.len() > budget {
        return Err(PermissionError::PartitionBudget);
    }
    let mut ranked: Vec<_> = rules.iter().collect();
    ranked.sort_by_key(|r| {
        std::cmp::Reverse((r.priority, r.effect == Effect::Deny, r.policy.policy_id))
    });
    let mut remaining = vec![requested.clone()];
    let mut policies = std::collections::BTreeSet::new();
    for rule in ranked {
        let mut next = Vec::new();
        for region in remaining {
            if !region
                .intersection(&rule.region)
                .map_err(|_| PermissionError::PartitionBudget)?
                .is_empty()
            {
                if rule.effect == Effect::Deny {
                    return Err(PermissionError::ExplicitDeny(rule.policy));
                }
                policies.insert(rule.policy);
            }
            let pieces = region
                .difference(&rule.region)
                .map_err(|_| PermissionError::PartitionBudget)?;
            if next.len().saturating_add(pieces.len()) > budget {
                return Err(PermissionError::PartitionBudget);
            }
            next.extend(pieces);
        }
        remaining = next;
        if remaining.is_empty() {
            return Ok(policies);
        }
    }
    Err(PermissionError::Uncovered)
}
