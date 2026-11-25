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

/// Resource axes have separate types and enforce their domain at construction
/// and deserialization. Empty is the lattice bottom, not an invalid interval.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct BoundedSet<const MIN: u64, const END: u64>(IntervalSet);
impl<const MIN: u64, const END: u64> Default for BoundedSet<MIN, END> {
    fn default() -> Self {
        Self::empty()
    }
}
pub type PortSet = BoundedSet<1, 65536>;
pub type Ipv4Set = BoundedSet<0, 4_294_967_296>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpResourcesV1 {
    pub source_addresses: Ipv4Set,
    pub destination_addresses: Ipv4Set,
    pub destination_ports: PortSet,
}
impl TcpResourcesV1 {
    /// # Errors
    /// A TCP grant cannot grant an empty resource product.
    pub fn validate(&self) -> Result<(), crate::ContractError> {
        for addresses in [&self.source_addresses, &self.destination_addresses] {
            if addresses.as_host().is_some_and(|address| {
                address.is_unspecified() || address.is_multicast() || address.is_broadcast()
            }) {
                return Err(crate::ContractError::InvalidMeshAddress);
            }
        }
        if self.source_addresses.is_empty() || self.destination_addresses.is_empty() {
            return Err(crate::ContractError::InvalidMeshAddress);
        }
        if self.destination_ports.is_empty() {
            return Err(crate::ContractError::InvalidTcpPorts);
        }
        Ok(())
    }
    #[must_use]
    pub fn region(&self) -> Region<3> {
        Region([
            self.source_addresses.as_set().clone(),
            self.destination_addresses.as_set().clone(),
            self.destination_ports.as_set().clone(),
        ])
    }
    /// # Errors
    /// Emits bounded canonical intervals, without expanding addresses or ports.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, crate::ContractError> {
        self.validate()?;
        let mut result = b"AUTHORITY-TCP-RESOURCES-V1\0".to_vec();
        for set in [
            self.source_addresses.as_set(),
            self.destination_addresses.as_set(),
            self.destination_ports.as_set(),
        ] {
            crate::push_u32(&mut result, set.intervals().len());
            for interval in set.intervals() {
                result.extend_from_slice(&interval.start.to_be_bytes());
                result.extend_from_slice(&interval.end.to_be_bytes());
            }
        }
        Ok(result)
    }
}

impl<'de, const MIN: u64, const END: u64> Deserialize<'de> for BoundedSet<MIN, END> {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let set = IntervalSet::deserialize(decoder)?;
        Self::try_from(set).map_err(serde::de::Error::custom)
    }
}
impl<const MIN: u64, const END: u64> TryFrom<IntervalSet> for BoundedSet<MIN, END> {
    type Error = ResourceError;
    fn try_from(set: IntervalSet) -> Result<Self, Self::Error> {
        if MIN >= END || set.intervals().iter().any(|i| i.start < MIN || i.end > END) {
            return Err(ResourceError::Invalid);
        }
        Ok(Self(set))
    }
}
impl<const MIN: u64, const END: u64> BoundedSet<MIN, END> {
    #[must_use]
    pub const fn empty() -> Self {
        Self(IntervalSet::empty())
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    #[must_use]
    pub fn intervals(&self) -> &[Interval] {
        self.0.intervals()
    }
    #[must_use]
    pub const fn as_set(&self) -> &IntervalSet {
        &self.0
    }
    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }
    #[must_use]
    pub fn contains_point(&self, point: u64) -> bool {
        self.0.contains_point(point)
    }
    /// # Errors
    /// Rejects malformed ranges, points outside the domain and partition overflow.
    pub fn new(intervals: Vec<Interval>) -> Result<Self, ResourceError> {
        Self::try_from(IntervalSet::new(intervals)?)
    }
    /// # Errors
    /// Rejects a result exceeding the exact interval budget.
    pub fn union(&self, other: &Self) -> Result<Self, ResourceError> {
        Ok(Self(self.0.union(&other.0)?))
    }
    /// # Errors
    /// Rejects a result exceeding the exact interval budget.
    pub fn intersection(&self, other: &Self) -> Result<Self, ResourceError> {
        Ok(Self(self.0.intersection(&other.0)?))
    }
    /// # Errors
    /// Rejects a result exceeding the exact interval budget.
    pub fn difference(&self, other: &Self) -> Result<Self, ResourceError> {
        Ok(Self(self.0.difference(&other.0)?))
    }
}
impl PortSet {
    /// # Errors
    /// Inclusive port bounds exclude zero and must be ordered.
    pub fn range(first: u16, last: u16) -> Result<Self, ResourceError> {
        Self::try_from(IntervalSet::ports(first, last)?)
    }
    /// Point syntax is normalized only at the boundary. Core algorithms never
    /// enumerate a range into individual ports.
    ///
    /// # Errors
    /// Rejects port zero or excessive symbolic fragmentation.
    pub fn from_ports(points: &std::collections::BTreeSet<u16>) -> Result<Self, ResourceError> {
        if points.contains(&0) {
            return Err(ResourceError::Invalid);
        }
        let mut intervals: Vec<Interval> = Vec::new();
        for &point in points {
            let point = u64::from(point);
            if let Some(last) = intervals.last_mut()
                && last.end == point
            {
                last.end = point + 1;
            } else {
                intervals.push(Interval {
                    start: point,
                    end: point + 1,
                });
            }
        }
        Self::new(intervals)
    }
    #[must_use]
    pub fn contains(&self, port: &u16) -> bool {
        self.contains_point(u64::from(*port))
    }
}
impl std::str::FromStr for PortSet {
    type Err = ResourceError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut intervals = Vec::new();
        for item in value.split(',') {
            if intervals.len() >= MAX_INTERVALS {
                return Err(ResourceError::Budget);
            }
            let item = item.trim();
            let (first, last) = if let Some((first, last)) = item.split_once('-') {
                (
                    first
                        .trim()
                        .parse::<u16>()
                        .map_err(|_| ResourceError::Invalid)?,
                    last.trim()
                        .parse::<u16>()
                        .map_err(|_| ResourceError::Invalid)?,
                )
            } else {
                let port = item.parse::<u16>().map_err(|_| ResourceError::Invalid)?;
                (port, port)
            };
            if first == 0 || first > last {
                return Err(ResourceError::Invalid);
            }
            intervals.push(Interval {
                start: u64::from(first),
                end: u64::from(last) + 1,
            });
        }
        Self::new(intervals)
    }
}
impl Ipv4Set {
    #[must_use]
    pub fn host(address: Ipv4Addr) -> Self {
        let point = u64::from(u32::from(address));
        Self(IntervalSet(vec![Interval {
            start: point,
            end: point + 1,
        }]))
    }
    /// # Errors
    /// Rejects noncanonical networks or invalid prefix lengths.
    pub fn cidr(network: Ipv4Addr, prefix: u8) -> Result<Self, ResourceError> {
        Self::try_from(IntervalSet::cidr(network, prefix)?)
    }
    #[must_use]
    pub fn as_host(&self) -> Option<Ipv4Addr> {
        if let [interval] = self.intervals()
            && interval.end == interval.start + 1
        {
            return u32::try_from(interval.start).ok().map(Ipv4Addr::from);
        }
        None
    }
}
impl std::str::FromStr for Ipv4Set {
    type Err = ResourceError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some((address, prefix)) = value.split_once('/') {
            Self::cidr(
                address.parse().map_err(|_| ResourceError::Invalid)?,
                prefix.parse().map_err(|_| ResourceError::Invalid)?,
            )
        } else {
            Ok(Self::host(
                value.parse().map_err(|_| ResourceError::Invalid)?,
            ))
        }
    }
}
impl From<Ipv4Addr> for Ipv4Set {
    fn from(address: Ipv4Addr) -> Self {
        Self::host(address)
    }
}
impl From<[u8; 4]> for Ipv4Set {
    fn from(address: [u8; 4]) -> Self {
        Self::host(address.into())
    }
}

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
    pub fn operation_cost(&self, other: &Self) -> usize {
        self.0
            .iter()
            .chain(&other.0)
            .fold(0_usize, |cost, axis| {
                cost.saturating_add(axis.intervals().len())
            })
            .saturating_mul(2)
    }
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
    let mut work = budget.saturating_mul(64);
    let mut remaining = if requested.is_empty() {
        Vec::new()
    } else {
        vec![requested.clone()]
    };
    for covering in cover {
        let mut next = Vec::new();
        for region in remaining {
            work = work
                .checked_sub(region.operation_cost(covering))
                .ok_or(ResourceError::Budget)?;
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
