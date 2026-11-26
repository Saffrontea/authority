//! Policy ordering over shared exact resource products.
pub use authority_contracts_model::resources::*;

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
    use authority_planning_core::authority::{self as kernel, Error, Rule};
    if requested.is_empty() {
        return Err(PermissionError::InvalidRequest);
    }
    if rules
        .iter()
        .any(|r| r.policy.revision < 1 || r.region.is_empty())
    {
        return Err(PermissionError::InvalidRule);
    }
    let rules = rules
        .iter()
        .map(|rule| Rule {
            identity: (),
            space: NumericSpace(rule.region.clone()),
            priority: rule.priority,
            deny: rule.effect == Effect::Deny,
            order: rule.policy.policy_id,
            provenance: rule.policy,
        })
        .collect::<Vec<_>>();
    kernel::authorize(&(), &NumericSpace(requested.clone()), &rules, budget).map_err(|error| {
        match error {
            Error::Denied(policy) => PermissionError::ExplicitDeny(policy),
            Error::Uncovered => PermissionError::Uncovered,
            Error::Invalid => PermissionError::InvalidRule,
            Error::Algebra | Error::Budget => PermissionError::PartitionBudget,
        }
    })
}

#[derive(Clone)]
struct NumericSpace<const N: usize>(Region<N>);
impl<const N: usize> authority_planning_core::authority::Space for NumericSpace<N> {
    type Error = ResourceError;
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn intersection(&self, other: &Self) -> Result<Self, ResourceError> {
        self.0.intersection(&other.0).map(Self)
    }
    fn difference(&self, other: &Self) -> Result<Vec<Self>, ResourceError> {
        self.0
            .difference(&other.0)
            .map(|pieces| pieces.into_iter().map(Self).collect())
    }
    fn operation_cost(&self, other: &Self) -> usize {
        self.0.operation_cost(&other.0)
    }
}
