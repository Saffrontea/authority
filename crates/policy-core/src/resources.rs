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
    let mut work = budget.saturating_mul(64);
    let mut policies = std::collections::BTreeSet::new();
    for rule in ranked {
        let mut next = Vec::new();
        for region in remaining {
            work = work
                .checked_sub(region.operation_cost(&rule.region))
                .ok_or(PermissionError::PartitionBudget)?;
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
