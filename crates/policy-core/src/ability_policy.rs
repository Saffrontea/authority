//! Permission evaluation over concrete authority, including every scope atom and
//! time segment. Direct and derived abilities have independent policy winners.

use std::collections::BTreeSet;

use crate::{
    Effect, PolicyRef,
    scoped::{AbilityScope, ScopedAbility, Validity},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbilityRule {
    pub policy: PolicyRef,
    pub priority: i32,
    pub effect: Effect,
    pub authority: ScopedAbility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionError {
    InvalidRule,
    InvalidRequest,
    ExplicitDeny(PolicyRef),
    Uncovered,
}

fn atoms(scope: &AbilityScope) -> Vec<AbilityScope> {
    match scope {
        AbilityScope::TcpAdmission { ports, .. } | AbilityScope::TcpConnection { ports, .. } => {
            ports
                .iter()
                .map(|port| {
                    let mut atom = scope.clone();
                    match &mut atom {
                        AbilityScope::TcpAdmission { ports, .. }
                        | AbilityScope::TcpConnection { ports, .. } => {
                            *ports = BTreeSet::from([*port]);
                        }
                        _ => unreachable!(),
                    }
                    atom
                })
                .collect()
        }
        AbilityScope::SshCredential { principals, .. }
        | AbilityScope::SshSession { principals, .. } => principals
            .iter()
            .map(|principal| {
                let mut atom = scope.clone();
                match &mut atom {
                    AbilityScope::SshCredential { principals, .. }
                    | AbilityScope::SshSession { principals, .. } => {
                        *principals = BTreeSet::from([principal.clone()]);
                    }
                    _ => unreachable!(),
                }
                atom
            })
            .collect(),
        _ => vec![scope.clone()],
    }
}

/// Authorize the entire requested interval and scope, returning every winning
/// policy needed as evidence. A narrow deny cannot disappear behind a broad allow.
/// Rules are supplied from one authenticated, locked policy snapshot.
///
/// # Errors
/// Rejects invalid inputs, any uncovered atom/time segment, or a winning deny.
pub fn authorize(
    requested: &ScopedAbility,
    rules: &[AbilityRule],
) -> Result<BTreeSet<PolicyRef>, PermissionError> {
    if !requested.contains(requested) {
        return Err(PermissionError::InvalidRequest);
    }
    if rules
        .iter()
        .any(|rule| rule.policy.revision < 1 || !rule.authority.contains(&rule.authority))
    {
        return Err(PermissionError::InvalidRule);
    }
    let mut boundaries =
        BTreeSet::from([requested.validity.not_before, requested.validity.expires_at]);
    for rule in rules {
        if rule.authority.binding == requested.binding
            && rule.authority.scope.kind() == requested.scope.kind()
        {
            for boundary in [
                rule.authority.validity.not_before,
                rule.authority.validity.expires_at,
            ] {
                if requested.validity.not_before < boundary
                    && boundary < requested.validity.expires_at
                {
                    boundaries.insert(boundary);
                }
            }
        }
    }
    let boundaries: Vec<_> = boundaries.into_iter().collect();
    let mut sources = BTreeSet::new();
    for scope in atoms(&requested.scope) {
        for interval in boundaries.windows(2) {
            let atom = ScopedAbility {
                binding: requested.binding,
                validity: Validity {
                    not_before: interval[0],
                    expires_at: interval[1],
                },
                scope: scope.clone(),
            };
            let winner = rules
                .iter()
                .filter(|rule| rule.authority.contains(&atom))
                .max_by_key(|rule| {
                    (
                        rule.priority,
                        rule.policy.revision,
                        rule.effect == Effect::Deny,
                        rule.policy.policy_id,
                    )
                })
                .ok_or(PermissionError::Uncovered)?;
            if winner.effect == Effect::Deny {
                return Err(PermissionError::ExplicitDeny(winner.policy));
            }
            sources.insert(winner.policy);
        }
    }
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoped::AccessBinding;
    use proptest::prelude::*;
    use uuid::Uuid;

    proptest! {
        #[test]
        fn interval_partition_matches_pointwise_policy_oracle(
            specs in prop::collection::vec((1_u8..4, 10_i64..30, 1_i64..12, any::<bool>(), -2_i32..3), 0..12),
        ) {
            let mut rules: Vec<_> = specs.into_iter().enumerate().map(|(index, (mask, start, duration, deny, priority))| {
                let ports: Vec<_> = [80,443].into_iter().enumerate().filter_map(|(bit, port)| (mask & (1 << bit) != 0).then_some(port)).collect();
                let mut entry = rule(index as u128 + 1, authority(&ports, start, start + duration), if deny { Effect::Deny } else { Effect::Allow });
                entry.priority = priority;
                entry
            }).collect();
            // Independent oracle: enumerate every integer second and requested
            // port; no use of the production partitioning or containment code.
            let mut expected = true;
            for port in [80,443] {
                for time in 10..30 {
                    let winner = rules.iter().filter(|entry| {
                        let AbilityScope::TcpConnection { ports, .. } = &entry.authority.scope else { return false; };
                        ports.contains(&port) && entry.authority.validity.not_before <= time && time < entry.authority.validity.expires_at
                    }).max_by_key(|entry| (entry.priority, entry.policy.revision, entry.effect == Effect::Deny, entry.policy.policy_id));
                    expected &= winner.is_some_and(|entry| entry.effect == Effect::Allow);
                }
            }
            let actual = authorize(&authority(&[80,443],10,30), &rules);
            prop_assert_eq!(actual.is_ok(), expected);
            rules.reverse();
            prop_assert_eq!(authorize(&authority(&[80,443],10,30), &rules), actual);
        }
    }

    fn authority(ports: &[u16], start: i64, end: i64) -> ScopedAbility {
        ScopedAbility {
            binding: AccessBinding {
                domain_id: Uuid::from_u128(1),
                subject_user_id: Uuid::from_u128(2),
                device_id: Uuid::from_u128(3),
                target_node_id: Uuid::from_u128(4),
            },
            validity: Validity {
                not_before: start,
                expires_at: end,
            },
            scope: AbilityScope::TcpConnection {
                source: [10, 0, 0, 1].into(),
                destination: [10, 0, 0, 2].into(),
                ports: ports.iter().copied().collect(),
            },
        }
    }

    fn rule(id: u128, authority: ScopedAbility, effect: Effect) -> AbilityRule {
        AbilityRule {
            policy: PolicyRef {
                policy_id: Uuid::from_u128(id),
                revision: 1,
            },
            priority: 0,
            effect,
            authority,
        }
    }

    #[test]
    fn narrow_deny_overrides_broad_allow_only_for_covered_ports_and_time() {
        let rules = [
            rule(1, authority(&[80, 443], 10, 30), Effect::Allow),
            rule(2, authority(&[443], 15, 20), Effect::Deny),
        ];
        assert!(authorize(&authority(&[80], 10, 30), &rules).is_ok());
        assert!(authorize(&authority(&[443], 10, 15), &rules).is_ok());
        assert_eq!(
            authorize(&authority(&[80, 443], 10, 30), &rules),
            Err(PermissionError::ExplicitDeny(rules[1].policy))
        );
    }

    #[test]
    fn disjoint_rules_can_cover_scope_and_time_without_widening_authority() {
        let rules = [
            rule(1, authority(&[80], 10, 20), Effect::Allow),
            rule(2, authority(&[443], 10, 20), Effect::Allow),
            rule(3, authority(&[80, 443], 20, 30), Effect::Allow),
        ];
        assert_eq!(
            authorize(&authority(&[80, 443], 10, 30), &rules)
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            authorize(&authority(&[80, 443], 10, 31), &rules),
            Err(PermissionError::Uncovered)
        );
        let mut other = authority(&[80], 10, 20);
        other.binding.device_id = Uuid::from_u128(5);
        assert_eq!(authorize(&other, &rules), Err(PermissionError::Uncovered));
        other = authority(&[80], 10, 20);
        if let AbilityScope::TcpConnection {
            source,
            destination,
            ports,
        } = other.scope
        {
            other.scope = AbilityScope::TcpAdmission {
                source,
                destination,
                ports,
            };
        }
        assert_eq!(authorize(&other, &rules), Err(PermissionError::Uncovered));
    }
}
