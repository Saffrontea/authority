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
    PartitionBudget,
}

/// Authorize an entire symbolic product. At equal priority deny wins;
/// policy revisions identify provenance and never rank independent policies.
///
/// # Errors
/// Rejects invalid, uncovered or denied authority, including algebra budgets.
pub fn authorize(
    requested: &ScopedAbility,
    rules: &[AbilityRule],
) -> Result<BTreeSet<PolicyRef>, PermissionError> {
    use authority_access_catalog::algebra::authority;
    use authority_planning_core::authority::{self as kernel, Error, Rule};
    let (identity, region) = authority(requested).map_err(|_| PermissionError::InvalidRequest)?;
    let rules = rules
        .iter()
        .map(|rule| {
            if rule.policy.revision < 1 {
                return Err(PermissionError::InvalidRule);
            }
            let (identity, space) =
                authority(&rule.authority).map_err(|_| PermissionError::InvalidRule)?;
            Ok(Rule {
                identity,
                space,
                priority: rule.priority,
                deny: rule.effect == Effect::Deny,
                order: rule.policy.policy_id,
                provenance: rule.policy,
            })
        })
        .collect::<Result<Vec<_>, PermissionError>>()?;
    kernel::authorize(&identity, &region, &rules, crate::resources::MAX_INTERVALS).map_err(
        |error| match error {
            Error::Denied(policy) => PermissionError::ExplicitDeny(policy),
            Error::Uncovered => PermissionError::Uncovered,
            Error::Invalid => PermissionError::InvalidRule,
            Error::Algebra | Error::Budget => PermissionError::PartitionBudget,
        },
    )
}

/// Exact semantic inclusion of unions, with no resource-point enumeration.
#[must_use]
pub fn authority_leq(left: &BTreeSet<ScopedAbility>, right: &BTreeSet<ScopedAbility>) -> bool {
    authority_leq_checked(left, right).unwrap_or(false)
}

/// # Errors
/// Callers must reject the whole selection on invalid scope or budget failure.
pub fn authority_leq_checked(
    left: &BTreeSet<ScopedAbility>,
    right: &BTreeSet<ScopedAbility>,
) -> Result<bool, crate::resources::ResourceError> {
    use crate::resources::{MAX_INTERVALS, ResourceError};
    use authority_access_catalog::algebra::authority;
    use authority_planning_core::authority::{Error, covered};
    let left = left.iter().map(authority).collect::<Result<Vec<_>, _>>()?;
    let right = right.iter().map(authority).collect::<Result<Vec<_>, _>>()?;
    covered(&left, &right, MAX_INTERVALS).map_err(|error| match error {
        Error::Invalid => ResourceError::Invalid,
        _ => ResourceError::Budget,
    })
}

/// Key choice is explicit policy: request possession or an exact pinned key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyBinding {
    Request,
    Pinned { value: String },
}

impl KeyBinding {
    fn resolve(&self, requested: &str) -> String {
        match self {
            Self::Request => requested.to_owned(),
            Self::Pinned { value } => value.clone(),
        }
    }
}

/// Resource and operation selectors stored as typed JSON, never capability strings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AbilitySelector {
    MeshMembership {
        wireguard_public_key: String,
        address: std::net::Ipv4Addr,
    },
    NetworkRouteAuthorization {
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
    },
    NetworkReachability {
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
    },
    SshCredential {
        principals: BTreeSet<String>,
        key: KeyBinding,
        terminal_token: KeyBinding,
    },
    SshSession {
        principals: BTreeSet<String>,
        key: KeyBinding,
        terminal_token: KeyBinding,
    },
    MtlsCredential {
        service_audience: String,
        key: KeyBinding,
    },
    ServiceIdentity {
        service_audience: String,
        key: KeyBinding,
    },
    TcpAdmission {
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        ports: BTreeSet<u16>,
    },
    TcpConnection {
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        ports: BTreeSet<u16>,
    },
    /// Symbolic policy resources. They are intersected with the concrete request;
    /// a broad policy never widens the authority projected into an adapter grant.
    TcpAdmissionRange {
        source: crate::resources::IntervalSet,
        destination: crate::resources::IntervalSet,
        ports: crate::resources::IntervalSet,
    },
    TcpConnectionRange {
        source: crate::resources::IntervalSet,
        destination: crate::resources::IntervalSet,
        ports: crate::resources::IntervalSet,
    },
}

impl AbilitySelector {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let key_valid = |key: &KeyBinding| match key {
            KeyBinding::Request => true,
            KeyBinding::Pinned { value } => !value.is_empty(),
        };
        match self {
            Self::SshCredential {
                principals,
                key,
                terminal_token,
            }
            | Self::SshSession {
                principals,
                key,
                terminal_token,
            } => {
                !principals.is_empty()
                    && principals.iter().all(|principal| !principal.is_empty())
                    && key_valid(key)
                    && key_valid(terminal_token)
            }
            Self::TcpAdmission { ports, .. } | Self::TcpConnection { ports, .. } => {
                !ports.is_empty()
                    && ports.len() <= authority_contracts_model::protocol::MAX_TCP_PORTS
                    && !ports.contains(&0)
            }
            Self::TcpAdmissionRange {
                source,
                destination,
                ports,
            }
            | Self::TcpConnectionRange {
                source,
                destination,
                ports,
            } => {
                let within = |set: &crate::resources::IntervalSet, first, end| {
                    !set.is_empty()
                        && set
                            .intervals()
                            .iter()
                            .all(|i| first <= i.start && i.end <= end)
                };
                within(source, 0, 1_u64 << 32)
                    && within(destination, 0, 1_u64 << 32)
                    && within(ports, 1, 65536)
            }
            Self::MtlsCredential {
                service_audience,
                key,
            }
            | Self::ServiceIdentity {
                service_audience,
                key,
            } => !service_audience.is_empty() && key_valid(key),
            Self::MeshMembership {
                wireguard_public_key,
                ..
            } => !wireguard_public_key.is_empty(),
            Self::NetworkRouteAuthorization { .. } | Self::NetworkReachability { .. } => true,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> crate::realization::Ability {
        use crate::realization::Ability;
        match self {
            Self::MeshMembership { .. } => Ability::MeshMembership,
            Self::NetworkRouteAuthorization { .. } => Ability::NetworkRouteAuthorization,
            Self::NetworkReachability { .. } => Ability::NetworkReachability,
            Self::SshCredential { .. } => Ability::SshCredential,
            Self::SshSession { .. } => Ability::SshSession,
            Self::MtlsCredential { .. } => Ability::MtlsCredential,
            Self::ServiceIdentity { .. } => Ability::ServiceIdentity,
            Self::TcpAdmission { .. } | Self::TcpAdmissionRange { .. } => Ability::TcpAdmission,
            Self::TcpConnection { .. } | Self::TcpConnectionRange { .. } => Ability::TcpConnection,
        }
    }

    pub(crate) fn principals(&self) -> Option<&BTreeSet<String>> {
        match self {
            Self::SshCredential { principals, .. } | Self::SshSession { principals, .. } => {
                Some(principals)
            }
            _ => None,
        }
    }

    /// Resolve only explicitly request-bound key material. Resources and authority
    /// kinds always come from the stored selector, even for deny rules.
    pub(crate) fn scope(&self, requested: &AbilityScope) -> Option<AbilityScope> {
        if matches!(
            self,
            Self::TcpAdmissionRange { .. } | Self::TcpConnectionRange { .. }
        ) {
            return self.range_scope(requested);
        }
        Some(match (self, requested) {
            (
                Self::MeshMembership {
                    wireguard_public_key,
                    address,
                },
                _,
            ) => AbilityScope::MeshMembership {
                wireguard_public_key: wireguard_public_key.clone(),
                address: *address,
            },
            (
                Self::NetworkRouteAuthorization {
                    source,
                    destination,
                },
                _,
            ) => AbilityScope::NetworkRouteAuthorization {
                source: (*source).into(),
                destination: (*destination).into(),
            },
            (
                Self::NetworkReachability {
                    source,
                    destination,
                },
                _,
            ) => AbilityScope::NetworkReachability {
                source: (*source).into(),
                destination: (*destination).into(),
            },
            (
                Self::TcpAdmission {
                    source,
                    destination,
                    ports,
                },
                _,
            ) => AbilityScope::TcpAdmission {
                source: (*source).into(),
                destination: (*destination).into(),
                ports: crate::resources::PortSet::from_ports(ports).ok()?,
            },
            (
                Self::TcpConnection {
                    source,
                    destination,
                    ports,
                },
                _,
            ) => AbilityScope::TcpConnection {
                source: (*source).into(),
                destination: (*destination).into(),
                ports: crate::resources::PortSet::from_ports(ports).ok()?,
            },
            _ => return self.key_scope(requested),
        })
    }

    fn range_scope(&self, requested: &AbilityScope) -> Option<AbilityScope> {
        use crate::resources::{Ipv4Set, PortSet};
        let (source, destination, ports) = match self {
            Self::TcpAdmissionRange {
                source,
                destination,
                ports,
            }
            | Self::TcpConnectionRange {
                source,
                destination,
                ports,
            } => (
                Ipv4Set::try_from(source.clone()).ok()?,
                Ipv4Set::try_from(destination.clone()).ok()?,
                PortSet::try_from(ports.clone()).ok()?,
            ),
            _ => return None,
        };
        Some(match (self, requested) {
            (Self::TcpAdmissionRange { .. }, AbilityScope::TcpAdmission { .. }) => {
                AbilityScope::TcpAdmission {
                    source,
                    destination,
                    ports,
                }
            }
            (Self::TcpConnectionRange { .. }, AbilityScope::TcpConnection { .. }) => {
                AbilityScope::TcpConnection {
                    source,
                    destination,
                    ports,
                }
            }
            _ => return None,
        })
    }

    fn key_scope(&self, requested: &AbilityScope) -> Option<AbilityScope> {
        Some(match (self, requested) {
            (
                Self::SshCredential {
                    principals,
                    key,
                    terminal_token,
                },
                AbilityScope::SshCredential {
                    public_key_fingerprint,
                    terminal_token_hash,
                    ..
                },
            ) => AbilityScope::SshCredential {
                public_key_fingerprint: key.resolve(public_key_fingerprint),
                terminal_token_hash: terminal_token.resolve(terminal_token_hash),
                principals: principals.clone(),
            },
            (
                Self::SshSession {
                    principals,
                    key,
                    terminal_token,
                },
                AbilityScope::SshSession {
                    public_key_fingerprint,
                    terminal_token_hash,
                    ..
                },
            ) => AbilityScope::SshSession {
                public_key_fingerprint: key.resolve(public_key_fingerprint),
                terminal_token_hash: terminal_token.resolve(terminal_token_hash),
                principals: principals.clone(),
            },
            (
                Self::MtlsCredential {
                    service_audience,
                    key,
                },
                AbilityScope::MtlsCredential {
                    client_spki_sha256,
                    identity_uri,
                    ..
                },
            ) => AbilityScope::MtlsCredential {
                client_spki_sha256: key.resolve(client_spki_sha256),
                identity_uri: identity_uri.clone(),
                service_audience: service_audience.clone(),
            },
            (
                Self::ServiceIdentity {
                    service_audience,
                    key,
                },
                AbilityScope::ServiceIdentity {
                    client_spki_sha256,
                    identity_uri,
                    ..
                },
            ) => AbilityScope::ServiceIdentity {
                client_spki_sha256: key.resolve(client_spki_sha256),
                identity_uri: identity_uri.clone(),
                service_audience: service_audience.clone(),
            },
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAbilityPolicy {
    pub policy: PolicyRef,
    pub domain_id: uuid::Uuid,
    pub subject_user_id: uuid::Uuid,
    pub required_device_id: Option<uuid::Uuid>,
    pub target_node_id: uuid::Uuid,
    pub enabled: bool,
    pub revoked: bool,
    pub priority: i32,
    pub effect: Effect,
    pub validity: Validity,
    pub selector: AbilitySelector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbilityPolicySnapshot {
    pub identity: crate::IdentityFacts,
    pub rules: Vec<StoredAbilityPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbilityDecision {
    pub intent: crate::AccessIntent,
    pub sources: std::collections::BTreeMap<crate::realization::Ability, BTreeSet<PolicyRef>>,
}

impl AbilityDecision {
    /// Fixed-size commitment to the complete, canonically ordered policy set.
    #[must_use]
    pub fn policy_reference(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"authority:ability-policy-set:v1\0");
        for policy in self.policies() {
            digest.update(policy.policy_id.as_bytes());
            digest.update(policy.revision.to_be_bytes());
        }
        format!("ability-policy-sha256:{:x}", digest.finalize())
    }

    #[must_use]
    pub fn policies(&self) -> BTreeSet<PolicyRef> {
        self.sources.values().flatten().copied().collect()
    }
}

/// Evaluate trusted deployment alternatives using concrete ability policies.
/// # Errors
/// Returns a fail-closed denial and replayable candidate evidence.
pub fn evaluate_selection(
    request: &crate::AccessRequest,
    snapshot: &AbilityPolicySnapshot,
    requested: &crate::scoped::RequestedAccess,
    resources: &crate::scoped::NetworkResources,
    limits: crate::scoped::LifetimeLimits,
    options: &crate::selection::SelectionOptions,
) -> Result<(AbilityDecision, crate::scoped::AuthorizedPlan), crate::selection::SelectionFailure> {
    crate::selection::evaluate_with(
        request,
        requested,
        resources,
        options,
        |candidate, inputs| {
            crate::scoped::evaluate_ability_scoped(candidate, snapshot, inputs, resources, limits)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoped::AccessBinding;
    use proptest::prelude::*;
    use uuid::Uuid;

    #[test]
    fn authority_union_covers_split_resources_and_time_but_never_fills_gaps() {
        let whole = BTreeSet::from([authority(&[80, 443], 10, 30)]);
        let cover = BTreeSet::from([
            authority(&[80], 10, 20),
            authority(&[80], 20, 30),
            authority(&[443], 10, 30),
        ]);
        assert!(authority_leq(&whole, &cover));
        assert!(authority_leq(&cover, &whole));
        let hole = BTreeSet::from([
            authority(&[80], 10, 19),
            authority(&[80], 20, 30),
            authority(&[443], 10, 30),
        ]);
        assert!(!authority_leq(&whole, &hole));
        assert!(authority_leq(&hole, &whole));
        assert!(!authority_leq(
            &BTreeSet::from([authority(&[22], 10, 30)]),
            &whole
        ));
    }

    proptest! {
    #[test]
        fn same_priority_deny_wins_independently_of_policy_revisions(
            allow_revision in 1_i64..=i64::MAX, deny_revision in 1_i64..=i64::MAX,
            priority in any::<i32>(),
        ) {
            let mut allow=rule(1,authority(&[443],10,30),Effect::Allow);
            let mut deny=rule(2,authority(&[443],10,30),Effect::Deny);
            allow.priority=priority;deny.priority=priority;
            allow.policy.revision=allow_revision;deny.policy.revision=deny_revision;
            let expected=Err(PermissionError::ExplicitDeny(deny.policy));
            prop_assert_eq!(authorize(&authority(&[443],10,30),&[allow.clone(),deny.clone()]),expected.clone());
            prop_assert_eq!(authorize(&authority(&[443],10,30),&[deny,allow]),expected);
        }
    }

    #[test]
    fn stored_selectors_require_explicit_key_binding_and_preserve_pins() {
        let requested = AbilityScope::SshCredential {
            public_key_fingerprint: "request-key".into(),
            principals: BTreeSet::from(["deploy".into()]),
            terminal_token_hash: "request-token".into(),
        };
        let selector = AbilitySelector::SshCredential {
            principals: BTreeSet::from(["deploy".into()]),
            key: KeyBinding::Pinned {
                value: "pinned-key".into(),
            },
            terminal_token: KeyBinding::Request,
        };
        assert_eq!(
            selector.scope(&requested),
            Some(AbilityScope::SshCredential {
                public_key_fingerprint: "pinned-key".into(),
                principals: BTreeSet::from(["deploy".into()]),
                terminal_token_hash: "request-token".into(),
            })
        );
        assert!(selector.scope(&requested.effective()).is_none());
        for invalid in [
            serde_json::json!({"kind":"ssh_credential", "principals":["deploy"]}),
            serde_json::json!({"kind":"ssh_credential", "principals":["deploy"], "key":{"mode":"request"}, "terminal_token":{"mode":"request"}, "future":"ignored"}),
            serde_json::json!({"kind":"future_ability"}),
        ] {
            assert!(serde_json::from_value::<AbilitySelector>(invalid).is_err());
        }
    }

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
                    let applicable: Vec<_> = rules.iter().filter(|entry| {
                        let AbilityScope::TcpConnection { ports, .. } = &entry.authority.scope else { return false; };
                        ports.contains(&port) && entry.authority.validity.not_before <= time && time < entry.authority.validity.expires_at
                    }).collect();
                    let highest = applicable.iter().map(|entry| entry.priority).max();
                    expected &= highest.is_some() && !applicable.iter().any(|entry| Some(entry.priority) == highest && entry.effect == Effect::Deny);
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
                ports: crate::resources::PortSet::from_ports(&ports.iter().copied().collect())
                    .unwrap(),
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
