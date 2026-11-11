//! Storage- and adapter-independent access planning and policy evaluation.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Ssh,
    NetworkReachability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Direct,
    MeshRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessIntent {
    pub outcomes: BTreeSet<Outcome>,
    pub route: Route,
}

impl AccessIntent {
    #[must_use]
    pub fn ssh(route: Route) -> Self {
        Self {
            outcomes: BTreeSet::from([Outcome::Ssh]),
            route,
        }
    }

    #[must_use]
    pub fn network() -> Self {
        Self {
            outcomes: BTreeSet::from([Outcome::NetworkReachability]),
            route: Route::MeshRequired,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    MeshJoin,
    NetworkReach,
    SshIssue,
}

/// Computes the least set of capabilities required to realize an intent.
#[must_use]
pub fn plan(intent: &AccessIntent) -> BTreeSet<Capability> {
    let mut required = BTreeSet::new();
    if intent.outcomes.contains(&Outcome::Ssh) {
        required.insert(Capability::SshIssue);
    }
    if intent.outcomes.contains(&Outcome::NetworkReachability)
        || (intent.outcomes.contains(&Outcome::Ssh) && intent.route == Route::MeshRequired)
    {
        required.insert(Capability::NetworkReach);
    }
    if required.contains(&Capability::NetworkReach) && intent.route == Route::MeshRequired {
        required.insert(Capability::MeshJoin);
    }
    required
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub domain_id: Uuid,
    pub subject_user_id: Uuid,
    pub device_id: Uuid,
    pub target_node_id: Uuid,
    pub evaluated_at: i64,
    pub intent: AccessIntent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFacts {
    pub device_domain_id: Uuid,
    pub device_owner_user_id: Uuid,
    pub device_active: bool,
    pub target_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub policy_id: Uuid,
    pub domain_id: Uuid,
    pub subject_user_id: Uuid,
    pub required_device_id: Option<Uuid>,
    pub target_node_id: Uuid,
    pub enabled: bool,
    pub effect: Effect,
    pub priority: i32,
    pub revision: i64,
    pub grants: BTreeSet<Capability>,
    pub revoked_at: Option<i64>,
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub identity: IdentityFacts,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyRef {
    pub policy_id: Uuid,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub required: BTreeSet<Capability>,
    pub sources: BTreeMap<Capability, PolicyRef>,
}

impl AccessDecision {
    #[must_use]
    pub fn policies(&self) -> BTreeSet<PolicyRef> {
        self.sources.values().copied().collect()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DenialReason {
    #[error("device identity does not match the authenticated subject")]
    DeviceMismatch,
    #[error("device or target is disabled")]
    Disabled,
    #[error("a required capability is explicitly denied")]
    ExplicitDeny(Capability),
    #[error("no applicable policy grants a required capability")]
    MissingCapability(Capability),
}

/// Evaluates an immutable snapshot using set operations only.
///
/// For each required capability, the highest-priority applicable rule wins.
/// A deny wins an exact priority and revision tie.
///
/// # Errors
///
/// Returns a stable reason when identity facts or a required capability deny
/// the requested intent.
pub fn evaluate(
    request: &AccessRequest,
    snapshot: &PolicySnapshot,
) -> Result<AccessDecision, DenialReason> {
    if snapshot.identity.device_domain_id != request.domain_id
        || snapshot.identity.device_owner_user_id != request.subject_user_id
    {
        return Err(DenialReason::DeviceMismatch);
    }
    if !snapshot.identity.device_active || !snapshot.identity.target_active {
        return Err(DenialReason::Disabled);
    }

    let required = plan(&request.intent);
    let mut sources = BTreeMap::new();
    for capability in &required {
        let winner = snapshot
            .rules
            .iter()
            .filter(|rule| applicable(request, rule) && rule.grants.contains(capability))
            .max_by_key(|rule| {
                (
                    rule.priority,
                    rule.revision,
                    matches!(rule.effect, Effect::Deny),
                    rule.policy_id,
                )
            })
            .ok_or(DenialReason::MissingCapability(*capability))?;
        if winner.effect == Effect::Deny {
            return Err(DenialReason::ExplicitDeny(*capability));
        }
        sources.insert(
            *capability,
            PolicyRef {
                policy_id: winner.policy_id,
                revision: winner.revision,
            },
        );
    }
    Ok(AccessDecision { required, sources })
}

fn applicable(request: &AccessRequest, rule: &PolicyRule) -> bool {
    rule.domain_id == request.domain_id
        && rule.subject_user_id == request.subject_user_id
        && rule.target_node_id == request.target_node_id
        && rule
            .required_device_id
            .is_none_or(|device_id| device_id == request.device_id)
        && rule.enabled
        && rule.revoked_at.is_none()
        && rule
            .valid_from
            .is_none_or(|time| time <= request.evaluated_at)
        && rule
            .valid_until
            .is_none_or(|time| time > request.evaluated_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_direct_ssh_without_mesh_capabilities() {
        assert_eq!(
            plan(&AccessIntent::ssh(Route::Direct)),
            BTreeSet::from([Capability::SshIssue])
        );
    }

    #[test]
    fn plans_network_access_as_mesh_join_and_reachability() {
        assert_eq!(
            plan(&AccessIntent::network()),
            BTreeSet::from([Capability::MeshJoin, Capability::NetworkReach])
        );
    }

    #[test]
    fn plans_ssh_over_mesh_as_a_dependency_closure() {
        assert_eq!(
            plan(&AccessIntent::ssh(Route::MeshRequired)),
            BTreeSet::from([
                Capability::MeshJoin,
                Capability::NetworkReach,
                Capability::SshIssue,
            ])
        );
    }

    #[test]
    fn composes_capabilities_from_independent_rules() {
        let (request, mut snapshot) = fixture(AccessIntent::ssh(Route::MeshRequired));
        snapshot.rules[0].grants = BTreeSet::from([Capability::SshIssue]);
        let mut network = snapshot.rules[0].clone();
        network.policy_id = Uuid::new_v4();
        network.grants = BTreeSet::from([Capability::MeshJoin, Capability::NetworkReach]);
        snapshot.rules.push(network);
        let decision = evaluate(&request, &snapshot).expect("composed allow");
        assert_eq!(decision.required.len(), 3);
        assert_eq!(decision.policies().len(), 2);
    }

    #[test]
    fn deny_wins_at_equal_precedence() {
        let (request, mut snapshot) = fixture(AccessIntent::ssh(Route::Direct));
        let mut deny = snapshot.rules[0].clone();
        deny.policy_id = Uuid::new_v4();
        deny.effect = Effect::Deny;
        snapshot.rules.push(deny);
        assert_eq!(
            evaluate(&request, &snapshot),
            Err(DenialReason::ExplicitDeny(Capability::SshIssue))
        );
    }

    fn fixture(intent: AccessIntent) -> (AccessRequest, PolicySnapshot) {
        let domain_id = Uuid::new_v4();
        let subject_user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let target_node_id = Uuid::new_v4();
        (
            AccessRequest {
                domain_id,
                subject_user_id,
                device_id,
                target_node_id,
                evaluated_at: 100,
                intent,
            },
            PolicySnapshot {
                identity: IdentityFacts {
                    device_domain_id: domain_id,
                    device_owner_user_id: subject_user_id,
                    device_active: true,
                    target_active: true,
                },
                rules: vec![PolicyRule {
                    policy_id: Uuid::new_v4(),
                    domain_id,
                    subject_user_id,
                    required_device_id: Some(device_id),
                    target_node_id,
                    enabled: true,
                    effect: Effect::Allow,
                    priority: 0,
                    revision: 1,
                    grants: BTreeSet::from([
                        Capability::MeshJoin,
                        Capability::NetworkReach,
                        Capability::SshIssue,
                    ]),
                    revoked_at: None,
                    valid_from: Some(50),
                    valid_until: Some(150),
                }],
            },
        )
    }
}
