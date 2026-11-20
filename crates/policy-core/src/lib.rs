//! Storage- and adapter-independent access planning and policy evaluation.

use std::collections::{BTreeMap, BTreeSet};

pub mod ability_policy;
pub mod capabilities;
pub mod realization;
pub mod scoped;
pub mod selection;

use realization::{AccessPlan, all_abilities, realize};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ssh,
    #[serde(rename = "network.reachability")]
    NetworkReachability,
    #[serde(rename = "mtls.service")]
    MtlsService,
    #[serde(rename = "tcp.connect")]
    TcpConnect,
}

impl Outcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::NetworkReachability => "network.reachability",
            Self::MtlsService => "mtls.service",
            Self::TcpConnect => "tcp.connect",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    Direct,
    MeshRequired,
}

impl Route {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::MeshRequired => "mesh_required",
        }
    }
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

    #[must_use]
    pub fn tcp(route: Route) -> Self {
        Self {
            outcomes: BTreeSet::from([Outcome::TcpConnect]),
            route,
        }
    }

    #[must_use]
    pub fn infrastructure(route: Route) -> Self {
        Self {
            outcomes: BTreeSet::from([Outcome::Ssh, Outcome::MtlsService]),
            route,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    MeshJoin,
    NetworkReach,
    SshIssue,
    MtlsIssue,
    TcpConnect,
}

impl Capability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MeshJoin => "mesh.join",
            Self::NetworkReach => "network.reach",
            Self::SshIssue => "ssh.issue",
            Self::MtlsIssue => "mtls.issue",
            Self::TcpConnect => "tcp.connect",
        }
    }
}

/// Compatibility view of a realization using the built-in access catalog.
/// Authorization uses `evaluate`, which selects inside the policy envelope.
///
/// # Panics
/// Panics if the built-in catalog cannot realize a supported intent within its
/// exhaustive 32-state budget. This is an internal catalog invariant.
#[must_use]
pub fn plan(intent: &AccessIntent) -> BTreeSet<Capability> {
    realize(intent, all_abilities())
        .expect("the built-in catalog realizes every supported intent within 32 states")
        .abilities
        .into_iter()
        .map(realization::Ability::permission)
        .collect()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    pub policy_id: Uuid,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDecision {
    pub realization: AccessPlan,
    pub intent: AccessIntent,
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
    #[error("stored policy contains invalid capability vocabulary")]
    InvalidPolicy,
    #[error("no authorized realization satisfies the requested intent")]
    NoRealization,
    #[error("planning search budget exhausted; authorization was not established")]
    PlanningSearchLimit,
    #[error("planning catalog contains duplicate mechanism identifiers")]
    InvalidPlanningCatalog,
    #[error("no policy applies to the requested access")]
    NoApplicablePolicy,
    #[error("device identity does not match the authenticated subject")]
    DeviceMismatch,
    #[error("device or target is disabled")]
    Disabled,
    #[error("a required capability is explicitly denied")]
    ExplicitDeny(Capability),
    #[error("no applicable policy grants a required capability")]
    MissingCapability(Capability),
    #[error("a concrete ability is explicitly denied")]
    ExplicitAbilityDeny(realization::Ability),
    #[error("no applicable policy grants a concrete ability")]
    MissingAbility(realization::Ability),
}

impl DenialReason {
    /// Stable machine-readable reason stored in audit events.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidPolicy => "invalid_policy",
            Self::NoApplicablePolicy => "no_applicable_policy",
            Self::NoRealization => "no_authorized_realization",
            Self::PlanningSearchLimit => "planning_search_limit",
            Self::InvalidPlanningCatalog => "invalid_planning_catalog",
            Self::DeviceMismatch => "device_mismatch",
            Self::Disabled => "device_or_target_disabled",
            Self::ExplicitDeny(_) => "explicit_deny",
            Self::MissingCapability(_) => "missing_capability",
            Self::ExplicitAbilityDeny(_) => "explicit_ability_deny",
            Self::MissingAbility(_) => "missing_ability",
        }
    }

    /// Capability involved in a capability-level denial, when applicable.
    #[must_use]
    pub const fn capability(&self) -> Option<Capability> {
        match self {
            Self::ExplicitAbilityDeny(ability) | Self::MissingAbility(ability) => {
                Some(ability.permission())
            }
            Self::ExplicitDeny(capability) | Self::MissingCapability(capability) => {
                Some(*capability)
            }
            Self::InvalidPolicy
            | Self::NoApplicablePolicy
            | Self::NoRealization
            | Self::PlanningSearchLimit
            | Self::InvalidPlanningCatalog
            | Self::DeviceMismatch
            | Self::Disabled => None,
        }
    }
}

impl From<authority_planning_core::PlanningError> for DenialReason {
    fn from(error: authority_planning_core::PlanningError) -> Self {
        match error {
            authority_planning_core::PlanningError::NoSolution => Self::NoRealization,
            authority_planning_core::PlanningError::SearchLimit => Self::PlanningSearchLimit,
            authority_planning_core::PlanningError::DuplicateMechanism => {
                Self::InvalidPlanningCatalog
            }
        }
    }
}

/// Evaluates an immutable snapshot using set operations only.
///
/// For each required capability, the highest-priority applicable rule wins.
/// A deny wins any priority tie; revisions do not rank different policies.
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

    // Evaluate the permission envelope first; no mechanism is selected here.
    let mut sources = BTreeMap::new();
    let mut denials = BTreeMap::new();
    for ability in all_abilities() {
        let capability = ability.permission();
        let winner = snapshot
            .rules
            .iter()
            .filter(|rule| applicable(request, rule) && rule.grants.contains(&capability))
            .max_by_key(|rule| {
                (
                    rule.priority,
                    matches!(rule.effect, Effect::Deny),
                    rule.policy_id,
                )
            });
        match winner {
            Some(rule) if rule.effect == Effect::Allow => {
                sources.insert(
                    capability,
                    PolicyRef {
                        policy_id: rule.policy_id,
                        revision: rule.revision,
                    },
                );
            }
            Some(_) => {
                denials.insert(capability, DenialReason::ExplicitDeny(capability));
            }
            None => {
                denials.insert(capability, DenialReason::MissingCapability(capability));
            }
        }
    }
    let permitted = all_abilities()
        .into_iter()
        .filter(|ability| sources.contains_key(&ability.permission()))
        .collect();
    let realization = realize(&request.intent, permitted).map_err(|error| {
        if error != authority_planning_core::PlanningError::NoSolution {
            return DenialReason::from(error);
        }
        // Preserve existing capability-level diagnostics for the built-in catalog.
        // A search failure itself can never produce an allow decision.
        plan(&request.intent)
            .iter()
            .find_map(|capability| denials.get(capability).cloned())
            .unwrap_or(DenialReason::NoRealization)
    })?;
    let required = realization
        .abilities
        .iter()
        .map(|ability| ability.permission())
        .collect::<BTreeSet<_>>();
    sources.retain(|capability, _| required.contains(capability));
    Ok(AccessDecision {
        realization,
        intent: request.intent.clone(),
        required,
        sources,
    })
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
    fn plans_ssh_and_mtls_over_one_mesh_dependency_closure() {
        assert_eq!(
            plan(&AccessIntent::infrastructure(Route::MeshRequired)),
            BTreeSet::from([
                Capability::MeshJoin,
                Capability::MtlsIssue,
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
        let denial = evaluate(&request, &snapshot).expect_err("explicit deny");
        assert_eq!(denial.code(), "explicit_deny");
        assert_eq!(denial.capability(), Some(Capability::SshIssue));
    }

    #[test]
    fn unneeded_denied_abilities_do_not_reject_or_expand_a_direct_plan() {
        let (request, mut snapshot) = fixture(AccessIntent::ssh(Route::Direct));
        let mut deny_mesh = snapshot.rules[0].clone();
        deny_mesh.policy_id = Uuid::new_v4();
        deny_mesh.effect = Effect::Deny;
        deny_mesh.priority = 1;
        deny_mesh.grants = BTreeSet::from([Capability::MeshJoin]);
        snapshot.rules.push(deny_mesh);
        let decision = evaluate(&request, &snapshot).unwrap();
        assert_eq!(
            decision.realization.mechanisms,
            vec![realization::AccessMechanism::SshCertificate]
        );
        assert_eq!(decision.required, BTreeSet::from([Capability::SshIssue]));
        assert_eq!(decision.sources.len(), 1);
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
