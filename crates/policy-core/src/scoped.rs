//! Scoped authorization and finite normalization for the ability planner.
//!
//! Production evaluates concrete ability rules over every scope atom and time
//! segment. The coarse capability evaluator is a separate model.

use authority_contracts_model::protocol::valid_ttl_seconds;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use authority_planning_core::{
    Derivation, Mechanism, Model, Plan, Request, solve_minimal_authority,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AccessDecision, AccessRequest, Capability, DenialReason, Outcome, PolicyRef, PolicySnapshot,
    evaluate,
    realization::{Ability, AccessMechanism},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessBinding {
    pub domain_id: Uuid,
    pub subject_user_id: Uuid,
    pub device_id: Uuid,
    pub target_node_id: Uuid,
}

impl AccessBinding {
    #[must_use]
    pub fn identity_uri(self) -> String {
        format!(
            "spiffe://authority.local/domain/{}/user/{}/device/{}",
            self.domain_id, self.subject_user_id, self.device_id
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validity {
    pub not_before: i64,
    pub expires_at: i64,
}

impl Validity {
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        other.not_before >= 0
            && self.not_before < self.expires_at
            && other.not_before < other.expires_at
            && self.not_before <= other.not_before
            && other.expires_at <= self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AbilityScope {
    MeshMembership {
        wireguard_public_key: String,
        address: Ipv4Addr,
    },
    NetworkReachability {
        source: Ipv4Addr,
        destination: Ipv4Addr,
    },
    NetworkRouteAuthorization {
        source: Ipv4Addr,
        destination: Ipv4Addr,
    },
    SshSession {
        public_key_fingerprint: String,
        principals: BTreeSet<String>,
        terminal_token_hash: String,
    },
    SshCredential {
        public_key_fingerprint: String,
        principals: BTreeSet<String>,
        terminal_token_hash: String,
    },
    ServiceIdentity {
        client_spki_sha256: String,
        identity_uri: String,
        service_audience: String,
    },
    MtlsCredential {
        client_spki_sha256: String,
        identity_uri: String,
        service_audience: String,
    },
    TcpConnection {
        source: Ipv4Addr,
        destination: Ipv4Addr,
        ports: BTreeSet<u16>,
    },
    TcpAdmission {
        source: Ipv4Addr,
        destination: Ipv4Addr,
        ports: BTreeSet<u16>,
    },
}

impl AbilityScope {
    #[must_use]
    pub const fn kind(&self) -> Ability {
        match self {
            Self::MeshMembership { .. } => Ability::MeshMembership,
            Self::NetworkReachability { .. } => Ability::NetworkReachability,
            Self::NetworkRouteAuthorization { .. } => Ability::NetworkRouteAuthorization,
            Self::SshSession { .. } => Ability::SshSession,
            Self::SshCredential { .. } => Ability::SshCredential,
            Self::ServiceIdentity { .. } => Ability::ServiceIdentity,
            Self::MtlsCredential { .. } => Ability::MtlsCredential,
            Self::TcpConnection { .. } => Ability::TcpConnection,
            Self::TcpAdmission { .. } => Ability::TcpAdmission,
        }
    }

    /// The effective scope corresponding to direct credential/rule authority.
    #[must_use]
    pub fn effective(&self) -> Self {
        match self {
            Self::NetworkRouteAuthorization {
                source,
                destination,
            } => Self::NetworkReachability {
                source: *source,
                destination: *destination,
            },
            Self::SshCredential {
                public_key_fingerprint,
                principals,
                terminal_token_hash,
            } => Self::SshSession {
                public_key_fingerprint: public_key_fingerprint.clone(),
                principals: principals.clone(),
                terminal_token_hash: terminal_token_hash.clone(),
            },
            Self::MtlsCredential {
                client_spki_sha256,
                identity_uri,
                service_audience,
            } => Self::ServiceIdentity {
                client_spki_sha256: client_spki_sha256.clone(),
                identity_uri: identity_uri.clone(),
                service_audience: service_audience.clone(),
            },
            Self::TcpAdmission {
                source,
                destination,
                ports,
            } => Self::TcpConnection {
                source: *source,
                destination: *destination,
                ports: ports.clone(),
            },
            other => other.clone(),
        }
    }

    fn direct(self) -> Self {
        match self {
            Self::NetworkReachability {
                source,
                destination,
            } => Self::NetworkRouteAuthorization {
                source,
                destination,
            },
            Self::SshSession {
                public_key_fingerprint,
                principals,
                terminal_token_hash,
            } => Self::SshCredential {
                public_key_fingerprint,
                principals,
                terminal_token_hash,
            },
            Self::ServiceIdentity {
                client_spki_sha256,
                identity_uri,
                service_audience,
            } => Self::MtlsCredential {
                client_spki_sha256,
                identity_uri,
                service_audience,
            },
            Self::TcpConnection {
                source,
                destination,
                ports,
            } => Self::TcpAdmission {
                source,
                destination,
                ports,
            },
            other => other,
        }
    }

    #[allow(clippy::match_same_arms)] // Separate authority kinds keep value-level proof branches explicit.
    fn contains(&self, requested: &Self) -> bool {
        match (self, requested) {
            (
                Self::SshSession {
                    public_key_fingerprint,
                    principals,
                    terminal_token_hash,
                },
                Self::SshSession {
                    public_key_fingerprint: key,
                    principals: selected,
                    terminal_token_hash: token,
                },
            ) => {
                public_key_fingerprint == key
                    && terminal_token_hash == token
                    && !selected.is_empty()
                    && selected.iter().all(|principal| !principal.is_empty())
                    && selected.is_subset(principals)
            }
            (
                Self::SshCredential {
                    public_key_fingerprint,
                    principals,
                    terminal_token_hash,
                },
                Self::SshCredential {
                    public_key_fingerprint: key,
                    principals: selected,
                    terminal_token_hash: token,
                },
            ) => {
                public_key_fingerprint == key
                    && terminal_token_hash == token
                    && !selected.is_empty()
                    && selected.iter().all(|principal| !principal.is_empty())
                    && selected.is_subset(principals)
            }
            (
                Self::TcpConnection {
                    source,
                    destination,
                    ports,
                },
                Self::TcpConnection {
                    source: from,
                    destination: to,
                    ports: selected,
                },
            ) => {
                source == from
                    && destination == to
                    && !selected.is_empty()
                    && selected.len() <= authority_contracts_model::protocol::MAX_TCP_PORTS
                    && !selected.contains(&0)
                    && selected.is_subset(ports)
            }
            (
                Self::TcpAdmission {
                    source,
                    destination,
                    ports,
                },
                Self::TcpAdmission {
                    source: from,
                    destination: to,
                    ports: selected,
                },
            ) => {
                source == from
                    && destination == to
                    && !selected.is_empty()
                    && selected.len() <= authority_contracts_model::protocol::MAX_TCP_PORTS
                    && !selected.contains(&0)
                    && selected.is_subset(ports)
            }
            _ => self == requested,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedAbility {
    pub binding: AccessBinding,
    pub validity: Validity,
    pub scope: AbilityScope,
}

impl ScopedAbility {
    #[must_use]
    pub fn contains(&self, requested: &Self) -> bool {
        self.binding == requested.binding
            && self.validity.contains(requested.validity)
            && self.scope.contains(&requested.scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation:
        Option<Box<authority_contracts_model::observation::SignedEndpointObservationV1>>,
    pub source_address: Ipv4Addr,
    pub target_address: Ipv4Addr,
    pub registered_wireguard_key: String,
    /// Trusted deployment configuration, not a client-selected audience.
    pub service_audience: String,
    pub environment: BTreeSet<crate::realization::EndpointFact>,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyScope {
    pub ssh_principals: BTreeSet<String>,
    pub tcp_ports: BTreeSet<u16>,
}

#[derive(Debug, Clone, Copy)]
pub struct LifetimeLimits {
    pub ssh_seconds: i64,
    pub network_seconds: i64,
}

impl LifetimeLimits {
    const fn for_ability(self, ability: Ability) -> i64 {
        if matches!(ability, Ability::SshSession | Ability::SshCredential) {
            self.ssh_seconds
        } else {
            self.network_seconds
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestedSsh {
    pub public_key_fingerprint: String,
    /// None selects the winning policy's principals, preserving the existing API.
    pub principals: Option<BTreeSet<String>>,
    pub terminal_token_hash: String,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct RequestedMtls {
    pub client_spki_sha256: String,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct RequestedTcp {
    pub ports: BTreeSet<u16>,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct RequestedNetwork {
    /// None uses the registered device key; Some must match it.
    pub wireguard_public_key: Option<String>,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone, Default)]
pub struct RequestedAccess {
    pub ssh: Option<RequestedSsh>,
    pub mtls: Option<RequestedMtls>,
    pub tcp: Option<RequestedTcp>,
    pub network: Option<RequestedNetwork>,
}

/// Constructed only by successful scoped policy evaluation. Callers cannot
/// replace bindings, lifetimes or key material after authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPlan {
    binding: AccessBinding,
    issued_at: i64,
    policy_reference: String,
    realization: Plan<ScopedAbility, AccessMechanism>,
    evidence: crate::selection::PlanningEvidence,
}

impl AuthorizedPlan {
    // One construction boundary for the invariant consumed by projection.
    // Keep the checks here even though normal instantiation supplies these facts.
    fn new(
        binding: AccessBinding,
        issued_at: i64,
        policy_reference: String,
        realization: Plan<ScopedAbility, AccessMechanism>,
        evidence: crate::selection::PlanningEvidence,
    ) -> Result<Self, ScopeError> {
        if issued_at < 0 {
            return Err(ScopeError::InvalidLifetime);
        }
        if realization
            .abilities
            .iter()
            .any(|ability| ability.binding != binding || ability.validity.not_before != issued_at)
        {
            return Err(ScopeError::InvalidRequest);
        }
        Ok(Self {
            binding,
            issued_at,
            policy_reference,
            realization,
            evidence,
        })
    }

    #[must_use]
    pub const fn evidence(&self) -> &crate::selection::PlanningEvidence {
        &self.evidence
    }

    pub(crate) fn set_selection(
        &mut self,
        options: &crate::selection::SelectionOptions,
        candidates: Vec<crate::selection::CandidateEvaluation>,
    ) {
        self.evidence.route_choice = options.choice;
        self.evidence.deployment = (options.choice == crate::selection::RouteChoice::Automatic)
            .then(|| options.availability.clone());
        self.evidence.candidates = candidates;
    }

    #[must_use]
    pub const fn binding(&self) -> AccessBinding {
        self.binding
    }
    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }
    #[must_use]
    pub fn policy_reference(&self) -> &str {
        &self.policy_reference
    }
    #[must_use]
    pub const fn realization(&self) -> &Plan<ScopedAbility, AccessMechanism> {
        &self.realization
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScopeError {
    #[error("no deployment implementation is available")]
    NoAvailableImplementation,
    #[error("no available implementation satisfies policy and scope constraints")]
    NoAuthorizedImplementation,
    #[error(transparent)]
    Policy(#[from] DenialReason),
    #[error("requested scopes do not match the intent")]
    InvalidRequest,
    #[error("invalid or overflowing authorization lifetime")]
    InvalidLifetime,
    #[error("authorization outlives the winning policy or configured lifetime limit")]
    LifetimeExceeded(Ability),
    #[error("requested ability is outside the winning policy scope")]
    ScopeDenied(Ability),
    #[error("requested WireGuard key does not match the registered device key")]
    WireGuardKeyMismatch,
}

impl ScopeError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoAvailableImplementation => "no_available_implementation",
            Self::NoAuthorizedImplementation => "no_authorized_implementation",
            Self::Policy(reason) => reason.code(),
            Self::InvalidRequest => "invalid_access_scope",
            Self::InvalidLifetime => "invalid_authorization_lifetime",
            Self::LifetimeExceeded(_) => "policy_lifetime_exceeded",
            Self::ScopeDenied(Ability::TcpConnection) => "tcp_port_denied",
            Self::ScopeDenied(Ability::SshSession) => "ssh_principal_denied",
            Self::ScopeDenied(_) => "ability_scope_denied",
            Self::WireGuardKeyMismatch => "wireguard_key_mismatch",
        }
    }

    #[must_use]
    pub const fn capability(&self) -> Option<Capability> {
        match self {
            Self::Policy(reason) => reason.capability(),
            Self::LifetimeExceeded(ability) | Self::ScopeDenied(ability) => {
                Some(ability.permission())
            }
            Self::WireGuardKeyMismatch => Some(Capability::MeshJoin),
            Self::InvalidRequest
            | Self::InvalidLifetime
            | Self::NoAvailableImplementation
            | Self::NoAuthorizedImplementation => None,
        }
    }
}

fn validity(now: i64, ttl: i64) -> Result<Validity, ScopeError> {
    if now < 0 || !valid_ttl_seconds(ttl) {
        return Err(ScopeError::InvalidLifetime);
    }
    Ok(Validity {
        not_before: now,
        expires_at: now.checked_add(ttl).ok_or(ScopeError::InvalidLifetime)?,
    })
}

pub(crate) fn binding(request: &AccessRequest) -> AccessBinding {
    AccessBinding {
        domain_id: request.domain_id,
        subject_user_id: request.subject_user_id,
        device_id: request.device_id,
        target_node_id: request.target_node_id,
    }
}

fn validate_selection(
    decision: &AccessDecision,
    requested: &RequestedAccess,
) -> Result<(), ScopeError> {
    let required = &decision.required;
    if decision.intent.outcomes.is_empty()
        || requested.ssh.is_some() != required.contains(&Capability::SshIssue)
        || requested.mtls.is_some() != required.contains(&Capability::MtlsIssue)
        || requested.tcp.is_some() != required.contains(&Capability::TcpConnect)
        || requested.network.is_some() != required.contains(&Capability::NetworkReach)
    {
        return Err(ScopeError::InvalidRequest);
    }
    Ok(())
}

fn requested_scope(
    kind: Ability,
    request: &AccessRequest,
    requested: &RequestedAccess,
    resources: &NetworkResources,
    policy: &PolicyScope,
) -> Result<(AbilityScope, i64), ScopeError> {
    let (scope, ttl) = match kind.effective() {
        Ability::MeshMembership | Ability::NetworkReachability => {
            let input = requested
                .network
                .as_ref()
                .ok_or(ScopeError::InvalidRequest)?;
            let scope = if kind == Ability::MeshMembership {
                AbilityScope::MeshMembership {
                    wireguard_public_key: input
                        .wireguard_public_key
                        .as_ref()
                        .unwrap_or(&resources.registered_wireguard_key)
                        .clone(),
                    address: resources.source_address,
                }
            } else {
                AbilityScope::NetworkReachability {
                    source: resources.source_address,
                    destination: resources.target_address,
                }
            };
            (scope, input.ttl_seconds)
        }
        Ability::SshSession => {
            let input = requested.ssh.as_ref().ok_or(ScopeError::InvalidRequest)?;
            (
                AbilityScope::SshSession {
                    public_key_fingerprint: input.public_key_fingerprint.clone(),
                    principals: input
                        .principals
                        .as_ref()
                        .unwrap_or(&policy.ssh_principals)
                        .clone(),
                    terminal_token_hash: input.terminal_token_hash.clone(),
                },
                input.ttl_seconds,
            )
        }
        Ability::ServiceIdentity => {
            let input = requested.mtls.as_ref().ok_or(ScopeError::InvalidRequest)?;
            (
                AbilityScope::ServiceIdentity {
                    client_spki_sha256: input.client_spki_sha256.clone(),
                    identity_uri: binding(request).identity_uri(),
                    service_audience: resources.service_audience.clone(),
                },
                input.ttl_seconds,
            )
        }
        Ability::TcpConnection => {
            let input = requested.tcp.as_ref().ok_or(ScopeError::InvalidRequest)?;
            (
                AbilityScope::TcpConnection {
                    source: resources.source_address,
                    destination: resources.target_address,
                    ports: input.ports.clone(),
                },
                input.ttl_seconds,
            )
        }
        _ => return Err(ScopeError::InvalidRequest),
    };
    Ok((
        if kind == kind.effective() {
            scope
        } else {
            scope.direct()
        },
        ttl,
    ))
}

fn permission(
    ability: &ScopedAbility,
    policy: &PolicyScope,
    resources: &NetworkResources,
    validity: Validity,
) -> ScopedAbility {
    let mut grant = ability.clone();
    grant.validity = validity;
    match &mut grant.scope {
        AbilityScope::SshSession { principals, .. }
        | AbilityScope::SshCredential { principals, .. } => {
            principals.clone_from(&policy.ssh_principals);
        }
        AbilityScope::TcpConnection { ports, .. } | AbilityScope::TcpAdmission { ports, .. } => {
            ports.clone_from(&policy.tcp_ports);
        }
        AbilityScope::MeshMembership {
            wireguard_public_key,
            ..
        } => wireguard_public_key.clone_from(&resources.registered_wireguard_key),
        _ => {}
    }
    grant
}

struct ScopeInstantiation {
    abilities: BTreeMap<Ability, ScopedAbility>,
    permissions: BTreeMap<Ability, (ScopedAbility, BTreeSet<PolicyRef>)>,
}

fn scoped_abilities(
    request: &AccessRequest,
    snapshot: &PolicySnapshot,
    decision: &AccessDecision,
    scopes: &BTreeMap<PolicyRef, PolicyScope>,
    requested: &RequestedAccess,
    resources: &NetworkResources,
    limits: LifetimeLimits,
) -> Result<ScopeInstantiation, ScopeError> {
    let mut abilities = BTreeMap::new();
    let mut permissions = BTreeMap::new();
    for kind in crate::realization::all_abilities() {
        let Some(source) = decision.sources.get(&kind.permission()) else {
            continue;
        };
        let rule = snapshot
            .rules
            .iter()
            .find(|rule| rule.policy_id == source.policy_id && rule.revision == source.revision)
            .ok_or(ScopeError::InvalidRequest)?;
        let empty = PolicyScope::default();
        let policy = scopes.get(source).unwrap_or(&empty);
        let (scope, ttl) = requested_scope(kind, request, requested, resources, policy)?;
        let ability = ScopedAbility {
            binding: binding(request),
            validity: validity(request.evaluated_at, ttl)?,
            scope,
        };
        let limit = validity(request.evaluated_at, limits.for_ability(kind))?;
        let permitted_time = Validity {
            not_before: rule.valid_from.unwrap_or(request.evaluated_at),
            expires_at: rule
                .valid_until
                .map_or(limit.expires_at, |end| end.min(limit.expires_at)),
        };
        let grant = permission(&ability, policy, resources, permitted_time);
        if !grant.validity.contains(ability.validity) {
            return Err(ScopeError::LifetimeExceeded(kind.effective()));
        }
        if !grant.contains(&ability) {
            return Err(if kind == Ability::MeshMembership {
                ScopeError::WireGuardKeyMismatch
            } else {
                ScopeError::ScopeDenied(kind.effective())
            });
        }
        permissions.insert(kind, (grant, BTreeSet::from([*source])));
        abilities.insert(kind, ability);
    }
    Ok(ScopeInstantiation {
        abilities,
        permissions,
    })
}

pub(crate) fn instantiate(
    request: &AccessRequest,
    abilities: &BTreeMap<Ability, ScopedAbility>,
    resources: &NetworkResources,
) -> Model<ScopedAbility, AccessMechanism> {
    let catalog = crate::realization::conditional_catalog(request.intent.route)
        .instantiate(&resources.environment);
    let scope = |kinds: &BTreeSet<Ability>| {
        kinds
            .iter()
            .map(|kind| abilities.get(kind).cloned())
            .collect::<Option<BTreeSet<_>>>()
    };
    Model {
        mechanisms: catalog
            .mechanisms
            .into_iter()
            .filter_map(|edge| {
                Some(Mechanism {
                    id: edge.id,
                    requires: scope(&edge.requires)?,
                    provides: scope(&edge.provides)?,
                })
            })
            .collect(),
        derivations: catalog
            .derivations
            .into_iter()
            .filter_map(|edge| {
                let requires = scope(&edge.requires)?;
                let provides = scope(&edge.provides)?;
                if !provides.iter().all(|output| {
                    requires.iter().all(|input| {
                        input.binding == output.binding && input.validity.contains(output.validity)
                    }) && requires
                        .iter()
                        .any(|input| input.scope.effective() == output.scope)
                }) {
                    return None;
                }
                Some(Derivation { requires, provides })
            })
            .collect(),
    }
}

/// Evaluates policy, normalizes permitted scoped abilities, then solves the
/// instantiated catalog. Each returned plan is bound to its complete inputs.
///
/// # Errors
/// Rejects policy denials, scope expansion, expired/overflowing lifetimes, missing
/// adapter inputs and any plan that cannot be realized within the search budget.
pub fn evaluate_scoped(
    request: &AccessRequest,
    snapshot: &PolicySnapshot,
    scopes: &BTreeMap<PolicyRef, PolicyScope>,
    requested: &RequestedAccess,
    resources: &NetworkResources,
    limits: LifetimeLimits,
) -> Result<(AccessDecision, AuthorizedPlan), ScopeError> {
    let decision = evaluate(request, snapshot)?;
    validate_selection(&decision, requested)?;
    let ScopeInstantiation {
        abilities,
        permissions,
    } = scoped_abilities(
        request, snapshot, &decision, scopes, requested, resources, limits,
    )?;
    let goals = request
        .intent
        .outcomes
        .iter()
        .map(|outcome| {
            let kind = match outcome {
                Outcome::Ssh => Ability::SshSession,
                Outcome::NetworkReachability => Ability::NetworkReachability,
                Outcome::MtlsService => Ability::ServiceIdentity,
                Outcome::TcpConnect => Ability::TcpConnection,
            };
            abilities
                .get(&kind)
                .cloned()
                .ok_or(ScopeError::InvalidRequest)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let model = instantiate(request, &abilities, resources);
    let realization = solve_minimal_authority(
        &model,
        &Request {
            goals: goals.clone(),
            available: BTreeSet::new(),
            permitted: abilities.values().cloned().collect(),
            forbidden_mechanisms: BTreeSet::new(),
            max_mechanisms: authority_contracts_model::protocol::MAX_PLAN_MECHANISMS_V1,
            max_states: crate::realization::ACCESS_PLANNING_STATES,
        },
        |_| true,
        crate::ability_policy::authority_leq,
    )
    .map_err(|error| ScopeError::Policy(DenialReason::from(error)))?;
    let proof = crate::selection::plan_evidence(&realization, &model, &goals, &permissions)?;
    let evidence = crate::selection::PlanningEvidence::authorized(request, proof, resources);
    if !evidence.is_consistent() {
        return Err(ScopeError::InvalidRequest);
    }
    let plan = AuthorizedPlan::new(
        binding(request),
        request.evaluated_at,
        decision
            .policies()
            .iter()
            .map(|source| format!("{}@{}", source.policy_id, source.revision))
            .collect::<Vec<_>>()
            .join("."),
        realization,
        evidence,
    )?;
    Ok((decision, plan))
}

fn applicable_ability_rules<'a>(
    request: &AccessRequest,
    snapshot: &'a crate::ability_policy::AbilityPolicySnapshot,
    requested: &RequestedAccess,
) -> Result<Vec<&'a crate::ability_policy::StoredAbilityPolicy>, ScopeError> {
    if snapshot.identity.device_domain_id != request.domain_id
        || snapshot.identity.device_owner_user_id != Some(request.subject_user_id)
    {
        return Err(DenialReason::DeviceMismatch.into());
    }
    if !snapshot.identity.device_active || !snapshot.identity.target_active {
        return Err(DenialReason::Disabled.into());
    }
    let required = crate::plan(&request.intent);
    if request.intent.outcomes.is_empty()
        || requested.ssh.is_some() != required.contains(&Capability::SshIssue)
        || requested.mtls.is_some() != required.contains(&Capability::MtlsIssue)
        || requested.tcp.is_some() != required.contains(&Capability::TcpConnect)
        || requested.network.is_some() != required.contains(&Capability::NetworkReach)
    {
        return Err(ScopeError::InvalidRequest);
    }
    if snapshot.rules.iter().any(|rule| {
        rule.policy.revision < 1
            || !rule.validity.contains(rule.validity)
            || !rule.selector.is_valid()
    }) {
        return Err(DenialReason::InvalidPolicy.into());
    }
    let applicable = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.domain_id == request.domain_id
                && rule.subject_user_id == request.subject_user_id
                && rule.target_node_id == request.target_node_id
                && rule
                    .required_device_id
                    .is_none_or(|device| device == request.device_id)
                && rule.enabled
                && !rule.revoked
        })
        .collect();
    Ok(applicable)
}

fn authorize_ability(
    ability: &ScopedAbility,
    rules: &[crate::ability_policy::AbilityRule],
    has_kind_policy: bool,
) -> Result<BTreeSet<PolicyRef>, ScopeError> {
    use crate::ability_policy::{PermissionError, authorize};
    let kind = ability.scope.kind();
    match authorize(ability, rules) {
        Ok(sources) => Ok(sources),
        Err(PermissionError::InvalidRule) => Err(DenialReason::InvalidPolicy.into()),
        Err(PermissionError::InvalidRequest | PermissionError::PartitionBudget) => {
            Err(ScopeError::InvalidRequest)
        }
        Err(PermissionError::ExplicitDeny(_)) => {
            Err(DenialReason::ExplicitAbilityDeny(kind).into())
        }
        Err(PermissionError::Uncovered) => {
            let mut instant = ability.clone();
            instant.validity.expires_at = instant.validity.not_before + 1;
            Err(if authorize(&instant, rules).is_ok() {
                ScopeError::LifetimeExceeded(kind.effective())
            } else if !has_kind_policy {
                ScopeError::Policy(DenialReason::MissingAbility(kind))
            } else {
                ScopeError::ScopeDenied(kind.effective())
            })
        }
    }
}

struct AbilityInstantiation {
    scoped: ScopeInstantiation,
    denials: BTreeMap<Ability, ScopeError>,
}

fn ability_permissions(
    request: &AccessRequest,
    snapshot: &crate::ability_policy::AbilityPolicySnapshot,
    requested: &RequestedAccess,
    resources: &NetworkResources,
    limits: LifetimeLimits,
) -> Result<AbilityInstantiation, ScopeError> {
    use crate::ability_policy::AbilityRule;
    let applicable = applicable_ability_rules(request, snapshot, requested)?;
    let default_scope = PolicyScope {
        ssh_principals: applicable
            .iter()
            .filter(|rule| rule.effect == crate::Effect::Allow)
            .filter_map(|rule| rule.selector.principals())
            .flatten()
            .cloned()
            .collect(),
        tcp_ports: BTreeSet::new(),
    };
    let mut abilities = BTreeMap::new();
    let mut permissions = BTreeMap::new();
    let mut denials = BTreeMap::new();
    for kind in crate::realization::all_abilities() {
        let present = match kind.effective() {
            Ability::MeshMembership | Ability::NetworkReachability => requested.network.is_some(),
            Ability::SshSession => requested.ssh.is_some(),
            Ability::ServiceIdentity => requested.mtls.is_some(),
            Ability::TcpConnection => requested.tcp.is_some(),
            _ => false,
        };
        if !present {
            continue;
        }
        let (scope, ttl) = requested_scope(kind, request, requested, resources, &default_scope)?;
        let ability = ScopedAbility {
            binding: binding(request),
            validity: validity(request.evaluated_at, ttl)?,
            scope,
        };
        if !validity(request.evaluated_at, limits.for_ability(kind))?.contains(ability.validity) {
            return Err(ScopeError::LifetimeExceeded(kind.effective()));
        }
        if kind == Ability::MeshMembership
            && !matches!(&ability.scope, AbilityScope::MeshMembership { wireguard_public_key, .. } if wireguard_public_key == &resources.registered_wireguard_key)
        {
            return Err(ScopeError::WireGuardKeyMismatch);
        }
        let rules: Vec<_> = applicable
            .iter()
            .filter(|rule| rule.selector.kind() == kind)
            .filter_map(|rule| {
                Some(AbilityRule {
                    policy: rule.policy,
                    priority: rule.priority,
                    effect: rule.effect,
                    authority: ScopedAbility {
                        binding: binding(request),
                        validity: rule.validity,
                        scope: rule.selector.scope(&ability.scope)?,
                    },
                })
            })
            .collect();
        if !ability.contains(&ability) {
            return Err(ScopeError::InvalidRequest);
        }
        // A range selector can have an empty resource intersection. Its policy
        // still exists: distinguish out-of-scope from an entirely missing kind.
        let has_kind_policy = applicable.iter().any(|rule| rule.selector.kind() == kind);
        match authorize_ability(&ability, &rules, has_kind_policy) {
            Ok(sources) => {
                permissions.insert(kind, (ability.clone(), sources));
            }
            Err(error) => {
                denials.insert(kind, error);
            }
        }
        abilities.insert(kind, ability);
    }
    Ok(AbilityInstantiation {
        scoped: ScopeInstantiation {
            abilities,
            permissions,
        },
        denials,
    })
}

/// Production authorization over concrete ability rules. The complete candidate
/// graph is instantiated before permission filtering, so denied derived effects
/// cannot disappear from mandatory closure.
/// # Errors
/// Rejects identity, policy, scope, validity and solver failures.
pub fn evaluate_ability_scoped(
    request: &AccessRequest,
    snapshot: &crate::ability_policy::AbilityPolicySnapshot,
    requested: &RequestedAccess,
    resources: &NetworkResources,
    limits: LifetimeLimits,
) -> Result<(crate::ability_policy::AbilityDecision, AuthorizedPlan), ScopeError> {
    use crate::ability_policy::AbilityDecision;
    let AbilityInstantiation {
        scoped: ScopeInstantiation {
            abilities,
            permissions,
        },
        denials,
    } = ability_permissions(request, snapshot, requested, resources, limits)?;
    let goals: BTreeSet<_> = request
        .intent
        .outcomes
        .iter()
        .map(|outcome| match outcome {
            Outcome::Ssh => Ability::SshSession,
            Outcome::NetworkReachability => Ability::NetworkReachability,
            Outcome::MtlsService => Ability::ServiceIdentity,
            Outcome::TcpConnect => Ability::TcpConnection,
        })
        .map(|kind| {
            abilities
                .get(&kind)
                .cloned()
                .ok_or(ScopeError::InvalidRequest)
        })
        .collect::<Result<_, _>>()?;
    let model = instantiate(request, &abilities, resources);
    let realization = solve_minimal_authority(
        &model,
        &Request {
            goals: goals.clone(),
            available: BTreeSet::new(),
            permitted: permissions
                .keys()
                .map(|kind| abilities[kind].clone())
                .collect(),
            forbidden_mechanisms: BTreeSet::new(),
            max_mechanisms: authority_contracts_model::protocol::MAX_PLAN_MECHANISMS_V1,
            max_states: crate::realization::ACCESS_PLANNING_STATES,
        },
        |_| true,
        crate::ability_policy::authority_leq,
    )
    .map_err(|error| {
        if error == authority_planning_core::PlanningError::NoSolution {
            denials
                .values()
                .next()
                .cloned()
                .unwrap_or(ScopeError::Policy(DenialReason::NoRealization))
        } else {
            ScopeError::Policy(error.into())
        }
    })?;
    let decision = AbilityDecision {
        intent: request.intent.clone(),
        sources: realization
            .abilities
            .iter()
            .map(|ability| {
                (
                    ability.scope.kind(),
                    permissions[&ability.scope.kind()].1.clone(),
                )
            })
            .collect(),
    };
    let proof = crate::selection::plan_evidence(&realization, &model, &goals, &permissions)?;
    let evidence = crate::selection::PlanningEvidence::authorized(request, proof, resources);
    if !evidence.is_consistent() {
        return Err(ScopeError::InvalidRequest);
    }
    let plan = AuthorizedPlan::new(
        binding(request),
        request.evaluated_at,
        decision.policy_reference(),
        realization,
        evidence,
    )?;
    Ok((decision, plan))
}

#[cfg(test)]
mod construction_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn checked_plan_constructor_establishes_projection_invariant(
            issued_at in prop_oneof![any::<i64>(), Just(100_i64)],
            inputs in prop::collection::vec((0_u8..6, any::<i64>(), any::<u128>()), 0..8),
        ) {
            let fixture: serde_json::Value = serde_json::from_str(include_str!(
                "../../../contracts/test-vectors/policy-plan-evaluated-v2/valid/wireguard-mesh.json"
            )).unwrap();
            let evidence: crate::selection::PlanningEvidence = serde_json::from_value(fixture["planning"].clone()).unwrap();
            let binding = evidence.binding;
            let abilities = inputs.iter().map(|(change, timestamp, identity)| {
                let mut selected = binding;
                match change {
                    1 => selected.domain_id = Uuid::from_u128(*identity),
                    2 => selected.subject_user_id = Uuid::from_u128(*identity),
                    3 => selected.device_id = Uuid::from_u128(*identity),
                    4 => selected.target_node_id = Uuid::from_u128(*identity),
                    _ => {},
                }
                ScopedAbility {
                    binding: selected,
                    validity: Validity { not_before: if *change == 5 { *timestamp } else { issued_at }, expires_at: i64::MAX },
                    scope: AbilityScope::NetworkReachability {
                        source: "10.0.0.1".parse().unwrap(), destination: "10.0.0.2".parse().unwrap(),
                    },
                }
            }).collect::<BTreeSet<_>>();
            let expected = issued_at >= 0 && abilities.iter().all(|ability|
                ability.binding == binding && ability.validity.not_before == issued_at);
            let realization = Plan { mechanisms: vec![], abilities };
            let result = AuthorizedPlan::new(binding, issued_at, "policy@1".into(), realization.clone(), evidence.clone());
            prop_assert_eq!(result.is_ok(), expected);
            if let Ok(plan) = result {
                prop_assert_eq!(plan.binding(), binding);
                prop_assert_eq!(plan.issued_at(), issued_at);
                prop_assert_eq!(plan.realization(), &realization);
                prop_assert_eq!(plan.evidence(), &evidence);
                for ability in &plan.realization().abilities {
                    prop_assert_eq!(ability.binding, plan.binding());
                    prop_assert_eq!(ability.validity.not_before, plan.issued_at());
                }
            }
        }
    }
}
