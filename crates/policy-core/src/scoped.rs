//! Scoped authorization and finite normalization for the ability planner.
//!
//! Policy precedence is resolved before scope containment. Scopes from losing
//! policies are never unioned with those of the winning capability source.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use authority_planning_core::{Mechanism, Model, Plan, Request, solve};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AccessDecision, AccessRequest, Capability, DenialReason, Outcome, PolicyRef, PolicySnapshot,
    evaluate,
    realization::{Ability, AccessMechanism, catalog},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccessBinding {
    pub domain_id: Uuid,
    pub subject_user_id: Uuid,
    pub device_id: Uuid,
    pub target_node_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AbilityScope {
    MeshMembership {
        wireguard_public_key: String,
        address: Ipv4Addr,
    },
    NetworkReachability {
        source: Ipv4Addr,
        destination: Ipv4Addr,
    },
    SshSession {
        public_key_fingerprint: String,
        principals: BTreeSet<String>,
        terminal_token_hash: String,
    },
    ServiceIdentity {
        client_spki_sha256: String,
        identity_uri: String,
        service_audience: String,
    },
    TcpConnection {
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
            Self::SshSession { .. } => Ability::SshSession,
            Self::ServiceIdentity { .. } => Ability::ServiceIdentity,
            Self::TcpConnection { .. } => Ability::TcpConnection,
        }
    }

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
                    && selected.len() <= 64
                    && !selected.contains(&0)
                    && selected.is_subset(ports)
            }
            _ => self == requested,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone)]
pub struct NetworkResources {
    pub source_address: Ipv4Addr,
    pub target_address: Ipv4Addr,
    pub registered_wireguard_key: String,
    /// Trusted deployment configuration, not a client-selected audience.
    pub service_audience: String,
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
        if matches!(ability, Ability::SshSession) {
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
}

impl AuthorizedPlan {
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
            Self::InvalidRequest | Self::InvalidLifetime => None,
        }
    }
}

fn validity(now: i64, ttl: i64) -> Result<Validity, ScopeError> {
    if now < 0 || !(1..=600).contains(&ttl) {
        return Err(ScopeError::InvalidLifetime);
    }
    Ok(Validity {
        not_before: now,
        expires_at: now.checked_add(ttl).ok_or(ScopeError::InvalidLifetime)?,
    })
}

fn binding(request: &AccessRequest) -> AccessBinding {
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
    if requested.ssh.is_some() != required.contains(&Capability::SshIssue)
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
    Ok(match kind {
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
                    identity_uri: format!(
                        "spiffe://authority.local/domain/{}/user/{}/device/{}",
                        request.domain_id, request.subject_user_id, request.device_id
                    ),
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
    })
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
        AbilityScope::SshSession { principals, .. } => {
            principals.clone_from(&policy.ssh_principals);
        }
        AbilityScope::TcpConnection { ports, .. } => ports.clone_from(&policy.tcp_ports),
        AbilityScope::MeshMembership {
            wireguard_public_key,
            ..
        } => wireguard_public_key.clone_from(&resources.registered_wireguard_key),
        _ => {}
    }
    grant
}

fn scoped_abilities(
    request: &AccessRequest,
    snapshot: &PolicySnapshot,
    decision: &AccessDecision,
    scopes: &BTreeMap<PolicyRef, PolicyScope>,
    requested: &RequestedAccess,
    resources: &NetworkResources,
    limits: LifetimeLimits,
) -> Result<BTreeMap<Ability, ScopedAbility>, ScopeError> {
    let mut abilities = BTreeMap::new();
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
            return Err(ScopeError::LifetimeExceeded(kind));
        }
        if !grant.contains(&ability) {
            return Err(if kind == Ability::MeshMembership {
                ScopeError::WireGuardKeyMismatch
            } else {
                ScopeError::ScopeDenied(kind)
            });
        }
        abilities.insert(kind, ability);
    }
    Ok(abilities)
}

fn instantiate(
    request: &AccessRequest,
    abilities: &BTreeMap<Ability, ScopedAbility>,
) -> Model<ScopedAbility, AccessMechanism> {
    let mechanisms = catalog(request.intent.route)
        .mechanisms
        .into_iter()
        .filter_map(|mechanism| {
            Some(Mechanism {
                id: mechanism.id,
                requires: mechanism
                    .requires
                    .iter()
                    .map(|kind| abilities.get(kind).cloned())
                    .collect::<Option<_>>()?,
                provides: mechanism
                    .provides
                    .iter()
                    .map(|kind| abilities.get(kind).cloned())
                    .collect::<Option<_>>()?,
            })
        })
        .collect();
    Model {
        mechanisms,
        derivations: Vec::new(),
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
    let abilities = scoped_abilities(
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
        .collect::<Result<_, _>>()?;
    let realization = solve(
        &instantiate(request, &abilities),
        &Request {
            goals,
            available: BTreeSet::new(),
            permitted: abilities.values().cloned().collect(),
            forbidden_mechanisms: BTreeSet::new(),
            max_mechanisms: 5,
            max_states: 32,
        },
        |_| true,
    )
    .map_err(|_| ScopeError::Policy(DenialReason::NoRealization))?;
    let plan = AuthorizedPlan {
        binding: binding(request),
        issued_at: request.evaluated_at,
        policy_reference: decision
            .policies()
            .iter()
            .map(|source| format!("{}@{}", source.policy_id, source.revision))
            .collect::<Vec<_>>()
            .join("."),
        realization,
    };
    Ok((decision, plan))
}
