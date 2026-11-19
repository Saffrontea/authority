//! The current access catalog, separate from the protocol-independent solver.
//!
//! This coarse topology is instantiated with identity/resource/principal/port/time
//! scopes by `scoped::evaluate_ability_scoped` in the production authorization path.
//! The compatibility enums alone do not authorize adapter contract material.

use std::collections::BTreeSet;

use authority_planning_core::{Mechanism, Model, Plan, PlanningError, Request, solve};

use serde::{Deserialize, Serialize};

use crate::{AccessIntent, Capability, Outcome, Route};

/// OSI layers describe reachability; identity and application access are distinct
/// semantic dimensions, rather than being forced into an OSI layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbilityDimension {
    Network,
    Transport,
    Identity,
    Application,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ability {
    MeshMembership,
    NetworkRouteAuthorization,
    SshCredential,
    MtlsCredential,
    TcpAdmission,
    NetworkReachability,
    SshSession,
    ServiceIdentity,
    TcpConnection,
}

impl Ability {
    #[must_use]
    pub const fn dimension(self) -> AbilityDimension {
        match self {
            Self::MeshMembership | Self::NetworkReachability | Self::NetworkRouteAuthorization => {
                AbilityDimension::Network
            }
            Self::TcpConnection | Self::TcpAdmission => AbilityDimension::Transport,
            Self::ServiceIdentity | Self::MtlsCredential | Self::SshCredential => {
                AbilityDimension::Identity
            }
            Self::SshSession => AbilityDimension::Application,
        }
    }

    #[must_use]
    pub const fn effective(self) -> Self {
        match self {
            Self::NetworkRouteAuthorization => Self::NetworkReachability,
            Self::SshCredential => Self::SshSession,
            Self::MtlsCredential => Self::ServiceIdentity,
            Self::TcpAdmission => Self::TcpConnection,
            other => other,
        }
    }

    /// Compatibility bridge from the existing policy vocabulary. This mapping
    /// does not replace scoped policy evaluation and projection binding.
    #[must_use]
    pub const fn permission(self) -> Capability {
        match self {
            Self::MeshMembership => Capability::MeshJoin,
            Self::NetworkReachability | Self::NetworkRouteAuthorization => Capability::NetworkReach,
            Self::SshSession | Self::SshCredential => Capability::SshIssue,
            Self::ServiceIdentity | Self::MtlsCredential => Capability::MtlsIssue,
            Self::TcpConnection | Self::TcpAdmission => Capability::TcpConnect,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMechanism {
    #[serde(rename = "wireguard_peer")]
    WireGuardPeer,
    NetworkRoute,
    SshCertificate,
    MtlsCertificate,
    TcpAdmission,
}

/// Exhaustive subset budget for the current wire-evidence plan bound.
pub const ACCESS_PLANNING_STATES: usize =
    1 << authority_contracts_model::protocol::MAX_PLAN_MECHANISMS_V1;

pub type AccessPlan = Plan<Ability, AccessMechanism>;

#[must_use]
pub fn all_abilities() -> BTreeSet<Ability> {
    BTreeSet::from([
        Ability::NetworkRouteAuthorization,
        Ability::SshCredential,
        Ability::MtlsCredential,
        Ability::TcpAdmission,
        Ability::MeshMembership,
        Ability::NetworkReachability,
        Ability::SshSession,
        Ability::ServiceIdentity,
        Ability::TcpConnection,
    ])
}

/// Finds an authorized realization using the built-in access catalog.
///
/// # Errors
/// Returns an error if no permitted realization exists or the solver fails closed.
pub fn realize(
    intent: &AccessIntent,
    permitted: BTreeSet<Ability>,
) -> Result<AccessPlan, PlanningError> {
    let goals = intent
        .outcomes
        .iter()
        .map(|outcome| match outcome {
            Outcome::Ssh => Ability::SshSession,
            Outcome::NetworkReachability => Ability::NetworkReachability,
            Outcome::MtlsService => Ability::ServiceIdentity,
            Outcome::TcpConnect => Ability::TcpConnection,
        })
        .collect();
    solve(
        &catalog(intent.route),
        &Request {
            goals,
            available: BTreeSet::new(),
            permitted,
            forbidden_mechanisms: BTreeSet::new(),
            max_mechanisms: authority_contracts_model::protocol::MAX_PLAN_MECHANISMS_V1,
            max_states: ACCESS_PLANNING_STATES,
        },
        |_| true,
    )
}

/// Operator-declared endpoint configuration, never a client-provided permission.
/// These describe support/trust, not current network or process liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointFact {
    SshCaTrusted,
    MtlsCaTrusted,
    TcpEnforcement,
    MeshRouteConfigured,
    ExistingRouteConfigured,
}

#[must_use]
pub fn endpoint_facts() -> BTreeSet<EndpointFact> {
    BTreeSet::from([
        EndpointFact::SshCaTrusted,
        EndpointFact::MtlsCaTrusted,
        EndpointFact::TcpEnforcement,
        EndpointFact::MeshRouteConfigured,
        EndpointFact::ExistingRouteConfigured,
    ])
}

pub(crate) fn conditional_catalog(
    route: Route,
) -> authority_planning_core::ConditionalModel<Ability, AccessMechanism, EndpointFact> {
    use authority_planning_core::{Conditional, ConditionalModel, Derivation};
    let route_mechanism = match route {
        Route::MeshRequired => Mechanism {
            id: AccessMechanism::WireGuardPeer,
            requires: BTreeSet::new(),
            provides: BTreeSet::from([Ability::MeshMembership, Ability::NetworkRouteAuthorization]),
        },
        Route::Direct => Mechanism {
            id: AccessMechanism::NetworkRoute,
            requires: BTreeSet::new(),
            provides: BTreeSet::from([Ability::NetworkRouteAuthorization]),
        },
    };
    let mechanisms = [
        route_mechanism,
        Mechanism {
            id: AccessMechanism::SshCertificate,
            requires: BTreeSet::new(),
            provides: BTreeSet::from([Ability::SshCredential]),
        },
        Mechanism {
            id: AccessMechanism::MtlsCertificate,
            requires: BTreeSet::new(),
            provides: BTreeSet::from([Ability::MtlsCredential]),
        },
        Mechanism {
            id: AccessMechanism::TcpAdmission,
            requires: BTreeSet::new(),
            provides: BTreeSet::from([Ability::TcpAdmission]),
        },
    ]
    .into_iter()
    .map(|value| Conditional {
        value,
        requires_facts: BTreeSet::new(),
    })
    .collect();
    let derivations = [
        (
            Ability::NetworkRouteAuthorization,
            Ability::NetworkReachability,
            None,
        ),
        (
            Ability::SshCredential,
            Ability::SshSession,
            Some(EndpointFact::SshCaTrusted),
        ),
        (
            Ability::MtlsCredential,
            Ability::ServiceIdentity,
            Some(EndpointFact::MtlsCaTrusted),
        ),
        (
            Ability::TcpAdmission,
            Ability::TcpConnection,
            Some(EndpointFact::TcpEnforcement),
        ),
    ]
    .into_iter()
    .map(|(input, output, fact)| {
        let mut requires = BTreeSet::from([input]);
        if route == Route::MeshRequired {
            if output == Ability::NetworkReachability {
                requires.insert(Ability::MeshMembership);
            } else {
                requires.insert(Ability::NetworkReachability);
            }
        }
        let fact = if output == Ability::NetworkReachability && route == Route::MeshRequired {
            Some(EndpointFact::MeshRouteConfigured)
        } else {
            fact
        };
        let mut requires_facts: BTreeSet<_> = fact.into_iter().collect();
        if route == Route::Direct {
            requires_facts.insert(EndpointFact::ExistingRouteConfigured);
        }
        Conditional {
            value: Derivation {
                requires,
                provides: BTreeSet::from([output]),
            },
            requires_facts,
        }
    })
    .collect();
    ConditionalModel {
        mechanisms,
        derivations,
    }
}

pub(crate) fn catalog(route: Route) -> Model<Ability, AccessMechanism> {
    conditional_catalog(route).instantiate(&endpoint_facts())
}
