//! The current access catalog, separate from the protocol-independent solver.
//!
//! Each invocation is scoped to one authenticated request's subject, device and
//! target. Port/principal/TTL restrictions are still checked by the existing API;
//! these enum values do not authorize arbitrary ports, identities or resources.

use std::collections::BTreeSet;

use authority_planning_core::{Mechanism, Model, Plan, PlanningError, Request, solve};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ability {
    MeshMembership,
    NetworkReachability,
    SshSession,
    ServiceIdentity,
    TcpConnection,
}

impl Ability {
    #[must_use]
    pub const fn dimension(self) -> AbilityDimension {
        match self {
            Self::MeshMembership | Self::NetworkReachability => AbilityDimension::Network,
            Self::TcpConnection => AbilityDimension::Transport,
            Self::ServiceIdentity => AbilityDimension::Identity,
            Self::SshSession => AbilityDimension::Application,
        }
    }

    /// Compatibility bridge from the existing policy vocabulary. This mapping
    /// does not replace the API's scoped principal, port and lifetime checks.
    #[must_use]
    pub const fn permission(self) -> Capability {
        match self {
            Self::MeshMembership => Capability::MeshJoin,
            Self::NetworkReachability => Capability::NetworkReach,
            Self::SshSession => Capability::SshIssue,
            Self::ServiceIdentity => Capability::MtlsIssue,
            Self::TcpConnection => Capability::TcpConnect,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessMechanism {
    WireGuardPeer,
    NetworkRoute,
    SshCertificate,
    MtlsCertificate,
    TcpAdmission,
}

pub type AccessPlan = Plan<Ability, AccessMechanism>;

#[must_use]
pub fn all_abilities() -> BTreeSet<Ability> {
    BTreeSet::from([
        Ability::MeshMembership,
        Ability::NetworkReachability,
        Ability::SshSession,
        Ability::ServiceIdentity,
        Ability::TcpConnection,
    ])
}

fn catalog(route: Route) -> Model<Ability, AccessMechanism> {
    let mesh = route == Route::MeshRequired;
    let service_requires = if mesh {
        BTreeSet::from([Ability::NetworkReachability])
    } else {
        BTreeSet::new()
    };
    // Direct means the route is externally available, as in the existing API.
    // It does not infer mesh membership from TCP or identity credentials.
    Model {
        mechanisms: vec![
            Mechanism {
                id: AccessMechanism::WireGuardPeer,
                requires: BTreeSet::new(),
                provides: BTreeSet::from([Ability::MeshMembership]),
            },
            Mechanism {
                id: AccessMechanism::NetworkRoute,
                requires: if mesh {
                    BTreeSet::from([Ability::MeshMembership])
                } else {
                    BTreeSet::new()
                },
                provides: BTreeSet::from([Ability::NetworkReachability]),
            },
            Mechanism {
                id: AccessMechanism::SshCertificate,
                requires: service_requires.clone(),
                provides: BTreeSet::from([Ability::SshSession]),
            },
            Mechanism {
                id: AccessMechanism::MtlsCertificate,
                requires: service_requires.clone(),
                provides: BTreeSet::from([Ability::ServiceIdentity]),
            },
            Mechanism {
                id: AccessMechanism::TcpAdmission,
                requires: service_requires,
                provides: BTreeSet::from([Ability::TcpConnection]),
            },
        ],
        derivations: Vec::new(),
    }
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
            max_mechanisms: 5,
            max_states: 32,
        },
        |_| true,
    )
}
