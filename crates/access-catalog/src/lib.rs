//! Protocol vocabulary and deployment topology for the access adapters.
//! Generic policy ordering and planning live in `authority-planning-core`.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub mod algebra;
pub mod realization;
pub mod scoped;
pub mod resources {
    pub use authority_contracts_model::resources::*;
}

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
