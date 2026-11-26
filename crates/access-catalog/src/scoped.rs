//! Resource semantics of the current access adapters.
use crate::realization::Ability;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr};
use uuid::Uuid;

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
        source: crate::resources::Ipv4Set,
        destination: crate::resources::Ipv4Set,
    },
    NetworkRouteAuthorization {
        source: crate::resources::Ipv4Set,
        destination: crate::resources::Ipv4Set,
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
        source: crate::resources::Ipv4Set,
        destination: crate::resources::Ipv4Set,
        ports: crate::resources::PortSet,
    },
    TcpAdmission {
        source: crate::resources::Ipv4Set,
        destination: crate::resources::Ipv4Set,
        ports: crate::resources::PortSet,
    },
}

impl AbilityScope {
    #[must_use]
    pub fn tcp_resources(&self) -> Option<crate::resources::TcpResourcesV1> {
        match self {
            Self::TcpAdmission {
                source,
                destination,
                ports,
            }
            | Self::TcpConnection {
                source,
                destination,
                ports,
            } => Some(crate::resources::TcpResourcesV1 {
                source_addresses: source.clone(),
                destination_addresses: destination.clone(),
                destination_ports: ports.clone(),
            }),
            _ => None,
        }
    }

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
                source: source.clone(),
                destination: destination.clone(),
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
                source: source.clone(),
                destination: destination.clone(),
                ports: ports.clone(),
            },
            other => other.clone(),
        }
    }

    #[must_use]
    pub fn direct(self) -> Self {
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

    #[allow(clippy::match_same_arms, clippy::too_many_lines)] // Explicit authority-kind branches are extracted for value-level proofs.
    fn contains(&self, requested: &Self) -> bool {
        match (self, requested) {
            (
                Self::NetworkRouteAuthorization {
                    source,
                    destination,
                },
                Self::NetworkRouteAuthorization {
                    source: from,
                    destination: to,
                },
            )
            | (
                Self::NetworkReachability {
                    source,
                    destination,
                },
                Self::NetworkReachability {
                    source: from,
                    destination: to,
                },
            ) => {
                !from.is_empty()
                    && !to.is_empty()
                    && from.is_subset(source)
                    && to.is_subset(destination)
            }

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
                !from.is_empty()
                    && !to.is_empty()
                    && from.is_subset(source)
                    && to.is_subset(destination)
                    && !selected.is_empty()
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
                !from.is_empty()
                    && !to.is_empty()
                    && from.is_subset(source)
                    && to.is_subset(destination)
                    && !selected.is_empty()
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
        Option<Box<authority_contracts_model::observation::SignedEndpointObservationV3>>,
    pub source_address: Ipv4Addr,
    pub target_address: Ipv4Addr,
    pub registered_wireguard_key: String,
    /// Trusted deployment configuration, not a client-selected audience.
    pub service_audience: String,
    pub environment: BTreeSet<crate::realization::EndpointFact>,
}
