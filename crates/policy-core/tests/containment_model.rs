//! Value-level correspondence with formal/verus/scopes.rs. The independent
//! oracle enumerates atomic authorities rather than repeating the predicates.
use std::{collections::BTreeSet, net::Ipv4Addr};

use authority_policy_core::scoped::{AbilityScope, AccessBinding, ScopedAbility, Validity};
use proptest::prelude::*;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Atom {
    Peer(String, Ipv4Addr),
    Route(Ipv4Addr, Ipv4Addr),
    RouteInstalled(Ipv4Addr, Ipv4Addr),
    Ssh(String, String, String),
    CredentialSsh(String, String, String),
    Identity(String, String, String),
    CredentialMtls(String, String, String),
    Tcp(Ipv4Addr, Ipv4Addr, u16),
    AdmissionTcp(Ipv4Addr, Ipv4Addr, u16),
}

fn atoms(scope: &AbilityScope) -> BTreeSet<Atom> {
    match scope {
        AbilityScope::MeshMembership {
            wireguard_public_key,
            address,
        } => BTreeSet::from([Atom::Peer(wireguard_public_key.clone(), *address)]),
        AbilityScope::NetworkReachability {
            source,
            destination,
        } => BTreeSet::from([Atom::Route(*source, *destination)]),
        AbilityScope::NetworkRouteAuthorization {
            source,
            destination,
        } => BTreeSet::from([Atom::RouteInstalled(*source, *destination)]),
        AbilityScope::SshSession {
            public_key_fingerprint,
            principals,
            terminal_token_hash,
        } => principals
            .iter()
            .map(|principal| {
                Atom::Ssh(
                    public_key_fingerprint.clone(),
                    principal.clone(),
                    terminal_token_hash.clone(),
                )
            })
            .collect(),
        AbilityScope::SshCredential {
            public_key_fingerprint,
            principals,
            terminal_token_hash,
        } => principals
            .iter()
            .map(|principal| {
                Atom::CredentialSsh(
                    public_key_fingerprint.clone(),
                    principal.clone(),
                    terminal_token_hash.clone(),
                )
            })
            .collect(),
        AbilityScope::ServiceIdentity {
            client_spki_sha256,
            identity_uri,
            service_audience,
        } => BTreeSet::from([Atom::Identity(
            client_spki_sha256.clone(),
            identity_uri.clone(),
            service_audience.clone(),
        )]),
        AbilityScope::MtlsCredential {
            client_spki_sha256,
            identity_uri,
            service_audience,
        } => BTreeSet::from([Atom::CredentialMtls(
            client_spki_sha256.clone(),
            identity_uri.clone(),
            service_audience.clone(),
        )]),
        AbilityScope::TcpConnection {
            source,
            destination,
            ports,
        } => ports
            .iter()
            .map(|port| Atom::Tcp(*source, *destination, *port))
            .collect(),
        AbilityScope::TcpAdmission {
            source,
            destination,
            ports,
        } => ports
            .iter()
            .map(|port| Atom::AdmissionTcp(*source, *destination, *port))
            .collect(),
    }
}

fn request_valid(scope: &AbilityScope) -> bool {
    match scope {
        AbilityScope::SshSession { principals, .. }
        | AbilityScope::SshCredential { principals, .. } => {
            !principals.is_empty() && !principals.contains("")
        }
        AbilityScope::TcpConnection { ports, .. } | AbilityScope::TcpAdmission { ports, .. } => {
            !ports.is_empty() && ports.len() <= 64 && !ports.contains(&0)
        }
        _ => true,
    }
}

fn scope(
    kind: u8,
    key: &str,
    token: &str,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    principals: &BTreeSet<String>,
    ports: &BTreeSet<u16>,
) -> AbilityScope {
    if kind >= 5 {
        return match scope(kind - 4, key, token, source, destination, principals, ports) {
            AbilityScope::NetworkReachability {
                source,
                destination,
            } => AbilityScope::NetworkRouteAuthorization {
                source,
                destination,
            },
            AbilityScope::SshSession {
                public_key_fingerprint,
                principals,
                terminal_token_hash,
            } => AbilityScope::SshCredential {
                public_key_fingerprint,
                principals,
                terminal_token_hash,
            },
            AbilityScope::ServiceIdentity {
                client_spki_sha256,
                identity_uri,
                service_audience,
            } => AbilityScope::MtlsCredential {
                client_spki_sha256,
                identity_uri,
                service_audience,
            },
            AbilityScope::TcpConnection {
                source,
                destination,
                ports,
            } => AbilityScope::TcpAdmission {
                source,
                destination,
                ports,
            },
            _ => unreachable!(),
        };
    }
    match kind {
        0 => AbilityScope::MeshMembership {
            wireguard_public_key: key.into(),
            address: source,
        },
        1 => AbilityScope::NetworkReachability {
            source,
            destination,
        },
        2 => AbilityScope::SshSession {
            public_key_fingerprint: key.into(),
            principals: principals.clone(),
            terminal_token_hash: token.into(),
        },
        3 => AbilityScope::ServiceIdentity {
            client_spki_sha256: key.into(),
            identity_uri: token.into(),
            service_audience: "service".into(),
        },
        _ => AbilityScope::TcpConnection {
            source,
            destination,
            ports: ports.clone(),
        },
    }
}

proptest! {
    #[test]
    fn production_containment_matches_atomic_authority_model(
        kind in 0_u8..9, mutation in 0_u8..12,
        (key, token) in ("[a-z]{0,8}", "[a-z]{0,8}"),
        (from, to) in (any::<u32>(), any::<u32>()),
        principals in prop::collection::btree_set("[a-z]{0,6}", 0..8),
        ports in prop::collection::btree_set(any::<u16>(), 0..70),
        (start, end) in (any::<i64>(), any::<i64>()),
    ) {
        let binding = AccessBinding { domain_id: Uuid::from_u128(1), subject_user_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3), target_node_id: Uuid::from_u128(4) };
        let grant = ScopedAbility {
            binding, validity: Validity { not_before: 100, expires_at: 500 },
            scope: scope(kind, &key, &token, from.into(), to.into(), &principals, &ports),
        };
        let mut requested = grant.clone();
        requested.validity = Validity { not_before: 120, expires_at: 200 };
        match mutation {
            0 => {},
            1 => requested.scope = scope(kind, &(key + "changed"), &token,
                from.wrapping_add(1).into(), to.into(), &principals, &ports),
            2 => requested.scope = scope(kind, &key, &(token + "changed"),
                from.into(), to.wrapping_add(1).into(), &principals, &ports),
            3 => {
                match &mut requested.scope {
                    AbilityScope::SshSession { principals, .. } | AbilityScope::SshCredential { principals, .. } => { principals.pop_first(); },
                    AbilityScope::TcpConnection { ports, .. } | AbilityScope::TcpAdmission { ports, .. } => { ports.pop_first(); },
                    _ => {},
                }
            },
            4 => {
                match &mut requested.scope {
                    AbilityScope::SshSession { principals, .. } | AbilityScope::SshCredential { principals, .. } => { principals.insert("outside".into()); },
                    AbilityScope::TcpConnection { ports, .. } | AbilityScope::TcpAdmission { ports, .. } => { ports.insert(u16::MAX); },
                    AbilityScope::ServiceIdentity { service_audience, .. } => *service_audience = "other".into(),
                    _ => {},
                }
            },
            5 => {
                match &mut requested.scope {
                    AbilityScope::SshSession { principals, .. } | AbilityScope::SshCredential { principals, .. } => { principals.insert(String::new()); },
                    AbilityScope::TcpConnection { ports, .. } | AbilityScope::TcpAdmission { ports, .. } => { ports.insert(0); },
                    _ => {},
                }
            },
            6 => requested.binding.domain_id = Uuid::from_u128(99),
            7 => requested.binding.subject_user_id = Uuid::from_u128(99),
            8 => requested.binding.device_id = Uuid::from_u128(99),
            9 => requested.binding.target_node_id = Uuid::from_u128(99),
            10 => requested.validity = Validity { not_before: start, expires_at: end },
            _ => requested.scope = scope((kind + 1) % 5, &key, &token, from.into(), to.into(), &principals, &ports),
        }
        let interval = requested.validity.not_before >= 100
            && requested.validity.not_before < requested.validity.expires_at
            && requested.validity.expires_at <= 500;
        let expected = requested.binding == binding && interval && request_valid(&requested.scope)
            && atoms(&requested.scope).is_subset(&atoms(&grant.scope));
        prop_assert_eq!(grant.contains(&requested), expected);
    }
}
