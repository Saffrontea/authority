use std::collections::{BTreeMap, BTreeSet};

use authority_policy_core::{
    AccessDecision, AccessIntent, AccessRequest, Capability, Effect, IdentityFacts, PolicyRef,
    PolicyRule, PolicySnapshot, Route,
    realization::{Ability, AccessMechanism},
    scoped::{
        AbilityScope, AccessBinding, AuthorizedPlan, LifetimeLimits, NetworkResources, PolicyScope,
        RequestedAccess, RequestedNetwork, RequestedSsh, RequestedTcp, ScopeError, ScopedAbility,
        Validity, evaluate_scoped,
    },
};
use proptest::prelude::*;
use uuid::Uuid;

struct Fixture {
    request: AccessRequest,
    snapshot: PolicySnapshot,
    scopes: BTreeMap<PolicyRef, PolicyScope>,
    requested: RequestedAccess,
    resources: NetworkResources,
    limits: LifetimeLimits,
}

impl Fixture {
    fn tcp() -> Self {
        let request = AccessRequest {
            domain_id: Uuid::from_u128(1),
            subject_user_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3),
            target_node_id: Uuid::from_u128(4),
            evaluated_at: 100,
            intent: AccessIntent::tcp(Route::Direct),
        };
        let source = PolicyRef {
            policy_id: Uuid::from_u128(5),
            revision: 1,
        };
        let rule = PolicyRule {
            policy_id: source.policy_id,
            revision: source.revision,
            domain_id: request.domain_id,
            subject_user_id: request.subject_user_id,
            required_device_id: Some(request.device_id),
            target_node_id: request.target_node_id,
            enabled: true,
            effect: Effect::Allow,
            priority: 0,
            grants: BTreeSet::from([
                Capability::TcpConnect,
                Capability::SshIssue,
                Capability::MeshJoin,
                Capability::NetworkReach,
            ]),
            revoked_at: None,
            valid_from: Some(90),
            valid_until: Some(400),
        };
        let identity = IdentityFacts {
            device_domain_id: request.domain_id,
            device_owner_user_id: request.subject_user_id,
            device_active: true,
            target_active: true,
        };
        Self {
            request,
            snapshot: PolicySnapshot {
                identity,
                rules: vec![rule],
            },
            scopes: BTreeMap::from([(
                source,
                PolicyScope {
                    ssh_principals: BTreeSet::from(["deploy".into()]),
                    tcp_ports: BTreeSet::from([8080, 8081]),
                },
            )]),
            requested: RequestedAccess {
                tcp: Some(RequestedTcp {
                    ports: BTreeSet::from([8080]),
                    ttl_seconds: 20,
                }),
                ..RequestedAccess::default()
            },
            resources: NetworkResources {
                source_address: "10.77.0.1".parse().unwrap(),
                target_address: "10.77.0.2".parse().unwrap(),
                registered_wireguard_key: "registered-device-key".into(),
                service_audience: "demo-api".into(),
            },
            limits: LifetimeLimits {
                ssh_seconds: 60,
                network_seconds: 300,
            },
        }
    }

    fn authorize(&self) -> Result<(AccessDecision, AuthorizedPlan), ScopeError> {
        evaluate_scoped(
            &self.request,
            &self.snapshot,
            &self.scopes,
            &self.requested,
            &self.resources,
            self.limits,
        )
    }
}

#[test]
fn tcp_plan_binds_only_requested_ports_resource_identity_and_interval() {
    let fixture = Fixture::tcp();
    let (_, plan) = fixture.authorize().unwrap();
    assert_eq!(
        plan.binding().target_node_id,
        fixture.request.target_node_id
    );
    assert_eq!(
        plan.realization().mechanisms,
        vec![AccessMechanism::TcpAdmission]
    );
    assert_eq!(plan.realization().abilities.len(), 1);
    let ability = plan.realization().abilities.first().unwrap();
    assert_eq!(
        ability.validity,
        Validity {
            not_before: 100,
            expires_at: 120
        }
    );
    assert_eq!(
        ability.scope,
        AbilityScope::TcpConnection {
            source: fixture.resources.source_address,
            destination: fixture.resources.target_address,
            ports: BTreeSet::from([8080]),
        }
    );
}

#[test]
fn losing_policy_ports_cannot_expand_the_winning_policy_scope() {
    let mut fixture = Fixture::tcp();
    let mut winner = fixture.snapshot.rules[0].clone();
    winner.policy_id = Uuid::from_u128(6);
    winner.priority = 10;
    fixture.scopes.insert(
        PolicyRef {
            policy_id: winner.policy_id,
            revision: winner.revision,
        },
        PolicyScope {
            tcp_ports: BTreeSet::from([8081]),
            ..PolicyScope::default()
        },
    );
    fixture.snapshot.rules.push(winner);
    assert_eq!(
        fixture.authorize().unwrap_err(),
        ScopeError::ScopeDenied(Ability::TcpConnection)
    );
    fixture.requested.tcp.as_mut().unwrap().ports = BTreeSet::from([8081]);
    let (decision, _) = fixture.authorize().unwrap();
    assert_eq!(
        decision.sources[&Capability::TcpConnect].policy_id,
        Uuid::from_u128(6)
    );
}

#[test]
fn ssh_principals_are_selected_from_the_winning_policy_and_can_only_narrow() {
    let mut fixture = Fixture::tcp();
    fixture.request.intent = AccessIntent::ssh(Route::Direct);
    fixture.requested = RequestedAccess {
        ssh: Some(RequestedSsh {
            public_key_fingerprint: "key-fingerprint".into(),
            principals: None,
            terminal_token_hash: "terminal-binding".into(),
            ttl_seconds: 30,
        }),
        ..RequestedAccess::default()
    };
    let (_, plan) = fixture.authorize().unwrap();
    assert!(
        matches!(&plan.realization().abilities.first().unwrap().scope,
        AbilityScope::SshSession { principals, .. } if principals == &BTreeSet::from(["deploy".into()]))
    );
    fixture.requested.ssh.as_mut().unwrap().principals = Some(BTreeSet::from(["root".into()]));
    assert_eq!(
        fixture.authorize().unwrap_err(),
        ScopeError::ScopeDenied(Ability::SshSession)
    );
    fixture.requested.ssh.as_mut().unwrap().principals = Some(BTreeSet::new());
    assert!(fixture.authorize().is_err());
}

#[test]
fn policy_and_configured_expiry_are_enforced_at_the_exact_boundary() {
    let mut fixture = Fixture::tcp();
    fixture.snapshot.rules[0].valid_until = Some(120);
    fixture.authorize().unwrap();
    fixture.requested.tcp.as_mut().unwrap().ttl_seconds = 21;
    assert_eq!(
        fixture.authorize().unwrap_err(),
        ScopeError::LifetimeExceeded(Ability::TcpConnection)
    );
    fixture.snapshot.rules[0].valid_until = None;
    fixture.limits.network_seconds = 20;
    assert_eq!(
        fixture.authorize().unwrap_err(),
        ScopeError::LifetimeExceeded(Ability::TcpConnection)
    );
    fixture.request.evaluated_at = i64::MAX - 5;
    assert_eq!(
        fixture.authorize().unwrap_err(),
        ScopeError::InvalidLifetime
    );
}

#[test]
fn invalid_ports_lifetimes_and_extra_adapter_material_fail_closed() {
    for ports in [BTreeSet::new(), BTreeSet::from([0]), BTreeSet::from([8082])] {
        let mut fixture = Fixture::tcp();
        fixture.requested.tcp.as_mut().unwrap().ports = ports;
        assert_eq!(fixture.authorize().unwrap_err().code(), "tcp_port_denied");
    }
    for ttl in [i64::MIN, -1, 0, 601, i64::MAX] {
        let mut fixture = Fixture::tcp();
        fixture.requested.tcp.as_mut().unwrap().ttl_seconds = ttl;
        assert_eq!(
            fixture.authorize().unwrap_err(),
            ScopeError::InvalidLifetime
        );
    }
    let mut fixture = Fixture::tcp();
    fixture.requested.network = Some(RequestedNetwork {
        wireguard_public_key: None,
        ttl_seconds: 300,
    });
    assert_eq!(fixture.authorize().unwrap_err(), ScopeError::InvalidRequest);
}

#[test]
fn mesh_key_is_registered_and_each_adapter_keeps_its_own_deadline() {
    let mut fixture = Fixture::tcp();
    fixture.request.intent = AccessIntent::tcp(Route::MeshRequired);
    fixture.requested.network = Some(RequestedNetwork {
        wireguard_public_key: None,
        ttl_seconds: 300,
    });
    let (_, plan) = fixture.authorize().unwrap();
    for ability in &plan.realization().abilities {
        assert_eq!(
            ability.validity.expires_at,
            if ability.scope.kind() == Ability::TcpConnection {
                120
            } else {
                400
            }
        );
    }
    fixture
        .requested
        .network
        .as_mut()
        .unwrap()
        .wireguard_public_key = Some("other-device-key".into());
    assert_eq!(
        fixture.authorize().unwrap_err(),
        ScopeError::WireGuardKeyMismatch
    );
}

#[test]
fn full_binding_and_key_material_are_part_of_containment() {
    let fixture = Fixture::tcp();
    let (_, plan) = fixture.authorize().unwrap();
    let ability = plan.realization().abilities.first().unwrap();
    for field in 0..4 {
        let mut other = ability.clone();
        match field {
            0 => other.binding.domain_id = Uuid::from_u128(99),
            1 => other.binding.subject_user_id = Uuid::from_u128(99),
            2 => other.binding.device_id = Uuid::from_u128(99),
            _ => other.binding.target_node_id = Uuid::from_u128(99),
        }
        assert!(!ability.contains(&other));
    }
    let mut other = ability.clone();
    if let AbilityScope::TcpConnection { destination, .. } = &mut other.scope {
        *destination = "10.77.0.3".parse().unwrap();
    }
    assert!(!ability.contains(&other));
}

proptest! {
    #[test]
    fn containment_matches_port_subset_and_interval_inclusion(
        allowed in prop::collection::btree_set(1_u16..65535, 1..=64),
        selection in any::<u64>(), extra in any::<bool>(),
        start in 0_i64..1000, end in 0_i64..1500,
    ) {
        let mut selected = allowed.iter().enumerate()
            .filter(|(index, _)| selection & (1_u64 << index) != 0)
            .map(|(_, port)| *port).collect::<BTreeSet<_>>();
        if extra { selected.insert(65535); }
        let binding = AccessBinding { domain_id: Uuid::from_u128(1), subject_user_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3), target_node_id: Uuid::from_u128(4) };
        let scope = |ports| AbilityScope::TcpConnection { source: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(), ports };
        let grant = ScopedAbility { binding, validity: Validity { not_before: 100, expires_at: 1000 }, scope: scope(allowed.clone()) };
        let request = ScopedAbility { binding, validity: Validity { not_before: start, expires_at: end }, scope: scope(selected.clone()) };
        prop_assert_eq!(grant.contains(&request), !selected.is_empty() && selected.is_subset(&allowed)
            && start >= 100 && start < end && end <= 1000);
    }
}
