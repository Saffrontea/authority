use std::collections::{BTreeMap, BTreeSet};

use authority_policy_core::selection::{
    CandidateId, CandidateResult, DeploymentAvailability, ExistingRouteAvailability,
    PlanningEvidence, RouteChoice, SelectionOptions, evaluate_selection,
};
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
    fn automatic(&self) -> SelectionOptions {
        SelectionOptions {
            choice: RouteChoice::Automatic,
            availability: DeploymentAvailability {
                existing_route: Some(ExistingRouteAvailability {
                    source: self.resources.source_address,
                    destination: self.resources.target_address,
                    registered_wireguard_key: self.resources.registered_wireguard_key.clone(),
                }),
                wireguard_target: Some(self.resources.target_address),
            },
        }
    }

    fn alternatives(
        &self,
        options: &SelectionOptions,
    ) -> Result<(AccessDecision, AuthorizedPlan), authority_policy_core::selection::SelectionFailure>
    {
        evaluate_selection(
            &self.request,
            &self.snapshot,
            &self.scopes,
            &self.requested,
            &self.resources,
            self.limits,
            options,
        )
    }

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
fn automatic_selection_chooses_the_smallest_authorized_implementation() {
    let mut fixture = Fixture::tcp();
    fixture.requested.network = Some(RequestedNetwork {
        wireguard_public_key: None,
        ttl_seconds: 300,
    });
    let (decision, plan) = fixture.alternatives(&fixture.automatic()).unwrap();
    assert_eq!(decision.intent.route, Route::Direct);
    assert_eq!(plan.evidence().selected, Some(CandidateId::ExistingRoute));
    assert_eq!(
        plan.evidence().candidates[0].result,
        CandidateResult::Authorized { mechanism_count: 1 }
    );
    assert_eq!(
        plan.evidence().candidates[1].result,
        CandidateResult::Authorized { mechanism_count: 3 }
    );
    assert!(plan.evidence().is_consistent());
    let serialized = serde_json::to_vec(plan.evidence()).unwrap();
    let restored: PlanningEvidence = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(&restored, plan.evidence());
    assert!(restored.is_consistent());
}

#[test]
fn automatic_selection_falls_back_when_the_existing_route_is_not_declared() {
    let mut fixture = Fixture::tcp();
    fixture.requested.network = Some(RequestedNetwork {
        wireguard_public_key: None,
        ttl_seconds: 300,
    });
    let mut options = fixture.automatic();
    options.availability.existing_route = None;
    let (_, plan) = fixture.alternatives(&options).unwrap();
    assert_eq!(plan.evidence().selected, Some(CandidateId::WireGuardMesh));
    assert!(plan.evidence().is_consistent());
    assert!(
        matches!(&plan.evidence().candidates[0].result, CandidateResult::Rejected { reason, .. } if reason == "no_available_implementation")
    );
    let proof = plan.evidence().plan.as_ref().unwrap();
    assert_eq!(proof.steps[0].mechanism, AccessMechanism::WireGuardPeer);
    assert!(!proof.steps[1].requires.is_empty());
    assert_eq!(proof.steps[2].mechanism, AccessMechanism::TcpAdmission);
}

#[test]
fn a_rejected_candidate_does_not_abort_other_authorized_choices() {
    let mut fixture = Fixture::tcp();
    fixture.requested.network = Some(RequestedNetwork {
        wireguard_public_key: None,
        ttl_seconds: 300,
    });
    fixture.snapshot.rules[0].valid_until = Some(120); // TCP fits; a 300s peer does not.
    let (_, plan) = fixture.alternatives(&fixture.automatic()).unwrap();
    assert_eq!(plan.evidence().selected, Some(CandidateId::ExistingRoute));
    assert!(matches!(&plan.evidence().candidates[1].result,
        CandidateResult::Rejected { reason, capability } if reason == "policy_lifetime_exceeded" && capability.as_deref() == Some("mesh.join")));
    assert!(plan.evidence().is_consistent());
}

#[test]
fn declared_availability_must_match_the_source_target_and_registered_key() {
    let fixture = Fixture::tcp(); // No peer input: a matching existing route is required.
    for field in 0..3 {
        let mut options = fixture.automatic();
        let route = options.availability.existing_route.as_mut().unwrap();
        match field {
            0 => route.source = "10.77.0.99".parse().unwrap(),
            1 => route.destination = "10.77.0.99".parse().unwrap(),
            _ => route.registered_wireguard_key = "different-device".into(),
        }
        options.availability.wireguard_target = None;
        let failure = fixture.alternatives(&options).unwrap_err();
        assert_eq!(failure.reason, ScopeError::NoAvailableImplementation);
        assert!(failure.evidence.is_consistent());
        assert!(failure.evidence.plan.is_none());
    }
}

#[test]
fn explicit_mesh_constraint_never_falls_back_to_an_existing_route() {
    let mut fixture = Fixture::tcp();
    fixture.request.intent.route = Route::MeshRequired;
    fixture.requested.network = Some(RequestedNetwork {
        wireguard_public_key: None,
        ttl_seconds: 300,
    });
    fixture.snapshot.rules[0]
        .grants
        .remove(&Capability::MeshJoin);
    let options = SelectionOptions {
        choice: RouteChoice::Exact(Route::MeshRequired),
        ..fixture.automatic()
    };
    let failure = fixture.alternatives(&options).unwrap_err();
    assert_eq!(failure.capability(), Some(Capability::MeshJoin));
    assert_eq!(failure.evidence.candidates.len(), 1);
    assert!(failure.evidence.is_consistent());
    let (_, plan) = fixture.alternatives(&fixture.automatic()).unwrap();
    assert_eq!(plan.evidence().selected, Some(CandidateId::ExistingRoute));
}

#[test]
fn audit_replay_rejects_scope_expansion_forward_dependencies_and_wrong_selection() {
    let fixture = Fixture::tcp();
    let (_, plan) = fixture.alternatives(&fixture.automatic()).unwrap();
    let mut expanded = plan.evidence().clone();
    if let AbilityScope::TcpConnection { ports, .. } =
        &mut expanded.plan.as_mut().unwrap().abilities[0].ability.scope
    {
        ports.insert(8082);
    }
    assert!(!expanded.is_consistent());
    let mut forward = plan.evidence().clone();
    forward.plan.as_mut().unwrap().steps[0].requires.push(0);
    assert!(!forward.is_consistent());
    let mut unavailable = plan.evidence().clone();
    unavailable.deployment.as_mut().unwrap().existing_route = None;
    assert!(!unavailable.is_consistent());
    let mut rebound = plan.evidence().clone();
    rebound.resources.as_mut().unwrap().target_address = "10.77.0.99".parse().unwrap();
    assert!(!rebound.is_consistent());
    let mut wrong = plan.evidence().clone();
    wrong.selected = Some(CandidateId::WireGuardMesh);
    assert!(!wrong.is_consistent());
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

#[test]
fn available_routes_never_override_policy_and_mismatched_exact_constraints_are_rejected() {
    let mut fixture = Fixture::tcp();
    fixture.requested.network = Some(RequestedNetwork {
        wireguard_public_key: None,
        ttl_seconds: 300,
    });
    fixture.snapshot.rules[0].grants.clear();
    let failure = fixture.alternatives(&fixture.automatic()).unwrap_err();
    assert!(failure.evidence.selected.is_none());
    assert!(failure.evidence.is_consistent());
    fixture.request.intent.route = Route::MeshRequired;
    assert_eq!(
        fixture
            .alternatives(&SelectionOptions::exact(Route::Direct))
            .unwrap_err()
            .reason,
        ScopeError::InvalidRequest
    );
}

proptest! {
    #[test]
    fn validity_matches_integer_interval_spec_at_machine_boundaries(
        (outer_start, outer_end, inner_start, inner_end) in
            (any::<i64>(), any::<i64>(), any::<i64>(), any::<i64>()),
    ) {
        let outer = Validity { not_before: outer_start, expires_at: outer_end };
        let inner = Validity { not_before: inner_start, expires_at: inner_end };
        // Mathematical integers avoid making the oracle share machine overflow.
        let (a, b, c, d) = (i128::from(outer_start), i128::from(outer_end),
            i128::from(inner_start), i128::from(inner_end));
        let expected = c >= 0 && a < b && c < d && a <= c && d <= b;
        prop_assert_eq!(outer.contains(inner), expected);
        if outer.contains(inner) {
            prop_assert!(d - c <= b - a);
        }
    }

    #[test]
    fn containment_is_transitive_for_valid_narrowings(
        start in 0_i64..=i64::MAX - 1800,
        widths in prop::array::uniform3(1_i64..=600),
        ports in prop::collection::btree_set(1_u16..=u16::MAX, 1..=64),
        selection in any::<u64>(),
    ) {
        let binding = AccessBinding { domain_id: Uuid::from_u128(1), subject_user_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3), target_node_id: Uuid::from_u128(4) };
        let narrow = ports.iter().enumerate().filter(|(index, _)| selection & (1_u64 << index) != 0)
            .map(|(_, port)| *port).chain(ports.iter().next().copied()).collect::<BTreeSet<_>>();
        let make = |expires_at, ports| ScopedAbility {
            binding, validity: Validity { not_before: start, expires_at },
            scope: AbilityScope::TcpConnection { source: "10.0.0.1".parse().unwrap(),
                destination: "10.0.0.2".parse().unwrap(), ports },
        };
        let a = make(start + widths.iter().sum::<i64>(), ports.clone());
        let b = make(start + widths[0] + widths[1], narrow.clone());
        let c = make(start + widths[0], BTreeSet::from([*narrow.first().unwrap()]));
        prop_assert!(a.contains(&b));
        prop_assert!(b.contains(&c));
        prop_assert!(a.contains(&c));
        let mut rebound = c;
        rebound.binding.target_node_id = Uuid::from_u128(99);
        prop_assert!(!a.contains(&rebound));
    }
}
