use std::collections::{BTreeMap, BTreeSet};

use authority_policy_core::selection::{
    DeploymentAvailability, ExistingRouteAvailability, RouteChoice, SelectionOptions,
    evaluate_selection,
};
use authority_policy_core::{
    AccessIntent, AccessRequest, Capability, Effect, IdentityFacts, PolicyRef, PolicyRule,
    PolicySnapshot, Route,
    scoped::{
        AuthorizedPlan, LifetimeLimits, NetworkResources, PolicyScope, RequestedAccess,
        RequestedMtls, RequestedNetwork, RequestedSsh, RequestedTcp, evaluate_scoped,
    },
};
use authority_projection_core::{CommonDecisionClaims, ProjectionError, project_authorized};
use uuid::Uuid;

fn authorize(
    intent: AccessIntent,
    requested: &RequestedAccess,
) -> (AuthorizedPlan, CommonDecisionClaims) {
    authorize_selected(intent, requested, None)
}

fn authorize_selected(
    intent: AccessIntent,
    requested: &RequestedAccess,
    options: Option<&SelectionOptions>,
) -> (AuthorizedPlan, CommonDecisionClaims) {
    try_authorize_selected(intent, requested, options).unwrap()
}

fn try_authorize_selected(
    intent: AccessIntent,
    requested: &RequestedAccess,
    options: Option<&SelectionOptions>,
) -> Result<(AuthorizedPlan, CommonDecisionClaims), authority_policy_core::scoped::ScopeError> {
    let request = AccessRequest {
        domain_id: Uuid::from_u128(1),
        subject_user_id: Uuid::from_u128(2),
        device_id: Uuid::from_u128(3),
        target_node_id: Uuid::from_u128(4),
        evaluated_at: 1_700_000_000,
        intent,
    };
    let policy = PolicyRef {
        policy_id: Uuid::from_u128(5),
        revision: 7,
    };
    let snapshot = PolicySnapshot {
        identity: IdentityFacts {
            device_domain_id: request.domain_id,
            device_owner_user_id: request.subject_user_id,
            device_active: true,
            target_active: true,
        },
        rules: vec![PolicyRule {
            policy_id: policy.policy_id,
            revision: policy.revision,
            domain_id: request.domain_id,
            subject_user_id: request.subject_user_id,
            required_device_id: Some(request.device_id),
            target_node_id: request.target_node_id,
            enabled: true,
            effect: Effect::Allow,
            priority: 0,
            grants: BTreeSet::from([
                Capability::MeshJoin,
                Capability::NetworkReach,
                Capability::SshIssue,
                Capability::MtlsIssue,
                Capability::TcpConnect,
            ]),
            revoked_at: None,
            valid_from: None,
            valid_until: None,
        }],
    };
    let scopes = BTreeMap::from([(
        policy,
        PolicyScope {
            ssh_principals: BTreeSet::from(["deploy".into()]),
            tcp_ports: BTreeSet::from([8080, 8081]),
        },
    )]);
    let resources = NetworkResources {
        environment: authority_policy_core::realization::endpoint_facts(),
        source_address: "10.77.0.1".parse().unwrap(),
        target_address: "10.77.0.2".parse().unwrap(),
        registered_wireguard_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        service_audience: "demo-api".into(),
    };
    let limits = LifetimeLimits {
        ssh_seconds: 60,
        network_seconds: 300,
    };
    let (_, plan) = if let Some(options) = options {
        evaluate_selection(
            &request, &snapshot, &scopes, requested, &resources, limits, options,
        )
        .map_err(|failure| failure.reason)?
    } else {
        evaluate_scoped(&request, &snapshot, &scopes, requested, &resources, limits)?
    };
    let common = CommonDecisionClaims {
        decision_id: "0123456789abcdef0123456789abcdef".into(),
        issuer: format!("domain-authority:{}", request.domain_id),
        domain_id: request.domain_id.to_string(),
        subject_user_id: request.subject_user_id.to_string(),
        device_id: request.device_id.to_string(),
        target_node_id: request.target_node_id.to_string(),
        policy_id: plan.policy_reference().into(),
        issued_at: request.evaluated_at,
    };
    Ok((plan, common))
}

#[test]
fn changing_request_after_authorization_cannot_change_projected_tcp_scope() {
    let mut requested = RequestedAccess {
        tcp: Some(RequestedTcp {
            ports: BTreeSet::from([8080]),
            ttl_seconds: 20,
        }),
        ..RequestedAccess::default()
    };
    let (plan, common) = authorize(AccessIntent::tcp(Route::Direct), &requested);
    requested.tcp.as_mut().unwrap().ports.insert(8081);
    requested.tcp.as_mut().unwrap().ttl_seconds = 300;
    let result = project_authorized(&common, &plan).unwrap();
    let grant = result.tcp_grant.unwrap();
    assert_eq!(grant.destination_ports, vec![8080]);
    assert_eq!(grant.source_address, "10.77.0.1");
    assert_eq!(grant.destination_address, "10.77.0.2");
    assert_eq!(grant.expires_at, common.issued_at + 20);
    assert!(result.network_grant.is_none());
    assert!(result.ssh_issuance.is_none());
    assert!(result.mtls_issuance.is_none());
}

#[test]
fn infrastructure_projection_preserves_authorized_material_and_independent_deadlines() {
    let mut requested = RequestedAccess {
        ssh: Some(RequestedSsh {
            public_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            principals: None,
            terminal_token_hash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
            ttl_seconds: 60,
        }),
        mtls: Some(RequestedMtls {
            client_spki_sha256: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
            ttl_seconds: 120,
        }),
        network: Some(RequestedNetwork {
            wireguard_public_key: None,
            ttl_seconds: 300,
        }),
        ..RequestedAccess::default()
    };
    let (plan, common) = authorize(
        AccessIntent::infrastructure(Route::MeshRequired),
        &requested,
    );
    requested.ssh.as_mut().unwrap().principals = Some(BTreeSet::from(["root".into()]));
    requested.ssh.as_mut().unwrap().public_key_fingerprint = "other-key".into();
    requested.mtls.as_mut().unwrap().client_spki_sha256 = "other-key".into();
    let result = project_authorized(&common, &plan).unwrap();
    let ssh = result.ssh_issuance.unwrap();
    assert_eq!(ssh.principals, vec!["deploy"]);
    assert_eq!(
        ssh.ssh_public_key_fingerprint,
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(ssh.expires_at, common.issued_at + 60);
    assert_eq!(
        result.ssh_node_install.unwrap().nonce,
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    );
    let network = result.network_grant.unwrap();
    assert_eq!(network.expires_at, common.issued_at + 300);
    assert_eq!(
        network.wireguard_public_key,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    );
    let mtls = result.mtls_issuance.unwrap();
    assert_eq!(mtls.expires_at, common.issued_at + 120);
    assert_eq!(
        mtls.client_spki_sha256,
        "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    );
    assert_eq!(mtls.service_audience, "demo-api");
    assert_eq!(
        mtls.identity_uri,
        format!(
            "spiffe://authority.local/domain/{}/user/{}/device/{}",
            common.domain_id, common.subject_user_id, common.device_id
        )
    );
    assert!(result.tcp_grant.is_none());
}

#[test]
fn projection_cannot_rebind_identity_policy_or_issuance_time() {
    let requested = RequestedAccess {
        tcp: Some(RequestedTcp {
            ports: BTreeSet::from([8080]),
            ttl_seconds: 20,
        }),
        ..RequestedAccess::default()
    };
    let (plan, common) = authorize(AccessIntent::tcp(Route::Direct), &requested);
    for field in 0..7 {
        let mut changed = common.clone();
        match field {
            0 => changed.domain_id = Uuid::from_u128(99).to_string(),
            1 => changed.subject_user_id = Uuid::from_u128(99).to_string(),
            2 => changed.device_id = Uuid::from_u128(99).to_string(),
            3 => changed.target_node_id = Uuid::from_u128(99).to_string(),
            4 => changed.policy_id = "different-policy@1".into(),
            5 => changed.issuer = "other-issuer".into(),
            _ => changed.issued_at += 1,
        }
        assert!(matches!(
            project_authorized(&changed, &plan),
            Err(ProjectionError::ScopeMismatch)
        ));
    }
}

#[test]
fn automatic_projection_emits_only_the_selected_route_material() {
    let requested = RequestedAccess {
        tcp: Some(RequestedTcp {
            ports: BTreeSet::from([8080]),
            ttl_seconds: 20,
        }),
        network: Some(RequestedNetwork {
            wireguard_public_key: None,
            ttl_seconds: 300,
        }),
        ..RequestedAccess::default()
    };
    let mut options = SelectionOptions {
        choice: RouteChoice::Automatic,
        availability: DeploymentAvailability {
            existing_route: Some(ExistingRouteAvailability {
                source: "10.77.0.1".parse().unwrap(),
                destination: "10.77.0.2".parse().unwrap(),
                registered_wireguard_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            }),
            wireguard_target: Some("10.77.0.2".parse().unwrap()),
        },
    };
    let (plan, common) =
        authorize_selected(AccessIntent::tcp(Route::Direct), &requested, Some(&options));
    let result = project_authorized(&common, &plan).unwrap();
    assert!(result.network_grant.is_none());
    assert_eq!(result.tcp_grant.unwrap().destination_ports, vec![8080]);
    options.availability.existing_route = None;
    let (plan, common) =
        authorize_selected(AccessIntent::tcp(Route::Direct), &requested, Some(&options));
    let result = project_authorized(&common, &plan).unwrap();
    assert_eq!(
        result.network_grant.unwrap().expires_at,
        common.issued_at + 300
    );
    assert_eq!(result.tcp_grant.unwrap().expires_at, common.issued_at + 20);
    assert!(result.ssh_issuance.is_none());
    assert!(result.mtls_issuance.is_none());
}

proptest::proptest! {
    #[test]
    fn authorized_tcp_projection_refines_selected_scope(
        select_both in proptest::prelude::any::<bool>(),
        ttl in 1_i64..=300,
        changed_field in 0_usize..7,
    ) {
        use proptest::prelude::*;
        let ports = if select_both { BTreeSet::from([8080, 8081]) } else { BTreeSet::from([8080]) };
        let requested = RequestedAccess {
            tcp: Some(RequestedTcp { ports: ports.clone(), ttl_seconds: ttl }),
            ..RequestedAccess::default()
        };
        let (plan, common) = authorize(AccessIntent::tcp(Route::Direct), &requested);
        let result = project_authorized(&common, &plan).unwrap();
        let grant = result.tcp_grant.unwrap();
        prop_assert_eq!(grant.destination_ports, ports.into_iter().collect::<Vec<_>>());
        prop_assert_eq!(grant.issued_at, common.issued_at);
        prop_assert_eq!(grant.expires_at, common.issued_at + ttl);
        prop_assert_eq!(&grant.domain_id, &common.domain_id);
        prop_assert_eq!(&grant.subject_user_id, &common.subject_user_id);
        prop_assert_eq!(&grant.device_id, &common.device_id);
        prop_assert_eq!(&grant.target_node_id, &common.target_node_id);
        prop_assert_eq!(&grant.policy_id, &common.policy_id);
        prop_assert!(result.network_grant.is_none() && result.ssh_issuance.is_none()
            && result.ssh_node_install.is_none() && result.mtls_issuance.is_none());
        let mut rebound = common;
        match changed_field {
            0 => rebound.domain_id = Uuid::from_u128(99).to_string(),
            1 => rebound.subject_user_id = Uuid::from_u128(99).to_string(),
            2 => rebound.device_id = Uuid::from_u128(99).to_string(),
            3 => rebound.target_node_id = Uuid::from_u128(99).to_string(),
            4 => rebound.policy_id = "other-policy@1".into(),
            5 => rebound.issuer = "other-issuer".into(),
            _ => rebound.issued_at += 1,
        }
        prop_assert!(matches!(project_authorized(&rebound, &plan), Err(ProjectionError::ScopeMismatch)));
    }
}

proptest::proptest! {
    #[test]
    fn private_plan_factory_supplies_pipeline_invariant_and_exact_expiries(
        ssh_ttl in 1_i64..=60, mtls_ttl in 1_i64..=300, network_ttl in 1_i64..=300,
    ) {
        use proptest::prelude::*;
        let requested = RequestedAccess {
            ssh: Some(RequestedSsh {
                public_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                principals: None, terminal_token_hash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(), ttl_seconds: ssh_ttl,
            }),
            mtls: Some(RequestedMtls { client_spki_sha256: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".into(), ttl_seconds: mtls_ttl }),
            network: Some(RequestedNetwork { wireguard_public_key: None, ttl_seconds: network_ttl }),
            ..RequestedAccess::default()
        };
        let outcome = try_authorize_selected(AccessIntent::infrastructure(Route::MeshRequired), &requested,None);
        if network_ttl < ssh_ttl.max(mtls_ttl) {
            prop_assert!(outcome.is_err());
            return Ok(());
        }
        let (plan,common) = outcome.unwrap();
        prop_assert!(plan.issued_at() >= 0);
        for ability in &plan.realization().abilities {
            prop_assert_eq!(ability.binding, plan.binding());
            prop_assert_eq!(ability.validity.not_before, plan.issued_at());
        }
        let output = project_authorized(&common, &plan).unwrap();
        let ssh = output.ssh_issuance.unwrap();
        prop_assert_eq!(ssh.expires_at, common.issued_at + ssh_ttl);
        prop_assert_eq!(output.ssh_node_install.unwrap().nonce, requested.ssh.unwrap().terminal_token_hash);
        prop_assert_eq!(output.network_grant.unwrap().expires_at, common.issued_at + network_ttl);
        prop_assert_eq!(output.mtls_issuance.unwrap().expires_at, common.issued_at + mtls_ttl);
        prop_assert_eq!(output.mtls_node_install.unwrap().expires_at, common.issued_at + mtls_ttl);
        prop_assert!(output.tcp_grant.is_none());
    }
}
