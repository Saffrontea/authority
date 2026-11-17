use authority_policy_core::{
    AccessIntent, Route,
    realization::{all_abilities, realize},
};
use authority_projection_core::{
    CommonDecisionClaims, MtlsProjectionRequest, NetworkProjectionRequest, ProjectionError,
    ProjectionInputs, ProjectionLifetimes, SshProjectionRequest, TcpProjectionRequest, project,
    project_plan,
};

fn common() -> CommonDecisionClaims {
    CommonDecisionClaims {
        decision_id: "0123456789abcdef0123456789abcdef".into(),
        issuer: "domain-authority:example".into(),
        domain_id: "domain_example".into(),
        subject_user_id: "user_01".into(),
        device_id: "device_01".into(),
        target_node_id: "node_01".into(),
        policy_id: "policy_01@1".into(),
        issued_at: 1_700_000_000,
    }
}

#[test]
fn tcp_only_needs_no_peer_or_certificate_material() {
    let plan = realize(&AccessIntent::tcp(Route::Direct), all_abilities()).unwrap();
    let result = project_plan(
        &common(),
        &plan,
        ProjectionInputs {
            tcp: Some((
                &TcpProjectionRequest {
                    source_address: "10.77.0.1".into(),
                    destination_address: "10.77.0.2".into(),
                    destination_ports: vec![8080],
                },
                20,
            )),
            ..ProjectionInputs::default()
        },
    )
    .unwrap();
    assert_eq!(result.tcp_grant.unwrap().destination_ports, vec![8080]);
    assert!(result.network_grant.is_none());
    assert!(result.ssh_issuance.is_none());
    assert!(result.ssh_node_install.is_none());
    assert!(result.mtls_issuance.is_none());
    assert!(result.mtls_node_install.is_none());
}

#[test]
fn a_selected_dependency_cannot_be_silently_omitted() {
    let plan = realize(&AccessIntent::tcp(Route::MeshRequired), all_abilities()).unwrap();
    assert!(matches!(
        project_plan(&common(), &plan, ProjectionInputs::default()),
        Err(ProjectionError::MissingInput("network")),
    ));
}

#[test]
fn selected_infrastructure_preserves_existing_contracts() {
    let common = common();
    let ssh = SshProjectionRequest {
        public_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        principals: vec!["deploy".into()],
        terminal_token_hash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
    };
    let network = NetworkProjectionRequest {
        wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        mesh_address: "10.77.0.1".into(),
    };
    let mtls = MtlsProjectionRequest {
        client_spki_sha256: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
        identity_uri: "spiffe://authority.example/user/user_01/device/device_01".into(),
        service_audience: "demo-api".into(),
    };
    let plan = realize(
        &AccessIntent::infrastructure(Route::MeshRequired),
        all_abilities(),
    )
    .unwrap();
    let result = project_plan(
        &common,
        &plan,
        ProjectionInputs {
            ssh: Some((&ssh, 60)),
            network: Some((&network, 90)),
            mtls: Some((&mtls, 120)),
            ..ProjectionInputs::default()
        },
    )
    .unwrap();
    let previous = project(
        &common,
        &ssh,
        &network,
        &mtls,
        ProjectionLifetimes {
            ssh_seconds: 60,
            network_seconds: 90,
            mtls_seconds: 120,
        },
    )
    .unwrap();
    assert_eq!(result.ssh_issuance.unwrap(), previous.ssh_issuance);
    assert_eq!(result.ssh_node_install.unwrap(), previous.ssh_node_install);
    assert_eq!(result.network_grant.unwrap(), previous.network_grant);
    assert_eq!(result.mtls_issuance.unwrap(), previous.mtls_issuance);
    assert_eq!(
        result.mtls_node_install.unwrap(),
        previous.mtls_node_install
    );
    assert!(result.tcp_grant.is_none());

    let mut invalid = common;
    invalid.issued_at = i64::MAX;
    assert!(matches!(
        project_plan(
            &invalid,
            &plan,
            ProjectionInputs {
                ssh: Some((&ssh, 60)),
                network: Some((&network, 90)),
                mtls: Some((&mtls, 120)),
                ..ProjectionInputs::default()
            }
        ),
        Err(ProjectionError::InvalidLifetime),
    ));
}
