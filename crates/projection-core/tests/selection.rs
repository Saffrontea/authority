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
                    resources: authority_contracts_model::resources::TcpResourcesV1 {
                        source_addresses: ("10.77.0.1").parse().unwrap(),
                        destination_addresses: ("10.77.0.2").parse().unwrap(),
                        destination_ports: {
                            let points: Vec<u16> = vec![8080];
                            authority_contracts_model::resources::PortSet::from_ports(
                                &points.into_iter().collect(),
                            )
                            .unwrap()
                        },
                    },
                },
                20,
            )),
            ..ProjectionInputs::default()
        },
    )
    .unwrap();
    assert_eq!(
        result.tcp_grant.unwrap().resources.destination_ports,
        "8080".parse().unwrap()
    );
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

use proptest::prelude::*;

proptest! {
    #[test]
    fn generated_mechanism_sequences_match_projection_model(
        ids in prop::collection::vec(0_u8..5, 0..20),
        available in 0_u8..16,
        ttls in prop::array::uniform4(prop_oneof![Just(0_i64), Just(601_i64), 1_i64..=600]),
        issued_at in prop_oneof![Just(1_700_000_000_i64), (0_i64..=600).prop_map(|n| i64::MAX - n)],
        identifier in any::<u64>(),
        ports in prop::collection::btree_set(1_u16..=u16::MAX, 1..=8),
    ) {
        use std::collections::BTreeSet;
        use authority_policy_core::realization::{AccessMechanism, AccessPlan};
        let mechanisms = ids.iter().map(|id| match id {
            0 => AccessMechanism::NetworkRoute, 1 => AccessMechanism::WireGuardPeer,
            2 => AccessMechanism::SshCertificate, 3 => AccessMechanism::MtlsCertificate,
            _ => AccessMechanism::TcpAdmission,
        }).collect::<Vec<_>>();
        let needed = mechanisms.iter().fold(0_u8, |mask, m| mask | match m {
            AccessMechanism::NetworkRoute => 0, AccessMechanism::WireGuardPeer => 2,
            AccessMechanism::SshCertificate => 1, AccessMechanism::MtlsCertificate => 4,
            AccessMechanism::TcpAdmission => 8,
        });
        let mut claims = common();
        claims.issued_at = issued_at;
        claims.subject_user_id = format!("user_{identifier}");
        claims.decision_id = format!("{identifier:032x}");
        let ssh = SshProjectionRequest {
            public_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            principals: vec!["deploy".into()],
            terminal_token_hash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
        };
        let network = NetworkProjectionRequest { wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(), mesh_address: "10.77.0.1".into() };
        let mtls = MtlsProjectionRequest { client_spki_sha256: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
            identity_uri: "spiffe://authority.example/user/user_01/device/device_01".into(), service_audience: "demo-api".into() };
        let tcp = TcpProjectionRequest { resources: authority_contracts_model::resources::TcpResourcesV1 { source_addresses:[10,77,0,1].into(), destination_addresses:[10,77,0,2].into(), destination_ports: authority_contracts_model::resources::PortSet::from_ports(&ports).unwrap() } };
        let plan = AccessPlan { mechanisms, abilities: BTreeSet::new() };
        let projected = project_plan(&claims, &plan, ProjectionInputs {
            ssh: (available & 1 != 0).then_some((&ssh, ttls[0])),
            network: (available & 2 != 0).then_some((&network, ttls[1])),
            mtls: (available & 4 != 0).then_some((&mtls, ttls[2])),
            tcp: (available & 8 != 0).then_some((&tcp, ttls[3])),
        });
        let expected = needed & !available == 0 && ttls.iter().enumerate().all(|(i, ttl)| {
            let end = i128::from(issued_at) + i128::from(*ttl);
            needed & (1 << i) == 0 || ((1..=600).contains(ttl) && end <= i128::from(i64::MAX))
        });
        prop_assert_eq!(projected.is_ok(), expected);
        if let Ok(result) = projected {
            prop_assert_eq!(result.ssh_issuance.is_some(), needed & 1 != 0);
            prop_assert_eq!(result.ssh_node_install.is_some(), needed & 1 != 0);
            prop_assert_eq!(result.network_grant.is_some(), needed & 2 != 0);
            prop_assert_eq!(result.mtls_issuance.is_some(), needed & 4 != 0);
            prop_assert_eq!(result.mtls_node_install.is_some(), needed & 4 != 0);
            prop_assert_eq!(result.tcp_grant.is_some(), needed & 8 != 0);
            macro_rules! common_fields {
                ($grant:expr, $ttl:expr) => {{
                    let c = $grant;
                    prop_assert_eq!(&c.issuer, &claims.issuer);
                    prop_assert_eq!(&c.domain_id, &claims.domain_id);
                    prop_assert_eq!(&c.subject_user_id, &claims.subject_user_id);
                    prop_assert_eq!(&c.device_id, &claims.device_id);
                    prop_assert_eq!(&c.target_node_id, &claims.target_node_id);
                    prop_assert_eq!(&c.policy_id, &claims.policy_id);
                    prop_assert_eq!(c.issued_at, issued_at);
                    prop_assert_eq!(c.not_before, issued_at);
                    prop_assert_eq!(i128::from(c.expires_at) - i128::from(issued_at), i128::from($ttl));
                }};
            }
            if let Some(c) = result.ssh_issuance {
                common_fields!(&c, ttls[0]);
                prop_assert_eq!(&c.version, "2");
                prop_assert_eq!(c.ssh_public_key_fingerprint, ssh.public_key_fingerprint.clone());
                prop_assert_eq!(c.principals, ssh.principals.clone());
                prop_assert_eq!(c.nonce, claims.decision_id.clone());
                prop_assert_eq!(c.audience, "credential-issuer");
            }
            if let Some(c) = result.ssh_node_install {
                common_fields!(&c, ttls[0]);
                prop_assert_eq!(&c.version, "2");
                prop_assert_eq!(c.ssh_public_key_fingerprint, ssh.public_key_fingerprint);
                prop_assert_eq!(c.principals, ssh.principals);
                prop_assert_eq!(c.nonce, ssh.terminal_token_hash);
                prop_assert_eq!(c.audience, "node-agent");
            }
            if let Some(c) = result.network_grant {
                common_fields!(&c, ttls[1]);
                prop_assert_eq!(&c.version, "1");
                prop_assert_eq!(c.wireguard_public_key, network.wireguard_public_key);
                prop_assert_eq!(c.mesh_address, network.mesh_address);
                prop_assert_eq!(c.nonce, claims.decision_id.clone());
                prop_assert_eq!(c.audience, "node-agent");
            }
            for (output, audience) in [(result.mtls_issuance, "credential-issuer"), (result.mtls_node_install, "node-agent")] {
                if let Some(c) = output {
                    common_fields!(&c, ttls[2]);
                prop_assert_eq!(&c.version, "1");
                    prop_assert_eq!(&c.client_spki_sha256, &mtls.client_spki_sha256);
                    prop_assert_eq!(&c.identity_uri, &mtls.identity_uri);
                    prop_assert_eq!(&c.service_audience, &mtls.service_audience);
                    prop_assert_eq!(&c.decision_id, &claims.decision_id);
                    prop_assert_eq!(c.nonce, format!("{}_mtls_{}", claims.decision_id, audience.replace('-', "_")));
                    prop_assert_eq!(c.audience, audience);
                }
            }
            if let Some(c) = result.tcp_grant {
                common_fields!(&c, ttls[3]);
                prop_assert_eq!(&c.version, "2");
                prop_assert_eq!(c.resources.source_addresses, tcp.resources.source_addresses);
                prop_assert_eq!(c.resources.destination_addresses, tcp.resources.destination_addresses);
                prop_assert_eq!(c.resources.destination_ports, tcp.resources.destination_ports);
                prop_assert_eq!(c.decision_id, claims.decision_id);
                prop_assert_eq!(c.audience, "network-agent");
            }
        }
    }
}
