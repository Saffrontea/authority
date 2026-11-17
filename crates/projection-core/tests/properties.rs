use authority_projection_core::{
    CommonDecisionClaims, MtlsProjectionRequest, NetworkProjectionRequest, ProjectionLifetimes,
    SshProjectionRequest, project,
};
use proptest::prelude::*;

fn fixture(
    ssh: i64,
    network: i64,
    mtls: i64,
) -> Result<authority_projection_core::ProjectionSet, authority_projection_core::ProjectionError> {
    project(
        &CommonDecisionClaims {
            decision_id: "0123456789abcdef0123456789abcdef".into(),
            issuer: "domain-authority:example".into(),
            domain_id: "domain_example".into(),
            subject_user_id: "user_01".into(),
            device_id: "device_01".into(),
            target_node_id: "node_01".into(),
            policy_id: "policy_01@1".into(),
            issued_at: 1_700_000_000,
        },
        &SshProjectionRequest {
            public_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            principals: vec!["deploy".into()],
            terminal_token_hash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
        },
        &NetworkProjectionRequest {
            wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            mesh_address: "10.77.0.1".into(),
        },
        &MtlsProjectionRequest {
            client_spki_sha256: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
            identity_uri: "spiffe://authority.example/user/user_01/device/device_01".into(),
            service_audience: "demo-api".into(),
        },
        ProjectionLifetimes {
            ssh_seconds: ssh,
            network_seconds: network,
            mtls_seconds: mtls,
        },
    )
}

proptest! {
    #[test]
    fn all_protocols_preserve_common_claims(ssh in 1_i64..=600, network in 1_i64..=600, mtls in 1_i64..=600) {
        let result = fixture(ssh, network, mtls).expect("valid projection");
        prop_assert_eq!(&result.ssh_issuance.domain_id, &result.network_grant.domain_id);
        prop_assert_eq!(&result.network_grant.domain_id, &result.mtls_issuance.domain_id);
        prop_assert_eq!(&result.ssh_issuance.target_node_id, &result.mtls_issuance.target_node_id);
        prop_assert_eq!(&result.ssh_issuance.policy_id, &result.network_grant.policy_id);
        prop_assert_eq!(&result.mtls_issuance.decision_id, &result.network_grant.nonce);
        prop_assert_ne!(&result.mtls_issuance.nonce, &result.ssh_issuance.nonce);
        prop_assert_eq!(result.ssh_issuance.expires_at - result.ssh_issuance.issued_at, ssh);
        prop_assert_eq!(result.network_grant.expires_at - result.network_grant.issued_at, network);
        prop_assert_eq!(result.mtls_issuance.expires_at - result.mtls_issuance.issued_at, mtls);
    }

    #[test]
    fn invalid_adapter_lifetime_rejects_the_whole_projection(index in 0_usize..3, value in prop_oneof![-100_i64..=0, 601_i64..=1000]) {
        let mut ttls = [60, 60, 60];
        ttls[index] = value;
        prop_assert!(fixture(ttls[0], ttls[1], ttls[2]).is_err());
    }
}

proptest! {
    #[test]
    fn tcp_projection_preserves_selected_ports_and_independent_deadline(
        ports in prop::collection::btree_set(1_u16..=65535, 1..=64), ttl in 1_i64..=600,
    ) {
        use authority_projection_core::{project_tcp, project_network, TcpProjectionRequest};
        let common = CommonDecisionClaims {
            decision_id: "0123456789abcdef0123456789abcdef".into(),
            issuer: "domain-authority:example".into(), domain_id: "domain_example".into(),
            subject_user_id: "user_01".into(), device_id: "device_01".into(), target_node_id: "node_01".into(),
            policy_id: "policy_01@1".into(), issued_at: 1_700_000_000,
        };
        let ports = ports.into_iter().collect::<Vec<_>>();
        let tcp = project_tcp(&common, &TcpProjectionRequest {
            source_address: "10.77.0.1".into(), destination_address: "10.77.0.2".into(), destination_ports: ports.clone(),
        }, ttl).unwrap();
        prop_assert_eq!(&tcp.destination_ports, &ports);
        prop_assert_eq!(tcp.expires_at - tcp.issued_at, ttl);
        prop_assert_eq!(&tcp.decision_id, &common.decision_id);
        let network = project_network(&common, &NetworkProjectionRequest {
            mesh_address: "10.77.0.1".into(), wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        }, 600).unwrap();
        prop_assert_eq!(tcp.decision_id, network.nonce);
        prop_assert_eq!(tcp.source_address, network.mesh_address);
        prop_assert_eq!(network.expires_at - network.issued_at, 600);
    }
}
