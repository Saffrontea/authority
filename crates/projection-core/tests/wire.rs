//! Native correspondence from scoped policy evaluation to signed JSON consumers.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

use authority_contracts_model::{
    SignedIssuanceAuthorizationV1, SignedMtlsIssuanceAuthorizationV1, SignedNetworkAccessGrantV1,
    SignedTcpAccessGrantV1,
    protocol::{CREDENTIAL_ISSUER_AUDIENCE, NETWORK_AGENT_AUDIENCE, NODE_AGENT_AUDIENCE},
};
use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
use authority_issuer_core::{
    AuthorizationEnvelopeError, sign_authorization, sign_mtls_authorization, sign_network_grant,
    sign_tcp_grant, verify_authorization, verify_mtls_authorization, verify_network_grant_for_node,
    verify_tcp_grant_for_node,
};
use authority_policy_core::{
    AccessIntent, AccessRequest, Capability, Effect, IdentityFacts, Outcome, PolicyRef, PolicyRule,
    PolicySnapshot, Route,
    scoped::{
        AuthorizedPlan, LifetimeLimits, NetworkResources, PolicyScope, RequestedAccess,
        RequestedMtls, RequestedNetwork, RequestedSsh, RequestedTcp, evaluate_scoped,
    },
};
use authority_projection_core::{CommonDecisionClaims, project_authorized};
use proptest::prelude::*;
use serde_json::{Value, json};
use uuid::Uuid;

static KEYS: LazyLock<(OpenSslEd25519Signer, OpenSslEd25519Verifier)> = LazyLock::new(|| {
    let signer = OpenSslEd25519Signer::generate("wire-properties").unwrap();
    let verifier =
        OpenSslEd25519Verifier::from_pem("wire-properties", &signer.public_key_to_pem().unwrap())
            .unwrap();
    (signer, verifier)
});

#[derive(Debug)]
struct Case {
    ids: [u128; 4],
    now: i64,
    mask: u8,
    ttls: [i64; 4],
    principals: BTreeSet<String>,
    ports: BTreeSet<u16>,
    service: String,
}

fn authorize(
    case: &Case,
) -> Result<(AuthorizedPlan, CommonDecisionClaims), authority_policy_core::scoped::ScopeError> {
    let [domain_id, subject_user_id, device_id, target_node_id] = case.ids.map(Uuid::from_u128);
    let mut outcomes = BTreeSet::new();
    for (bit, outcome) in [
        (1, Outcome::Ssh),
        (2, Outcome::MtlsService),
        (4, Outcome::TcpConnect),
        (8, Outcome::NetworkReachability),
    ] {
        if case.mask & bit != 0 {
            outcomes.insert(outcome);
        }
    }
    let request = AccessRequest {
        domain_id,
        subject_user_id,
        device_id,
        target_node_id,
        evaluated_at: case.now,
        intent: AccessIntent {
            outcomes,
            route: if case.mask & 8 != 0 {
                Route::MeshRequired
            } else {
                Route::Direct
            },
        },
    };
    let policy = PolicyRef {
        policy_id: Uuid::from_u128(5),
        revision: 7,
    };
    let snapshot = PolicySnapshot {
        identity: IdentityFacts {
            device_domain_id: domain_id,
            device_owner_user_id: Some(subject_user_id),
            device_active: true,
            target_active: true,
        },
        rules: vec![PolicyRule {
            policy_id: policy.policy_id,
            revision: policy.revision,
            domain_id,
            subject_user_id,
            required_device_id: Some(device_id),
            target_node_id,
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
            valid_from: Some(case.now),
            valid_until: Some(case.now + 300),
        }],
    };
    let scopes = BTreeMap::from([(
        policy,
        PolicyScope {
            ssh_principals: case.principals.clone(),
            tcp_ports: case.ports.clone(),
        },
    )]);
    let requested = requested(case);
    let resources = NetworkResources {
        environment: authority_policy_core::realization::endpoint_facts(),
        source_address: "10.77.0.1".parse().unwrap(),
        target_address: "10.77.0.2".parse().unwrap(),
        registered_wireguard_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        service_audience: case.service.clone(),
    };
    let (_, plan) = evaluate_scoped(
        &request,
        &snapshot,
        &scopes,
        &requested,
        &resources,
        LifetimeLimits {
            ssh_seconds: 60,
            network_seconds: 300,
        },
    )?;
    let common = CommonDecisionClaims {
        decision_id: format!("{:032x}", case.ids[0]),
        issuer: format!("domain-authority:{domain_id}"),
        domain_id: domain_id.to_string(),
        subject_user_id: subject_user_id.to_string(),
        device_id: device_id.to_string(),
        target_node_id: target_node_id.to_string(),
        policy_id: plan.policy_reference().into(),
        issued_at: case.now,
    };
    Ok((plan, common))
}

fn requested(case: &Case) -> RequestedAccess {
    RequestedAccess {
        ssh: (case.mask & 1 != 0).then(|| RequestedSsh {
            public_key_fingerprint: hash('A'),
            principals: Some(case.principals.clone()),
            terminal_token_hash: "B".repeat(43),
            ttl_seconds: case.ttls[0],
        }),
        mtls: (case.mask & 2 != 0).then(|| RequestedMtls {
            client_spki_sha256: hash('C'),
            ttl_seconds: case.ttls[1],
        }),
        tcp: (case.mask & 4 != 0).then(|| RequestedTcp {
            ports: case.ports.clone(),
            ttl_seconds: case.ttls[2],
        }),
        network: (case.mask & 8 != 0).then_some(RequestedNetwork {
            wireguard_public_key: None,
            ttl_seconds: case.ttls[3],
        }),
    }
}

fn hash(first: char) -> String {
    format!("SHA256:{first}{}", "A".repeat(42))
}

#[derive(Clone, Copy, Debug)]
enum Family {
    SshIssuer,
    SshNode,
    MtlsIssuer,
    MtlsNode,
    Wg,
    Tcp,
}
impl Family {
    fn body(self) -> &'static str {
        if matches!(self, Self::Wg | Self::Tcp) {
            "grant"
        } else {
            "authorization"
        }
    }
    fn ttl(self, case: &Case) -> i64 {
        case.ttls[match self {
            Self::SshIssuer | Self::SshNode => 0,
            Self::MtlsIssuer | Self::MtlsNode => 1,
            Self::Tcp => 2,
            Self::Wg => 3,
        }]
    }
    fn audience(self) -> &'static str {
        match self {
            Self::SshIssuer | Self::MtlsIssuer => CREDENTIAL_ISSUER_AUDIENCE,
            Self::Tcp => NETWORK_AGENT_AUDIENCE,
            _ => NODE_AGENT_AUDIENCE,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum WireError {
    #[error(transparent)]
    Schema(#[from] serde_json::Error),
    #[error(transparent)]
    Envelope(#[from] AuthorizationEnvelopeError),
}

fn consume(family: Family, value: &Value, target: &str, now: i64) -> Result<(), WireError> {
    consume_wire(family, &serde_json::to_vec(value)?, target, now)
}

fn consume_wire(family: Family, wire: &[u8], target: &str, now: i64) -> Result<(), WireError> {
    match family {
        Family::SshIssuer | Family::SshNode => {
            let envelope: SignedIssuanceAuthorizationV1 = serde_json::from_slice(wire)?;
            verify_authorization(&envelope, &KEYS.1)?;
        }
        Family::MtlsIssuer | Family::MtlsNode => {
            let envelope: SignedMtlsIssuanceAuthorizationV1 = serde_json::from_slice(wire)?;
            verify_mtls_authorization(&envelope, &KEYS.1)?;
        }
        Family::Wg => {
            let envelope: SignedNetworkAccessGrantV1 = serde_json::from_slice(wire)?;
            verify_network_grant_for_node(&envelope, &KEYS.1, target, now)?;
        }
        Family::Tcp => {
            let envelope: SignedTcpAccessGrantV1 = serde_json::from_slice(wire)?;
            verify_tcp_grant_for_node(&envelope, &KEYS.1, target, now)?;
        }
    }
    Ok(())
}

fn changed(value: &Value, key: &str) -> Value {
    match value {
        Value::Number(number) => json!(number.as_i64().unwrap() + 1),
        Value::Array(values) if key == "destination_ports" => {
            let mut ports: BTreeSet<u16> = values
                .iter()
                .map(|v| u16::try_from(v.as_u64().unwrap()).unwrap())
                .collect();
            ports.insert((1..=u16::MAX).find(|p| !ports.contains(p)).unwrap());
            json!(ports)
        }
        Value::Array(values) => {
            let mut values = values.clone();
            values.push(json!("z-unauthorized"));
            values.sort_by_key(Value::to_string);
            json!(values)
        }
        Value::String(text) if key.ends_with("fingerprint") || key.ends_with("sha256") => {
            json!(hash('D'))
        }
        Value::String(_) if key.ends_with("address") => json!("10.77.0.99"),
        Value::String(text)
            if key == "wireguard_public_key"
                || key == "signature"
                || (key == "nonce" && text.len() == 43) =>
        {
            let first = if text.starts_with('A') { 'B' } else { 'A' };
            json!(format!("{first}{}", &text[1..]))
        }
        Value::String(text) => json!(format!("{text}-other")),
        _ => panic!("unhandled protocol field {key}"),
    }
}

proptest! {
    #[test]
    fn authorized_scopes_survive_signed_wire_consumers_and_reject_claim_mutation(
        ids in any::<[u128; 4]>(),
        now in prop_oneof![Just(0_i64), Just(i64::MAX - 301), 0_i64..2_000_000_000],
        mask in 1_u8..16,
        ttls in (1_i64..=60, 1_i64..=300, 1_i64..=300, 1_i64..=300),
        principals in prop::collection::btree_set("[a-z][a-z0-9_-]{0,7}", 1..=3),
        ports in prop::collection::btree_set(1_u16..=u16::MAX, 1..=4),
        service in "[a-z][a-z0-9-]{0,15}",
    ) {
        let case = Case { ids, now, mask, ttls: [ttls.0, ttls.1, ttls.2, ttls.3], principals, ports, service };
        let outcome = authorize(&case);
        if case.mask & 8 != 0 && [(1,case.ttls[0]),(2,case.ttls[1]),(4,case.ttls[2])].iter().any(|(bit,ttl)|case.mask & bit != 0 && *ttl > case.ttls[3]) {
            prop_assert!(outcome.is_err());
            return Ok(());
        }
        let (plan, common) = outcome.unwrap();
        let projected = project_authorized(&common, &plan).unwrap();
        let mut envelopes = Vec::new();
        macro_rules! add { ($field:ident, $family:expr, $sign:ident) => {
            if let Some(claims) = projected.$field { envelopes.push(($family, serde_json::to_value($sign(claims, &KEYS.0).unwrap()).unwrap())); }
        }; }
        add!(ssh_issuance, Family::SshIssuer, sign_authorization);
        add!(ssh_node_install, Family::SshNode, sign_authorization);
        add!(mtls_issuance, Family::MtlsIssuer, sign_mtls_authorization);
        add!(mtls_node_install, Family::MtlsNode, sign_mtls_authorization);
        add!(network_grant, Family::Wg, sign_network_grant);
        add!(tcp_grant, Family::Tcp, sign_tcp_grant);
        let expected = usize::from(mask & 1 != 0) * 2 + usize::from(mask & 2 != 0) * 2
            + usize::from(mask & 4 != 0) + usize::from(mask & 8 != 0);
        prop_assert_eq!(envelopes.len(), expected);
        for (family, signed) in envelopes {
            // Value serialization changes object ordering; pretty JSON also changes whitespace.
            let wire = serde_json::to_vec_pretty(&signed).unwrap();
            let decoded: Value = serde_json::from_slice(&wire).unwrap();
            prop_assert!(consume_wire(family, &wire, &common.target_node_id, now).is_ok());
            let body = &decoded[family.body()];
            for (key, expected) in [("issuer", &common.issuer), ("domain_id", &common.domain_id),
                ("subject_user_id", &common.subject_user_id), ("device_id", &common.device_id),
                ("target_node_id", &common.target_node_id), ("policy_id", &common.policy_id)] {
                prop_assert_eq!(&body[key], &json!(expected));
            }
            prop_assert_eq!(&body["audience"], &json!(family.audience()));
            prop_assert_eq!(&body["issued_at"], &json!(now));
            prop_assert_eq!(&body["not_before"], &json!(now));
            prop_assert_eq!(&body["expires_at"], &json!(now + family.ttl(&case)));
            match family {
                Family::SshIssuer | Family::SshNode => {
                    prop_assert_eq!(&body["principals"], &json!(case.principals));
                    prop_assert_eq!(&body["ssh_public_key_fingerprint"], &json!(hash('A')));
                    prop_assert_eq!(&body["nonce"], &json!(if matches!(family, Family::SshNode) { "B".repeat(43) } else { common.decision_id.clone() }));
                }
                Family::MtlsIssuer | Family::MtlsNode => {
                    prop_assert_eq!(&body["client_spki_sha256"], &json!(hash('C')));
                    prop_assert_eq!(&body["service_audience"], &json!(case.service));
                    prop_assert_eq!(&body["identity_uri"], &json!(format!("spiffe://authority.local/domain/{}/user/{}/device/{}", common.domain_id, common.subject_user_id, common.device_id)));
                    prop_assert_eq!(&body["decision_id"], &json!(common.decision_id));
                }
                Family::Wg => {
                    prop_assert_eq!(&body["wireguard_public_key"], &json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
                    prop_assert_eq!(&body["mesh_address"], &json!("10.77.0.1"));
                    prop_assert_eq!(&body["nonce"], &json!(common.decision_id));
                }
                Family::Tcp => {
                    prop_assert_eq!(&body["destination_ports"], &json!(case.ports));
                    prop_assert_eq!(&body["source_address"], &json!("10.77.0.1"));
                    prop_assert_eq!(&body["destination_address"], &json!("10.77.0.2"));
                    prop_assert_eq!(&body["decision_id"], &json!(common.decision_id));
                }
            }
            for key in body.as_object().unwrap().keys() {
                let mut tampered = decoded.clone();
                tampered[family.body()][key] = changed(&body[key], key);
                prop_assert!(consume(family, &tampered, &common.target_node_id, now).is_err(), "unsigned claim mutation accepted: {family:?}/{key}");
                let mut missing = decoded.clone();
                missing[family.body()].as_object_mut().unwrap().remove(key);
                prop_assert!(matches!(consume(family, &missing, &common.target_node_id, now), Err(WireError::Schema(_))), "missing claim accepted: {key}");
            }
            for key in ["algorithm", "key_id", "signature"] {
                let mut tampered = decoded.clone();
                tampered[key] = changed(&decoded[key], key);
                prop_assert!(consume(family, &tampered, &common.target_node_id, now).is_err());
                let mut missing = decoded.clone();
                missing.as_object_mut().unwrap().remove(key);
                prop_assert!(matches!(consume(family, &missing, &common.target_node_id, now), Err(WireError::Schema(_))));
            }
            for other in [Family::SshIssuer, Family::MtlsIssuer, Family::Wg, Family::Tcp] {
                if std::mem::discriminant(&other) != std::mem::discriminant(&family)
                    && !matches!((family, other), (Family::SshNode, Family::SshIssuer) | (Family::MtlsNode, Family::MtlsIssuer)) {
                    prop_assert!(consume(other, &decoded, &common.target_node_id, now).is_err(), "cross-family envelope accepted");
                }
            }
            for nested in [false, true] {
                let mut unknown = decoded.clone();
                if nested { unknown[family.body()]["unknown_authority"] = json!(true); }
                else { unknown["unknown_authority"] = json!(true); }
                prop_assert!(matches!(consume(family, &unknown, &common.target_node_id, now), Err(WireError::Schema(_))));
            }
            let mut valid_tamper = decoded.clone();
            valid_tamper[family.body()]["target_node_id"] = json!(Uuid::from_u128(case.ids[3] ^ 1).to_string());
            prop_assert!(matches!(consume(family, &valid_tamper, &common.target_node_id, now), Err(WireError::Envelope(AuthorizationEnvelopeError::VerificationFailed))));
            if matches!(family, Family::Wg | Family::Tcp) {
                // Sign well-shaped, deliberately misdirected claims: signature
                // verification succeeds, so the receiver context must reject them.
                let mut bad_audience = body.clone();
                bad_audience["audience"] = json!("other-consumer");
                let resigned = match family {
                    Family::Wg => serde_json::to_value(sign_network_grant(serde_json::from_value(bad_audience).unwrap(), &KEYS.0).unwrap()).unwrap(),
                    Family::Tcp => serde_json::to_value(sign_tcp_grant(serde_json::from_value(bad_audience).unwrap(), &KEYS.0).unwrap()).unwrap(),
                    _ => unreachable!(),
                };
                prop_assert!(matches!(consume(family, &resigned, &common.target_node_id, now), Err(WireError::Envelope(AuthorizationEnvelopeError::InvalidAudience))));
                let end = now + family.ttl(&case);
                prop_assert!(consume(family, &decoded, &common.target_node_id, end - 1).is_ok());
                for outside in [now - 1, end] {
                    prop_assert!(matches!(consume(family, &decoded, &common.target_node_id, outside), Err(WireError::Envelope(AuthorizationEnvelopeError::GrantNotActive))));
                }
                let other = Uuid::from_u128(case.ids[3] ^ 1).to_string();
                prop_assert!(matches!(consume(family, &decoded, &other, now), Err(WireError::Envelope(AuthorizationEnvelopeError::TargetNodeMismatch))));
            }
        }
    }
}
