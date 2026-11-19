use std::{fs, path::Path};

use authority_contracts_model::{
    AccessAuthorizationBundleV1, IssuanceAuthorizationV1, MtlsIssuanceAuthorizationV1,
    NetworkAccessGrantV1, PolicyDecisionEvaluatedV1, PolicyDecisionEvaluatedV2,
    SignedDecisionRevocationNoticeV1, SignedDecisionRevocationNoticeV2,
    SignedIssuanceAuthorizationV1, SignedNetworkAccessGrantV1,
};

#[test]
fn protocol_bounds_match_the_versioned_wire_schemas() {
    use authority_contracts_model::protocol::{
        MAX_PLAN_CANDIDATES_V1, MAX_PLAN_MECHANISMS_V1, MAX_TCP_PORTS, PLANNING_EVIDENCE_VERSION_V2,
    };
    let plan: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/artifacts/policy-plan-evaluated-v2.schema.json"
    ))
    .unwrap();
    let tcp: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/artifacts/tcp-access-grant-v1.schema.json"
    ))
    .unwrap();
    assert_eq!(
        plan["$defs"]["planning"]["properties"]["selection_rule"]["const"].as_str(),
        Some(authority_contracts_model::protocol::PLAN_SELECTION_RULE_V1)
    );
    assert_eq!(
        plan["$defs"]["planning"]["properties"]["version"]["const"].as_u64(),
        Some(u64::from(PLANNING_EVIDENCE_VERSION_V2))
    );
    assert_eq!(
        plan["$defs"]["plan"]["properties"]["steps"]["maxItems"].as_u64(),
        u64::try_from(MAX_PLAN_MECHANISMS_V1).ok()
    );
    assert_eq!(
        plan["$defs"]["planning"]["properties"]["candidates"]["maxItems"].as_u64(),
        u64::try_from(MAX_PLAN_CANDIDATES_V1).ok()
    );
    assert_eq!(
        tcp["properties"]["destination_ports"]["maxItems"].as_u64(),
        u64::try_from(MAX_TCP_PORTS).ok()
    );
}

#[test]
fn valid_vectors_conform_and_have_stable_preimages() {
    for path in vectors("valid") {
        let bytes = fs::read(&path).expect("read valid vector");
        let contract: IssuanceAuthorizationV1 =
            serde_json::from_slice(&bytes).expect("deserialize valid vector");
        contract.validate().expect("validate valid vector");
        let first = contract.signing_preimage().expect("build preimage");
        let second = contract.signing_preimage().expect("rebuild preimage");
        assert_eq!(first, second, "unstable preimage for {}", path.display());

        let golden_path = path.with_extension("preimage.hex");
        let golden = fs::read_to_string(&golden_path).expect("read golden signing preimage");
        assert_eq!(
            encode_hex(&first),
            golden.trim(),
            "signing preimage changed for {}",
            path.display()
        );
    }
}

#[test]
fn mtls_authorization_vectors_conform() {
    for path in contract_vectors("mtls-issuance-authorization-v1", "valid") {
        let value: MtlsIssuanceAuthorizationV1 =
            serde_json::from_slice(&fs::read(&path).expect("read vector"))
                .expect("deserialize mTLS authorization");
        value.validate().expect("validate mTLS authorization");
    }
    for path in contract_vectors("mtls-issuance-authorization-v1", "invalid") {
        let rejected = serde_json::from_slice::<MtlsIssuanceAuthorizationV1>(
            &fs::read(&path).expect("read vector"),
        )
        .map_or(true, |value| value.validate().is_err());
        assert!(
            rejected,
            "invalid mTLS authorization accepted: {}",
            path.display()
        );
    }
}

#[test]
fn common_revocation_vectors_conform() {
    for path in contract_vectors("signed-decision-revocation-notice-v2", "valid") {
        let value: SignedDecisionRevocationNoticeV2 =
            serde_json::from_slice(&fs::read(&path).expect("read vector"))
                .expect("deserialize common revocation");
        value.validate().expect("validate common revocation");
    }
    for path in contract_vectors("signed-decision-revocation-notice-v2", "invalid") {
        let rejected = serde_json::from_slice::<SignedDecisionRevocationNoticeV2>(
            &fs::read(&path).expect("read vector"),
        )
        .map_or(true, |value| value.validate().is_err());
        assert!(
            rejected,
            "invalid common revocation accepted: {}",
            path.display()
        );
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[test]
fn invalid_vectors_are_rejected() {
    for path in vectors("invalid") {
        let bytes = fs::read(&path).expect("read invalid vector");
        let rejected = serde_json::from_slice::<IssuanceAuthorizationV1>(&bytes)
            .map_or(true, |contract| contract.validate().is_err());
        assert!(rejected, "invalid vector was accepted: {}", path.display());
    }
}

#[test]
fn signed_envelope_vectors_conform() {
    for path in envelope_vectors("valid") {
        let bytes = fs::read(&path).expect("read valid envelope vector");
        let contract: SignedIssuanceAuthorizationV1 =
            serde_json::from_slice(&bytes).expect("deserialize valid envelope vector");
        contract.validate().expect("validate envelope vector");
    }

    for path in envelope_vectors("invalid") {
        let bytes = fs::read(&path).expect("read invalid envelope vector");
        let rejected = serde_json::from_slice::<SignedIssuanceAuthorizationV1>(&bytes)
            .map_or(true, |contract| contract.validate().is_err());
        assert!(
            rejected,
            "invalid envelope vector was accepted: {}",
            path.display()
        );
    }
}

#[test]
fn network_grant_vectors_conform() {
    for path in contract_vectors("network-access-grant-v1", "valid") {
        let bytes = fs::read(&path).expect("read valid network grant");
        let grant: NetworkAccessGrantV1 =
            serde_json::from_slice(&bytes).expect("deserialize valid network grant");
        grant.validate().expect("validate network grant");
        let preimage = grant.signing_preimage().expect("build network preimage");
        let golden =
            fs::read_to_string(path.with_extension("preimage.hex")).expect("read network preimage");
        assert_eq!(encode_hex(&preimage), golden.trim());
    }
    for path in contract_vectors("network-access-grant-v1", "invalid") {
        let bytes = fs::read(&path).expect("read invalid network grant");
        let rejected = serde_json::from_slice::<NetworkAccessGrantV1>(&bytes)
            .map_or(true, |grant| grant.validate().is_err());
        assert!(
            rejected,
            "invalid network grant accepted: {}",
            path.display()
        );
    }
}

#[test]
fn signed_network_grant_vectors_conform() {
    for path in contract_vectors("signed-network-access-grant-v1", "valid") {
        let bytes = fs::read(&path).expect("read signed network grant");
        let grant: SignedNetworkAccessGrantV1 =
            serde_json::from_slice(&bytes).expect("deserialize signed network grant");
        grant.validate().expect("validate signed network grant");
    }
    for path in contract_vectors("signed-network-access-grant-v1", "invalid") {
        let bytes = fs::read(&path).expect("read invalid signed network grant");
        let rejected = serde_json::from_slice::<SignedNetworkAccessGrantV1>(&bytes)
            .map_or(true, |grant| grant.validate().is_err());
        assert!(
            rejected,
            "invalid signed network grant accepted: {}",
            path.display()
        );
    }
}

#[test]
fn access_authorization_bundle_vectors_conform() {
    for path in contract_vectors("access-authorization-bundle-v1", "valid") {
        let bytes = fs::read(&path).expect("read access authorization bundle");
        let bundle: AccessAuthorizationBundleV1 =
            serde_json::from_slice(&bytes).expect("deserialize access authorization bundle");
        bundle
            .validate()
            .expect("validate access authorization bundle");
    }
    for path in contract_vectors("access-authorization-bundle-v1", "invalid") {
        let bytes = fs::read(&path).expect("read invalid access authorization bundle");
        let rejected = serde_json::from_slice::<AccessAuthorizationBundleV1>(&bytes)
            .map_or(true, |bundle| bundle.validate().is_err());
        assert!(
            rejected,
            "invalid access authorization bundle accepted: {}",
            path.display()
        );
    }
}

#[test]
fn policy_decision_vectors_conform() {
    for path in contract_vectors("policy-decision-evaluated-v1", "valid") {
        let bytes = fs::read(&path).expect("read policy decision trace");
        let trace: PolicyDecisionEvaluatedV1 =
            serde_json::from_slice(&bytes).expect("deserialize policy decision trace");
        trace.validate().expect("validate policy decision trace");
    }
    for path in contract_vectors("policy-decision-evaluated-v1", "invalid") {
        let bytes = fs::read(&path).expect("read invalid policy decision trace");
        let rejected = serde_json::from_slice::<PolicyDecisionEvaluatedV1>(&bytes)
            .map_or(true, |trace| trace.validate().is_err());
        assert!(
            rejected,
            "invalid policy decision trace accepted: {}",
            path.display()
        );
    }
}

#[test]
fn ability_policy_decision_vectors_conform() {
    for (kind, expected) in [("valid", true), ("invalid", false)] {
        for path in contract_vectors("policy-decision-evaluated-v2", kind) {
            let bytes = fs::read(&path).unwrap();
            let valid = serde_json::from_slice::<PolicyDecisionEvaluatedV2>(&bytes)
                .is_ok_and(|trace| trace.validate().is_ok());
            assert_eq!(valid, expected, "{}", path.display());
        }
    }
}

#[test]
fn signed_revocation_notice_vectors_conform() {
    for path in contract_vectors("signed-decision-revocation-notice-v1", "valid") {
        let bytes = fs::read(&path).expect("read signed revocation notice");
        let notice: SignedDecisionRevocationNoticeV1 =
            serde_json::from_slice(&bytes).expect("deserialize signed revocation notice");
        notice
            .validate()
            .expect("validate signed revocation notice");
    }
    for path in contract_vectors("signed-decision-revocation-notice-v1", "invalid") {
        let bytes = fs::read(&path).expect("read invalid signed revocation notice");
        let rejected = serde_json::from_slice::<SignedDecisionRevocationNoticeV1>(&bytes)
            .map_or(true, |notice| notice.validate().is_err());
        assert!(
            rejected,
            "invalid revocation notice accepted: {}",
            path.display()
        );
    }
}

fn contract_vectors(contract: &str, kind: &str) -> Vec<std::path::PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test-vectors")
        .join(contract)
        .join(kind);
    let mut paths: Vec<_> = fs::read_dir(directory)
        .expect("read contract vector directory")
        .map(|entry| entry.expect("read vector entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "contract vector set must not be empty");
    paths
}

fn vectors(kind: &str) -> Vec<std::path::PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test-vectors/issuance-authorization-v1")
        .join(kind);
    let mut paths: Vec<_> = fs::read_dir(directory)
        .expect("read vector directory")
        .map(|entry| entry.expect("read vector entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "contract vector set must not be empty");
    paths
}

fn envelope_vectors(kind: &str) -> Vec<std::path::PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test-vectors/signed-issuance-authorization-v1")
        .join(kind);
    let mut paths: Vec<_> = fs::read_dir(directory)
        .expect("read envelope vector directory")
        .map(|entry| entry.expect("read vector entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "envelope vector set must not be empty");
    paths
}

#[test]
fn tcp_grant_vectors_conform_and_preserve_preimages() {
    use authority_contracts_model::{SignedTcpAccessGrantV1, TcpAccessGrantV1};
    for path in contract_vectors("tcp-access-grant-v1", "valid") {
        let grant: TcpAccessGrantV1 = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let preimage = grant.signing_preimage().unwrap();
        assert_eq!(
            encode_hex(&preimage),
            fs::read_to_string(path.with_extension("preimage.hex"))
                .unwrap()
                .trim()
        );
    }
    for path in contract_vectors("signed-tcp-access-grant-v1", "valid") {
        let grant: SignedTcpAccessGrantV1 =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        grant.validate().unwrap();
    }
    for path in contract_vectors("tcp-access-grant-v1", "invalid") {
        assert!(
            serde_json::from_slice::<TcpAccessGrantV1>(&fs::read(&path).unwrap())
                .map_or(true, |grant| grant.validate().is_err()),
            "{}",
            path.display()
        );
    }
    for path in contract_vectors("signed-tcp-access-grant-v1", "invalid") {
        assert!(
            serde_json::from_slice::<SignedTcpAccessGrantV1>(&fs::read(&path).unwrap())
                .map_or(true, |grant| grant.validate().is_err()),
            "{}",
            path.display()
        );
    }
}
