//! Exercise the same issuance path used by HTTP, including nonce persistence.
use super::*;
use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
use authority_issuer_core::{sign_authorization, sign_mtls_authorization};
use authority_projection_core::{
    CommonDecisionClaims, MtlsProjectionRequest, NetworkProjectionRequest, ProjectionLifetimes,
    SshProjectionRequest, project,
};
use authority_replay_ledger::ReplayLedger;
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::Private,
};
use openssl::{
    stack::Stack,
    x509::{
        X509ExtendedKeyUsage, X509KeyUsage, X509PurposeId, X509StoreContext,
        store::X509StoreBuilder, verify::X509VerifyParam,
    },
};
use proptest::prelude::*;
use ssh_key::{Algorithm, Certificate, PrivateKey};
use std::sync::LazyLock;
use tempfile::TempDir;

struct Keys {
    control: OpenSslEd25519Signer,
    ssh_ca: PrivateKey,
    ssh: [PrivateKey; 2],
    mtls: [PKey<Private>; 2],
    ca: crate::mtls_ca::MtlsCa,
    now: i64,
}
static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let ca = crate::mtls_ca::load_or_generate(
        &directory.path().join("key"),
        &directory.path().join("cert"),
    )
    .unwrap();
    Keys {
        control: OpenSslEd25519Signer::generate("consumer-properties").unwrap(),
        ssh_ca: PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
        ssh: std::array::from_fn(|_| PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()),
        mtls: std::array::from_fn(|_| PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()),
        ca,
        now: unix_timestamp().unwrap() + 10,
    }
});

struct Case {
    id: u128,
    now: i64,
    ttl: i64,
    principals: Vec<String>,
    key: usize,
}
fn fixture(case: &Case) -> (TempDir, AppState, authority_projection_core::ProjectionSet) {
    let directory = tempfile::tempdir().unwrap();
    let verifier = OpenSslEd25519Verifier::from_pem(
        "consumer-properties",
        &KEYS.control.public_key_to_pem().unwrap(),
    )
    .unwrap();
    let state = AppState::new(
        verifier,
        KEYS.ssh_ca.clone(),
        ReplayLedger::open(directory.path().join("ledger"), case.now).unwrap(),
        42,
    );
    state
        .install_mtls_ca(crate::mtls_ca::MtlsCa {
            key: KEYS.ca.key.clone(),
            certificate: KEYS.ca.certificate.clone(),
        })
        .unwrap();
    let common = CommonDecisionClaims {
        decision_id: format!("{:032x}", case.id),
        issuer: "domain-authority:example".into(),
        domain_id: "domain_example".into(),
        subject_user_id: format!("user_{:x}", case.id),
        device_id: "device_01".into(),
        target_node_id: "node_01".into(),
        policy_id: "policy_01@1".into(),
        issued_at: case.now,
    };
    let spki = KEYS.mtls[case.key].public_key_to_der().unwrap();
    let fingerprint = format!(
        "SHA256:{}",
        openssl::base64::encode_block(&openssl::sha::sha256(&spki)).trim_end_matches('=')
    );
    let projections = project(
        &common,
        &SshProjectionRequest {
            public_key_fingerprint: KEYS.ssh[case.key]
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string(),
            principals: case.principals.clone(),
            terminal_token_hash: "B".repeat(43),
        },
        &NetworkProjectionRequest {
            wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            mesh_address: "10.77.0.1".into(),
        },
        &MtlsProjectionRequest {
            client_spki_sha256: fingerprint,
            identity_uri: format!(
                "spiffe://authority.local/domain/domain_example/user/{}/device/device_01",
                common.subject_user_id
            ),
            service_audience: format!("service-{:x}.example", case.id),
        },
        ProjectionLifetimes {
            ssh_seconds: case.ttl,
            network_seconds: 300,
            mtls_seconds: case.ttl,
        },
    )
    .unwrap();
    (directory, state, projections)
}

fn ssh_request(
    auth: &SignedIssuanceAuthorizationV1,
    key: &PrivateKey,
) -> IssueSshCertificateRequest {
    serde_json::from_value(
        json!({"authorization": auth, "ssh_public_key": key.public_key().to_openssh().unwrap()}),
    )
    .unwrap()
}
fn mtls_request(
    auth: &SignedMtlsIssuanceAuthorizationV1,
    key: &PKey<Private>,
) -> IssueMtlsCertificateRequest {
    serde_json::from_value(json!({"authorization": auth, "public_key_pem": String::from_utf8(key.public_key_to_pem().unwrap()).unwrap()})).unwrap()
}

proptest! {
    #[test]
    fn issuer_context_and_certificate_material_match_projected_authority(
        id in any::<u128>(), offset in 0_i64..600, ttl in 1_i64..=300,
        principals in prop::collection::btree_set("[a-z][a-z0-9_-]{0,7}", 1..=3),
        key in 0_usize..2, mtls in any::<bool>(),
    ) {
        let case = Case { id, now: KEYS.now + offset, ttl, principals: principals.into_iter().collect(), key };
        let (_directory, state, projections) = fixture(&case);
        if mtls {
            let claims = projections.mtls_issuance;
            let envelope = sign_mtls_authorization(claims.clone(), &KEYS.control).unwrap();
            let valid = || mtls_request(&envelope, &KEYS.mtls[key]);
            for time in [case.now - 1, case.now + ttl] {
                let result = issue_mtls_certificate_with_clock(&state, &valid(), || Ok(time));
                prop_assert_eq!(result.expect_err("reject inactive").code, "authorization_expired");
            }
            let wrong = sign_mtls_authorization(projections.mtls_node_install, &KEYS.control).unwrap();
            let result = issue_mtls_certificate_with_clock(&state, &mtls_request(&wrong, &KEYS.mtls[key]), || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject node audience").code, "invalid_audience");
            let result = issue_mtls_certificate_with_clock(&state, &mtls_request(&envelope, &KEYS.mtls[1-key]), || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject wrong key").code, "mtls_key_fingerprint_mismatch");
            let mut malformed = valid(); malformed.public_key_pem = "not a public key".into();
            let result = issue_mtls_certificate_with_clock(&state, &malformed, || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject malformed key").code, "invalid_mtls_public_key");
            let mut corrupt = valid(); corrupt.authorization.signature.replace_range(..1, if envelope.signature.starts_with('A') { "B" } else { "A" });
            let result = issue_mtls_certificate_with_clock(&state, &corrupt, || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject signature").code, "invalid_mtls_authorization");
            // Rejections must neither consume the valid nonce nor advance serials.
            let response = issue_mtls_certificate_with_clock(&state, &valid(), || Ok(case.now)).unwrap();
            let certificate = X509::from_pem(response.certificate_pem.as_bytes()).unwrap();
            prop_assert_eq!(certificate.serial_number().to_bn().unwrap().to_dec_str().unwrap().to_string(), "42");
            prop_assert!(certificate.verify(&KEYS.ca.key).unwrap());
            prop_assert_eq!(certificate.key_usage(), Some(X509KeyUsage::DIGITAL_SIGNATURE));
            prop_assert_eq!(certificate.extended_key_usage(), Some(X509ExtendedKeyUsage::SSL_CLIENT));
            let mut store = X509StoreBuilder::new().unwrap();
            store.add_cert(KEYS.ca.certificate.clone()).unwrap();
            store.set_purpose(X509PurposeId::SSL_CLIENT).unwrap();
            let mut parameters = X509VerifyParam::new().unwrap();
            parameters.set_time(case.now);
            store.set_param(&parameters).unwrap();
            let store = store.build();
            let chain = Stack::new().unwrap();
            let mut context = X509StoreContext::new().unwrap();
            prop_assert!(context.init(&store, &certificate, &chain, openssl::x509::X509StoreContextRef::verify_cert).unwrap());
            prop_assert!(certificate.public_key().unwrap().public_eq(&KEYS.mtls[key]));
            prop_assert_eq!(certificate.not_before().compare(Asn1Time::from_unix(case.now).unwrap().as_ref()).unwrap(), std::cmp::Ordering::Equal);
            prop_assert_eq!(certificate.not_after().compare(Asn1Time::from_unix(case.now + ttl).unwrap().as_ref()).unwrap(), std::cmp::Ordering::Equal);
            let names = certificate.subject_alt_names().unwrap();
            prop_assert_eq!(names.len(), 2);
            prop_assert_eq!(names.iter().filter_map(|name| name.uri()).collect::<Vec<_>>(), vec![claims.identity_uri.as_str()]);
            prop_assert_eq!(names.iter().filter_map(|name| name.dnsname()).collect::<Vec<_>>(), vec![claims.service_audience.as_str()]);
            prop_assert_eq!(certificate.subject_name().entries_by_nid(Nid::COMMONNAME).next().unwrap().data().to_string().unwrap(), claims.decision_id.clone());
            prop_assert_eq!(&response.identity_uri, &claims.identity_uri);
            prop_assert_eq!(&response.decision_id, &claims.decision_id);
            prop_assert_eq!(response.expires_at, case.now + ttl);
            let result = issue_mtls_certificate_with_clock(&state, &valid(), || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject replay").code, "authorization_replayed");
            let mut last = claims; last.nonce.push_str("_last");
            let last = mtls_request(&sign_mtls_authorization(last, &KEYS.control).unwrap(), &KEYS.mtls[key]);
            prop_assert!(issue_mtls_certificate_with_clock(&state, &last, || Ok(case.now + ttl - 1)).is_ok());
        } else {
            let claims = projections.ssh_issuance;
            let envelope = sign_authorization(claims.clone(), &KEYS.control).unwrap();
            let valid = || ssh_request(&envelope, &KEYS.ssh[key]);
            for time in [case.now - 1, case.now + ttl] {
                let result = issue_ssh_certificate_with_clock(&state, &valid(), || Ok(time));
                prop_assert_eq!(result.expect_err("reject inactive").code, "authorization_expired");
            }
            let wrong = sign_authorization(projections.ssh_node_install, &KEYS.control).unwrap();
            let result = issue_ssh_certificate_with_clock(&state, &ssh_request(&wrong, &KEYS.ssh[key]), || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject node audience").code, "invalid_audience");
            let result = issue_ssh_certificate_with_clock(&state, &ssh_request(&envelope, &KEYS.ssh[1-key]), || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject wrong key").code, "ssh_key_fingerprint_mismatch");
            let mut malformed = valid(); malformed.ssh_public_key = "not a public key".into();
            let result = issue_ssh_certificate_with_clock(&state, &malformed, || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject malformed key").code, "invalid_ssh_public_key");
            let mut corrupt = valid(); corrupt.authorization.signature.replace_range(..1, if envelope.signature.starts_with('A') { "B" } else { "A" });
            let result = issue_ssh_certificate_with_clock(&state, &corrupt, || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject signature").code, "invalid_authorization");
            let response = issue_ssh_certificate_with_clock(&state, &valid(), || Ok(case.now)).unwrap();
            let certificate = Certificate::from_openssh(&response.certificate).unwrap();
            certificate.validate_at(u64::try_from(case.now).unwrap(), [&KEYS.ssh_ca.fingerprint(HashAlg::Sha256)]).unwrap();
            prop_assert_eq!(response.serial, 42);
            prop_assert_eq!(certificate.cert_type(), certificate::CertType::User);
            prop_assert_eq!(certificate.public_key(), KEYS.ssh[key].public_key().key_data());
            prop_assert_eq!(certificate.valid_principals(), case.principals);
            prop_assert_eq!(certificate.valid_after(), u64::try_from(case.now).unwrap());
            prop_assert_eq!(certificate.valid_before(), u64::try_from(case.now + ttl).unwrap());
            prop_assert_eq!(certificate.key_id(), format!("{}:{}", claims.subject_user_id, claims.device_id));
            prop_assert_eq!(response.expires_at, case.now + ttl);
            let result = issue_ssh_certificate_with_clock(&state, &valid(), || Ok(case.now));
            prop_assert_eq!(result.expect_err("reject replay").code, "authorization_replayed");
            let mut last = claims; last.nonce.push_str("_last");
            let last = ssh_request(&sign_authorization(last, &KEYS.control).unwrap(), &KEYS.ssh[key]);
            prop_assert!(issue_ssh_certificate_with_clock(&state, &last, || Ok(case.now + ttl - 1)).is_ok());
        }
    }
}
