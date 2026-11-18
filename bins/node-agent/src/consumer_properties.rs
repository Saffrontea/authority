//! Native certificate-installation checks, including filesystem and lease effects.
use super::*;
use crate::state::{AgentCredentials, AgentPaths};
use ::ssh_key::{Algorithm, PrivateKey, certificate, rand_core::OsRng};
use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
use authority_issuer_core::sign_authorization;
use authority_projection_core::{
    CommonDecisionClaims, MtlsProjectionRequest, NetworkProjectionRequest, ProjectionLifetimes,
    SshProjectionRequest, project,
};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
};
use proptest::prelude::*;
use std::sync::LazyLock;

struct Keys {
    control: OpenSslEd25519Signer,
    ca: [PrivateKey; 2],
    subject: [PrivateKey; 2],
    mtls: PKey<Private>,
    now: i64,
}
static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    Keys {
        control: OpenSslEd25519Signer::generate("node-consumer-properties").unwrap(),
        ca: std::array::from_fn(|_| PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()),
        subject: std::array::from_fn(|_| {
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
        }),
        mtls: PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap(),
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
fn projections(case: &Case) -> authority_projection_core::ProjectionSet {
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
    project(
        &common,
        &SshProjectionRequest {
            public_key_fingerprint: KEYS.subject[case.key]
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string(),
            principals: case.principals.clone(),
            terminal_token_hash: encode_base64url(&sha256(
                format!("terminal-{}", case.id).as_bytes(),
            )),
        },
        &NetworkProjectionRequest {
            wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            mesh_address: "10.77.0.1".into(),
        },
        &MtlsProjectionRequest {
            client_spki_sha256: format!("SHA256:{}", "A".repeat(43)),
            identity_uri: format!("spiffe://authority.local/user/{}", common.subject_user_id),
            service_audience: "demo-api".into(),
        },
        ProjectionLifetimes {
            ssh_seconds: case.ttl,
            network_seconds: 300,
            mtls_seconds: case.ttl,
        },
    )
    .unwrap()
}

fn state(directory: &std::path::Path, case: &Case) -> AppState {
    AppState::new(
        AgentCredentials {
            ssh_private_key: KEYS.subject[case.key].clone(),
            mtls_private_key: KEYS.mtls.clone(),
        },
        vec![KEYS.ca[0].public_key().clone()],
        AgentPaths {
            private_key: directory.join("private"),
            certificate: directory.join("certificate"),
            known_hosts: directory.join("known-hosts"),
        },
        None,
        22,
        vec![],
        OpenSslEd25519Verifier::from_pem(
            "node-consumer-properties",
            &KEYS.control.public_key_to_pem().unwrap(),
        )
        .unwrap(),
    )
}

#[derive(Clone, Copy)]
enum Variant {
    Valid,
    Host,
    WrongIdentity,
    WrongPrincipal,
    LongerLifetime,
    EarlierStart,
    WrongKey,
    WrongCa,
}
fn certificate(case: &Case, variant: Variant) -> String {
    let key = if matches!(variant, Variant::WrongKey) {
        1 - case.key
    } else {
        case.key
    };
    let after = case.now - i64::from(matches!(variant, Variant::EarlierStart));
    let before = case.now + case.ttl + i64::from(matches!(variant, Variant::LongerLifetime));
    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        KEYS.subject[key].public_key(),
        u64::try_from(after).unwrap(),
        u64::try_from(before).unwrap(),
    )
    .unwrap();
    builder
        .cert_type(if matches!(variant, Variant::Host) {
            certificate::CertType::Host
        } else {
            certificate::CertType::User
        })
        .unwrap();
    builder
        .key_id(if matches!(variant, Variant::WrongIdentity) {
            "other-user:other-device".into()
        } else {
            format!("user_{:x}:device_01", case.id)
        })
        .unwrap();
    for principal in &case.principals {
        builder.valid_principal(principal).unwrap();
    }
    if matches!(variant, Variant::WrongPrincipal) {
        builder.valid_principal("unauthorized-principal").unwrap();
    }
    builder.extension("permit-pty", "").unwrap();
    builder
        .sign(&KEYS.ca[usize::from(matches!(variant, Variant::WrongCa))])
        .unwrap()
        .to_openssh()
        .unwrap()
}

fn request(
    authorization: Option<&SignedIssuanceAuthorizationV1>,
    certificate: &str,
) -> InstallCertificateRequest {
    serde_json::from_value(json!({"authorization": authorization, "certificate": certificate}))
        .unwrap()
}

proptest! {
    #[test]
    fn node_installs_only_matching_user_certificates_without_rejection_side_effects(
        id in any::<u128>(), offset in 0_i64..600, ttl in 1_i64..=300,
        principals in prop::collection::btree_set("[a-z][a-z0-9_-]{0,7}", 1..=3), key in 0_usize..2,
    ) {
        let case = Case { id, now: KEYS.now + offset, ttl, principals: principals.into_iter().collect(), key };
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path(), &case);
        fs::write(state.certificate_path(), "previous-certificate").unwrap();
        let previous_hash = encode_base64url(&sha256(b"previous-terminal-token"));
        state.install_terminal_lease(TerminalLease { token_hash: previous_hash.clone(), expires_at: case.now + 600 }).unwrap();
        let projected = projections(&case);
        let claims = projected.ssh_node_install;
        let signed = sign_authorization(claims.clone(), &KEYS.control).unwrap();
        let valid_certificate = certificate(&case, Variant::Valid);
        let mut rejected = Vec::new();
        rejected.push((request(None, &valid_certificate), case.now, "missing_node_authorization"));
        let issuer = sign_authorization(projected.ssh_issuance, &KEYS.control).unwrap();
        rejected.push((request(Some(&issuer), &valid_certificate), case.now, "node_authorization_not_active"));
        for time in [case.now - 1, case.now + ttl] {
            rejected.push((request(Some(&signed), &valid_certificate), time, "node_authorization_not_active"));
        }
        let mut bad_claim = claims.clone();
        bad_claim.ssh_public_key_fingerprint = KEYS.subject[1-key].public_key().fingerprint(HashAlg::Sha256).to_string();
        rejected.push((request(Some(&sign_authorization(bad_claim, &KEYS.control).unwrap()), &valid_certificate), case.now, "node_authorization_key_mismatch"));
        let mut bad_signature = signed.clone();
        bad_signature.signature.replace_range(..1, if signed.signature.starts_with('A') { "B" } else { "A" });
        rejected.push((request(Some(&bad_signature), &valid_certificate), case.now, "invalid_node_authorization"));
        rejected.push((request(Some(&signed), "invalid certificate"), case.now, "invalid_ssh_certificate"));
        for (variant, error) in [(Variant::WrongKey, "certificate_key_mismatch"),
            (Variant::WrongCa, "untrusted_ssh_certificate"), (Variant::WrongPrincipal, "certificate_authorization_mismatch"),
            (Variant::LongerLifetime, "certificate_authorization_mismatch"), (Variant::EarlierStart, "certificate_authorization_mismatch"),
            (Variant::Host, "certificate_authorization_mismatch"), (Variant::WrongIdentity, "certificate_authorization_mismatch")] {
            rejected.push((request(Some(&signed), &certificate(&case, variant)), case.now, error));
        }
        for (request, time, error) in rejected {
            let result = install_ssh_certificate_with_clock(&state, &request, || Ok(time));
            prop_assert!(result.is_err(), "unexpected certificate acceptance: {error}; material={:?}", Certificate::from_openssh(&request.certificate).map(|cert| (cert.cert_type(), cert.key_id().to_owned())));
            prop_assert_eq!(result.err().unwrap().code, error);
            prop_assert_eq!(fs::read_to_string(state.certificate_path()).unwrap(), "previous-certificate");
            prop_assert!(state.terminal_authorized(&previous_hash, case.now).unwrap());
            prop_assert!(!state.terminal_authorized(&claims.nonce, case.now).unwrap());
        }
        let valid = request(Some(&signed), &valid_certificate);
        let response = install_ssh_certificate_with_clock(&state, &valid, || Ok(case.now)).unwrap();
        prop_assert_eq!(response.certificate_file, state.certificate_path().display().to_string());
        prop_assert_eq!(fs::read_to_string(state.certificate_path()).unwrap(), valid_certificate);
        prop_assert!(!state.terminal_authorized(&previous_hash, case.now).unwrap());
        prop_assert!(state.terminal_authorized(&claims.nonce, case.now + ttl - 1).unwrap());
        prop_assert!(!state.terminal_authorized(&claims.nonce, case.now + ttl).unwrap());
        prop_assert!(install_ssh_certificate_with_clock(&state, &valid, || Ok(case.now + ttl - 1)).is_ok());
    }
}
