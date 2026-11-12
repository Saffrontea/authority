use std::time::{SystemTime, UNIX_EPOCH};

use authority_contracts_model::SignedIssuanceAuthorizationV1;
use authority_issuer_core::verify_authorization;
use axum::http::{HeaderValue, Method, header::CONTENT_TYPE};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssh_key::{HashAlg, PublicKey, certificate, rand_core::OsRng};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::error;

use crate::state::AppState;

pub fn router(state: AppState, browser_origins: Vec<HeaderValue>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/ssh-certificates", post(issue_ssh_certificate))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(browser_origins))
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([CONTENT_TYPE]),
        )
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
struct IssueSshCertificateRequest {
    authorization: SignedIssuanceAuthorizationV1,
    ssh_public_key: String,
}

#[derive(Debug, Serialize)]
struct IssueSshCertificateResponse {
    certificate: String,
    ca_public_key: String,
    ca_fingerprint: String,
    serial: u64,
    expires_at: i64,
}

async fn issue_ssh_certificate(
    State(state): State<AppState>,
    Json(request): Json<IssueSshCertificateRequest>,
) -> Result<Json<IssueSshCertificateResponse>, ApiError> {
    issue_ssh_certificate_inner(&state, &request).map(Json)
}

fn issue_ssh_certificate_inner(
    state: &AppState,
    request: &IssueSshCertificateRequest,
) -> Result<IssueSshCertificateResponse, ApiError> {
    verify_authorization(&request.authorization, state.verifier())
        .map_err(|cause| ApiError::unauthorized_with_log("invalid_authorization", cause))?;
    let authorization = &request.authorization.authorization;
    if authorization.audience != "credential-issuer" {
        return Err(ApiError::unauthorized("invalid_audience"));
    }
    let now = unix_timestamp()?;
    if now < authorization.not_before || now >= authorization.expires_at {
        return Err(ApiError::unauthorized("authorization_expired"));
    }

    let public_key = PublicKey::from_openssh(&request.ssh_public_key)
        .map_err(|_| ApiError::bad_request("invalid_ssh_public_key"))?;
    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
    if fingerprint != authorization.ssh_public_key_fingerprint {
        return Err(ApiError::unauthorized("ssh_key_fingerprint_mismatch"));
    }
    if !state
        .consume_nonce(&authorization.nonce, authorization.expires_at, now)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::conflict("authorization_replayed"));
    }

    let serial = state.next_serial();
    let valid_after = u64::try_from(authorization.not_before).map_err(ApiError::internal)?;
    let valid_before = u64::try_from(authorization.expires_at).map_err(ApiError::internal)?;
    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        &public_key,
        valid_after,
        valid_before,
    )
    .map_err(ApiError::internal)?;
    builder.serial(serial).map_err(ApiError::internal)?;
    builder
        .cert_type(certificate::CertType::User)
        .map_err(ApiError::internal)?;
    builder
        .key_id(format!(
            "{}:{}",
            authorization.subject_user_id, authorization.device_id
        ))
        .map_err(ApiError::internal)?;
    for principal in &authorization.principals {
        builder
            .valid_principal(principal)
            .map_err(ApiError::internal)?;
    }
    builder
        .extension("permit-pty", "")
        .map_err(ApiError::internal)?;
    let ca_key = state.ca_key().map_err(ApiError::internal)?;
    let certificate = builder.sign(&*ca_key).map_err(ApiError::internal)?;

    Ok(IssueSshCertificateResponse {
        certificate: certificate.to_openssh().map_err(ApiError::internal)?,
        ca_fingerprint: ca_key.fingerprint(HashAlg::Sha256).to_string(),
        ca_public_key: ca_key
            .public_key()
            .to_openssh()
            .map_err(ApiError::internal)?,
        serial,
        expires_at: authorization.expires_at,
    })
}

fn unix_timestamp() -> Result<i64, ApiError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(ApiError::internal)?
        .as_secs();
    i64::try_from(seconds).map_err(ApiError::internal)
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    fn bad_request(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
        }
    }

    fn unauthorized(code: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
        }
    }

    fn unauthorized_with_log(code: &'static str, cause: impl std::fmt::Display) -> Self {
        error!(%cause, "authorization verification failed");
        Self::unauthorized(code)
    }

    fn conflict(code: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
        }
    }

    fn internal(cause: impl std::fmt::Display) -> Self {
        error!(%cause, "credential issuance failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.code }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use authority_contracts_model::IssuanceAuthorizationV1;
    use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
    use authority_issuer_core::sign_authorization;
    use authority_replay_ledger::ReplayLedger;
    use ssh_key::{Algorithm, Certificate, PrivateKey, rand_core::OsRng};

    use super::*;

    #[test]
    fn issues_valid_certificate_and_rejects_replay() {
        let control_signer = OpenSslEd25519Signer::generate("control-plane-key-1")
            .expect("generate control-plane key");
        let verifier = OpenSslEd25519Verifier::from_pem(
            "control-plane-key-1",
            &control_signer
                .public_key_to_pem()
                .expect("encode control-plane public key"),
        )
        .expect("load control-plane public key");
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("generate CA key");
        let ca_fingerprint = ca_key.fingerprint(HashAlg::Sha256);
        let subject_key =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("generate subject key");
        let now = unix_timestamp().expect("current timestamp");
        let authorization = IssuanceAuthorizationV1 {
            version: "1".to_owned(),
            issuer: "domain-authority:example".to_owned(),
            domain_id: "domain_example".to_owned(),
            subject_user_id: "user_01".to_owned(),
            device_id: "device_01".to_owned(),
            target_node_id: "node_01".to_owned(),
            ssh_public_key_fingerprint: subject_key
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string(),
            principals: vec!["deploy".to_owned()],
            policy_id: "policy_01".to_owned(),
            nonce: "dGVzdC1ub25jZS0wMTIzNDU2Nzg5YWJjZGVm".to_owned(),
            issued_at: now,
            not_before: now,
            expires_at: now + 300,
            audience: "credential-issuer".to_owned(),
        };
        let envelope = sign_authorization(authorization, &control_signer).expect("sign envelope");
        let request = || IssueSshCertificateRequest {
            authorization: envelope.clone(),
            ssh_public_key: subject_key
                .public_key()
                .to_openssh()
                .expect("encode subject public key"),
        };
        let ledger_path = std::env::temp_dir().join(format!(
            "authority-issuer-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let replay_ledger = ReplayLedger::open(ledger_path, now).expect("open replay ledger");
        let state = AppState::new(verifier, ca_key, replay_ledger, 42);

        let first_request = request();
        let response =
            issue_ssh_certificate_inner(&state, &first_request).expect("issue certificate");
        assert_eq!(response.serial, 42);
        let certificate =
            Certificate::from_openssh(&response.certificate).expect("parse certificate");
        certificate
            .validate_at(
                u64::try_from(now).expect("positive timestamp"),
                [&ca_fingerprint],
            )
            .expect("validate certificate");
        assert_eq!(certificate.valid_principals(), ["deploy"]);

        let replay_request = request();
        let replay =
            issue_ssh_certificate_inner(&state, &replay_request).expect_err("reject replay");
        assert_eq!(replay.code, "authorization_replayed");
    }

    #[test]
    fn ca_rotation_issues_with_the_new_key_and_supports_an_overlap_window() {
        let control_signer = OpenSslEd25519Signer::generate("control-plane-key-1")
            .expect("generate control-plane key");
        let verifier = OpenSslEd25519Verifier::from_pem(
            "control-plane-key-1",
            &control_signer
                .public_key_to_pem()
                .expect("encode control-plane public key"),
        )
        .expect("load control-plane public key");
        let old_ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("old CA");
        let new_ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("new CA");
        let old_fingerprint = old_ca.fingerprint(HashAlg::Sha256);
        let new_fingerprint = new_ca.fingerprint(HashAlg::Sha256);
        let subject_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("subject key");
        let now = unix_timestamp().expect("current timestamp");
        let ledger_path = std::env::temp_dir().join(format!(
            "authority-issuer-rotation-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let replay_ledger = ReplayLedger::open(ledger_path, now).expect("open replay ledger");
        let state = AppState::new(verifier, old_ca, replay_ledger, 100);
        let request = |nonce: &str| IssueSshCertificateRequest {
            authorization: sign_authorization(
                IssuanceAuthorizationV1 {
                    version: "1".to_owned(),
                    issuer: "domain-authority:example".to_owned(),
                    domain_id: "domain_example".to_owned(),
                    subject_user_id: "user_01".to_owned(),
                    device_id: "device_01".to_owned(),
                    target_node_id: "node_01".to_owned(),
                    ssh_public_key_fingerprint: subject_key
                        .public_key()
                        .fingerprint(HashAlg::Sha256)
                        .to_string(),
                    principals: vec!["deploy".to_owned()],
                    policy_id: "policy_01".to_owned(),
                    nonce: nonce.to_owned(),
                    issued_at: now,
                    not_before: now,
                    expires_at: now + 300,
                    audience: "credential-issuer".to_owned(),
                },
                &control_signer,
            )
            .expect("sign authorization"),
            ssh_public_key: subject_key
                .public_key()
                .to_openssh()
                .expect("encode subject key"),
        };

        let old_response =
            issue_ssh_certificate_inner(&state, &request("b2xkLWNhLXJvdGF0aW9uLW5vbmNlLTAx"))
                .expect("issue from old CA");
        state.rotate_ca(new_ca).expect("activate new CA");
        let new_response =
            issue_ssh_certificate_inner(&state, &request("bmV3LWNhLXJvdGF0aW9uLW5vbmNlLTAy"))
                .expect("issue from new CA");
        let old_certificate =
            Certificate::from_openssh(&old_response.certificate).expect("old certificate");
        let new_certificate =
            Certificate::from_openssh(&new_response.certificate).expect("new certificate");
        assert_eq!(old_response.ca_fingerprint, old_fingerprint.to_string());
        assert_eq!(new_response.ca_fingerprint, new_fingerprint.to_string());

        old_certificate
            .validate_at(
                u64::try_from(now).expect("timestamp"),
                [&old_fingerprint, &new_fingerprint],
            )
            .expect("overlap trusts old certificate");
        new_certificate
            .validate_at(
                u64::try_from(now).expect("timestamp"),
                [&old_fingerprint, &new_fingerprint],
            )
            .expect("overlap trusts new certificate");
        assert!(
            old_certificate
                .validate_at(u64::try_from(now).expect("timestamp"), [&new_fingerprint])
                .is_err(),
            "retiring the old CA must reject certificates signed by it"
        );
        new_certificate
            .validate_at(u64::try_from(now).expect("timestamp"), [&new_fingerprint])
            .expect("new certificate survives retirement of old CA");
    }
}
