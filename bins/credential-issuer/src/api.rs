use authority_contracts_model::protocol::CREDENTIAL_ISSUER_AUDIENCE;
use std::time::{SystemTime, UNIX_EPOCH};

use authority_contracts_model::{SignedIssuanceAuthorizationV1, SignedMtlsIssuanceAuthorizationV1};
use authority_issuer_core::{verify_authorization, verify_mtls_authorization};
use axum::http::{HeaderValue, Method, header::CONTENT_TYPE};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::{MessageDigest, hash},
    pkey::{PKey, Public},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
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
        .route("/v1/mtls-certificates", post(issue_mtls_certificate))
        .route("/v1/revocations", post(acknowledge_mtls_revocation))
        .route("/v1/pki/{ca_id}/crl", get(get_crl))
        .route("/v1/pki/{ca_id}/ocsp", post(post_ocsp))
        .route("/v1/pki/{ca_id}/ocsp/{*request}", get(get_ocsp))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(browser_origins))
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([CONTENT_TYPE]),
        )
}

async fn get_crl(
    State(state): State<AppState>,
    axum::extract::Path(ca_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if ca_id != state.mtls_ca_id().map_err(ApiError::internal)? {
        return Err(ApiError::unauthorized("unknown_ca"));
    }
    let (certificate, key) = state
        .with_mtls_ca(|ca| Ok((ca.certificate.clone(), ca.key.clone())))
        .map_err(ApiError::internal)?;
    let bytes = authority_mtls_core::pki::crl(
        state.database().map_err(ApiError::internal)?,
        &ca_id,
        &certificate,
        &key,
    )
    .await
    .map_err(ApiError::internal)?;
    Ok((
        [
            ("content-type", "application/pkix-crl"),
            ("cache-control", "no-store"),
        ],
        bytes,
    ))
}
async fn ocsp_response(
    state: &AppState,
    ca_id: &str,
    body: &[u8],
) -> Result<axum::response::Response, ApiError> {
    if ca_id != state.mtls_ca_id().map_err(ApiError::internal)? {
        return Err(ApiError::unauthorized("unknown_ca"));
    }
    let (certificate, key) = state
        .with_mtls_ca(|ca| Ok((ca.certificate.clone(), ca.key.clone())))
        .map_err(ApiError::internal)?;
    let bytes = authority_mtls_core::pki::ocsp(
        state.database().map_err(ApiError::internal)?,
        ca_id,
        &certificate,
        &key,
        body,
    )
    .await
    .map_err(ApiError::internal)?;
    Ok((
        [
            ("content-type", "application/ocsp-response"),
            ("cache-control", "no-store"),
        ],
        bytes,
    )
        .into_response())
}
async fn post_ocsp(
    State(state): State<AppState>,
    axum::extract::Path(ca_id): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, ApiError> {
    ocsp_response(&state, &ca_id, &body).await
}
async fn get_ocsp(
    State(state): State<AppState>,
    axum::extract::Path((ca_id, request)): axum::extract::Path<(String, String)>,
) -> Result<axum::response::Response, ApiError> {
    let bytes = decode_ocsp_request(&request)?;
    ocsp_response(&state, &ca_id, &bytes).await
}

fn decode_ocsp_request(request: &str) -> Result<Vec<u8>, ApiError> {
    openssl::base64::decode_block(request)
        .map_err(|_| ApiError::bad_request("invalid_ocsp_encoding"))
}

async fn acknowledge_mtls_revocation(
    State(state): State<AppState>,
    Json(envelope): Json<authority_contracts_model::SignedDecisionRevocationNoticeV2>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // The issuer is not node-bound: the exact committed-notice DB check below
    // is the authority for domain/target scope; this call verifies signature/time/adapter.
    authority_issuer_core::verify_revocation_notice_v2_for_adapter(
        &envelope,
        state.verifier(),
        &envelope.notice.target_node_id,
        authority_contracts_model::AdapterGrantKindV1::MtlsClientCertificate,
        unix_timestamp()?,
    )
    .map_err(|cause| ApiError::unauthorized_with_log("invalid_mtls_revocation", cause))?;
    if !state
        .database()
        .map_err(ApiError::internal)?
        .committed_notice(&envelope)
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unauthorized("revocation_not_committed"));
    }
    Ok(Json(
        json!({"acknowledged":true,"decision_id":envelope.notice.decision_id,"sequence":envelope.notice.sequence,"adapter":"mtls.client_certificate"}),
    ))
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
    let public_key = checked_ssh_key(&state, &request, unix_timestamp()?)?;
    let claims = &request.authorization.authorization;
    let serial = state
        .database()
        .map_err(ApiError::internal)?
        .consume_serial(
            authority_contracts_model::AdapterGrantKindV1::SshCertificate.as_str(),
            &claims.nonce,
            claims.expires_at,
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::conflict("authorization_replayed"))?;
    sign_ssh_certificate(&state, &request, &public_key, serial).map(Json)
}

#[derive(Deserialize)]
struct IssueMtlsCertificateRequest {
    authorization: SignedMtlsIssuanceAuthorizationV1,
    public_key_pem: String,
}

#[derive(Debug, Serialize)]
struct IssueMtlsCertificateResponse {
    certificate_pem: String,
    ca_certificate_pem: String,
    decision_id: String,
    identity_uri: String,
    expires_at: i64,
}

async fn issue_mtls_certificate(
    State(state): State<AppState>,
    Json(request): Json<IssueMtlsCertificateRequest>,
) -> Result<Json<IssueMtlsCertificateResponse>, ApiError> {
    let public_key = checked_mtls_key(&state, &request)?;
    let ca_id = state.mtls_ca_id().map_err(ApiError::internal)?;
    let extensions = authority_mtls_core::pki::certificate_extensions(state.pki_origin(), &ca_id)
        .map_err(ApiError::internal)?;
    let certificate = state
        .database()
        .map_err(ApiError::internal)?
        .issue(&ca_id, &request.authorization.authorization, |serial| {
            state.with_mtls_ca(|ca| {
                build_mtls_certificate(
                    &public_key,
                    &request.authorization.authorization,
                    ca,
                    serial,
                    extensions,
                )
                .map_err(|e| e.to_string())
            })
        })
        .await
        .map_err(mtls_access_error)?;
    mtls_response(&state, &request, &certificate).map(Json)
}

#[cfg(test)]
fn issue_mtls_certificate_with_clock(
    state: &AppState,
    request: &IssueMtlsCertificateRequest,
    clock: impl FnOnce() -> Result<i64, ApiError>,
) -> Result<IssueMtlsCertificateResponse, ApiError> {
    let public_key = checked_mtls_key(state, request)?;
    let authorization = &request.authorization.authorization;
    let extensions = authority_mtls_core::pki::certificate_extensions(
        state.pki_origin(),
        &state.mtls_ca_id().map_err(ApiError::internal)?,
    )
    .map_err(ApiError::internal)?;
    let certificate = state
        .access()
        .issue(
            authorization,
            || clock().map_err(|e| e.code.to_owned()),
            || {
                state.with_mtls_ca(|ca| {
                    build_mtls_certificate(
                        &public_key,
                        authorization,
                        ca,
                        state.next_serial(),
                        extensions,
                    )
                    .map_err(|error| error.to_string())
                })
            },
        )
        .map_err(mtls_access_error)?;
    mtls_response(state, request, &certificate)
}

fn mtls_response(
    state: &AppState,
    request: &IssueMtlsCertificateRequest,
    certificate: &X509,
) -> Result<IssueMtlsCertificateResponse, ApiError> {
    let authorization = &request.authorization.authorization;
    let ca_certificate_pem = state
        .with_mtls_ca(|ca| {
            String::from_utf8(ca.certificate.to_pem().map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())
        })
        .map_err(ApiError::internal)?;
    Ok(IssueMtlsCertificateResponse {
        certificate_pem: String::from_utf8(certificate.to_pem().map_err(ApiError::internal)?)
            .map_err(ApiError::internal)?,
        ca_certificate_pem,
        decision_id: authorization.decision_id.clone(),
        identity_uri: authorization.identity_uri.clone(),
        expires_at: authorization.expires_at,
    })
}

fn checked_mtls_key(
    state: &AppState,
    request: &IssueMtlsCertificateRequest,
) -> Result<PKey<Public>, ApiError> {
    verify_mtls_authorization(&request.authorization, state.verifier())
        .map_err(|cause| ApiError::unauthorized_with_log("invalid_mtls_authorization", cause))?;
    let authorization = &request.authorization.authorization;
    if authorization.audience != CREDENTIAL_ISSUER_AUDIENCE {
        return Err(ApiError::unauthorized("invalid_audience"));
    }
    let public_key = PKey::public_key_from_pem(request.public_key_pem.as_bytes())
        .map_err(|_| ApiError::bad_request("invalid_mtls_public_key"))?;
    let digest = hash(
        MessageDigest::sha256(),
        &public_key.public_key_to_der().map_err(ApiError::internal)?,
    )
    .map_err(ApiError::internal)?;
    let fingerprint = format!(
        "SHA256:{}",
        openssl::base64::encode_block(&digest).trim_end_matches('=')
    );
    if fingerprint != authorization.client_spki_sha256 {
        return Err(ApiError::unauthorized("mtls_key_fingerprint_mismatch"));
    }
    Ok(public_key)
}
fn mtls_access_error(error: authority_mtls_core::AccessError) -> ApiError {
    match error {
        authority_mtls_core::AccessError::Revoked => {
            ApiError::unauthorized("mtls_authorization_revoked")
        }
        authority_mtls_core::AccessError::Replay => ApiError::conflict("authorization_replayed"),
        authority_mtls_core::AccessError::NotActive => {
            ApiError::unauthorized("authorization_expired")
        }
        other => ApiError::internal(other),
    }
}

fn build_mtls_certificate(
    public_key: &PKey<Public>,
    authorization: &authority_contracts_model::MtlsIssuanceAuthorizationV1,
    ca: &crate::mtls_ca::MtlsCa,
    serial: u64,
    extensions: Vec<openssl::x509::X509Extension>,
) -> Result<X509, openssl::error::ErrorStack> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", &authorization.decision_id)?;
    let name = name.build();
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let serial = BigNum::from_dec_str(&serial.to_string())?;
    let serial = Asn1Integer::from_bn(&serial)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca.certificate.subject_name())?;
    builder.set_pubkey(public_key)?;
    builder.set_not_before(Asn1Time::from_unix(authorization.not_before)?.as_ref())?;
    builder.set_not_after(Asn1Time::from_unix(authorization.expires_at)?.as_ref())?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    builder.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
    let context = builder.x509v3_context(Some(&ca.certificate), None);
    let san = SubjectAlternativeName::new()
        .uri(&authorization.identity_uri)
        .uri(&format!(
            "urn:authority:target:{}",
            authorization.target_node_id
        ))
        .dns(&authorization.service_audience)
        .build(&context)?;
    builder.append_extension(san)?;
    for extension in extensions {
        builder.append_extension(extension)?;
    }
    builder.sign(&ca.key, MessageDigest::sha256())?;
    Ok(builder.build())
}

#[cfg(test)]
fn issue_ssh_certificate_inner(
    state: &AppState,
    request: &IssueSshCertificateRequest,
) -> Result<IssueSshCertificateResponse, ApiError> {
    issue_ssh_certificate_with_clock(state, request, unix_timestamp)
}

#[cfg(test)]
fn issue_ssh_certificate_with_clock(
    state: &AppState,
    request: &IssueSshCertificateRequest,
    clock: impl FnOnce() -> Result<i64, ApiError>,
) -> Result<IssueSshCertificateResponse, ApiError> {
    let now = clock()?;
    let public_key = checked_ssh_key(state, request, now)?;
    let authorization = &request.authorization.authorization;
    if !state
        .consume_nonce(&authorization.nonce, authorization.expires_at, now)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::conflict("authorization_replayed"));
    }

    sign_ssh_certificate(state, request, &public_key, state.next_serial())
}

fn checked_ssh_key(
    state: &AppState,
    request: &IssueSshCertificateRequest,
    now: i64,
) -> Result<PublicKey, ApiError> {
    verify_authorization(&request.authorization, state.verifier())
        .map_err(|cause| ApiError::unauthorized_with_log("invalid_authorization", cause))?;
    let authorization = &request.authorization.authorization;
    if authorization.audience != CREDENTIAL_ISSUER_AUDIENCE {
        return Err(ApiError::unauthorized("invalid_audience"));
    }
    if now < authorization.not_before || now >= authorization.expires_at {
        return Err(ApiError::unauthorized("authorization_expired"));
    }

    let public_key = PublicKey::from_openssh(&request.ssh_public_key)
        .map_err(|_| ApiError::bad_request("invalid_ssh_public_key"))?;
    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
    if fingerprint != authorization.ssh_public_key_fingerprint {
        return Err(ApiError::unauthorized("ssh_key_fingerprint_mismatch"));
    }
    Ok(public_key)
}

fn sign_ssh_certificate(
    state: &AppState,
    request: &IssueSshCertificateRequest,
    public_key: &PublicKey,
    serial: u64,
) -> Result<IssueSshCertificateResponse, ApiError> {
    let authorization = &request.authorization.authorization;
    let valid_after = u64::try_from(authorization.not_before).map_err(ApiError::internal)?;
    let valid_before = u64::try_from(authorization.expires_at).map_err(ApiError::internal)?;
    let mut builder = certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        public_key,
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
    #[test]
    fn malformed_ocsp_transport_encoding_is_a_client_error() {
        let error = super::decode_ocsp_request("!not-base64!").err().unwrap();
        assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "invalid_ocsp_encoding");
        assert_eq!(super::decode_ocsp_request("MAA=").unwrap(), [0x30, 0]);
    }

    use std::{
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    use authority_contracts_model::IssuanceAuthorizationV1;
    use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
    use authority_issuer_core::sign_authorization;
    use authority_replay_ledger::ReplayLedger;
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
        x509::extension::SubjectAlternativeName,
    };
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

    #[test]
    fn issued_client_certificate_completes_a_real_mutual_tls_handshake() {
        let unique = format!("{}-{}", std::process::id(), unix_timestamp().expect("time"));
        let directory = std::env::temp_dir().join(format!("authority-mtls-{unique}"));
        fs::create_dir_all(&directory).expect("create temp directory");
        let ca = crate::mtls_ca::load_or_generate(
            &directory.join("ca-key.pem"),
            &directory.join("ca-cert.pem"),
        )
        .expect("generate mTLS CA");
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("curve");
        let client_key =
            PKey::from_ec_key(EcKey::generate(&group).expect("client key")).expect("client pkey");
        let now = unix_timestamp().expect("time");
        let authorization = authority_contracts_model::MtlsIssuanceAuthorizationV1 {
            version: "1".into(),
            issuer: "domain-authority:example".into(),
            domain_id: "domain_example".into(),
            subject_user_id: "user_01".into(),
            device_id: "device_01".into(),
            target_node_id: "node_01".into(),
            client_spki_sha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            identity_uri: "spiffe://authority.example/user/user_01/device/device_01".into(),
            service_audience: "demo-api".into(),
            policy_id: "policy_01@1".into(),
            decision_id: "0123456789abcdef0123456789abcdef".into(),
            nonce: "0123456789abcdef0123456789abcdef_mtls_test".into(),
            issued_at: now,
            not_before: now - 1,
            expires_at: now + 60,
            audience: "credential-issuer".into(),
        };
        let client_cert = build_mtls_certificate(
            &PKey::public_key_from_der(&client_key.public_key_to_der().expect("public der"))
                .expect("public key"),
            &authorization,
            &ca,
            7,
            Vec::new(),
        )
        .expect("client certificate");
        let (server_key, server_cert) = test_server_certificate(&ca, &group, now);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS server");
        let address = listener.local_addr().expect("server address");
        let mut acceptor =
            SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).expect("acceptor");
        acceptor.set_private_key(&server_key).expect("server key");
        acceptor.set_certificate(&server_cert).expect("server cert");
        acceptor
            .cert_store_mut()
            .add_cert(ca.certificate.clone())
            .expect("client CA");
        acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let acceptor = acceptor.build();
        let server = thread::spawn(move || {
            let stream = listener.accept().expect("accept TCP").0;
            let mut stream = acceptor.accept(stream).expect("mutual TLS accept");
            let peer = stream.ssl().peer_certificate().expect("client certificate");
            let common_name = peer
                .subject_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .expect("client CN")
                .data()
                .to_string()
                .expect("utf8 CN");
            assert_eq!(common_name, "0123456789abcdef0123456789abcdef");
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).expect("read protected byte");
            stream.write_all(&byte).expect("echo protected byte");
        });

        let mut connector = SslConnector::builder(SslMethod::tls_client()).expect("connector");
        connector.set_private_key(&client_key).expect("client key");
        connector
            .set_certificate(&client_cert)
            .expect("client cert");
        connector
            .cert_store_mut()
            .add_cert(ca.certificate.clone())
            .expect("server CA");
        let mut stream = connector
            .build()
            .connect(
                "localhost",
                TcpStream::connect(address).expect("connect TCP"),
            )
            .expect("mutual TLS connect");
        stream.write_all(b"x").expect("write protected byte");
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).expect("read protected byte");
        assert_eq!(&byte, b"x");
        server.join().expect("TLS server");
        fs::remove_dir_all(directory).expect("remove temp directory");
    }

    fn test_server_certificate(
        ca: &crate::mtls_ca::MtlsCa,
        group: &EcGroup,
        now: i64,
    ) -> (PKey<openssl::pkey::Private>, X509) {
        let key =
            PKey::from_ec_key(EcKey::generate(group).expect("server key")).expect("server pkey");
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "localhost").expect("CN");
        let name = name.build();
        let mut builder = X509::builder().expect("certificate");
        builder.set_version(2).expect("version");
        let serial_bn = BigNum::from_u32(9).expect("serial");
        let serial = Asn1Integer::from_bn(&serial_bn).expect("serial integer");
        builder.set_serial_number(&serial).expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder
            .set_issuer_name(ca.certificate.subject_name())
            .expect("issuer");
        builder.set_pubkey(&key).expect("public key");
        builder
            .set_not_before(Asn1Time::from_unix(now - 1).expect("not before").as_ref())
            .expect("not before");
        builder
            .set_not_after(Asn1Time::from_unix(now + 60).expect("not after").as_ref())
            .expect("not after");
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&builder.x509v3_context(Some(&ca.certificate), None))
            .expect("SAN");
        builder.append_extension(san).expect("SAN extension");
        builder
            .sign(&ca.key, MessageDigest::sha256())
            .expect("sign server cert");
        (key, builder.build())
    }
}

#[cfg(test)]
#[path = "consumer_properties.rs"]
mod consumer_properties;
