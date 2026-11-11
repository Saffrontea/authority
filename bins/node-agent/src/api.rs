use std::fs;

use ::ssh_key::{Certificate, HashAlg};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::error;

use crate::state::AppState;

pub fn router(state: AppState, browser_origins: Vec<HeaderValue>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/ssh-key", get(get_ssh_key))
        .route("/v1/ssh-certificate", post(install_ssh_certificate))
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

#[derive(Serialize)]
struct SshKeyResponse {
    public_key: String,
    fingerprint: String,
}

async fn get_ssh_key(State(state): State<AppState>) -> Result<Json<SshKeyResponse>, ApiError> {
    let public_key = state.private_key().public_key();
    Ok(Json(SshKeyResponse {
        public_key: public_key.to_openssh().map_err(ApiError::internal)?,
        fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
    }))
}

#[derive(Deserialize)]
struct InstallCertificateRequest {
    certificate: String,
}

#[derive(Serialize)]
struct InstallCertificateResponse {
    private_key_file: String,
    certificate_file: String,
}

async fn install_ssh_certificate(
    State(state): State<AppState>,
    Json(request): Json<InstallCertificateRequest>,
) -> Result<Json<InstallCertificateResponse>, ApiError> {
    let certificate = Certificate::from_openssh(&request.certificate)
        .map_err(|_| ApiError::bad_request("invalid_ssh_certificate"))?;
    if certificate.public_key() != state.private_key().public_key().key_data() {
        return Err(ApiError::bad_request("certificate_key_mismatch"));
    }
    let ca_fingerprint = state.trusted_ca().fingerprint(HashAlg::Sha256);
    certificate
        .validate([&ca_fingerprint])
        .map_err(|cause| ApiError::unauthorized_with_log("untrusted_ssh_certificate", cause))?;
    if let Some(parent) = state.certificate_path().parent() {
        fs::create_dir_all(parent).map_err(ApiError::internal)?;
    }
    fs::write(state.certificate_path(), request.certificate).map_err(ApiError::internal)?;

    Ok(Json(InstallCertificateResponse {
        private_key_file: state.private_key_path().display().to_string(),
        certificate_file: state.certificate_path().display().to_string(),
    }))
}

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

    fn unauthorized_with_log(code: &'static str, cause: impl std::fmt::Display) -> Self {
        error!(%cause, "SSH certificate verification failed");
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
        }
    }

    fn internal(cause: impl std::fmt::Display) -> Self {
        error!(%cause, "node agent request failed");
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
