use std::{fs, net::IpAddr, process::Stdio};

use ::ssh_key::{Certificate, HashAlg};
use axum::{
    Json, Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{CONTENT_TYPE, ORIGIN},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::{OwnedSemaphorePermit, mpsc},
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::error;

use crate::state::AppState;

pub fn router(state: AppState, browser_origins: Vec<HeaderValue>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/ssh-key", get(get_ssh_key))
        .route("/v1/ssh-certificate", post(install_ssh_certificate))
        .route("/v1/ssh-terminal", get(open_ssh_terminal))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(browser_origins))
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([CONTENT_TYPE]),
        )
}

async fn open_ssh_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let origin = headers
        .get(ORIGIN)
        .ok_or_else(|| ApiError::forbidden("missing_origin"))?;
    if !state.browser_origin_allowed(origin) {
        return Err(ApiError::forbidden("origin_not_allowed"));
    }
    let target = state
        .ssh_target()
        .ok_or_else(|| ApiError::unavailable("ssh_target_not_configured"))?;
    let permit = state
        .terminal_slots()
        .try_acquire_owned()
        .map_err(|_| ApiError::unavailable("ssh_terminal_capacity_reached"))?;
    Ok(upgrade
        .on_upgrade(move |socket| run_ssh_terminal(socket, state, target, permit))
        .into_response())
}

async fn run_ssh_terminal(
    mut socket: WebSocket,
    state: AppState,
    target: IpAddr,
    _permit: OwnedSemaphorePermit,
) {
    let certificate_option = format!("CertificateFile={}", state.certificate_path().display());
    let known_hosts_option = format!("UserKnownHostsFile={}", state.known_hosts_path().display());
    let destination = format!("deploy@{target}");
    let child = Command::new("/usr/bin/ssh")
        .args([
            "-tt",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            known_hosts_option.as_str(),
            "-o",
            "LogLevel=ERROR",
            "-i",
        ])
        .arg(state.private_key_path())
        .args(["-o", certificate_option.as_str(), destination.as_str()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        let _ = socket
            .send(Message::Text("[authority] failed to start ssh\r\n".into()))
            .await;
        return;
    };
    let Some(mut stdin) = child.stdin.take() else {
        return;
    };
    let Some(stdout) = child.stdout.take() else {
        return;
    };
    let Some(stderr) = child.stderr.take() else {
        return;
    };
    let (output_tx, mut output_rx) = mpsc::channel::<Vec<u8>>(32);
    tokio::spawn(pump_output(stdout, output_tx.clone()));
    tokio::spawn(pump_output(stderr, output_tx));
    let _ = socket
        .send(Message::Text(
            format!("[authority] connecting to {destination}\r\n").into(),
        ))
        .await;

    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if stdin.write_all(text.as_bytes()).await.is_err() { break; }
                }
                Some(Ok(Message::Binary(bytes))) => {
                    if stdin.write_all(&bytes).await.is_err() { break; }
                }
                Some(Ok(Message::Ping(bytes))) => {
                    if socket.send(Message::Pong(bytes)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(Message::Pong(_))) => {}
            },
            output = output_rx.recv() => match output {
                Some(bytes) => {
                    if socket.send(Message::Binary(bytes.into())).await.is_err() { break; }
                }
                None => break,
            }
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn pump_output(mut reader: impl AsyncRead + Unpin, sender: mpsc::Sender<Vec<u8>>) {
    let mut buffer = vec![0_u8; 4096];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(length) => {
                if sender.send(buffer[..length].to_vec()).await.is_err() {
                    break;
                }
            }
        }
    }
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

    fn forbidden(code: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code,
        }
    }

    fn unavailable(code: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.code }))).into_response()
    }
}
