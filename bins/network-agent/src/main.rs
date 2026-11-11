use std::{
    collections::HashMap,
    env,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use authority_contracts_model::SignedNetworkAccessGrantV1;
use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
use authority_device_auth_core::{encode_base64url, node_enrollment_preimage};
use authority_issuer_core::{AuthorizationSigner, verify_network_grant_for_node};
use authority_replay_ledger::ReplayLedger;
use axum::{
    Json, Router,
    extract::State,
    http::{Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use openssl::sha::sha256;
use serde::Serialize;
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState(Arc<Inner>);

struct Inner {
    verifier: OpenSslEd25519Verifier,
    node_id: String,
    interface: String,
    replay_ledger: Mutex<ReplayLedger>,
    active_peers: Mutex<HashMap<String, i64>>,
    identity: NodeIdentity,
}

struct NodeIdentity {
    public_key: String,
    proof: String,
}

#[derive(Serialize)]
struct ApplyResponse {
    peer_public_key: String,
    allowed_ip: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct IdentityResponse {
    node_id: String,
    public_key: String,
    proof: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let bind: SocketAddr = value("AUTHORITY_NETWORK_AGENT_BIND", "0.0.0.0:3003")?.parse()?;
    let interface = value("AUTHORITY_WIREGUARD_INTERFACE", "wg0")?;
    if interface.is_empty()
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("invalid AUTHORITY_WIREGUARD_INTERFACE".into());
    }
    let verifier = OpenSslEd25519Verifier::from_pem_file(
        value("AUTHORITY_CONTROL_PLANE_KEY_ID", "control-plane-key-1")?,
        PathBuf::from(required("AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE")?),
    )?;
    let identity_path = PathBuf::from(value(
        "AUTHORITY_NETWORK_AGENT_IDENTITY_FILE",
        "/var/lib/authority/node-identity.pem",
    )?);
    let identity_signer = load_or_generate_identity(&identity_path)?;
    let raw_public_key = identity_signer.public_key_raw()?;
    let node_id = node_id_from_public_key(&raw_public_key);
    let public_key = encode_base64url(&raw_public_key);
    let proof =
        encode_base64url(&identity_signer.sign(&node_enrollment_preimage(&node_id, &public_key))?);
    let now = unix_timestamp()?;
    let replay_ledger = ReplayLedger::open(
        PathBuf::from(value(
            "AUTHORITY_NETWORK_AGENT_REPLAY_LEDGER_FILE",
            "/var/lib/authority/network-agent-replay-ledger",
        )?),
        now,
    )?;
    clear_all_peers(&interface)?;
    let state = AppState(Arc::new(Inner {
        verifier,
        node_id,
        interface,
        replay_ledger: Mutex::new(replay_ledger),
        active_peers: Mutex::new(HashMap::new()),
        identity: NodeIdentity { public_key, proof },
    }));
    let router = Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/identity", get(identity))
        .route("/v1/network-grants", post(apply_grant))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([CONTENT_TYPE]),
        );
    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(%bind, "network agent listening");
    axum::serve(listener, router).await?;
    Ok(())
}

async fn identity(State(state): State<AppState>) -> Json<IdentityResponse> {
    Json(IdentityResponse {
        node_id: state.0.node_id.clone(),
        public_key: state.0.identity.public_key.clone(),
        proof: state.0.identity.proof.clone(),
    })
}

fn node_id_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = sha256(public_key);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn load_or_generate_identity(path: &PathBuf) -> Result<OpenSslEd25519Signer, String> {
    match OpenSslEd25519Signer::from_pem_file("node-identity", path) {
        Ok(signer) => Ok(signer),
        Err(_) if !path.exists() => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            let signer = OpenSslEd25519Signer::generate("node-identity")
                .map_err(|error| error.to_string())?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|error| error.to_string())?;
            file.write_all(
                &signer
                    .private_key_to_pem()
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            Ok(signer)
        }
        Err(error) => Err(error.to_string()),
    }
}

async fn apply_grant(
    State(state): State<AppState>,
    Json(envelope): Json<SignedNetworkAccessGrantV1>,
) -> Result<Json<ApplyResponse>, ApiError> {
    let now = unix_timestamp().map_err(ApiError::internal)?;
    verify_network_grant_for_node(&envelope, &state.0.verifier, &state.0.node_id, now)
        .map_err(|cause| ApiError::unauthorized("invalid_network_grant", cause))?;
    let nonce = envelope.grant.nonce.clone();
    if !state
        .0
        .replay_ledger
        .lock()
        .map_err(ApiError::internal)?
        .consume(&nonce, envelope.grant.expires_at, now)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::conflict("network_grant_replayed"));
    }

    let peer = envelope.grant.wireguard_public_key.clone();
    let allowed_ip = format!("{}/32", envelope.grant.mesh_address);
    run_wg(&[
        "set",
        &state.0.interface,
        "peer",
        &peer,
        "allowed-ips",
        &allowed_ip,
    ])
    .map_err(ApiError::internal)?;

    let expires_at = envelope.grant.expires_at;
    state
        .0
        .active_peers
        .lock()
        .map_err(ApiError::internal)?
        .insert(peer.clone(), expires_at);
    let interface = state.0.interface.clone();
    let expiry_state = state.clone();
    let delay = u64::try_from(expires_at.saturating_sub(now)).unwrap_or(0);
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(delay));
        let should_remove = expiry_state
            .0
            .active_peers
            .lock()
            .map_or(true, |mut peers| {
                if peers.get(&peer) == Some(&expires_at) {
                    peers.remove(&peer);
                    true
                } else {
                    false
                }
            });
        if !should_remove {
            return;
        }
        if let Err(cause) = run_wg(&["set", &interface, "peer", &peer, "remove"]) {
            error!(%cause, %peer, "failed to expire WireGuard peer");
        } else {
            info!(%peer, "expired WireGuard peer");
        }
    });

    Ok(Json(ApplyResponse {
        peer_public_key: envelope.grant.wireguard_public_key,
        allowed_ip,
        expires_at,
    }))
}

fn run_wg(arguments: &[&str]) -> Result<(), String> {
    let output = Command::new("/usr/bin/wg")
        .args(arguments)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

fn clear_all_peers(interface: &str) -> Result<(), String> {
    let output = Command::new("/usr/bin/wg")
        .args(["show", interface, "peers"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    for peer in String::from_utf8_lossy(&output.stdout).split_whitespace() {
        run_wg(&["set", interface, "peer", peer, "remove"])?;
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    i64::try_from(seconds).map_err(|error| error.to_string())
}

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} must be set"))
}

fn value(name: &str, default: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if value.is_empty() => Err(format!("{name} must not be empty")),
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(error) => Err(format!("cannot read {name}: {error}")),
    }
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    fn unauthorized(code: &'static str, cause: impl std::fmt::Display) -> Self {
        error!(%cause, "network grant rejected");
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
        }
    }

    fn conflict(code: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
        }
    }

    fn internal(cause: impl std::fmt::Display) -> Self {
        error!(%cause, "network agent operation failed");
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
