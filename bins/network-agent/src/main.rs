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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use authority_contracts_model::{SignedDecisionRevocationNoticeV1, SignedNetworkAccessGrantV1};
use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
use authority_device_auth_core::{encode_base64url, node_enrollment_preimage};
use authority_issuer_core::{
    AuthorizationSigner, verify_network_grant_for_node, verify_revocation_notice_for_node,
};
use authority_replay_ledger::ReplayLedger;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use openssl::sha::sha256;
use serde::Serialize;
use serde_json::json;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState(Arc<Inner>);

struct Inner {
    verifier: OpenSslEd25519Verifier,
    node_id: String,
    interface: String,
    replay_ledger: Mutex<ReplayLedger>,
    policy_state: Mutex<PolicyState>,
    identity: NodeIdentity,
}

#[derive(Default)]
struct PolicyState {
    active_peers: HashMap<String, ActivePeer>,
    revoked_decisions: HashMap<String, i64>,
}

struct ActivePeer {
    decision_id: String,
    expires_at: i64,
}

impl PolicyState {
    fn purge_expired_revocations(&mut self, now: i64) {
        self.revoked_decisions
            .retain(|_, expires_at| *expires_at > now);
    }

    fn is_revoked(&mut self, decision_id: &str, now: i64) -> bool {
        self.purge_expired_revocations(now);
        self.revoked_decisions.contains_key(decision_id)
    }

    fn record_revocation(
        &mut self,
        decision_id: &str,
        expires_at: i64,
        now: i64,
    ) -> Option<String> {
        self.purge_expired_revocations(now);
        self.revoked_decisions
            .entry(decision_id.to_owned())
            .and_modify(|current| *current = (*current).max(expires_at))
            .or_insert(expires_at);
        self.active_peers
            .iter()
            .find_map(|(peer, active)| (active.decision_id == decision_id).then(|| peer.clone()))
    }
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
struct RevokeResponse {
    decision_id: String,
    sequence: i64,
    peer_removed: bool,
}

const MAX_ACTIVE_PEERS: usize = 1024;

#[cfg(test)]
mod revocation_tests {
    use super::*;

    #[test]
    fn revocation_is_idempotent_and_blocks_a_late_grant() {
        let mut state = PolicyState::default();
        state.active_peers.insert(
            "peer".to_owned(),
            ActivePeer {
                decision_id: "decision".to_owned(),
                expires_at: 200,
            },
        );
        assert_eq!(
            state.record_revocation("decision", 200, 100),
            Some("peer".to_owned())
        );
        state.active_peers.remove("peer");
        assert_eq!(state.record_revocation("decision", 200, 100), None);
        assert!(state.is_revoked("decision", 101));
        assert!(!state.is_revoked("decision", 200));
    }
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
    let browser_origins = origins(
        "AUTHORITY_BROWSER_ORIGINS",
        "http://localhost:3000,http://localhost:3100",
    )?;
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
        policy_state: Mutex::new(PolicyState::default()),
        identity: NodeIdentity { public_key, proof },
    }));
    let router = Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/identity", get(identity))
        .route("/v1/network-grants", post(apply_grant))
        .route("/v1/revocations", post(apply_revocation))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(browser_origins))
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
    let peer = envelope.grant.wireguard_public_key.clone();
    let allowed_ip = format!("{}/32", envelope.grant.mesh_address);
    // Keep the peer registry locked from the capacity decision through the
    // successful kernel update and insertion. Otherwise concurrent grants can
    // both observe a free slot and exceed the configured bound.
    let mut policy = state.0.policy_state.lock().map_err(ApiError::internal)?;
    if policy.is_revoked(&envelope.grant.nonce, now) {
        return Err(ApiError::conflict("network_grant_revoked"));
    }
    if policy.active_peers.len() >= MAX_ACTIVE_PEERS && !policy.active_peers.contains_key(&peer) {
        return Err(ApiError::unavailable("peer_capacity_reached"));
    }
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
    policy.active_peers.insert(
        peer.clone(),
        ActivePeer {
            decision_id: envelope.grant.nonce.clone(),
            expires_at,
        },
    );
    drop(policy);
    let interface = state.0.interface.clone();
    let expiry_state = state.clone();
    let delay = u64::try_from(expires_at.saturating_sub(now)).unwrap_or(0);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(delay)).await;
        let should_remove = expiry_state
            .0
            .policy_state
            .lock()
            .map_or(true, |mut policy| {
                if policy
                    .active_peers
                    .get(&peer)
                    .is_some_and(|active| active.expires_at == expires_at)
                {
                    policy.active_peers.remove(&peer);
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

async fn apply_revocation(
    State(state): State<AppState>,
    Json(envelope): Json<SignedDecisionRevocationNoticeV1>,
) -> Result<Json<RevokeResponse>, ApiError> {
    let now = unix_timestamp().map_err(ApiError::internal)?;
    verify_revocation_notice_for_node(&envelope, &state.0.verifier, &state.0.node_id, now)
        .map_err(|cause| ApiError::unauthorized("invalid_revocation_notice", cause))?;
    let decision_id = envelope.notice.decision_id.clone();
    let sequence = envelope.notice.sequence;
    let mut policy = state.0.policy_state.lock().map_err(ApiError::internal)?;
    let peer = policy.record_revocation(&decision_id, envelope.notice.expires_at, now);
    let peer_removed = if let Some(peer) = peer {
        run_wg(&["set", &state.0.interface, "peer", &peer, "remove"])
            .map_err(ApiError::internal)?;
        policy.active_peers.remove(&peer);
        info!(%peer, %decision_id, sequence, "revoked WireGuard peer");
        true
    } else {
        false
    };
    Ok(Json(RevokeResponse {
        decision_id,
        sequence,
        peer_removed,
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

fn origins(name: &str, default: &str) -> Result<Vec<HeaderValue>, String> {
    let raw = value(name, default)?;
    let parsed = raw
        .split(',')
        .map(str::trim)
        .map(|origin| {
            if origin.is_empty() || origin == "*" {
                return Err(format!("{name} contains an invalid origin"));
            }
            origin
                .parse::<HeaderValue>()
                .map_err(|error| format!("{name} contains an invalid origin: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.is_empty() {
        Err(format!("{name} must contain at least one origin"))
    } else {
        Ok(parsed)
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
