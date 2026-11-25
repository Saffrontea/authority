//! Root-only sshd leases. A separate systemd service owns each connection's
//! cgroup, so either enforcer process dying also terminates its connections.
use super::{ApiError, AppState, PolicyState};
use authority_contracts_model::{AdapterGrantKindV1 as Kind, fence::SshCertificateIdentityV2};
use axum::{Json, Router, extract::State, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::{
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    time::{Duration, Instant},
};

pub(super) struct Session {
    identity: SshCertificateIdentityV2,
    token: String,
    deadline: Instant,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    identity: SshCertificateIdentityV2,
    pid: u32,
    start: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Renewal {
    pid: u32,
    start: u64,
    token: String,
}

pub(super) fn tombstone(domain: &str, decision: &str) -> String {
    let digest = openssl::sha::sha256(format!("{}:{domain}{decision}", domain.len()).as_bytes());
    digest.iter().fold(String::from("ssh_"), |mut result, b| {
        let _ = write!(result, "{b:02x}");
        result
    })
}

fn allowed(
    state: &AppState,
    policy: &PolicyState,
    identity: &SshCertificateIdentityV2,
) -> Result<bool, String> {
    let now = super::unix_timestamp()?;
    if identity.validate().is_err()
        || identity.target_node_id != state.0.node_id
        || now < identity.not_before
        || now >= identity.expires_at
    {
        return Ok(false);
    }
    if policy
        .fences
        .get(&(identity.generation.domain_id.clone(), Kind::SshCertificate))
        .is_none_or(|store| store.rejects(&identity.generation))
    {
        return Ok(false);
    }
    if state
        .0
        .revocations
        .lock()
        .map_err(|e| e.to_string())?
        .contains(
            &tombstone(&identity.generation.domain_id, &identity.decision_id),
            now,
        )
    {
        return Ok(false);
    }
    state
        .0
        .observer
        .as_ref()
        .ok_or("SSH observation unavailable")?
        .allows_ssh(identity)
}

fn unit(pid: u32, start: u64) -> String {
    format!("authority-ssh-{pid}-{start}.service")
}

pub(super) fn reconcile(state: &AppState, policy: &mut PolicyState) -> Result<(), String> {
    let mut stopped = Vec::new();
    for (&(pid, start), session) in &policy.ssh_sessions {
        if Instant::now() >= session.deadline || !allowed(state, policy, &session.identity)? {
            let name = unit(pid, start);
            let status = std::process::Command::new("/usr/bin/systemctl")
                .args(["stop", &name])
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success()
                && std::process::Command::new("/usr/bin/systemctl")
                    .args(["is-active", "--quiet", &name])
                    .status()
                    .map_err(|e| e.to_string())?
                    .success()
            {
                return Err("failed to stop revoked SSH connection".into());
            }
            stopped.push((pid, start));
        }
    }
    for id in stopped {
        policy.ssh_sessions.remove(&id);
    }
    Ok(())
}

async fn admit(
    State(state): State<AppState>,
    Json(request): Json<Admission>,
) -> Result<Json<Value>, ApiError> {
    request.identity.validate().map_err(ApiError::internal)?;
    if request.pid < 2 || request.start == 0 {
        return Err(ApiError::conflict("invalid_ssh_process"));
    }
    let mut policy = state.0.policy_state.lock().map_err(ApiError::internal)?;
    super::fence::require(
        &state,
        &mut policy,
        &request.identity.generation,
        Kind::SshCertificate,
    )?;
    if !allowed(&state, &policy, &request.identity).map_err(ApiError::internal)? {
        return Err(ApiError::conflict("ssh_authority_revoked"));
    }
    if let Some(existing) = policy.ssh_sessions.get(&(request.pid, request.start)) {
        if existing.identity != request.identity {
            return Err(ApiError::conflict("ssh_process_already_bound"));
        }
        return Ok(Json(json!({"token":existing.token})));
    }
    if policy.ssh_sessions.len() >= 1024 {
        return Err(ApiError::unavailable("ssh_capacity_reached"));
    }
    let mut bytes = [0_u8; 32];
    openssl::rand::rand_bytes(&mut bytes).map_err(ApiError::internal)?;
    let token = authority_device_auth_core::encode_base64url(&bytes);
    policy.ssh_sessions.insert(
        (request.pid, request.start),
        Session {
            identity: request.identity,
            token: token.clone(),
            deadline: Instant::now() + Duration::from_secs(2),
        },
    );
    Ok(Json(json!({"token":token})))
}

async fn renew(
    State(state): State<AppState>,
    Json(request): Json<Renewal>,
) -> Result<Json<Value>, ApiError> {
    let mut policy = state.0.policy_state.lock().map_err(ApiError::internal)?;
    let session = policy
        .ssh_sessions
        .get(&(request.pid, request.start))
        .ok_or_else(|| ApiError::conflict("unknown_ssh_process"))?;
    if request.token != session.token
        || Instant::now() >= session.deadline
        || !allowed(&state, &policy, &session.identity).map_err(ApiError::internal)?
    {
        return Err(ApiError::conflict("ssh_authority_revoked"));
    }
    policy
        .ssh_sessions
        .get_mut(&(request.pid, request.start))
        .ok_or_else(|| ApiError::internal("SSH lease disappeared"))?
        .deadline = Instant::now() + Duration::from_secs(2);
    Ok(Json(json!({"renewed":true})))
}

pub(super) async fn start(state: AppState) -> Result<(), String> {
    let path = Path::new("/run/authority-ssh/enforcement.sock");
    let parent = path.parent().ok_or("missing SSH socket parent")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|e| e.to_string())?;
    let metadata = std::fs::metadata(parent).map_err(|e| e.to_string())?;
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
        return Err("unsafe SSH enforcement directory".into());
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || metadata.uid() != 0 {
                return Err("unsafe SSH socket path".into());
            }
            if tokio::net::UnixStream::connect(path).await.is_ok() {
                return Err("SSH socket already active".into());
            }
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let listener = tokio::net::UnixListener::bind(path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let router = Router::new()
        .route("/ssh/admit", post(admit))
        .route("/ssh/renew", post(renew))
        .with_state(state);
    tokio::spawn(async move {
        if let Err(cause) = axum::serve(listener, router).await {
            tracing::warn!(%cause,"SSH enforcement stopped");
        }
    });
    Ok(())
}
