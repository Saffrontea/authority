//! Root-only sshd leases. A separate systemd service owns each connection's
//! cgroup, so either enforcer process dying also terminates its connections.
use super::{ApiError, AppState};
use authority_contracts_model::fence::SshCertificateIdentityV2;
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
    revoked: bool,
}

#[derive(Default)]
pub(super) struct SshState {
    sessions: std::collections::HashMap<(u32, u64), Session>,
    pub(super) fence: Option<authority_replay_ledger::fence::FenceView>,
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
    ssh: &SshState,
    identity: &SshCertificateIdentityV2,
) -> Result<bool, String> {
    let now = super::unix_timestamp()?;
    if identity.validate().is_err()
        || identity.target_node_id != state.0.node_id
        || identity.generation.domain_id != state.0.domain_id
        || now < identity.not_before
        || now >= identity.expires_at
    {
        return Ok(false);
    }
    if ssh
        .fence
        .as_ref()
        .is_none_or(|view| view.rejects(&identity.generation))
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

pub(super) fn reconcile(state: &AppState) -> Result<(), String> {
    let stopped: Vec<_> = {
        let mut ssh = state.0.ssh_state.lock().map_err(|e| e.to_string())?;
        let mut stopped = Vec::new();
        for (&id, session) in &ssh.sessions {
            if session.revoked
                || Instant::now() >= session.deadline
                || !allowed(state, &ssh, &session.identity)?
            {
                stopped.push(id);
            }
        }
        for id in &stopped {
            ssh.sessions
                .get_mut(id)
                .ok_or("SSH session disappeared")?
                .revoked = true;
        }
        stopped
    };
    if stopped.is_empty() {
        return Ok(());
    }
    // Submit stop jobs together; never hold the renewal mutex across a command.
    let names: Vec<_> = stopped
        .iter()
        .map(|&(pid, start)| unit(pid, start))
        .collect();
    let submitted = super::bounded_command("/usr/bin/systemctl")
        .args(["stop", "--no-block", "--no-ask-password"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .args(&names)
        .status()
        .map_err(|e| e.to_string());
    let mut removed = Vec::new();
    for (&id, name) in stopped.iter().zip(names) {
        // The service cgroup includes the sshd monitor and every descendant.
        // A queued systemd job is not yet a cleanup receipt.
        let events = std::path::Path::new("/sys/fs/cgroup/system.slice")
            .join(name)
            .join("cgroup.events");
        match std::fs::read_to_string(events) {
            Ok(events) if events.lines().any(|line| line == "populated 0") => removed.push(id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => removed.push(id),
            Ok(_) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    let mut ssh = state.0.ssh_state.lock().map_err(|e| e.to_string())?;
    for id in removed {
        ssh.sessions.remove(&id);
    }
    if stopped.iter().any(|id| ssh.sessions.contains_key(id)) {
        if !submitted.is_ok_and(|status| status.success()) {
            return Err("SSH stop submission failed".into());
        }
        return Err("SSH cleanup pending".into());
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
    let mut ssh = state.0.ssh_state.lock().map_err(ApiError::internal)?;
    if !allowed(&state, &ssh, &request.identity).map_err(ApiError::internal)? {
        return Err(ApiError::conflict("ssh_authority_revoked"));
    }
    if let Some(existing) = ssh.sessions.get(&(request.pid, request.start)) {
        if existing.revoked || Instant::now() >= existing.deadline {
            return Err(ApiError::conflict("ssh_process_lease_expired"));
        }
        if existing.identity != request.identity {
            return Err(ApiError::conflict("ssh_process_already_bound"));
        }
        return Ok(Json(json!({"token":existing.token})));
    }
    if ssh.sessions.len() >= 1024 {
        return Err(ApiError::unavailable("ssh_capacity_reached"));
    }
    let mut bytes = [0_u8; 32];
    openssl::rand::rand_bytes(&mut bytes).map_err(ApiError::internal)?;
    let token = authority_device_auth_core::encode_base64url(&bytes);
    ssh.sessions.insert(
        (request.pid, request.start),
        Session {
            identity: request.identity,
            token: token.clone(),
            deadline: Instant::now() + Duration::from_secs(2),
            revoked: false,
        },
    );
    Ok(Json(json!({"token":token})))
}

async fn renew(
    State(state): State<AppState>,
    Json(request): Json<Renewal>,
) -> Result<Json<Value>, ApiError> {
    let mut ssh = state.0.ssh_state.lock().map_err(ApiError::internal)?;
    let session = ssh
        .sessions
        .get(&(request.pid, request.start))
        .ok_or_else(|| ApiError::conflict("unknown_ssh_process"))?;
    if session.revoked
        || request.token != session.token
        || Instant::now() >= session.deadline
        || !allowed(&state, &ssh, &session.identity).map_err(ApiError::internal)?
    {
        return Err(ApiError::conflict("ssh_authority_revoked"));
    }
    ssh.sessions
        .get_mut(&(request.pid, request.start))
        .ok_or_else(|| ApiError::internal("SSH lease disappeared"))?
        .deadline = Instant::now() + Duration::from_secs(2);
    Ok(Json(json!({"renewed":true})))
}

pub(super) fn initialize(state: &AppState) -> Result<(), String> {
    let mut policy = state.0.policy_state.lock().map_err(|e| e.to_string())?;
    let binding = authority_contracts_model::fence::GenerationBinding {
        domain_id: state.0.domain_id.clone(),
        subject_user_id: "startup".into(),
        device_id: "startup".into(),
        subject_generation: 1,
        device_generation: 1,
    };
    let view = super::fence::store(
        state,
        &mut policy,
        &binding,
        authority_contracts_model::AdapterGrantKindV1::SshCertificate,
    )?
    .view();
    state.0.ssh_state.lock().map_err(|e| e.to_string())?.fence = Some(view);

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Inner, NodeIdentity, PolicyState};
    use authority_contracts_model::fence::IdentityGenerations;
    use authority_credential_crypto_openssl::{OpenSslEd25519Signer, OpenSslEd25519Verifier};
    use std::sync::{Arc, Barrier, Mutex};

    fn state(path: &Path) -> (AppState, OpenSslEd25519Signer) {
        let root = OpenSslEd25519Signer::generate("cp-test").unwrap();
        let verifier =
            OpenSslEd25519Verifier::from_pem("cp-test", &root.public_key_to_pem().unwrap())
                .unwrap();
        let now = crate::unix_timestamp().unwrap();
        let state = AppState(Arc::new(Inner {
            observer: Some(Arc::new(crate::observation::tests::ssh_observer(
                path.join("observation"),
            ))),
            verifier,
            node_id: "node-test".into(),
            domain_id: "domain-test".into(),
            interface: "wg0".into(),
            replay_ledger: Mutex::new(
                authority_replay_ledger::ReplayLedger::open(path.join("replay"), now).unwrap(),
            ),
            revocations: Mutex::new(
                authority_replay_ledger::ReplayLedger::open(path.join("revoked"), now).unwrap(),
            ),
            policy_state: Mutex::new(PolicyState::default()),
            ssh_state: Mutex::new(SshState::default()),
            actuator_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            identity: NodeIdentity {
                public_key: String::new(),
                proof: String::new(),
            },
        }));
        let store = authority_replay_ledger::fence::FenceStore::open(
            path.join("identities"),
            "domain-test",
            "node-test",
        )
        .unwrap();
        state.0.ssh_state.lock().unwrap().fence = Some(store.view());
        (state, root)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lease_renewals_remain_live_while_the_actuator_transaction_is_blocked() {
        let directory = tempfile::tempdir().unwrap();
        let (state, _) = state(directory.path());
        let now = crate::unix_timestamp().unwrap();
        let identity = SshCertificateIdentityV2 {
            version: 2,
            generation: IdentityGenerations {
                subject: 1,
                device: 1,
            }
            .bind("domain-test", "alice", "client"),
            target_node_id: "node-test".into(),
            decision_id: "A".repeat(32),
            issued_at: now,
            not_before: now,
            expires_at: now + 60,
        };
        for pid in 2..202 {
            let _ = admit(
                State(state.clone()),
                Json(Admission {
                    identity: identity.clone(),
                    pid,
                    start: 1,
                }),
            )
            .await
            .unwrap();
        }
        let barrier = Arc::new(Barrier::new(2));
        let blocked_state = state.clone();
        let blocked_barrier = barrier.clone();
        let worker = std::thread::spawn(move || {
            let _transaction = blocked_state.0.policy_state.lock().unwrap();
            blocked_barrier.wait();
            std::thread::sleep(Duration::from_secs(4));
        });
        barrier.wait();
        for _ in 0..12 {
            let started = Instant::now();
            for pid in 2..202 {
                let token = state.0.ssh_state.lock().unwrap().sessions[&(pid, 1)]
                    .token
                    .clone();
                let _ = renew(
                    State(state.clone()),
                    Json(Renewal {
                        pid,
                        start: 1,
                        token,
                    }),
                )
                .await
                .unwrap();
            }
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "lease renewals waited for actuator I/O"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        worker.join().unwrap();
    }

    #[test]
    fn collected_session_cgroups_complete_cleanup_even_if_systemd_forgot_the_unit() {
        let directory = tempfile::tempdir().unwrap();
        let (state, _) = state(directory.path());
        let now = crate::unix_timestamp().unwrap();
        let identity = SshCertificateIdentityV2 {
            version: 2,
            generation: IdentityGenerations {
                subject: 1,
                device: 1,
            }
            .bind("domain-test", "alice", "client"),
            target_node_id: "node-test".into(),
            decision_id: "A".repeat(32),
            issued_at: now,
            not_before: now,
            expires_at: now + 60,
        };
        state.0.ssh_state.lock().unwrap().sessions.insert(
            (999_999_999, 1),
            Session {
                identity,
                token: "unused".into(),
                deadline: Instant::now(),
                revoked: true,
            },
        );
        reconcile(&state).unwrap();
        assert!(state.0.ssh_state.lock().unwrap().sessions.is_empty());
    }

    #[tokio::test]
    async fn correctly_signed_foreign_domain_notice_is_rejected_before_opening_a_store() {
        let directory = tempfile::tempdir().unwrap();
        let (state, root) = state(directory.path());
        let mut envelope: authority_contracts_model::fence::SignedScopedRevocationNoticeV3 = serde_json::from_str(include_str!("../../../contracts/test-vectors/signed-scoped-revocation-notice-v3/valid/subject.json")).unwrap();
        let now = crate::unix_timestamp().unwrap();
        envelope.notice.domain_id = "foreign-domain".into();
        envelope.notice.target_node_id = "node-test".into();
        envelope.notice.revoked_at = now;
        envelope.notice.expires_at = now + 60;
        let signed = authority_issuer_core::fence::sign(envelope.notice, &root).unwrap();
        let error = crate::fence::apply(State(state.clone()), Json(signed))
            .await
            .unwrap_err();
        assert_eq!(error.status, axum::http::StatusCode::UNAUTHORIZED);
        assert!(state.0.policy_state.lock().unwrap().fences.is_empty());
    }
}
