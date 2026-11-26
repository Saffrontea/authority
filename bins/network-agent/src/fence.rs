//! Persist selectors before cleanup; every installation observes the same mutex.
use super::{ApiError, AppState, PolicyState};
use authority_contracts_model::{
    AdapterGrantKindV1,
    fence::{GenerationBinding, RevocationSelector, SignedScopedRevocationNoticeV3},
};
use authority_replay_ledger::fence::FenceStore;
use axum::{Json, extract::State};
use serde_json::{Value, json};
use std::{collections::HashSet, path::PathBuf, time::Duration};

pub(super) fn store<'a>(
    state: &AppState,
    policy: &'a mut PolicyState,
    binding: &GenerationBinding,
    kind: AdapterGrantKindV1,
) -> Result<&'a mut FenceStore, String> {
    if binding.domain_id != state.0.domain_id {
        return Err("identity fence domain mismatch".into());
    }
    let domain = binding
        .domain_id
        .parse::<uuid::Uuid>()
        .map_err(|e| e.to_string())?;
    let key = (binding.domain_id.clone(), kind);
    if !policy.fences.contains_key(&key) {
        if policy.fences.len() >= 128 {
            return Err("identity fence domain capacity reached".into());
        }
        let root = std::env::var_os("AUTHORITY_IDENTITY_FENCE_DIR").map_or_else(
            || PathBuf::from("/var/lib/authority/identity-fences"),
            PathBuf::from,
        );
        let path = root
            .join(domain.to_string())
            .join(format!("{}.json", kind.as_str()));
        policy.fences.insert(
            key.clone(),
            FenceStore::open(path, &binding.domain_id, &state.0.node_id)?,
        );
    }
    policy
        .fences
        .get_mut(&key)
        .ok_or_else(|| "identity fence disappeared".into())
}

pub(super) fn require(
    state: &AppState,
    policy: &mut PolicyState,
    binding: &GenerationBinding,
    kind: AdapterGrantKindV1,
) -> Result<(), ApiError> {
    if binding.domain_id != state.0.domain_id {
        return Err(ApiError::unauthorized(
            "invalid_identity_domain",
            "grant belongs to another configured domain",
        ));
    }
    repair_uncertain(state, policy).map_err(ApiError::internal)?;
    if store(state, policy, binding, kind)
        .map_err(ApiError::internal)?
        .rejects(binding)
    {
        return Err(ApiError::conflict("identity_generation_revoked"));
    }
    Ok(())
}

fn repair_uncertain(state: &AppState, policy: &mut PolicyState) -> Result<(), String> {
    if policy.uncertain_tcp {
        policy.tcp.as_ref().ok_or("TCP not configured")?.sync()?;
        policy.uncertain_tcp = false;
    }
    if !policy.uncertain_peers.is_empty() {
        let peers: Vec<_> = policy.uncertain_peers.iter().cloned().collect();
        super::remove_peers(&state.0.interface, &peers)?;
        for peer in peers {
            policy.active_peers.remove(&peer);
            policy
                .bindings
                .remove(&(AdapterGrantKindV1::WireGuardPeer, peer));
        }
        policy.uncertain_peers.clear();
    }
    Ok(())
}

pub(super) fn reconcile(state: &AppState, policy: &mut PolicyState) -> Result<(), String> {
    repair_uncertain(state, policy)?;
    super::ssh::reconcile(state)?;
    let rejected: Vec<_> = policy
        .bindings
        .iter()
        .filter(|((kind, _), binding)| {
            policy
                .fences
                .get(&(binding.domain_id.clone(), *kind))
                .is_some_and(|store| store.rejects(binding))
        })
        .map(|(key, _)| key.clone())
        .collect();
    let tcp: HashSet<_> = rejected
        .iter()
        .filter(|(kind, _)| *kind == AdapterGrantKindV1::TcpPort)
        .map(|(_, id)| id.clone())
        .collect();
    if !tcp.is_empty() {
        policy
            .tcp
            .as_mut()
            .ok_or("TCP not configured")?
            .revoke_many(&tcp)?;
    }
    let peers: Vec<_> = rejected
        .iter()
        .filter(|(kind, id)| {
            *kind == AdapterGrantKindV1::WireGuardPeer && policy.active_peers.contains_key(id)
        })
        .map(|(_, id)| id.clone())
        .collect();
    super::remove_peers(&state.0.interface, &peers)?;
    for (kind, id) in rejected {
        if kind == AdapterGrantKindV1::WireGuardPeer {
            policy.active_peers.remove(&id);
        }
        policy.bindings.remove(&(kind, id));
    }
    policy.bindings.retain(|(kind, id), _| match kind {
        AdapterGrantKindV1::WireGuardPeer => policy.active_peers.contains_key(id),
        AdapterGrantKindV1::TcpPort => policy
            .tcp
            .as_ref()
            .is_some_and(|tcp| tcp.grants.contains_key(id)),
        _ => false,
    });
    Ok(())
}

pub(super) async fn apply(
    state: State<AppState>,
    envelope: Json<SignedScopedRevocationNoticeV3>,
) -> Result<Json<Value>, ApiError> {
    let permit = state
        .0
        .0
        .actuator_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::unavailable("actuator_busy"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        apply_blocking(state, envelope)
    })
    .await
    .map_err(ApiError::internal)?
}

fn apply_blocking(
    State(state): State<AppState>,
    Json(envelope): Json<SignedScopedRevocationNoticeV3>,
) -> Result<Json<Value>, ApiError> {
    let n = &envelope.notice;
    let now = super::unix_timestamp().map_err(ApiError::internal)?;
    let mut kinds = Vec::new();
    for kind in [
        AdapterGrantKindV1::WireGuardPeer,
        AdapterGrantKindV1::TcpPort,
        AdapterGrantKindV1::SshCertificate,
    ] {
        if n.adapter_kinds.contains(&kind) {
            authority_issuer_core::fence::verify(
                &envelope,
                &state.0.verifier,
                &state.0.domain_id,
                &state.0.node_id,
                kind,
                now,
            )
            .map_err(|e| ApiError::unauthorized("invalid_identity_revocation", e))?;
            kinds.push(kind);
        }
    }
    if kinds.is_empty() || matches!(n.selector, RevocationSelector::Decision { .. }) {
        return Err(ApiError::conflict("unsupported_identity_revocation"));
    }
    let binding = GenerationBinding {
        domain_id: n.domain_id.clone(),
        subject_user_id: "fence".into(),
        device_id: "fence".into(),
        subject_generation: 1,
        device_generation: 1,
    };
    let mut policy = state.0.policy_state.lock().map_err(ApiError::internal)?;
    for kind in kinds {
        let store = store(&state, &mut policy, &binding, kind).map_err(ApiError::internal)?;
        let result = store.advance(&n.selector);
        if kind == AdapterGrantKindV1::SshCertificate {
            // Publish even a poisoned view before retrying failed persistence.
            state.0.ssh_state.lock().map_err(ApiError::internal)?.fence = Some(store.view());
        }
        result.map_err(ApiError::internal)?;
    }
    reconcile(&state, &mut policy).map_err(ApiError::internal)?;
    let signature = state
        .0
        .observer
        .as_ref()
        .ok_or_else(|| ApiError::internal("missing node signer"))?
        .sign_receipt(n)
        .map_err(ApiError::internal)?;
    Ok(Json(
        json!({"sequence":n.sequence,"fence_persisted":true,"signature":signature}),
    ))
}

pub(super) fn start_monitor(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let cleanup_state = state.clone();
            let result = tokio::task::spawn_blocking(move || {
                let state = cleanup_state;
                state
                    .0
                    .policy_state
                    .lock()
                    .map_err(|e| e.to_string())
                    .and_then(|mut policy| {
                        reconcile(&state, &mut policy)?;
                        let now = super::unix_timestamp()?;
                        let peers: Vec<_> = policy
                            .active_peers
                            .iter()
                            .filter(|(_, active)| {
                                active.expires_at <= now
                                    || policy
                                        .revoked_decisions
                                        .get(&active.decision_id)
                                        .is_some_and(|expiry| *expiry > now)
                            })
                            .map(|(peer, _)| peer.clone())
                            .collect();
                        super::remove_peers(&state.0.interface, &peers)?;
                        for peer in peers {
                            policy.active_peers.remove(&peer);
                        }
                        notify_systemd("WATCHDOG=1")
                    })
            })
            .await
            .unwrap_or_else(|error| Err(error.to_string()));
            if let Err(cause) = result {
                tracing::warn!(%cause,"identity fence cleanup will retry");
            }
        }
    });
}

pub(super) fn notify_systemd(message: &str) -> Result<(), String> {
    use std::os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixDatagram},
    };
    let path = std::env::var("NOTIFY_SOCKET")
        .map_err(|_| "managed network agent requires a systemd watchdog")?;
    let address = if let Some(name) = path.strip_prefix('@') {
        SocketAddr::from_abstract_name(name)
    } else {
        SocketAddr::from_pathname(path)
    }
    .map_err(|e| e.to_string())?;
    UnixDatagram::unbound()
        .and_then(|socket| socket.send_to_addr(message.as_bytes(), &address))
        .map_err(|e| e.to_string())?;
    Ok(())
}
