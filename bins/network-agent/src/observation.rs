use super::{ApiError, AppState, unix_timestamp};
use authority_contracts_model::observation::{
    EndpointFact, EndpointObservationV2, MAX_CLOCK_SKEW, OBSERVATION_TTL,
    SignedEndpointChallengeV1, SignedEndpointObservationV2,
};
use authority_credential_crypto_openssl::OpenSslEd25519Signer;
use authority_device_auth_core::{decode_signature, encode_base64url};
use authority_issuer_core::{AuthorizationSigner, AuthorizationVerifier};
use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    time::Duration,
};
const PROBE: &str = "/usr/local/lib/authority/endpoint-probe.py";

pub struct Observer {
    signer: OpenSslEd25519Signer,
    nft_layout: Value,
    boot_id: String,
    probe_lock: tokio::sync::Mutex<()>,
    support: Mutex<Support>,
    fence_path: PathBuf,
}
struct Snapshot {
    signed: SignedEndpointChallengeV1,
    report: EndpointObservationV2,
}
struct Support {
    snapshot: Option<Snapshot>,
    healthy: bool,
    fence: i64,
}
impl Observer {
    pub fn supports_tcp(
        &self,
        ports: &authority_contracts_model::resources::PortSet,
    ) -> Result<bool, String> {
        let support = self.support.lock().map_err(|e| e.to_string())?;
        Ok(support.healthy
            && support
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| ports.is_subset(&snapshot.report.tcp_ports)))
    }
    pub fn allows_ssh(
        &self,
        identity: &authority_contracts_model::fence::SshCertificateIdentityV2,
    ) -> Result<bool, String> {
        let support = self.support.lock().map_err(|e| e.to_string())?;
        let Some(snapshot) = &support.snapshot else {
            return Ok(false);
        };
        let report = &snapshot.report;
        Ok(support.healthy
            && report.active(unix_timestamp()?)
            && identity.issued_at > support.fence
            && identity.expires_at <= report.expires_at
            && identity.generation.domain_id == report.challenge.domain_id
            && identity.target_node_id == report.challenge.target_node_id
            && report.facts.contains(&EndpointFact::SshCaTrusted))
    }
    pub(super) fn sign_receipt(
        &self,
        notice: &authority_contracts_model::fence::ScopedRevocationNoticeV3,
    ) -> Result<String, String> {
        let message = authority_issuer_core::fence::receipt_preimage(notice)
            .map_err(|error| error.to_string())?;
        let signature = self
            .signer
            .sign(&message)
            .map_err(|error| error.to_string())?;
        Ok(encode_base64url(&signature))
    }
    pub fn new(signer: OpenSslEd25519Signer, fence_path: PathBuf) -> Result<Self, String> {
        let output = Command::new("/usr/bin/python3")
            .args([PROBE, "capture-nft"])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() || output.stdout.len() > 65536 {
            return Err("cannot capture initialized nft layout".into());
        }
        let previous = match std::fs::read_to_string(&fence_path) {
            Ok(s) => s.trim().parse::<i64>().map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.to_string()),
        };
        if previous < 0 {
            return Err("invalid observation fence".into());
        }
        let fence = previous.max(unix_timestamp()?.saturating_add(MAX_CLOCK_SKEW));
        persist_fence(&fence_path, fence)?;
        Ok(Self {
            signer,
            nft_layout: serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?,
            boot_id: format!(
                "{}:{}",
                std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .map_err(|e| e.to_string())?
                    .trim(),
                uuid::Uuid::new_v4()
            ),
            probe_lock: tokio::sync::Mutex::new(()),
            support: Mutex::new(Support {
                snapshot: None,
                healthy: false,
                fence,
            }),
            fence_path,
        })
    }
    pub fn allows(
        &self,
        domain: &str,
        source: &str,
        target: Option<&str>,
        validity: (i64, i64),
        tcp: bool,
    ) -> Result<bool, String> {
        let (issued_at, expires_at) = validity;
        let support = self.support.lock().map_err(|e| e.to_string())?;
        let Some(snapshot) = &support.snapshot else {
            return Ok(false);
        };
        let o = &snapshot.report;
        let r = &o.challenge.resources;
        Ok(support.healthy
            && o.active(unix_timestamp()?)
            && issued_at > support.fence
            && expires_at <= o.expires_at
            && o.challenge.domain_id == domain
            && r.source.to_string() == source
            && target.is_none_or(|target| target == r.target.to_string())
            && o.facts.contains(&EndpointFact::MeshRouteConfigured)
            && (!tcp || o.facts.contains(&EndpointFact::TcpEnforcement)))
    }
    fn invalidate(&self) -> Result<(), String> {
        let mut support = self.support.lock().map_err(|e| e.to_string())?;
        let first = support.healthy;
        support.healthy = false;
        if first {
            support.fence = support
                .fence
                .max(unix_timestamp()?.saturating_add(MAX_CLOCK_SKEW));
        }
        persist_fence(&self.fence_path, support.fence)?;
        Ok(())
    }
    fn accept(
        &self,
        state: &AppState,
        signed: SignedEndpointChallengeV1,
        report: EndpointObservationV2,
    ) -> Result<(), String> {
        let withdraw = {
            let support = self.support.lock().map_err(|e| e.to_string())?;
            support.snapshot.as_ref().is_some_and(|old| {
                !support.healthy
                    || !old.report.active(report.observed_at)
                    || old.report.challenge.domain_id != report.challenge.domain_id
                    || old.report.challenge.resources != report.challenge.resources
                    || !old.report.facts.is_subset(&report.facts)
                    || !old.report.tcp_ports.is_subset(&report.tcp_ports)
            })
        };
        if withdraw {
            self.invalidate()?;
            withdraw_kernel(state)?;
        }
        let mut support = self.support.lock().map_err(|e| e.to_string())?;
        support.snapshot = Some(Snapshot { signed, report });
        support.healthy = true;
        Ok(())
    }
}
fn persist_fence(path: &Path, fence: i64) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension(format!("new-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        writeln!(file, "{fence}").map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, path).map_err(|e| e.to_string())?;
        std::fs::File::open(path.parent().ok_or("fence parent missing")?)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
fn withdraw_kernel(state: &AppState) -> Result<(), String> {
    let mut policy = state.0.policy_state.lock().map_err(|e| e.to_string())?;
    super::clear_all_peers(&state.0.interface)?;
    if let Some(tcp) = &mut policy.tcp {
        tcp.clear()?;
    }
    policy.active_peers.clear();
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeResult {
    tcp_ports: authority_contracts_model::resources::PortSet,
    facts: BTreeSet<EndpointFact>,
    configuration_sha256: String,
    probe_sha256: String,
    errors: Vec<String>,
}
async fn probe(
    observer: &Observer,
    state: &AppState,
    signed: &SignedEndpointChallengeV1,
) -> Result<ProbeResult, String> {
    use tokio::io::AsyncWriteExt;
    let work = async {
        let mut child = tokio::process::Command::new("/usr/bin/python3")
            .args([PROBE, "probe"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| e.to_string())?;
        let input =
            json!({"signed":signed,"interface":state.0.interface,"nft_layout":observer.nft_layout});
        child
            .stdin
            .take()
            .ok_or("probe stdin missing")?
            .write_all(&serde_json::to_vec(&input).map_err(|e| e.to_string())?)
            .await
            .map_err(|e| e.to_string())?;
        let output = child.wait_with_output().await.map_err(|e| e.to_string())?;
        if !output.status.success() || output.stdout.len() > 16384 {
            return Err("endpoint_probe_failed".to_owned());
        }
        serde_json::from_slice::<ProbeResult>(&output.stdout).map_err(|e| e.to_string())
    };
    tokio::time::timeout(Duration::from_secs(12), work)
        .await
        .map_err(|_| "endpoint_probe_timeout".to_owned())?
}
pub fn start_monitor(state: AppState) {
    tokio::spawn(async move {
        let Some(observer) = state.0.observer.clone() else {
            return;
        };
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Ok(_guard) = observer.probe_lock.try_lock() else {
                continue;
            };
            let snapshot = match observer.support.lock() {
                Ok(s) => s
                    .snapshot
                    .as_ref()
                    .map(|v| (v.signed.clone(), v.report.clone(), s.healthy)),
                Err(_) => return,
            };
            let Some((signed, report, healthy)) = snapshot else {
                continue;
            };
            let valid = match probe(&observer, &state, &signed).await {
                Ok(result) => {
                    report.active(unix_timestamp().unwrap_or(i64::MAX))
                        && report.facts.is_subset(&result.facts)
                        && report.tcp_ports.is_subset(&result.tcp_ports)
                }
                Err(cause) => {
                    tracing::warn!(%cause,"live endpoint probe failed");
                    false
                }
            };
            if !valid || !healthy {
                if let Err(cause) = observer.invalidate() {
                    tracing::error!(%cause,"cannot persist endpoint observation fence");
                }
                if let Err(cause) = withdraw_kernel(&state) {
                    tracing::warn!(%cause,"endpoint withdrawal will retry");
                }
            }
        }
    });
}
pub async fn observe(
    State(state): State<AppState>,
    Json(signed): Json<SignedEndpointChallengeV1>,
) -> Result<Json<SignedEndpointObservationV2>, (StatusCode, String)> {
    let now = unix_timestamp().map_err(internal)?;
    let challenge = &signed.challenge;
    let rejected = || {
        (
            StatusCode::UNAUTHORIZED,
            "invalid_endpoint_challenge".to_owned(),
        )
    };
    if signed.validate().is_err()
        || !challenge.active(now)
        || challenge.target_node_id != state.0.node_id
    {
        return Err(rejected());
    }
    let signature = decode_signature(&signed.signature).map_err(|_| rejected())?;
    if !state
        .0
        .verifier
        .verify(
            &signed.key_id,
            &challenge.signing_preimage().map_err(internal)?,
            &signature,
        )
        .map_err(internal)?
    {
        return Err(rejected());
    }
    let observer = state
        .0
        .observer
        .clone()
        .ok_or_else(|| internal("observer_not_configured"))?;
    if !state
        .0
        .replay_ledger
        .lock()
        .map_err(internal)?
        .consume(
            &format!("observation_{}", challenge.nonce),
            challenge.expires_at,
            now,
        )
        .map_err(internal)?
    {
        return Err((StatusCode::CONFLICT, "endpoint_challenge_replayed".into()));
    }
    let _guard = observer.probe_lock.lock().await;
    if !signed.challenge.active(unix_timestamp().map_err(internal)?) {
        return Err(rejected());
    }
    let observed_at = unix_timestamp().map_err(internal)?;
    let result = probe(&observer, &state, &signed).await.map_err(internal)?;
    for error in result.errors {
        tracing::warn!(%error,"endpoint probe withdrew a fact");
    }
    let now = unix_timestamp().map_err(internal)?;
    if !signed.challenge.active(now) {
        return Err(rejected());
    }
    let observation = EndpointObservationV2 {
        tcp_ports: result.tcp_ports,
        challenge: signed.challenge.clone(),
        boot_id: observer.boot_id.clone(),
        observed_at,
        expires_at: observed_at + OBSERVATION_TTL,
        configuration_sha256: result.configuration_sha256,
        probe_sha256: result.probe_sha256,
        facts: result.facts,
    };
    let signature = encode_base64url(
        &observer
            .signer
            .sign(&observation.signing_preimage().map_err(internal)?)
            .map_err(internal)?,
    );
    observer
        .accept(&state, signed, observation.clone())
        .map_err(internal)?;
    // Give a CP clock at the slow edge of the permitted skew a strictly newer
    // issuance second than the durable fence. No previous grant can cross it.
    let fence = observer.support.lock().map_err(internal)?.fence;
    let wait = fence
        .saturating_add(MAX_CLOCK_SKEW + 1)
        .saturating_sub(unix_timestamp().map_err(internal)?);
    if wait > 0 {
        tokio::time::sleep(Duration::from_secs(u64::try_from(wait).map_err(internal)?)).await;
    }
    if !observation
        .challenge
        .active(unix_timestamp().map_err(internal)?)
    {
        return Err(rejected());
    }
    Ok(Json(SignedEndpointObservationV2 {
        observation,
        signature,
    }))
}
fn internal(error: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::warn!(%error,"endpoint observation failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "endpoint_observation_unavailable".into(),
    )
}

pub fn require_network(
    state: &AppState,
    grant: &authority_contracts_model::NetworkAccessGrantV1,
    now: i64,
) -> Result<(), super::ApiError> {
    if state
        .0
        .replay_ledger
        .lock()
        .map_err(ApiError::internal)?
        .contains(&grant.nonce, now)
    {
        return Err(ApiError::conflict("network_grant_replayed"));
    }
    if !state
        .0
        .observer
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("endpoint_observation_unavailable"))?
        .allows(
            &grant.domain_id,
            &grant.mesh_address,
            None,
            (grant.issued_at, grant.expires_at),
            false,
        )
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unavailable("endpoint_observation_unavailable"));
    }
    Ok(())
}
pub fn require_tcp(
    state: &AppState,
    grant: &authority_contracts_model::TcpAccessGrantV2,
    decision_nonce: &str,
    now: i64,
) -> Result<(), super::ApiError> {
    if state
        .0
        .replay_ledger
        .lock()
        .map_err(ApiError::internal)?
        .contains(decision_nonce, now)
    {
        return Err(ApiError::conflict("tcp_grant_replayed"));
    }
    let source = grant
        .resources
        .source_addresses
        .as_host()
        .ok_or_else(|| ApiError::unavailable("tcp_resource_scope_unobserved"))?
        .to_string();
    let target = grant
        .resources
        .destination_addresses
        .as_host()
        .ok_or_else(|| ApiError::unavailable("tcp_resource_scope_unobserved"))?
        .to_string();
    let observer = state
        .0
        .observer
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("endpoint_observation_unavailable"))?;
    if !observer
        .supports_tcp(&grant.resources.destination_ports)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unavailable("tcp_resource_scope_unobserved"));
    }
    if !state
        .0
        .observer
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("endpoint_observation_unavailable"))?
        .allows(
            &grant.domain_id,
            &source,
            Some(&target),
            (grant.issued_at, grant.expires_at),
            true,
        )
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unavailable("endpoint_observation_unavailable"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use authority_contracts_model::observation::{
        CHALLENGE_TTL, EndpointChallengeV1, OBSERVATION_AUDIENCE, ObservationResources,
    };
    fn observer(path: PathBuf) -> Observer {
        let now = unix_timestamp().unwrap();
        let challenge = EndpointChallengeV1 {
            version: 1,
            audience: OBSERVATION_AUDIENCE.into(),
            domain_id: "domain-test".into(),
            target_node_id: "node-test".into(),
            nonce: "A".repeat(43),
            revision: 1,
            issued_at: now,
            expires_at: now + CHALLENGE_TTL,
            resources: ObservationResources {
                source: "10.77.0.1".parse().unwrap(),
                target: "10.77.0.2".parse().unwrap(),
                principal: "deploy".into(),
                ssh_ca_fingerprints: BTreeSet::from([format!("SHA256:{}", "A".repeat(43))]),
                mtls_ca_sha256: "a".repeat(64),
                service_audience: "demo-api".into(),
            },
        };
        let report = EndpointObservationV2 {
            tcp_ports: authority_contracts_model::resources::PortSet::range(8080, 8081).unwrap(),
            challenge: challenge.clone(),
            boot_id: "boot-test".into(),
            observed_at: now,
            expires_at: now + OBSERVATION_TTL,
            configuration_sha256: "b".repeat(64),
            probe_sha256: "c".repeat(64),
            facts: BTreeSet::from([
                EndpointFact::MeshRouteConfigured,
                EndpointFact::TcpEnforcement,
            ]),
        };
        Observer {
            signer: OpenSslEd25519Signer::generate("test").unwrap(),
            nft_layout: Value::Null,
            boot_id: "boot-test".into(),
            probe_lock: tokio::sync::Mutex::new(()),
            fence_path: path,
            support: Mutex::new(Support {
                snapshot: Some(Snapshot {
                    signed: SignedEndpointChallengeV1 {
                        challenge,
                        key_id: "cp-test".into(),
                        signature: "A".repeat(86),
                    },
                    report,
                }),
                healthy: true,
                fence: now - 2,
            }),
        }
    }
    #[test]
    fn lost_support_is_fenced_durably_and_old_grants_do_not_return_after_repair() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fence");
        let observer = observer(path.clone());
        let issued = unix_timestamp().unwrap();
        assert!(
            observer
                .allows(
                    "domain-test",
                    "10.77.0.1",
                    Some("10.77.0.2"),
                    (issued, issued + 20),
                    true
                )
                .unwrap()
        );
        observer.invalidate().unwrap();
        let fence = std::fs::read_to_string(&path)
            .unwrap()
            .trim()
            .parse::<i64>()
            .unwrap();
        assert!(fence >= issued + MAX_CLOCK_SKEW);
        assert!(
            !observer
                .allows(
                    "domain-test",
                    "10.77.0.1",
                    Some("10.77.0.2"),
                    (issued, issued + 20),
                    true
                )
                .unwrap()
        );
        observer.support.lock().unwrap().healthy = true;
        assert!(
            !observer
                .allows(
                    "domain-test",
                    "10.77.0.1",
                    Some("10.77.0.2"),
                    (issued, issued + 20),
                    true
                )
                .unwrap()
        );
        assert!(
            observer
                .allows(
                    "domain-test",
                    "10.77.0.1",
                    Some("10.77.0.2"),
                    (fence + 1, issued + 20),
                    true
                )
                .unwrap()
        );
        assert!(
            !observer
                .allows(
                    "other-domain",
                    "10.77.0.1",
                    Some("10.77.0.2"),
                    (fence + 1, issued + 20),
                    true
                )
                .unwrap()
        );
        assert!(
            !observer
                .allows(
                    "domain-test",
                    "10.77.0.3",
                    Some("10.77.0.2"),
                    (fence + 1, issued + 20),
                    true
                )
                .unwrap()
        );
    }
    #[test]
    fn a_failed_fence_write_keeps_admission_closed_and_is_retried() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("missing");
        let path = parent.join("fence");
        let observer = observer(path.clone());
        assert!(observer.invalidate().is_err());
        assert!(!observer.support.lock().unwrap().healthy);
        std::fs::create_dir(parent).unwrap();
        observer.invalidate().unwrap();
        assert!(path.is_file());
        assert!(!observer.support.lock().unwrap().healthy);
    }
}
