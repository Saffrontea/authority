//! Challenge issuance and publication are serialized by the registered target row.
use crate::state::AppState;
use authority_contracts_model::observation::{
    CHALLENGE_TTL, EndpointChallengeV1, OBSERVATION_AUDIENCE, ObservationResources,
    SignedEndpointChallengeV1, SignedEndpointObservationV1,
};
use authority_credential_crypto_openssl::verify_device_signature;
use authority_device_auth_core::{decode_signature, encode_base64url};
use authority_issuer_core::AuthorizationSigner;
use openssl::{hash::MessageDigest, rand::rand_bytes, sha::sha256, x509::X509};
use sqlx::{Postgres, Row, Transaction};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub fn now() -> Result<i64, String> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    )
    .map_err(|e| e.to_string())
}
fn ca_resources(
    source: std::net::Ipv4Addr,
    target: std::net::Ipv4Addr,
) -> Result<ObservationResources, String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.secrets");
    let ssh_path = std::env::var_os("AUTHORITY_SSH_TRUSTED_CA_FILE").map_or_else(
        || {
            let bundle = root.join("ssh-trusted-user-cas.pub");
            if bundle.exists() {
                bundle
            } else {
                root.join("ssh-ca.pub")
            }
        },
        PathBuf::from,
    );
    let mut fingerprints = BTreeSet::new();
    for line in std::fs::read_to_string(ssh_path)
        .map_err(|e| e.to_string())?
        .lines()
    {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let encoded = line
            .split_whitespace()
            .nth(1)
            .ok_or("invalid SSH trust bundle")?;
        let bytes = openssl::base64::decode_block(encoded).map_err(|e| e.to_string())?;
        fingerprints.insert(format!(
            "SHA256:{}",
            openssl::base64::encode_block(&sha256(&bytes)).trim_end_matches('=')
        ));
    }
    let ca_path = std::env::var_os("AUTHORITY_MTLS_CA_CERTIFICATE_FILE")
        .map_or_else(|| root.join("mtls-ca-cert.pem"), PathBuf::from);
    let ca = X509::from_pem(&std::fs::read(ca_path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let digest = ca
        .digest(MessageDigest::sha256())
        .map_err(|e| e.to_string())?;
    Ok(ObservationResources {
        source,
        target,
        principal: "deploy".into(),
        ssh_ca_fingerprints: fingerprints,
        mtls_ca_sha256: digest
            .iter()
            .fold(String::with_capacity(64), |mut output, b| {
                use std::fmt::Write;
                let _ = write!(output, "{b:02x}");
                output
            }),
        service_audience: crate::config::DEMO_SERVICE_AUDIENCE.into(),
    })
}
async fn lock_node(
    tx: &mut Transaction<'_, Postgres>,
    domain: Uuid,
    node: Uuid,
) -> Result<[u8; 32], String> {
    let row=sqlx::query("SELECT d.device_public_key FROM device.nodes n JOIN device.devices d ON d.id=n.device_id WHERE n.id=$1 AND d.domain_id=$2 AND d.owner_kind='domain' AND d.owner_domain_id=$2 AND n.status='active' AND d.status='active' FOR UPDATE OF n FOR SHARE OF d")
        .bind(node).bind(domain).fetch_optional(&mut **tx).await.map_err(|e|e.to_string())?.ok_or("target_not_registered")?;
    row.try_get::<Vec<u8>, _>("device_public_key")
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "invalid_target_public_key".into())
}

async fn issue_challenge(
    state: &AppState,
    subject: Uuid,
    device: Uuid,
    node: Uuid,
) -> Result<SignedEndpointChallengeV1, String> {
    let mut tx = crate::access_policy::begin_authorization(state.pool())
        .await
        .map_err(|e| e.to_string())?;
    lock_node(&mut tx, state.domain_id(), node).await?;
    let row=sqlx::query("SELECT host(d.mesh_address) AS source,host(n.mesh_address) AS target FROM device.devices d CROSS JOIN device.nodes n WHERE d.id=$1 AND d.domain_id=$2 AND n.id=$3 AND d.owner_user_id=$4 AND d.owner_kind='user' AND d.status='active' AND EXISTS (SELECT 1 FROM policy.ability_policies p WHERE p.domain_id=$2 AND p.subject_user_id=$4 AND p.target_node_id=$3 AND (p.required_device_id IS NULL OR p.required_device_id=$1) AND p.enabled AND p.effect='allow' AND p.revoked_at IS NULL)")
        .bind(device).bind(state.domain_id()).bind(node).bind(subject).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
    let identity: serde_json::Value = serde_json::from_slice(
        &std::fs::read(state.target_identity_file()).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if identity.get("node_id").and_then(serde_json::Value::as_str)
        != Some(node.to_string().as_str())
    {
        return Err("target_origin_binding_mismatch".into());
    }
    let resources = ca_resources(
        row.try_get::<String, _>("source")
            .map_err(|e| e.to_string())?
            .parse()
            .map_err(|_| "invalid_source")?,
        row.try_get::<String, _>("target")
            .map_err(|e| e.to_string())?
            .parse()
            .map_err(|_| "invalid_target")?,
    )?;
    let clock: i64 =
        sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
    let previous=sqlx::query("SELECT domain_id,revision,requested_at,window_start,attempts,pending_challenge,consumed FROM device.endpoint_observations WHERE node_id=$1")
        .bind(node).fetch_optional(&mut *tx).await.map_err(|e|e.to_string())?;
    let (revision, window_start, attempts) = next_revision(previous, clock, state.domain_id())?;
    let mut random = [0_u8; 32];
    rand_bytes(&mut random).map_err(|e| e.to_string())?;
    let challenge = EndpointChallengeV1 {
        version: 1,
        audience: OBSERVATION_AUDIENCE.into(),
        domain_id: state.domain_id().to_string(),
        target_node_id: node.to_string(),
        nonce: encode_base64url(&random),
        revision,
        issued_at: clock,
        expires_at: clock + CHALLENGE_TTL,
        resources,
    };
    let signature = encode_base64url(
        &state
            .signer()
            .sign(&challenge.signing_preimage()?)
            .map_err(|e| e.to_string())?,
    );
    sqlx::query("INSERT INTO device.endpoint_observations(node_id,domain_id,revision,requested_at,pending_challenge,window_start,attempts) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(node_id) DO UPDATE SET domain_id=EXCLUDED.domain_id,revision=EXCLUDED.revision,requested_at=EXCLUDED.requested_at,pending_challenge=EXCLUDED.pending_challenge,window_start=EXCLUDED.window_start,attempts=EXCLUDED.attempts,consumed=false,envelope=NULL")
        .bind(node).bind(state.domain_id()).bind(revision).bind(clock).bind(serde_json::to_value(&challenge).map_err(|e|e.to_string())?).bind(window_start).bind(attempts).execute(&mut *tx).await.map_err(|e|e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(SignedEndpointChallengeV1 {
        challenge,
        key_id: state.signer().key_id().into(),
        signature,
    })
}
fn next_revision(
    previous: Option<sqlx::postgres::PgRow>,
    clock: i64,
    domain: Uuid,
) -> Result<(i64, i64, i32), String> {
    let next = if let Some(row) = previous {
        let same_domain = row
            .try_get::<Uuid, _>("domain_id")
            .map_err(|e| e.to_string())?
            == domain;
        let pending: EndpointChallengeV1 = serde_json::from_value(
            row.try_get("pending_challenge")
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if !row
            .try_get::<bool, _>("consumed")
            .map_err(|e| e.to_string())?
            && same_domain
            && pending.expires_at > clock
        {
            return Err("endpoint_probe_busy".into());
        }
        let previous_window: i64 = row.try_get("window_start").map_err(|e| e.to_string())?;
        let previous_attempts: i32 = row.try_get("attempts").map_err(|e| e.to_string())?;
        let (window, attempts) = if !same_domain || clock - previous_window >= 30 {
            (clock, 1)
        } else {
            (previous_window, previous_attempts + 1)
        };
        if attempts > 64 {
            return Err("endpoint_probe_rate_limited".into());
        }
        (
            row.try_get::<i64, _>("revision")
                .map_err(|e| e.to_string())?
                .checked_add(1)
                .ok_or("observation_revision_exhausted")?,
            window,
            attempts,
        )
    } else {
        (1, clock, 1)
    };
    Ok(next)
}

pub async fn refresh(
    state: &AppState,
    subject: Uuid,
    device: Uuid,
    node: Uuid,
) -> Result<i64, String> {
    let signed = issue_challenge(state, subject, device, node).await?;
    let challenge = &signed.challenge;
    let revision = challenge.revision;
    let result = async {
        let envelope = fetch(state, &signed).await?;
        publish(state, challenge, &envelope).await?;
        Ok(revision)
    }
    .await;
    if result.is_err() {
        abort(state, node, revision).await;
    }
    result
}
async fn fetch(
    state: &AppState,
    signed: &SignedEndpointChallengeV1,
) -> Result<SignedEndpointObservationV1, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let mut response = client
        .post(format!(
            "{}/v1/endpoint-observations",
            state.network_agent_origin().trim_end_matches('/')
        ))
        .json(signed)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > 16384 {
            return Err("observation_response_too_large".into());
        }
        bytes.extend(chunk);
    }
    let envelope: SignedEndpointObservationV1 =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    Ok(envelope)
}
async fn abort(state: &AppState, node: Uuid, revision: i64) {
    if let Ok(mut tx) = crate::access_policy::begin_authorization(state.pool()).await
        && lock_node(&mut tx, state.domain_id(), node).await.is_ok()
    {
        let cleared=sqlx::query("UPDATE device.endpoint_observations SET consumed=true,envelope=NULL WHERE node_id=$1 AND revision=$2 AND NOT consumed")
            .bind(node).bind(revision).execute(&mut *tx).await;
        if cleared.is_ok() {
            let _ = tx.commit().await;
        }
    }
}

pub(crate) async fn publish(
    state: &AppState,
    challenge: &EndpointChallengeV1,
    envelope: &SignedEndpointObservationV1,
) -> Result<(), String> {
    let mut tx = crate::access_policy::begin_authorization(state.pool())
        .await
        .map_err(|e| e.to_string())?;
    let node = challenge
        .target_node_id
        .parse()
        .map_err(|_| "invalid_node_id")?;
    let key = lock_node(&mut tx, state.domain_id(), node).await?;
    let row=sqlx::query("SELECT pending_challenge,consumed,revision FROM device.endpoint_observations WHERE node_id=$1 AND domain_id=$2")
        .bind(node).bind(state.domain_id()).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
    let pending: EndpointChallengeV1 = serde_json::from_value(
        row.try_get("pending_challenge")
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if row
        .try_get::<i64, _>("revision")
        .map_err(|e| e.to_string())?
        != pending.revision
        || row
            .try_get::<bool, _>("consumed")
            .map_err(|e| e.to_string())?
        || pending != *challenge
        || !pending.active(now()?)
        || pending.domain_id != state.domain_id().to_string()
    {
        return Err("endpoint_challenge_replayed_or_superseded".into());
    }
    verify(envelope, &key, &pending, now()?)?;
    sqlx::query(
        "UPDATE device.endpoint_observations SET envelope=$2,consumed=true WHERE node_id=$1",
    )
    .bind(node)
    .bind(serde_json::to_value(envelope).map_err(|e| e.to_string())?)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

pub fn verify(
    envelope: &SignedEndpointObservationV1,
    key: &[u8; 32],
    challenge: &EndpointChallengeV1,
    clock: i64,
) -> Result<(), String> {
    envelope.validate()?;
    if envelope.observation.challenge != *challenge || !envelope.observation.active(clock) {
        return Err("invalid_or_stale_endpoint_observation".into());
    }
    let signature =
        decode_signature(&envelope.signature).map_err(|_| "invalid_observation_signature")?;
    if !verify_device_signature(key, &envelope.observation.signing_preimage()?, &signature)
        .map_err(|e| e.to_string())?
    {
        return Err("invalid_observation_signature".into());
    }
    Ok(())
}

/// Re-verify stored bytes against the currently locked node key and resource binding.
pub(crate) fn snapshot(
    row: &sqlx::postgres::PgRow,
    request: &authority_policy_core::AccessRequest,
) -> Result<SignedEndpointObservationV1, String> {
    use authority_contracts_model::observation::{
        EndpointChallengeV1, SignedEndpointObservationV1,
    };
    let envelope: SignedEndpointObservationV1 = serde_json::from_value(
        row.try_get::<serde_json::Value, _>("observation")
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let challenge: EndpointChallengeV1 = serde_json::from_value(
        row.try_get("pending_challenge")
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let key: [u8; 32] = row
        .try_get::<Vec<u8>, _>("target_public_key")
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "invalid_public_key")?;
    if row
        .try_get::<Option<i64>, _>("observation_revision")
        .map_err(|e| e.to_string())?
        != Some(challenge.revision)
        || !row
            .try_get::<Option<bool>, _>("consumed")
            .map_err(|e| e.to_string())?
            .unwrap_or(false)
        || challenge.domain_id != request.domain_id.to_string()
        || challenge.target_node_id != request.target_node_id.to_string()
        || challenge.resources.source.to_string()
            != row
                .try_get::<String, _>("device_mesh_address")
                .map_err(|e| e.to_string())?
        || challenge.resources.target.to_string()
            != row
                .try_get::<String, _>("target_mesh_address")
                .map_err(|e| e.to_string())?
    {
        return Err("observation_binding_mismatch".into());
    }
    crate::endpoint_observation::verify(
        &envelope,
        &key,
        &challenge,
        crate::endpoint_observation::now()?,
    )?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authority_contracts_model::observation::{
        EndpointFact, EndpointObservationV1, OBSERVATION_TTL,
    };
    use authority_credential_crypto_openssl::OpenSslEd25519Signer;
    fn fixture() -> (OpenSslEd25519Signer, SignedEndpointObservationV1) {
        let key = OpenSslEd25519Signer::generate("node-test").unwrap();
        let challenge = EndpointChallengeV1 {
            version: 1,
            audience: OBSERVATION_AUDIENCE.into(),
            domain_id: Uuid::from_u128(1).to_string(),
            target_node_id: Uuid::from_u128(2).to_string(),
            nonce: "A".repeat(43),
            revision: 7,
            issued_at: 100,
            expires_at: 130,
            resources: ObservationResources {
                source: "10.77.0.1".parse().unwrap(),
                target: "10.77.0.2".parse().unwrap(),
                principal: "deploy".into(),
                ssh_ca_fingerprints: BTreeSet::from([format!("SHA256:{}", "A".repeat(43))]),
                mtls_ca_sha256: "a".repeat(64),
                service_audience: "demo-api".into(),
            },
        };
        let observation = EndpointObservationV1 {
            challenge,
            boot_id: "boot-test".into(),
            observed_at: 101,
            expires_at: 101 + OBSERVATION_TTL,
            configuration_sha256: "b".repeat(64),
            probe_sha256: "c".repeat(64),
            facts: BTreeSet::from([
                EndpointFact::TcpEnforcement,
                EndpointFact::ExistingRouteConfigured,
            ]),
        };
        let signature =
            encode_base64url(&key.sign(&observation.signing_preimage().unwrap()).unwrap());
        (
            key,
            SignedEndpointObservationV1 {
                observation,
                signature,
            },
        )
    }
    #[test]
    fn signed_reports_bind_every_resource_revision_fact_and_probe_generation() {
        let (key, original) = fixture();
        let public = key.public_key_raw().unwrap();
        let challenge = original.observation.challenge.clone();
        assert!(verify(&original, &public, &challenge, 101).is_ok());
        for index in 0..12 {
            let mut changed = original.clone();
            let o = &mut changed.observation;
            match index {
                0 => o.challenge.domain_id = Uuid::new_v4().to_string(),
                1 => o.challenge.target_node_id = Uuid::new_v4().to_string(),
                2 => o.challenge.revision += 1,
                3 => o.challenge.nonce = "B".repeat(43),
                4 => o.challenge.resources.source = "10.77.0.3".parse().unwrap(),
                5 => o.challenge.resources.target = "10.77.0.3".parse().unwrap(),
                6 => o.challenge.resources.mtls_ca_sha256 = "d".repeat(64),
                7 => o.facts.clear(),
                8 => o.configuration_sha256 = "d".repeat(64),
                9 => o.probe_sha256 = "d".repeat(64),
                10 => o.boot_id = "other-boot".into(),
                _ => {
                    o.observed_at += 1;
                    o.expires_at += 1;
                }
            }
            assert!(
                verify(&changed, &public, &changed.observation.challenge, 102).is_err(),
                "mutation {index}"
            );
        }
        assert!(
            verify(
                &original,
                &OpenSslEd25519Signer::generate("wrong-node")
                    .unwrap()
                    .public_key_raw()
                    .unwrap(),
                &challenge,
                101
            )
            .is_err()
        );
        assert!(
            verify(
                &original,
                &public,
                &challenge,
                original.observation.expires_at
            )
            .is_err()
        );
        assert!(verify(&original, &public, &challenge, 98).is_err());
        let mut json = serde_json::to_value(&original).unwrap();
        json["observation"]["facts"] = serde_json::json!(["future_fact"]);
        assert!(serde_json::from_value::<SignedEndpointObservationV1>(json).is_err());
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    use crate::state::EnrollmentConfig;
    use authority_contracts_model::observation::{
        EndpointFact, EndpointObservationV1, OBSERVATION_TTL,
    };
    use authority_credential_crypto_openssl::OpenSslEd25519Signer;
    struct Fixture {
        state: AppState,
        node: Uuid,
        device: Uuid,
        key: OpenSslEd25519Signer,
        report: SignedEndpointObservationV1,
    }
    impl Fixture {
        async fn new() -> Self {
            let pool = crate::access_policy::tests::lxc_pool(4).await;
            let domain = Uuid::new_v4();
            let node = Uuid::new_v4();
            let device = Uuid::new_v4();
            let key = OpenSslEd25519Signer::generate("target-test").unwrap();
            let webauthn = webauthn_rs::WebauthnBuilder::new(
                "localhost",
                &"http://localhost:3100".parse().unwrap(),
            )
            .unwrap()
            .build()
            .unwrap();
            let state = AppState::new(
                pool,
                webauthn,
                domain,
                "test-bootstrap",
                OpenSslEd25519Signer::generate("cp-test").unwrap(),
                EnrollmentConfig {
                    target_identity_file: "/unused/test-node".into(),
                    client_wireguard_public_key: "unused".into(),
                    network_agent_origin: "http://127.0.0.1:1".into(),
                    target_mesh_address: "10.77.0.2".into(),
                    existing_route_source_address: None,
                },
                (60, 60),
            );
            let bytes = node.as_bytes();
            let target = std::net::Ipv4Addr::new(127, bytes[13], bytes[14], bytes[15]);
            sqlx::query("INSERT INTO device.devices(id,domain_id,owner_kind,owner_domain_id,device_public_key,wireguard_public_key,status) VALUES($1,$2,'domain',$2,$3,$3,'active')")
                .bind(device).bind(domain).bind(key.public_key_raw().unwrap()).execute(state.pool()).await.unwrap();
            sqlx::query("INSERT INTO device.nodes(id,device_id,hostname,mesh_address,status) VALUES($1,$2,'observation-test',$3::inet,'active')")
                .bind(node).bind(device).bind(target.to_string()).execute(state.pool()).await.unwrap();
            let clock = now().unwrap();
            let challenge = EndpointChallengeV1 {
                version: 1,
                audience: OBSERVATION_AUDIENCE.into(),
                domain_id: domain.to_string(),
                target_node_id: node.to_string(),
                nonce: "A".repeat(43),
                revision: 1,
                issued_at: clock,
                expires_at: clock + CHALLENGE_TTL,
                resources: ObservationResources {
                    source: "10.77.0.1".parse().unwrap(),
                    target,
                    principal: "deploy".into(),
                    ssh_ca_fingerprints: BTreeSet::from([format!("SHA256:{}", "A".repeat(43))]),
                    mtls_ca_sha256: "a".repeat(64),
                    service_audience: "demo-api".into(),
                },
            };
            let observation = EndpointObservationV1 {
                challenge,
                boot_id: "boot-test".into(),
                observed_at: clock,
                expires_at: clock + OBSERVATION_TTL,
                configuration_sha256: "b".repeat(64),
                probe_sha256: "c".repeat(64),
                facts: BTreeSet::from([
                    EndpointFact::TcpEnforcement,
                    EndpointFact::ExistingRouteConfigured,
                ]),
            };
            let signature =
                encode_base64url(&key.sign(&observation.signing_preimage().unwrap()).unwrap());
            let report = SignedEndpointObservationV1 {
                observation,
                signature,
            };
            let fixture = Self {
                state,
                node,
                device,
                key,
                report,
            };
            fixture.pending(&fixture.report).await;
            fixture
        }
        async fn pending(&self, report: &SignedEndpointObservationV1) {
            let c = &report.observation.challenge;
            let mut tx = crate::access_policy::begin_authorization(self.state.pool())
                .await
                .unwrap();
            lock_node(&mut tx, self.state.domain_id(), self.node)
                .await
                .unwrap();
            sqlx::query("INSERT INTO device.endpoint_observations(node_id,domain_id,revision,requested_at,window_start,attempts,pending_challenge) VALUES($1,$2,$3,$4,$4,1,$5) ON CONFLICT(node_id) DO UPDATE SET revision=EXCLUDED.revision,pending_challenge=EXCLUDED.pending_challenge,consumed=false,envelope=NULL")
                .bind(self.node).bind(self.state.domain_id()).bind(c.revision).bind(c.issued_at).bind(serde_json::to_value(c).unwrap()).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        }
        async fn cleanup(&self) {
            sqlx::query("DELETE FROM device.endpoint_observations WHERE node_id=$1")
                .bind(self.node)
                .execute(self.state.pool())
                .await
                .unwrap();
            sqlx::query("DELETE FROM device.nodes WHERE id=$1")
                .bind(self.node)
                .execute(self.state.pool())
                .await
                .unwrap();
            sqlx::query("DELETE FROM device.devices WHERE id=$1")
                .bind(self.device)
                .execute(self.state.pool())
                .await
                .unwrap();
        }
    }
    #[tokio::test]
    #[ignore = "requires PostgreSQL migrations"]
    async fn publication_is_single_use_target_bound_and_rejects_old_keys() {
        let fixture = Fixture::new().await;
        let challenge = &fixture.report.observation.challenge;
        let mut tampered = fixture.report.clone();
        tampered.observation.facts.clear();
        assert!(publish(&fixture.state, challenge, &tampered).await.is_err());
        let consumed: bool = sqlx::query_scalar(
            "SELECT consumed FROM device.endpoint_observations WHERE node_id=$1",
        )
        .bind(fixture.node)
        .fetch_one(fixture.state.pool())
        .await
        .unwrap();
        assert!(!consumed);
        publish(&fixture.state, challenge, &fixture.report)
            .await
            .unwrap();
        assert!(
            publish(&fixture.state, challenge, &fixture.report)
                .await
                .is_err()
        );
        let mut next = fixture.report.clone();
        next.observation.challenge.revision += 1;
        next.observation.challenge.nonce = "B".repeat(43);
        next.signature = encode_base64url(
            &fixture
                .key
                .sign(&next.observation.signing_preimage().unwrap())
                .unwrap(),
        );
        fixture.pending(&next).await;
        assert!(
            publish(&fixture.state, challenge, &fixture.report)
                .await
                .is_err()
        );
        let replacement = OpenSslEd25519Signer::generate("replacement").unwrap();
        sqlx::query("UPDATE device.devices SET device_public_key=$2 WHERE id=$1")
            .bind(fixture.device)
            .bind(replacement.public_key_raw().unwrap())
            .execute(fixture.state.pool())
            .await
            .unwrap();
        assert!(
            publish(&fixture.state, &next.observation.challenge, &next)
                .await
                .is_err()
        );
        sqlx::query("UPDATE device.devices SET device_public_key=$2 WHERE id=$1")
            .bind(fixture.device)
            .bind(fixture.key.public_key_raw().unwrap())
            .execute(fixture.state.pool())
            .await
            .unwrap();
        publish(&fixture.state, &next.observation.challenge, &next)
            .await
            .unwrap();
        fixture.cleanup().await;
    }
    #[tokio::test]
    #[ignore = "requires PostgreSQL migrations"]
    async fn publication_waits_for_the_authorization_node_lock() {
        let fixture = Fixture::new().await;
        let mut reader = crate::access_policy::begin_authorization(fixture.state.pool())
            .await
            .unwrap();
        sqlx::query("SELECT id FROM device.nodes WHERE id=$1 FOR SHARE")
            .bind(fixture.node)
            .execute(&mut *reader)
            .await
            .unwrap();
        let state = fixture.state.clone();
        let report = fixture.report.clone();
        let mut writer =
            tokio::spawn(
                async move { publish(&state, &report.observation.challenge, &report).await },
            );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut writer)
                .await
                .is_err()
        );
        reader.commit().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        fixture.cleanup().await;
    }
    #[tokio::test]
    #[ignore = "requires PostgreSQL migrations"]
    async fn another_domain_cannot_hold_the_observation_publication_lock() {
        use authority_policy_core::{
            AccessIntent, Route,
            scoped::{LifetimeLimits, RequestedAccess},
            selection::SelectionOptions,
        };
        let fixture = Fixture::new().await;
        let mut unrelated = crate::access_policy::begin_authorization(fixture.state.pool())
            .await
            .unwrap();
        let request = crate::access_policy::request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            fixture.node,
            now().unwrap(),
            AccessIntent::tcp(Route::Direct),
        );
        let result = crate::access_policy::authorize(
            &mut unrelated,
            request,
            &RequestedAccess::default(),
            LifetimeLimits {
                ssh_seconds: 30,
                network_seconds: 30,
            },
            &SelectionOptions::exact(Route::Direct),
        )
        .await
        .unwrap();
        assert!(matches!(
            result,
            crate::access_policy::AuthorizationOutcome::Denied(_)
        ));
        let publication = tokio::time::timeout(
            Duration::from_secs(5),
            publish(
                &fixture.state,
                &fixture.report.observation.challenge,
                &fixture.report,
            ),
        )
        .await;
        unrelated.rollback().await.unwrap();
        fixture.cleanup().await;
        publication
            .expect("an unrelated domain must not lock the target node")
            .unwrap();
    }
}
