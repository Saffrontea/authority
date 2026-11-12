use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use authority_contracts_model::{
    AccessAuthorizationBundleV1, AdapterGrantKindV1, AdapterGrantV1, DecisionRevocationNoticeV1,
    IssuanceAuthorizationV1, NetworkAccessGrantV1, PolicyCapabilityV1, PolicyDecisionEvaluatedV1,
    PolicyIntentV1, PolicyOutcomeV1, PolicyRouteV1, PolicySourceV1,
    SignedDecisionRevocationNoticeV1, SignedIssuanceAuthorizationV1, SignedNetworkAccessGrantV1,
};
use authority_credential_crypto_openssl::verify_device_signature;
use authority_device_auth_core::{
    authentication_preimage, decode_public_key, decode_signature, encode_base64url,
    enrollment_preimage, node_enrollment_preimage, session_request_preimage,
};
use authority_issuer_core::{sign_authorization, sign_network_grant, sign_revocation_notice};
use authority_policy_core::{AccessIntent, Route};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use openssl::{rand::rand_bytes, sha::sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use tracing::error;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::ui;
use crate::{
    access_policy,
    state::{AppState, PendingAuthentication, PendingRegistration, Session},
};

const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_mins(15);
const MAX_SESSIONS: usize = 256;
const MAX_SESSION_NONCES: usize = 1024;
const MAX_PENDING_CHALLENGES: usize = 256;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(ui::index))
        .route("/health", get(health))
        .route("/v1/bootstrap/users", post(create_user))
        .route("/v1/bootstrap/config", get(bootstrap_config))
        .route("/v1/bootstrap/demo-access", post(create_demo_access))
        .route("/v1/passkeys/registration/start", post(start_registration))
        .route(
            "/v1/passkeys/registration/finish",
            post(finish_registration),
        )
        .route(
            "/v1/passkeys/authentication/start",
            post(start_authentication),
        )
        .route(
            "/v1/passkeys/authentication/finish",
            post(finish_authentication),
        )
        .route("/v1/session", get(get_session))
        .route(
            "/v1/access-authorizations",
            post(issue_access_authorization),
        )
        .route(
            "/v1/access-authorizations/{decision_id}/revocations",
            post(revoke_access_authorization),
        )
        .route("/v1/revocations", get(pull_revocations))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[derive(Deserialize, Serialize)]
struct TargetIdentityResponse {
    node_id: Uuid,
    public_key: String,
    proof: String,
}

#[derive(Serialize)]
struct BootstrapConfigResponse {
    target_identity: TargetIdentityResponse,
    wireguard_public_key: String,
    network_agent_origin: String,
}

async fn bootstrap_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BootstrapConfigResponse>, ApiError> {
    require_bootstrap_token(&state, &headers)?;
    let bytes = std::fs::read(state.target_identity_file()).map_err(ApiError::internal)?;
    let target_identity = serde_json::from_slice(&bytes).map_err(ApiError::internal)?;
    Ok(Json(BootstrapConfigResponse {
        target_identity,
        wireguard_public_key: state.client_wireguard_public_key().to_owned(),
        network_agent_origin: state.network_agent_origin().to_owned(),
    }))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    display_name: String,
}

#[derive(Serialize)]
struct UserResponse {
    user_id: Uuid,
    username: String,
    display_name: String,
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), ApiError> {
    require_bootstrap_token(&state, &headers)?;
    validate_username(&request.username)?;
    if request.display_name.trim().is_empty() || request.display_name.len() > 256 {
        return Err(ApiError::bad_request("invalid_display_name"));
    }

    let proposed_user_id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO identity.users (id, domain_id, username, display_name, status) \
         VALUES ($1, $2, $3, $4, 'active') \
         ON CONFLICT (domain_id, username) DO UPDATE \
         SET display_name = EXCLUDED.display_name, updated_at = now() \
         RETURNING id",
    )
    .bind(proposed_user_id)
    .bind(state.domain_id())
    .bind(&request.username)
    .bind(&request.display_name)
    .fetch_one(state.pool())
    .await
    .map_err(ApiError::internal)?;
    let user_id: Uuid = row.try_get("id").map_err(ApiError::internal)?;

    Ok((
        StatusCode::OK,
        Json(UserResponse {
            user_id,
            username: request.username,
            display_name: request.display_name,
        }),
    ))
}

#[derive(Deserialize)]
struct CreateDemoAccessRequest {
    user_id: Uuid,
    device_public_key: String,
    device_signature: String,
    target_node_id: Uuid,
    target_device_public_key: String,
    target_device_proof: String,
}

#[derive(Serialize)]
struct DemoAccessResponse {
    device_id: Uuid,
    target_node_id: Uuid,
    principal: String,
    wireguard_public_key: String,
}

#[allow(clippy::too_many_lines)]
async fn create_demo_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateDemoAccessRequest>,
) -> Result<(StatusCode, Json<DemoAccessResponse>), ApiError> {
    consume_bootstrap_token(&state, &headers)?;
    let user_exists = sqlx::query(
        "SELECT 1 FROM identity.users \
         WHERE id = $1 AND domain_id = $2 AND status = 'active'",
    )
    .bind(request.user_id)
    .bind(state.domain_id())
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?
    .is_some();
    if !user_exists {
        return Err(ApiError::not_found("user_not_found"));
    }

    let client_wireguard_key = state.client_wireguard_public_key().to_owned();
    let device_public_key = verify_device_enrollment(&request, &client_wireguard_key)?;
    let target_device_public_key = verify_node_enrollment(&request)?;

    let proposed_device_id = Uuid::new_v4();
    let target_device_id = Uuid::new_v4();
    let target_node_id = request.target_node_id;
    let policy_id = Uuid::new_v4();
    let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
    // This endpoint is guarded by the bootstrap token. Reusing the physical
    // PoC client key deliberately reassigns that demo device to the newly
    // bootstrapped user, making repeated E2E runs idempotent without weakening
    // the device key uniqueness constraint used by normal authorization.
    let device_id: Uuid = sqlx::query_scalar(
        "INSERT INTO device.devices \
         (id, domain_id, owner_kind, owner_user_id, owner_domain_id, device_public_key, wireguard_public_key, status, enrolled_at) \
         VALUES ($1, $2, 'user', $3, NULL, $4, $5, 'active', now()) \
         ON CONFLICT (domain_id, wireguard_public_key) DO UPDATE \
         SET owner_kind = 'user', owner_user_id = EXCLUDED.owner_user_id, owner_domain_id = NULL, \
             device_public_key = EXCLUDED.device_public_key, \
             status = 'active', enrolled_at = now() \
         RETURNING id",
    )
    .bind(proposed_device_id)
    .bind(state.domain_id())
    .bind(request.user_id)
    .bind(device_public_key.as_slice())
    .bind(client_wireguard_key.as_bytes())
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    let client_mesh_address = allocate_mesh_address(&mut transaction, "device", device_id).await?;
    sqlx::query("UPDATE device.devices SET mesh_address = $2::inet WHERE id = $1")
        .bind(device_id)
        .bind(&client_mesh_address)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::internal)?;

    let target_device_id: Uuid = sqlx::query_scalar(
        "INSERT INTO device.devices \
         (id, domain_id, owner_kind, owner_user_id, owner_domain_id, device_public_key, wireguard_public_key, status, enrolled_at) \
         VALUES ($1, $2, 'domain', NULL, $2, $3, $4, 'active', now()) \
         ON CONFLICT (domain_id, device_public_key) DO UPDATE \
         SET owner_kind = 'domain', owner_user_id = NULL, owner_domain_id = EXCLUDED.domain_id, \
             status = 'active', enrolled_at = now() \
         RETURNING id",
    )
    .bind(target_device_id)
    .bind(state.domain_id())
    .bind(target_device_public_key.as_slice())
    .bind(format!("poc-target-wireguard-{target_device_id}").into_bytes())
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    let target_mesh_address =
        allocate_mesh_address(&mut transaction, "node", target_node_id).await?;
    sqlx::query(
        "INSERT INTO device.nodes \
         (id, device_id, hostname, mesh_address, ssh_principals, status) \
         VALUES ($1, $2, 'poc-target', $3::inet, ARRAY['deploy'], 'active') \
         ON CONFLICT (id) DO UPDATE SET device_id = EXCLUDED.device_id, \
             mesh_address = EXCLUDED.mesh_address, status = 'active'",
    )
    .bind(target_node_id)
    .bind(target_device_id)
    .bind(target_mesh_address)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    sqlx::query(
        "INSERT INTO policy.access_policies \
         (id, domain_id, subject_user_id, required_device_id, target_node_id, ssh_principal, capabilities) \
         VALUES ($1, $2, $3, $4, $5, 'deploy', \
                 ARRAY['ssh.issue', 'mesh.join', 'network.reach'])",
    )
    .bind(policy_id)
    .bind(state.domain_id())
    .bind(request.user_id)
    .bind(device_id)
    .bind(target_node_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    transaction.commit().await.map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(DemoAccessResponse {
            device_id,
            target_node_id,
            principal: "deploy".to_owned(),
            wireguard_public_key: client_wireguard_key,
        }),
    ))
}

async fn allocate_mesh_address(
    transaction: &mut Transaction<'_, Postgres>,
    owner_kind: &str,
    owner_id: Uuid,
) -> Result<String, ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock(617284901)")
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::internal)?;
    if let Some(address) = sqlx::query_scalar::<_, String>(
        "SELECT host(address) FROM device.mesh_addresses \
         WHERE owner_kind = $1 AND owner_id = $2",
    )
    .bind(owner_kind)
    .bind(owner_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::internal)?
    {
        return Ok(address);
    }
    sqlx::query_scalar::<_, String>(
        "INSERT INTO device.mesh_addresses (address, owner_kind, owner_id) \
         SELECT candidate.address, $1, $2 \
         FROM ( \
             SELECT ('10.77.0.' || value)::inet AS address \
             FROM generate_series(1, 254) AS value \
         ) AS candidate \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM device.mesh_addresses allocated \
             WHERE allocated.address = candidate.address \
         ) \
         ORDER BY candidate.address \
         LIMIT 1 \
         RETURNING host(address)",
    )
    .bind(owner_kind)
    .bind(owner_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::internal)
}

fn verify_node_enrollment(request: &CreateDemoAccessRequest) -> Result<[u8; 32], ApiError> {
    let public_key = decode_public_key(&request.target_device_public_key)
        .map_err(|_| ApiError::bad_request("invalid_target_device_public_key"))?;
    if node_id_from_public_key(&public_key) != request.target_node_id {
        return Err(ApiError::bad_request("target_node_id_key_mismatch"));
    }
    let signature = decode_signature(&request.target_device_proof)
        .map_err(|_| ApiError::bad_request("invalid_target_device_proof"))?;
    let message = node_enrollment_preimage(
        &request.target_node_id.to_string(),
        &request.target_device_public_key,
    );
    if verify_device_signature(&public_key, &message, &signature).map_err(ApiError::internal)? {
        Ok(public_key)
    } else {
        Err(ApiError::unauthorized("invalid_target_device_proof"))
    }
}

fn node_id_from_public_key(public_key: &[u8; 32]) -> Uuid {
    let digest = sha256(public_key);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn verify_device_enrollment(
    request: &CreateDemoAccessRequest,
    wireguard_public_key: &str,
) -> Result<[u8; 32], ApiError> {
    let public_key = decode_public_key(&request.device_public_key)
        .map_err(|_| ApiError::bad_request("invalid_device_public_key"))?;
    let signature = decode_signature(&request.device_signature)
        .map_err(|_| ApiError::bad_request("invalid_device_signature"))?;
    let message = enrollment_preimage(
        &request.user_id.to_string(),
        &request.device_public_key,
        wireguard_public_key,
    );
    if verify_device_signature(&public_key, &message, &signature).map_err(ApiError::internal)? {
        Ok(public_key)
    } else {
        Err(ApiError::unauthorized("invalid_device_signature"))
    }
}

#[derive(Deserialize)]
struct StartRegistrationRequest {
    user_id: Uuid,
}

#[derive(Serialize)]
struct StartRegistrationResponse {
    challenge_id: Uuid,
    options: CreationChallengeResponse,
}

async fn start_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StartRegistrationRequest>,
) -> Result<Json<StartRegistrationResponse>, ApiError> {
    require_bootstrap_token(&state, &headers)?;
    let user = sqlx::query(
        "SELECT username, display_name FROM identity.users \
         WHERE id = $1 AND domain_id = $2 AND status = 'active'",
    )
    .bind(request.user_id)
    .bind(state.domain_id())
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::not_found("user_not_found"))?;
    let username: String = user.try_get("username").map_err(ApiError::internal)?;
    let display_name: String = user.try_get("display_name").map_err(ApiError::internal)?;

    let credential_rows =
        sqlx::query("SELECT credential_id FROM identity.webauthn_credentials WHERE user_id = $1")
            .bind(request.user_id)
            .fetch_all(state.pool())
            .await
            .map_err(ApiError::internal)?;
    let excluded = credential_rows
        .into_iter()
        .map(|row| row.try_get::<Vec<u8>, _>("credential_id"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;

    let (options, registration) = state
        .webauthn()
        .start_passkey_registration(
            request.user_id,
            &username,
            &display_name,
            (!excluded.is_empty()).then_some(excluded),
        )
        .map_err(ApiError::internal)?;
    let challenge_id = Uuid::new_v4();
    let mut registrations = state.registrations().lock().map_err(ApiError::internal)?;
    let now = Instant::now();
    registrations.retain(|_, pending| pending.expires_at > now);
    if registrations.len() >= MAX_PENDING_CHALLENGES {
        return Err(ApiError::unavailable("registration_capacity_reached"));
    }
    registrations.insert(
        challenge_id,
        PendingRegistration {
            user_id: request.user_id,
            state: registration,
            expires_at: now + CHALLENGE_TTL,
        },
    );

    Ok(Json(StartRegistrationResponse {
        challenge_id,
        options,
    }))
}

#[derive(Deserialize)]
struct FinishRegistrationRequest {
    challenge_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
struct FinishRegistrationResponse {
    credential_id: Uuid,
}

async fn finish_registration(
    State(state): State<AppState>,
    Json(request): Json<FinishRegistrationRequest>,
) -> Result<(StatusCode, Json<FinishRegistrationResponse>), ApiError> {
    let pending = state
        .registrations()
        .lock()
        .map_err(ApiError::internal)?
        .remove(&request.challenge_id)
        .ok_or_else(|| ApiError::bad_request("unknown_or_consumed_challenge"))?;
    if Instant::now() > pending.expires_at {
        return Err(ApiError::bad_request("expired_challenge"));
    }

    let passkey = state
        .webauthn()
        .finish_passkey_registration(&request.credential, &pending.state)
        .map_err(|cause| {
            ApiError::unauthorized_with_log("registration_verification_failed", cause)
        })?;
    let webauthn_credential_id = passkey.cred_id().clone();
    let passkey_json = serde_json::to_value(passkey).map_err(ApiError::internal)?;
    let credential_id = Uuid::new_v4();
    let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
    let result = sqlx::query(
        "INSERT INTO identity.webauthn_credentials \
         (id, user_id, credential_id, passkey) VALUES ($1, $2, $3, $4)",
    )
    .bind(credential_id)
    .bind(pending.user_id)
    .bind(webauthn_credential_id)
    .bind(passkey_json)
    .execute(&mut *transaction)
    .await;
    if let Err(cause) = result {
        if is_unique_violation(&cause) {
            return Err(ApiError::conflict("credential_already_registered"));
        }
        return Err(ApiError::internal(cause));
    }
    record_audit(
        &mut transaction,
        state.domain_id(),
        pending.user_id,
        "passkey.register",
        "webauthn_credential",
        credential_id,
        "allow",
    )
    .await?;
    transaction.commit().await.map_err(ApiError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(FinishRegistrationResponse { credential_id }),
    ))
}

#[derive(Deserialize)]
struct StartAuthenticationRequest {
    username: String,
    device_id: Uuid,
}

#[derive(Serialize)]
struct StartAuthenticationResponse {
    challenge_id: Uuid,
    options: RequestChallengeResponse,
    device_challenge: String,
}

async fn start_authentication(
    State(state): State<AppState>,
    Json(request): Json<StartAuthenticationRequest>,
) -> Result<Json<StartAuthenticationResponse>, ApiError> {
    let user = sqlx::query(
        "SELECT users.id, devices.device_public_key FROM identity.users AS users \
         JOIN device.devices AS devices \
           ON devices.id = $3 AND devices.domain_id = users.domain_id \
          AND devices.owner_user_id = users.id AND devices.status = 'active' \
         WHERE users.domain_id = $1 AND users.username = $2 AND users.status = 'active'",
    )
    .bind(state.domain_id())
    .bind(&request.username)
    .bind(request.device_id)
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::unauthorized("authentication_failed"))?;
    let user_id: Uuid = user.try_get("id").map_err(ApiError::internal)?;
    let device_public_key: Vec<u8> = user
        .try_get("device_public_key")
        .map_err(ApiError::internal)?;
    let device_public_key: [u8; 32] = device_public_key
        .try_into()
        .map_err(|_| ApiError::unauthorized("invalid_device_identity"))?;
    let passkeys = load_passkeys(&state, user_id).await?;
    if passkeys.is_empty() {
        return Err(ApiError::unauthorized("authentication_failed"));
    }

    let (options, authentication) = state
        .webauthn()
        .start_passkey_authentication(&passkeys)
        .map_err(ApiError::internal)?;
    let challenge_id = Uuid::new_v4();
    let mut device_challenge_bytes = [0_u8; 32];
    rand_bytes(&mut device_challenge_bytes).map_err(ApiError::internal)?;
    let device_challenge = encode_base64url(&device_challenge_bytes);
    let mut authentications = state.authentications().lock().map_err(ApiError::internal)?;
    let now = Instant::now();
    authentications.retain(|_, pending| pending.expires_at > now);
    if authentications.len() >= MAX_PENDING_CHALLENGES {
        return Err(ApiError::unavailable("authentication_capacity_reached"));
    }
    authentications.insert(
        challenge_id,
        PendingAuthentication {
            user_id,
            device_id: request.device_id,
            device_public_key,
            device_challenge: device_challenge.clone(),
            state: authentication,
            expires_at: now + CHALLENGE_TTL,
        },
    );

    Ok(Json(StartAuthenticationResponse {
        challenge_id,
        options,
        device_challenge,
    }))
}

#[derive(Deserialize)]
struct FinishAuthenticationRequest {
    challenge_id: Uuid,
    credential: PublicKeyCredential,
    device_signature: String,
}

#[derive(Serialize)]
struct FinishAuthenticationResponse {
    session_token: String,
    user_id: Uuid,
    device_id: Uuid,
    expires_at: u64,
}

async fn finish_authentication(
    State(state): State<AppState>,
    Json(request): Json<FinishAuthenticationRequest>,
) -> Result<Json<FinishAuthenticationResponse>, ApiError> {
    let pending = state
        .authentications()
        .lock()
        .map_err(ApiError::internal)?
        .remove(&request.challenge_id)
        .ok_or_else(|| ApiError::bad_request("unknown_or_consumed_challenge"))?;
    if Instant::now() > pending.expires_at {
        return Err(ApiError::bad_request("expired_challenge"));
    }
    let signature = decode_signature(&request.device_signature)
        .map_err(|_| ApiError::unauthorized("invalid_device_signature"))?;
    let device_message =
        authentication_preimage(&request.challenge_id.to_string(), &pending.device_challenge);
    if !verify_device_signature(&pending.device_public_key, &device_message, &signature)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unauthorized("invalid_device_signature"));
    }

    let result = state
        .webauthn()
        .finish_passkey_authentication(&request.credential, &pending.state)
        .map_err(|cause| ApiError::unauthorized_with_log("authentication_failed", cause))?;
    let row = sqlx::query(
        "SELECT id, passkey FROM identity.webauthn_credentials \
         WHERE user_id = $1 AND credential_id = $2",
    )
    .bind(pending.user_id)
    .bind(result.cred_id())
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::unauthorized("authentication_failed"))?;
    let credential_id: Uuid = row.try_get("id").map_err(ApiError::internal)?;
    let passkey_json: Value = row.try_get("passkey").map_err(ApiError::internal)?;
    let mut passkey: Passkey = serde_json::from_value(passkey_json).map_err(ApiError::internal)?;
    passkey
        .update_credential(&result)
        .ok_or_else(|| ApiError::unauthorized("authentication_failed"))?;

    let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
    sqlx::query(
        "UPDATE identity.webauthn_credentials \
         SET passkey = $1, sign_count = $2, last_used_at = now() WHERE id = $3",
    )
    .bind(serde_json::to_value(passkey).map_err(ApiError::internal)?)
    .bind(i64::from(result.counter()))
    .bind(credential_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    record_audit(
        &mut transaction,
        state.domain_id(),
        pending.user_id,
        "passkey.authenticate",
        "user",
        pending.user_id,
        "allow",
    )
    .await?;
    transaction.commit().await.map_err(ApiError::internal)?;

    let session_token = generate_session_token()?;
    let session_digest = session_token_digest(&session_token)?;
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(ApiError::internal)?
        .saturating_add(SESSION_TTL)
        .as_secs();
    let mut sessions = state.sessions().lock().map_err(ApiError::internal)?;
    let now = Instant::now();
    sessions.retain(|_, session| session.expires_at > now);
    if sessions.len() >= MAX_SESSIONS {
        return Err(ApiError::unavailable("session_capacity_reached"));
    }
    sessions.insert(
        session_digest,
        Session {
            user_id: pending.user_id,
            device_id: pending.device_id,
            device_public_key: pending.device_public_key,
            consumed_nonces: std::collections::HashSet::new(),
            expires_at: Instant::now() + SESSION_TTL,
            expires_at_unix: expires_at,
        },
    );

    Ok(Json(FinishAuthenticationResponse {
        session_token,
        user_id: pending.user_id,
        device_id: pending.device_id,
        expires_at,
    }))
}

#[derive(Serialize)]
struct SessionResponse {
    user_id: Uuid,
    device_id: Uuid,
    expires_at: u64,
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let session = authenticated_session(&state, &headers, "session.read", &[])?;
    Ok(Json(SessionResponse {
        user_id: session.user_id,
        device_id: session.device_id,
        expires_at: session.expires_at,
    }))
}

struct AuthenticatedSession {
    user_id: Uuid,
    device_id: Uuid,
    expires_at: u64,
}

fn authenticated_session(
    state: &AppState,
    headers: &HeaderMap,
    action: &str,
    bindings: &[String],
) -> Result<AuthenticatedSession, ApiError> {
    let token = bearer_token(headers)?;
    let token_digest = session_token_digest(&token)?;
    let timestamp = required_header(headers, "x-authority-timestamp")?;
    let timestamp_value = timestamp
        .parse::<i64>()
        .map_err(|_| ApiError::unauthorized("invalid_device_proof"))?;
    if unix_timestamp()?.abs_diff(timestamp_value) > 30 {
        return Err(ApiError::unauthorized("stale_device_proof"));
    }
    let nonce = required_header(headers, "x-authority-nonce")?;
    if !(16..=128).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::unauthorized("invalid_device_proof"));
    }
    let signature = decode_signature(required_header(headers, "x-authority-device-signature")?)
        .map_err(|_| ApiError::unauthorized("invalid_device_proof"))?;
    let proof_message = session_request_preimage(&token, action, bindings, timestamp, nonce);
    let mut sessions = state.sessions().lock().map_err(ApiError::internal)?;
    let now = Instant::now();
    let requested_expired = sessions
        .get(&token_digest)
        .is_some_and(|session| now > session.expires_at);
    sessions.retain(|_, session| session.expires_at > now);
    if requested_expired {
        return Err(ApiError::unauthorized("expired_session"));
    }
    let session = sessions
        .get_mut(&token_digest)
        .ok_or_else(|| ApiError::unauthorized("invalid_session"))?;
    if session.consumed_nonces.contains(nonce) {
        return Err(ApiError::unauthorized("device_proof_replayed"));
    }
    if session.consumed_nonces.len() >= MAX_SESSION_NONCES {
        return Err(ApiError::unauthorized("session_proof_capacity_reached"));
    }
    if !verify_device_signature(&session.device_public_key, &proof_message, &signature)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unauthorized("invalid_device_proof"));
    }
    session.consumed_nonces.insert(nonce.to_owned());
    Ok(AuthenticatedSession {
        user_id: session.user_id,
        device_id: session.device_id,
        expires_at: session.expires_at_unix,
    })
}

#[derive(Deserialize)]
struct IssueAccessAuthorizationRequest {
    device_id: Uuid,
    target_node_id: Uuid,
    ssh_public_key_fingerprint: String,
    wireguard_public_key: String,
    terminal_token_hash: String,
}

#[derive(Serialize)]
struct AccessAuthorizationResponse {
    version: String,
    decision_id: String,
    ssh_authorization: SignedIssuanceAuthorizationV1,
    network_grant: SignedNetworkAccessGrantV1,
    node_authorization: SignedIssuanceAuthorizationV1,
}

async fn issue_access_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueAccessAuthorizationRequest>,
) -> Result<Json<AccessAuthorizationResponse>, ApiError> {
    let bindings = vec![
        request.device_id.to_string(),
        request.target_node_id.to_string(),
        request.ssh_public_key_fingerprint.clone(),
        request.wireguard_public_key.clone(),
        request.terminal_token_hash.clone(),
    ];
    let session = authenticated_session(&state, &headers, "access.authorize", &bindings)?;
    if request.device_id != session.device_id {
        return Err(ApiError::forbidden("session_device_mismatch"));
    }
    let issued_at = unix_timestamp()?;
    let decision = access_policy::authorize(
        state.pool(),
        access_policy::request(
            state.domain_id(),
            session.user_id,
            session.device_id,
            request.target_node_id,
            issued_at,
            AccessIntent::ssh(Route::MeshRequired),
        ),
    )
    .await
    .map_err(ApiError::internal)?;
    let decision = match decision {
        access_policy::AuthorizationOutcome::Allowed(decision) => decision,
        access_policy::AuthorizationOutcome::Denied(reason) => {
            record_access_decision(
                &state,
                session.user_id,
                request.target_node_id,
                DecisionAudit {
                    decision: "deny",
                    denial_reason: Some(reason.code()),
                    denied_capability: reason
                        .capability()
                        .map(authority_policy_core::Capability::as_str),
                    evaluated: None,
                    authorization: None,
                },
            )
            .await?;
            return Err(ApiError::forbidden("policy_denied"));
        }
    };
    if decision.wireguard_public_key != request.wireguard_public_key.as_bytes() {
        record_access_decision(
            &state,
            session.user_id,
            request.target_node_id,
            DecisionAudit {
                decision: "deny",
                denial_reason: Some("wireguard_key_mismatch"),
                denied_capability: None,
                evaluated: Some(&decision),
                authorization: None,
            },
        )
        .await?;
        return Err(ApiError::forbidden("wireguard_key_mismatch"));
    }

    let response = build_access_bundle(&state, &session, &request, &decision, issued_at)?;
    record_access_decision(
        &state,
        session.user_id,
        request.target_node_id,
        DecisionAudit {
            decision: "allow",
            denial_reason: None,
            denied_capability: None,
            evaluated: Some(&decision),
            authorization: Some(&response),
        },
    )
    .await?;
    Ok(Json(response))
}

#[derive(Deserialize)]
struct RevokeAccessAuthorizationRequest {
    reason: String,
}

async fn revoke_access_authorization(
    State(state): State<AppState>,
    Path(decision_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RevokeAccessAuthorizationRequest>,
) -> Result<Json<SignedDecisionRevocationNoticeV1>, ApiError> {
    if !valid_contract_identifier(&decision_id) || !valid_contract_identifier(&request.reason) {
        return Err(ApiError::bad_request("invalid_revocation_request"));
    }
    let session = authenticated_session(
        &state,
        &headers,
        "access.revoke",
        &[decision_id.clone(), request.reason.clone()],
    )?;
    let row = sqlx::query(
        "SELECT payload FROM outbox.events \
         WHERE owner_module = 'policy' AND aggregate_type = 'access_decision' \
           AND aggregate_id = $1 AND event_type = 'access.authorization.issued' \
         ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(&decision_id)
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::not_found("authorization_not_found"))?;
    let payload: Value = row.try_get("payload").map_err(ApiError::internal)?;
    let bundle: AccessAuthorizationBundleV1 =
        serde_json::from_value(payload).map_err(ApiError::internal)?;
    if bundle.ssh_authorization.authorization.subject_user_id != session.user_id.to_string() {
        return Err(ApiError::not_found("authorization_not_found"));
    }
    let target_node_id = bundle.network_grant.grant.target_node_id.clone();
    let now = unix_timestamp()?;
    let expires_at = bundle
        .ssh_authorization
        .authorization
        .expires_at
        .max(bundle.network_grant.grant.expires_at);
    if now >= expires_at {
        return Err(ApiError::conflict("authorization_already_expired"));
    }

    if let Some(existing) = load_revocation(&state, &decision_id).await? {
        return Ok(Json(existing));
    }
    let sequence: i64 = sqlx::query_scalar("SELECT nextval('policy.revocation_notice_sequence')")
        .fetch_one(state.pool())
        .await
        .map_err(ApiError::internal)?;
    let envelope = sign_revocation_notice(
        DecisionRevocationNoticeV1 {
            version: "1".to_owned(),
            issuer: format!("domain-authority:{}", state.domain_id()),
            domain_id: state.domain_id().to_string(),
            target_node_id: target_node_id.clone(),
            decision_id: decision_id.clone(),
            reason: request.reason.clone(),
            sequence,
            revoked_at: now,
            expires_at,
            audience: "network-agent".to_owned(),
        },
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    persist_revocation(&state, session.user_id, envelope)
        .await
        .map(Json)
}

async fn persist_revocation(
    state: &AppState,
    actor_user_id: Uuid,
    envelope: SignedDecisionRevocationNoticeV1,
) -> Result<SignedDecisionRevocationNoticeV1, ApiError> {
    let notice = &envelope.notice;
    let target_uuid = notice
        .target_node_id
        .parse::<Uuid>()
        .map_err(ApiError::internal)?;
    let envelope_json = serde_json::to_value(&envelope).map_err(ApiError::internal)?;
    let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
    let inserted = sqlx::query(
        "INSERT INTO policy.revocation_notices \
         (sequence, domain_id, decision_id, target_node_id, reason, revoked_at, expires_at, envelope) \
         VALUES ($1, $2, $3, $4, $5, to_timestamp($6), to_timestamp($7), $8) \
         ON CONFLICT (domain_id, decision_id) DO NOTHING",
    )
    .bind(notice.sequence)
    .bind(state.domain_id())
    .bind(&notice.decision_id)
    .bind(target_uuid)
    .bind(&notice.reason)
    .bind(notice.revoked_at)
    .bind(notice.expires_at)
    .bind(&envelope_json)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    if inserted.rows_affected() == 0 {
        transaction.rollback().await.map_err(ApiError::internal)?;
        return load_revocation(state, &notice.decision_id)
            .await?
            .ok_or_else(|| ApiError::internal("conflicting revocation disappeared"));
    }
    sqlx::query(
        "INSERT INTO audit.events \
         (domain_id, actor_type, actor_id, action, target_type, target_id, decision, reason, payload) \
         VALUES ($1, 'user', $2, 'access.revoke', 'access_decision', $3, 'allow', $4, $5)",
    )
    .bind(state.domain_id())
    .bind(actor_user_id.to_string())
    .bind(&notice.decision_id)
    .bind(&notice.reason)
    .bind(&envelope_json)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    sqlx::query(
        "INSERT INTO outbox.events \
         (id, owner_module, aggregate_type, aggregate_id, event_type, contract_version, payload, occurred_at) \
         VALUES ($1, 'policy', 'access_decision', $2, 'access.authorization.revoked', 1, $3, now())",
    )
    .bind(Uuid::new_v4())
    .bind(&notice.decision_id)
    .bind(&envelope_json)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    transaction.commit().await.map_err(ApiError::internal)?;
    Ok(envelope)
}

async fn load_revocation(
    state: &AppState,
    decision_id: &str,
) -> Result<Option<SignedDecisionRevocationNoticeV1>, ApiError> {
    let value: Option<Value> = sqlx::query_scalar(
        "SELECT envelope FROM policy.revocation_notices \
         WHERE domain_id = $1 AND decision_id = $2",
    )
    .bind(state.domain_id())
    .bind(decision_id)
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?;
    value
        .map(serde_json::from_value)
        .transpose()
        .map_err(ApiError::internal)
}

#[derive(Deserialize)]
struct PullRevocationsQuery {
    target_node_id: Uuid,
    #[serde(default)]
    after: i64,
}

#[derive(Serialize)]
struct PullRevocationsResponse {
    notices: Vec<SignedDecisionRevocationNoticeV1>,
    next_cursor: i64,
}

async fn pull_revocations(
    State(state): State<AppState>,
    Query(query): Query<PullRevocationsQuery>,
) -> Result<Json<PullRevocationsResponse>, ApiError> {
    if query.after < 0 {
        return Err(ApiError::bad_request("invalid_revocation_cursor"));
    }
    let rows = sqlx::query(
        "SELECT sequence, envelope FROM policy.revocation_notices \
         WHERE domain_id = $1 AND target_node_id = $2 AND sequence > $3 \
           AND expires_at > now() ORDER BY sequence LIMIT 100",
    )
    .bind(state.domain_id())
    .bind(query.target_node_id)
    .bind(query.after)
    .fetch_all(state.pool())
    .await
    .map_err(ApiError::internal)?;
    let mut next_cursor = query.after;
    let notices = rows
        .into_iter()
        .map(|row| {
            next_cursor = row.try_get("sequence").map_err(ApiError::internal)?;
            let value: Value = row.try_get("envelope").map_err(ApiError::internal)?;
            serde_json::from_value(value).map_err(ApiError::internal)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PullRevocationsResponse {
        notices,
        next_cursor,
    }))
}

fn valid_contract_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
}

fn build_access_bundle(
    state: &AppState,
    session: &AuthenticatedSession,
    request: &IssueAccessAuthorizationRequest,
    decision: &access_policy::AuthorizedAccess,
    issued_at: i64,
) -> Result<AccessAuthorizationResponse, ApiError> {
    // A shared nonce is the cryptographic decision identifier: both signed
    // adapter contracts bind it, the policy, subject, device, target, and time.
    let decision_id = Uuid::new_v4().simple().to_string();
    let common_issuer = format!("domain-authority:{}", state.domain_id());
    let common_domain = state.domain_id().to_string();
    let common_subject = session.user_id.to_string();
    let common_device = request.device_id.to_string();
    let common_target = request.target_node_id.to_string();
    let common_policy = policy_reference(&decision.decision);
    let ssh_principal = decision
        .ssh_principal
        .clone()
        .ok_or_else(|| ApiError::internal("SSH decision has no principal binding"))?;
    let ssh_authorization = sign_authorization(
        IssuanceAuthorizationV1 {
            version: "1".to_owned(),
            issuer: common_issuer.clone(),
            domain_id: common_domain.clone(),
            subject_user_id: common_subject.clone(),
            device_id: common_device.clone(),
            target_node_id: common_target.clone(),
            ssh_public_key_fingerprint: request.ssh_public_key_fingerprint.clone(),
            principals: vec![ssh_principal.clone()],
            policy_id: common_policy.clone(),
            nonce: decision_id.clone(),
            issued_at,
            not_before: issued_at,
            expires_at: issued_at + state.ssh_authorization_ttl_seconds(),
            audience: "credential-issuer".to_owned(),
        },
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let network_grant = sign_network_grant(
        NetworkAccessGrantV1 {
            version: "1".to_owned(),
            issuer: common_issuer.clone(),
            domain_id: common_domain.clone(),
            subject_user_id: common_subject.clone(),
            device_id: common_device.clone(),
            target_node_id: common_target.clone(),
            wireguard_public_key: request.wireguard_public_key.clone(),
            mesh_address: decision.device_mesh_address.clone(),
            policy_id: common_policy.clone(),
            nonce: decision_id.clone(),
            issued_at,
            not_before: issued_at,
            expires_at: issued_at + state.network_grant_ttl_seconds(),
            audience: "node-agent".to_owned(),
        },
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let node_authorization = sign_authorization(
        IssuanceAuthorizationV1 {
            version: "1".to_owned(),
            issuer: common_issuer,
            domain_id: common_domain,
            subject_user_id: common_subject,
            device_id: common_device,
            target_node_id: common_target,
            ssh_public_key_fingerprint: request.ssh_public_key_fingerprint.clone(),
            principals: vec![ssh_principal.clone()],
            policy_id: common_policy,
            nonce: request.terminal_token_hash.clone(),
            issued_at,
            not_before: issued_at,
            expires_at: issued_at + state.ssh_authorization_ttl_seconds(),
            audience: "node-agent".to_owned(),
        },
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let bundle = AccessAuthorizationBundleV1 {
        version: "1".to_owned(),
        decision_id,
        ssh_authorization,
        network_grant,
    };
    bundle.validate().map_err(ApiError::internal)?;
    Ok(AccessAuthorizationResponse {
        version: bundle.version,
        decision_id: bundle.decision_id,
        ssh_authorization: bundle.ssh_authorization,
        network_grant: bundle.network_grant,
        node_authorization,
    })
}

struct DecisionAudit<'a> {
    decision: &'a str,
    denial_reason: Option<&'a str>,
    denied_capability: Option<&'a str>,
    evaluated: Option<&'a access_policy::AuthorizedAccess>,
    authorization: Option<&'a AccessAuthorizationResponse>,
}

async fn record_access_decision(
    state: &AppState,
    user_id: Uuid,
    target_node_id: Uuid,
    audit: DecisionAudit<'_>,
) -> Result<(), ApiError> {
    let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
    let payload = if let Some((bundle, evaluated)) = audit.authorization.zip(audit.evaluated) {
        policy_decision_payload(
            evaluated,
            &bundle.decision_id,
            vec![
                AdapterGrantV1 {
                    kind: AdapterGrantKindV1::SshCertificate,
                    audience: bundle.ssh_authorization.authorization.audience.clone(),
                    expires_at: bundle.ssh_authorization.authorization.expires_at,
                },
                AdapterGrantV1 {
                    kind: AdapterGrantKindV1::WireGuardPeer,
                    audience: bundle.network_grant.grant.audience.clone(),
                    expires_at: bundle.network_grant.grant.expires_at,
                },
                AdapterGrantV1 {
                    kind: AdapterGrantKindV1::SshSession,
                    audience: bundle.node_authorization.authorization.audience.clone(),
                    expires_at: bundle.node_authorization.authorization.expires_at,
                },
            ],
        )?
    } else {
        let mut payload = json!({
            "reason": audit.denial_reason.unwrap_or("policy_denied")
        });
        if let Some(capability) = audit.denied_capability {
            payload["capability"] = json!(capability);
        }
        if let Some(evaluated) = audit.evaluated {
            payload["policy"] = json!(policy_reference(&evaluated.decision));
            payload["required_capabilities"] = json!(
                evaluated
                    .decision
                    .required
                    .iter()
                    .map(|capability| capability.as_str())
                    .collect::<Vec<_>>()
            );
        }
        payload
    };
    sqlx::query(
        "INSERT INTO audit.events \
         (domain_id, actor_type, actor_id, action, target_type, target_id, decision, reason, payload) \
         VALUES ($1, 'user', $2, 'access.authorize', 'node', $3, $4, $5, $6)",
    )
    .bind(state.domain_id())
    .bind(user_id.to_string())
    .bind(target_node_id.to_string())
    .bind(audit.decision)
    .bind(
        (audit.decision == "deny")
            .then_some(audit.denial_reason.unwrap_or("policy_denied")),
    )
    .bind(&payload)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    if let Some(bundle) = audit.authorization {
        insert_decision_outbox(&mut transaction, &bundle.decision_id, &payload).await?;
        let signed_bundle = AccessAuthorizationBundleV1 {
            version: bundle.version.clone(),
            decision_id: bundle.decision_id.clone(),
            ssh_authorization: bundle.ssh_authorization.clone(),
            network_grant: bundle.network_grant.clone(),
        };
        sqlx::query(
            "INSERT INTO outbox.events \
             (id, owner_module, aggregate_type, aggregate_id, event_type, contract_version, payload, occurred_at) \
             VALUES ($1, 'policy', 'access_decision', $2, \
                     'access.authorization.issued', 1, $3, now())",
        )
        .bind(Uuid::new_v4())
        .bind(&bundle.decision_id)
        .bind(serde_json::to_value(signed_bundle).map_err(ApiError::internal)?)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::internal)?;
    }
    transaction.commit().await.map_err(ApiError::internal)
}

fn policy_decision_payload(
    evaluated: &access_policy::AuthorizedAccess,
    decision_id: &str,
    adapter_grants: Vec<AdapterGrantV1>,
) -> Result<Value, ApiError> {
    let decision = &evaluated.decision;
    let contract = PolicyDecisionEvaluatedV1 {
        decision_id: decision_id.to_owned(),
        intent: PolicyIntentV1 {
            outcomes: decision
                .intent
                .outcomes
                .iter()
                .map(|outcome| match outcome {
                    authority_policy_core::Outcome::Ssh => PolicyOutcomeV1::Ssh,
                    authority_policy_core::Outcome::NetworkReachability => {
                        PolicyOutcomeV1::NetworkReachability
                    }
                })
                .collect(),
            route: match decision.intent.route {
                Route::Direct => PolicyRouteV1::Direct,
                Route::MeshRequired => PolicyRouteV1::MeshRequired,
            },
        },
        required_capabilities: decision
            .required
            .iter()
            .map(|capability| policy_capability(*capability))
            .collect(),
        policy_sources: decision
            .sources
            .iter()
            .map(|(capability, policy)| PolicySourceV1 {
                capability: policy_capability(*capability),
                policy_id: policy.policy_id.to_string(),
                revision: policy.revision,
            })
            .collect(),
        adapter_grants,
    };
    contract.validate().map_err(ApiError::internal)?;
    serde_json::to_value(contract).map_err(ApiError::internal)
}

fn policy_capability(capability: authority_policy_core::Capability) -> PolicyCapabilityV1 {
    match capability {
        authority_policy_core::Capability::MeshJoin => PolicyCapabilityV1::MeshJoin,
        authority_policy_core::Capability::NetworkReach => PolicyCapabilityV1::NetworkReach,
        authority_policy_core::Capability::SshIssue => PolicyCapabilityV1::SshIssue,
    }
}

async fn insert_decision_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    decision_id: &str,
    payload: &Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO outbox.events \
         (id, owner_module, aggregate_type, aggregate_id, event_type, contract_version, payload, occurred_at) \
         VALUES ($1, 'policy', 'access_decision', $2, \
                 'policy.decision.evaluated', 1, $3, now())",
    )
    .bind(Uuid::new_v4())
    .bind(decision_id)
    .bind(payload)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::internal)?;
    Ok(())
}

fn policy_reference(decision: &authority_policy_core::AccessDecision) -> String {
    decision
        .policies()
        .into_iter()
        .map(|policy| format!("{}@{}", policy.policy_id, policy.revision))
        .collect::<Vec<_>>()
        .join("+")
}

async fn load_passkeys(state: &AppState, user_id: Uuid) -> Result<Vec<Passkey>, ApiError> {
    let rows = sqlx::query(
        "SELECT passkey FROM identity.webauthn_credentials \
         WHERE user_id = $1 AND passkey IS NOT NULL",
    )
    .bind(user_id)
    .fetch_all(state.pool())
    .await
    .map_err(ApiError::internal)?;
    rows.into_iter()
        .map(|row| {
            let value: Value = row.try_get("passkey").map_err(ApiError::internal)?;
            serde_json::from_value(value).map_err(ApiError::internal)
        })
        .collect()
}

async fn record_audit(
    transaction: &mut Transaction<'_, Postgres>,
    domain_id: Uuid,
    actor_id: Uuid,
    action: &str,
    target_type: &str,
    target_id: Uuid,
    decision: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO audit.events \
         (domain_id, actor_type, actor_id, action, target_type, target_id, decision, payload) \
         VALUES ($1, 'user', $2, $3, $4, $5, $6, '{}'::jsonb)",
    )
    .bind(domain_id)
    .bind(actor_id.to_string())
    .bind(action)
    .bind(target_type)
    .bind(target_id.to_string())
    .bind(decision)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::internal)?;
    Ok(())
}

fn require_bootstrap_token(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = bootstrap_token_header(headers)?;
    if state
        .verify_bootstrap_token(supplied)
        .map_err(ApiError::internal)?
    {
        Ok(())
    } else {
        Err(ApiError::unauthorized("invalid_bootstrap_token"))
    }
}

fn consume_bootstrap_token(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = bootstrap_token_header(headers)?;
    if state
        .consume_bootstrap_token(supplied)
        .map_err(ApiError::internal)?
    {
        Ok(())
    } else {
        Err(ApiError::unauthorized(
            "invalid_or_consumed_bootstrap_token",
        ))
    }
}

fn bootstrap_token_header(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("x-authority-bootstrap-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("invalid_bootstrap_token"))
}

fn bearer_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("invalid_session"))?;
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_owned())
    } else {
        Err(ApiError::unauthorized("invalid_session"))
    }
}

fn required_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing_device_proof"))
}

fn generate_session_token() -> Result<String, ApiError> {
    let mut bytes = [0_u8; 32];
    rand_bytes(&mut bytes).map_err(ApiError::internal)?;
    Ok(encode_hex(&bytes))
}

fn session_token_digest(token: &str) -> Result<[u8; 32], ApiError> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::unauthorized("invalid_session"));
    }
    Ok(sha256(token.as_bytes()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn unix_timestamp() -> Result<i64, ApiError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(ApiError::internal)?
        .as_secs();
    i64::try_from(seconds).map_err(ApiError::internal)
}

fn validate_username(username: &str) -> Result<(), ApiError> {
    let valid = !username.is_empty()
        && username.len() <= 128
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.@-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(ApiError::bad_request("invalid_username"))
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database) if database.code().as_deref() == Some("23505"))
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

    fn unauthorized(code: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
        }
    }

    fn unauthorized_with_log(code: &'static str, cause: impl std::fmt::Display) -> Self {
        error!(%cause, "WebAuthn verification failed");
        Self::unauthorized(code)
    }

    fn not_found(code: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
        }
    }

    fn conflict(code: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
        }
    }

    fn forbidden(code: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code,
        }
    }

    fn internal(cause: impl std::fmt::Display) -> Self {
        error!(%cause, "request failed");
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use authority_policy_core::{AccessDecision, Capability, PolicyRef};

    use super::*;

    #[test]
    fn session_tokens_are_random_and_only_digests_are_stable() {
        let Ok(first) = generate_session_token() else {
            panic!("generate first token");
        };
        let Ok(second) = generate_session_token() else {
            panic!("generate second token");
        };
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        let Ok(first_digest) = session_token_digest(&first) else {
            panic!("digest first token");
        };
        assert_eq!(session_token_digest(&first).ok(), Some(first_digest));
        assert_ne!(session_token_digest(&second).ok(), Some(first_digest));
        assert!(session_token_digest("not-a-session-token").is_err());
    }

    #[test]
    fn decision_audit_explains_intent_capabilities_sources_and_adapters() {
        let policy = PolicyRef {
            policy_id: Uuid::new_v4(),
            revision: 7,
        };
        let evaluated = access_policy::AuthorizedAccess {
            decision: AccessDecision {
                intent: AccessIntent::ssh(Route::MeshRequired),
                required: BTreeSet::from([
                    Capability::MeshJoin,
                    Capability::NetworkReach,
                    Capability::SshIssue,
                ]),
                sources: BTreeMap::from([
                    (Capability::MeshJoin, policy),
                    (Capability::NetworkReach, policy),
                    (Capability::SshIssue, policy),
                ]),
            },
            ssh_principal: Some("deploy".to_owned()),
            wireguard_public_key: Vec::new(),
            device_mesh_address: "10.77.0.1".to_owned(),
        };
        let Ok(payload) = policy_decision_payload(
            &evaluated,
            "decision-1",
            vec![
                AdapterGrantV1 {
                    kind: AdapterGrantKindV1::SshCertificate,
                    audience: "credential-issuer".to_owned(),
                    expires_at: 100,
                },
                AdapterGrantV1 {
                    kind: AdapterGrantKindV1::WireGuardPeer,
                    audience: "node-agent".to_owned(),
                    expires_at: 100,
                },
            ],
        ) else {
            panic!("valid policy decision trace");
        };
        assert_eq!(payload["intent"]["route"], "mesh_required");
        assert_eq!(
            payload["required_capabilities"].as_array().map(Vec::len),
            Some(3)
        );
        assert_eq!(payload["policy_sources"].as_array().map(Vec::len), Some(3));
        assert_eq!(payload["adapter_grants"].as_array().map(Vec::len), Some(2));
    }
}
