use std::time::{Duration, SystemTime, UNIX_EPOCH};

use authority_contracts_model::{
    AccessAuthorizationBundleV1, AdapterGrantKindV1, AdapterGrantV1, DecisionRevocationNoticeV2,
    PolicyCapabilityV1, PolicyDecisionEvaluatedV1, PolicyIntentV1, PolicyOutcomeV1, PolicyRouteV1,
    PolicySourceV1, SignedDecisionRevocationNoticeV2, SignedIssuanceAuthorizationV1,
    SignedMtlsIssuanceAuthorizationV1, SignedNetworkAccessGrantV1,
};
use authority_credential_crypto_openssl::verify_device_signature;
use authority_device_auth_core::{
    authentication_preimage, decode_public_key, decode_signature, encode_base64url,
    enrollment_preimage, node_enrollment_preimage, session_request_preimage,
};
use authority_issuer_core::{
    sign_authorization, sign_mtls_authorization, sign_network_grant, sign_revocation_notice_v2,
};
use authority_policy_core::{
    AccessIntent, Route,
    scoped::{
        AuthorizedPlan, LifetimeLimits, RequestedAccess, RequestedMtls, RequestedNetwork,
        RequestedSsh, RequestedTcp, ScopeError,
    },
    selection::{
        DeploymentAvailability, ExistingRouteAvailability, PlanningEvidence, RouteChoice,
        SelectionOptions,
    },
};
use authority_projection_core::{CommonDecisionClaims, project_authorized};
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
    state::{AppState, PendingAuthentication, PendingRegistration},
};

const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_mins(15);
const MAX_SESSIONS: usize = 256;
const MAX_SESSION_NONCES: usize = 1024;
const MAX_PENDING_CHALLENGES: usize = 256;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/tcp-authorizations", post(issue_tcp_authorization))
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
        .route(
            "/v1/access-authorizations/{decision_id}/revocations/status",
            get(revocation_status),
        )
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
    require_bootstrap_token(&state, &headers).await?;
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
    require_bootstrap_token(&state, &headers).await?;
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
    require_bootstrap_token(&state, &headers).await?;
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
    let mut transaction = access_policy::begin_authorization(state.pool())
        .await
        .map_err(ApiError::internal)?;
    consume_bootstrap_token(&state, &headers, &mut transaction).await?;
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
    let target_mesh_address = assign_target_mesh_address(
        &mut transaction,
        target_node_id,
        state.target_mesh_address(),
    )
    .await?;
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
         (id, domain_id, subject_user_id, required_device_id, target_node_id, ssh_principal, capabilities, tcp_ports) \
         VALUES ($1, $2, $3, $4, $5, 'deploy', \
                 ARRAY['ssh.issue', 'mtls.issue', 'mesh.join', 'network.reach', 'tcp.connect'], ARRAY[8080,8081])",
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

// The PoC mesh is provisioned before enrollment. Reserve its configured
// address, rather than assigning a second address which the target never uses.
async fn assign_target_mesh_address(
    transaction: &mut Transaction<'_, Postgres>,
    target_node_id: Uuid,
    address: &str,
) -> Result<String, ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock(617284901)")
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query_scalar(
        "INSERT INTO device.mesh_addresses (address, owner_kind, owner_id) \
        VALUES ($1::inet, 'node', $2) ON CONFLICT (owner_kind, owner_id) \
        DO UPDATE SET address = EXCLUDED.address RETURNING host(address)",
    )
    .bind(address)
    .bind(target_node_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
        {
            ApiError::conflict("target_mesh_address_already_allocated")
        } else {
            ApiError::internal(error)
        }
    })
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
    require_bootstrap_token(&state, &headers).await?;
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
    if !state
        .put_challenge(
            challenge_id,
            "registration",
            &PendingRegistration {
                user_id: request.user_id,
                state: registration,
            },
            i64::try_from(CHALLENGE_TTL.as_secs()).map_err(ApiError::internal)?,
            i64::try_from(MAX_PENDING_CHALLENGES).map_err(ApiError::internal)?,
        )
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unavailable("registration_capacity_reached"));
    }

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
    let pending: PendingRegistration = state
        .take_challenge(request.challenge_id, "registration")
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::bad_request("unknown_or_consumed_challenge"))?;

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
    if !state
        .put_challenge(
            challenge_id,
            "authentication",
            &PendingAuthentication {
                user_id,
                device_id: request.device_id,
                device_public_key,
                device_challenge: device_challenge.clone(),
                state: authentication,
            },
            i64::try_from(CHALLENGE_TTL.as_secs()).map_err(ApiError::internal)?,
            i64::try_from(MAX_PENDING_CHALLENGES).map_err(ApiError::internal)?,
        )
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unavailable("authentication_capacity_reached"));
    }

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

#[allow(clippy::too_many_lines)] // Keep credential/session mutation in one visible transaction.
async fn finish_authentication(
    State(state): State<AppState>,
    Json(request): Json<FinishAuthenticationRequest>,
) -> Result<Json<FinishAuthenticationResponse>, ApiError> {
    let pending: PendingAuthentication = state
        .take_challenge(request.challenge_id, "authentication")
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::bad_request("unknown_or_consumed_challenge"))?;
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
    let mut transaction = access_policy::begin_authorization(state.pool())
        .await
        .map_err(ApiError::internal)?;
    let row = sqlx::query(
        "SELECT id, passkey, sign_count FROM identity.webauthn_credentials \
         WHERE user_id = $1 AND credential_id = $2 FOR UPDATE",
    )
    .bind(pending.user_id)
    .bind(result.cred_id())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::unauthorized("authentication_failed"))?;
    let previous_counter: i64 = row.try_get("sign_count").map_err(ApiError::internal)?;
    if previous_counter > 0
        && result.counter() > 0
        && i64::from(result.counter()) <= previous_counter
    {
        return Err(ApiError::unauthorized("authentication_counter_replayed"));
    }
    let credential_id: Uuid = row.try_get("id").map_err(ApiError::internal)?;
    let passkey_json: Value = row.try_get("passkey").map_err(ApiError::internal)?;
    let mut passkey: Passkey = serde_json::from_value(passkey_json).map_err(ApiError::internal)?;
    passkey
        .update_credential(&result)
        .ok_or_else(|| ApiError::unauthorized("authentication_failed"))?;

    sqlx::query(
        "UPDATE identity.webauthn_credentials \
         SET passkey = $1, sign_count = $2, last_used_at = now() WHERE id = $3",
    )
    .bind(serde_json::to_value(passkey).map_err(ApiError::internal)?)
    .bind(previous_counter.max(i64::from(result.counter())))
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

    let session_token = generate_session_token()?;
    let session_digest = session_token_digest(&session_token)?;
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(ApiError::internal)?
        .saturating_add(SESSION_TTL)
        .as_secs();
    sqlx::query("SELECT domain_id FROM identity.auth_domains WHERE domain_id=$1 FOR UPDATE")
        .bind(state.domain_id())
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::internal)?;
    sqlx::query(
        "DELETE FROM identity.sessions WHERE domain_id=$1 AND expires_at<=clock_timestamp()",
    )
    .bind(state.domain_id())
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.sessions WHERE domain_id=$1")
            .bind(state.domain_id())
            .fetch_one(&mut *transaction)
            .await
            .map_err(ApiError::internal)?;
    if count >= i64::try_from(MAX_SESSIONS).map_err(ApiError::internal)? {
        return Err(ApiError::unavailable("session_capacity_reached"));
    }
    sqlx::query("INSERT INTO identity.sessions(domain_id,token_digest,user_id,device_id,device_public_key,expires_at) VALUES($1,$2,$3,$4,$5,to_timestamp($6::bigint))")
        .bind(state.domain_id()).bind(session_digest.as_slice()).bind(pending.user_id).bind(pending.device_id).bind(pending.device_public_key.as_slice()).bind(i64::try_from(expires_at).map_err(ApiError::internal)?)
        .execute(&mut *transaction).await.map_err(ApiError::internal)?;
    transaction.commit().await.map_err(ApiError::internal)?;

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
    let session = authenticated_session(&state, &headers, "session.read", &[]).await?;
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

async fn authenticated_session(
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
    let mut transaction = access_policy::begin_authorization(state.pool())
        .await
        .map_err(ApiError::internal)?;
    let row = sqlx::query("SELECT user_id,device_id,device_public_key,EXTRACT(EPOCH FROM expires_at)::bigint AS expiry, expires_at>clock_timestamp() AS active FROM identity.sessions WHERE domain_id=$1 AND token_digest=$2 FOR UPDATE")
        .bind(state.domain_id()).bind(token_digest.as_slice()).fetch_optional(&mut *transaction).await.map_err(ApiError::internal)?
        .ok_or_else(||ApiError::unauthorized("invalid_session"))?;
    if !row
        .try_get::<bool, _>("active")
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unauthorized("expired_session"));
    }
    let device_public_key: Vec<u8> = row
        .try_get("device_public_key")
        .map_err(ApiError::internal)?;
    let device_public_key: [u8; 32] = device_public_key
        .try_into()
        .map_err(|_| ApiError::internal("invalid stored device key"))?;
    if !verify_device_signature(&device_public_key, &proof_message, &signature)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::unauthorized("invalid_device_proof"));
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.session_nonces WHERE token_digest=$1")
            .bind(token_digest.as_slice())
            .fetch_one(&mut *transaction)
            .await
            .map_err(ApiError::internal)?;
    if count >= i64::try_from(MAX_SESSION_NONCES).map_err(ApiError::internal)? {
        return Err(ApiError::unauthorized("session_proof_capacity_reached"));
    }
    let inserted = sqlx::query("INSERT INTO identity.session_nonces(token_digest,nonce) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(token_digest.as_slice()).bind(nonce).execute(&mut *transaction).await.map_err(ApiError::internal)?.rows_affected();
    if inserted == 0 {
        return Err(ApiError::unauthorized("device_proof_replayed"));
    }
    let result = AuthenticatedSession {
        user_id: row.try_get("user_id").map_err(ApiError::internal)?,
        device_id: row.try_get("device_id").map_err(ApiError::internal)?,
        expires_at: u64::try_from(
            row.try_get::<i64, _>("expiry")
                .map_err(ApiError::internal)?,
        )
        .map_err(ApiError::internal)?,
    };
    transaction.commit().await.map_err(ApiError::internal)?;
    Ok(result)
}

#[derive(Deserialize)]
struct IssueAccessAuthorizationRequest {
    device_id: Uuid,
    target_node_id: Uuid,
    ssh_public_key_fingerprint: String,
    wireguard_public_key: String,
    mtls_client_spki_sha256: String,
    terminal_token_hash: String,
}

#[derive(Serialize)]
struct AccessAuthorizationResponse {
    version: String,
    decision_id: String,
    ssh_authorization: SignedIssuanceAuthorizationV1,
    network_grant: SignedNetworkAccessGrantV1,
    node_authorization: SignedIssuanceAuthorizationV1,
    mtls_authorization: SignedMtlsIssuanceAuthorizationV1,
    mtls_node_authorization: SignedMtlsIssuanceAuthorizationV1,
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
        request.mtls_client_spki_sha256.clone(),
        request.terminal_token_hash.clone(),
    ];
    let session = authenticated_session(&state, &headers, "access.authorize", &bindings).await?;
    if request.device_id != session.device_id {
        return Err(ApiError::forbidden("session_device_mismatch"));
    }
    let issued_at = unix_timestamp()?;
    let mut transaction = access_policy::begin_authorization(state.pool())
        .await
        .map_err(ApiError::database)?;
    let decision = access_policy::authorize(
        &mut transaction,
        access_policy::request(
            state.domain_id(),
            session.user_id,
            session.device_id,
            request.target_node_id,
            issued_at,
            AccessIntent::infrastructure(Route::MeshRequired),
        ),
        &RequestedAccess {
            ssh: Some(RequestedSsh {
                public_key_fingerprint: request.ssh_public_key_fingerprint.clone(),
                principals: None,
                terminal_token_hash: request.terminal_token_hash.clone(),
                ttl_seconds: state.ssh_authorization_ttl_seconds(),
            }),
            mtls: Some(RequestedMtls {
                client_spki_sha256: request.mtls_client_spki_sha256.clone(),
                ttl_seconds: state.network_grant_ttl_seconds(),
            }),
            network: Some(RequestedNetwork {
                wireguard_public_key: Some(request.wireguard_public_key.clone()),
                ttl_seconds: state.network_grant_ttl_seconds(),
            }),
            ..RequestedAccess::default()
        },
        lifetime_limits(&state),
        &SelectionOptions::exact(Route::MeshRequired),
    )
    .await
    .map_err(ApiError::database)?;
    let decision = match decision {
        access_policy::AuthorizationOutcome::Allowed(decision) => decision,
        access_policy::AuthorizationOutcome::Denied(reason) => {
            record_access_decision(
                &mut transaction,
                state.domain_id(),
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
                    planning: Some(&reason.evidence),
                },
            )
            .await?;
            transaction.commit().await.map_err(ApiError::database)?;
            return Err(authorization_denial(&reason.reason));
        }
    };
    let response = build_access_bundle(&state, &decision)?;
    record_access_decision(
        &mut transaction,
        state.domain_id(),
        session.user_id,
        request.target_node_id,
        DecisionAudit {
            decision: "allow",
            denial_reason: None,
            denied_capability: None,
            evaluated: Some(&decision),
            authorization: Some(&response),
            planning: None,
        },
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(response))
}

#[derive(Deserialize)]
struct RevokeAccessAuthorizationRequest {
    reason: String,
    #[serde(default)]
    adapter_kinds: Option<Vec<AdapterGrantKindV1>>,
}

const REVOCABLE_DECISION_QUERY: &str = "SELECT issued.payload, (SELECT MAX((adapter->>'expires_at')::bigint) \
          FROM outbox.events AS evaluated \
          CROSS JOIN LATERAL jsonb_array_elements(evaluated.payload->'adapter_grants') AS adapter \
          WHERE evaluated.aggregate_id = issued.aggregate_id \
            AND evaluated.event_type = 'policy.decision.evaluated') AS adapter_expires_at \
         FROM outbox.events AS issued \
         WHERE owner_module = 'policy' AND aggregate_type = 'access_decision' \
           AND aggregate_id = $1 AND event_type IN ('access.authorization.issued', 'access.tcp_authorization.issued') \
         ORDER BY occurred_at DESC LIMIT 1";

async fn revoke_access_authorization(
    State(state): State<AppState>,
    Path(decision_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RevokeAccessAuthorizationRequest>,
) -> Result<Json<SignedDecisionRevocationNoticeV2>, ApiError> {
    if !valid_contract_identifier(&decision_id) || !valid_contract_identifier(&request.reason) {
        return Err(ApiError::bad_request("invalid_revocation_request"));
    }
    let mut bindings = vec![decision_id.clone(), request.reason.clone()];
    if let Some(kinds) = &request.adapter_kinds {
        bindings.push(serde_json::to_string(kinds).map_err(ApiError::internal)?);
    }
    let session = authenticated_session(&state, &headers, "access.revoke", &bindings).await?;
    let row = sqlx::query(REVOCABLE_DECISION_QUERY)
        .bind(&decision_id)
        .fetch_optional(state.pool())
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("authorization_not_found"))?;
    let payload: Value = row.try_get("payload").map_err(ApiError::internal)?;
    let RevocableDecision {
        subject,
        target_node_id,
        mut expires_at,
        issued_kinds,
    } = revocable_decision(payload)?;
    if let Some(adapter_expiry) = row
        .try_get::<Option<i64>, _>("adapter_expires_at")
        .map_err(ApiError::internal)?
    {
        expires_at = expires_at.max(adapter_expiry);
    }
    if subject != session.user_id.to_string() {
        return Err(ApiError::not_found("authorization_not_found"));
    }
    let mut adapter_kinds = request.adapter_kinds.unwrap_or(issued_kinds.clone());
    if adapter_kinds.is_empty()
        || adapter_kinds
            .iter()
            .any(|kind| !issued_kinds.contains(kind))
    {
        return Err(ApiError::bad_request("invalid_revocation_adapters"));
    }
    adapter_kinds.sort_unstable();
    if adapter_kinds.windows(2).any(|kinds| kinds[0] == kinds[1]) {
        return Err(ApiError::bad_request("invalid_revocation_adapters"));
    }
    let now = unix_timestamp()?;
    if now >= expires_at {
        return Err(ApiError::conflict("authorization_already_expired"));
    }

    let notice = DecisionRevocationNoticeV2 {
        version: authority_contracts_model::protocol::CONTRACT_VERSION_V2.to_owned(),
        issuer: authority_contracts_model::protocol::domain_issuer(state.domain_id()),
        domain_id: state.domain_id().to_string(),
        target_node_id,
        decision_id,
        reason: request.reason,
        sequence: 0,
        revoked_at: now,
        expires_at,
        adapter_kinds,
    };
    let persisted = persist_revocation(&state, session.user_id, notice).await?;
    Ok(Json(persisted))
}

#[allow(clippy::too_many_lines)] // Publication, issuance fence and membership share one commit.
async fn persist_revocation(
    state: &AppState,
    actor_user_id: Uuid,
    mut notice: DecisionRevocationNoticeV2,
) -> Result<SignedDecisionRevocationNoticeV2, ApiError> {
    let mut transaction = access_policy::begin_authorization(state.pool())
        .await
        .map_err(ApiError::internal)?;
    // Serialize publication through commit: sequence order is commit order.
    sqlx::query("SELECT id FROM policy.revocation_stream FOR UPDATE")
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::internal)?;
    let existing: Option<Value> = sqlx::query_scalar("SELECT envelope FROM policy.revocation_notices WHERE domain_id=$1 AND decision_id=$2 AND scope_key=$3")
        .bind(state.domain_id()).bind(&notice.decision_id).bind(revocation_scope(&notice.adapter_kinds)).fetch_optional(&mut *transaction).await.map_err(ApiError::internal)?;
    if let Some(existing) = existing {
        transaction.commit().await.map_err(ApiError::internal)?;
        return serde_json::from_value(existing).map_err(ApiError::internal);
    }
    notice.sequence = sqlx::query_scalar("SELECT nextval('policy.revocation_notice_sequence')")
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::internal)?;
    let envelope = sign_revocation_notice_v2(notice, state.signer()).map_err(ApiError::internal)?;
    let notice = &envelope.notice;
    let target_uuid = notice
        .target_node_id
        .parse::<Uuid>()
        .map_err(ApiError::internal)?;
    let envelope_json = serde_json::to_value(&envelope).map_err(ApiError::internal)?;
    let inserted = sqlx::query(
        "INSERT INTO policy.revocation_notices \
         (sequence, domain_id, decision_id, target_node_id, reason, revoked_at, expires_at, envelope, scope_key) \
         VALUES ($1, $2, $3, $4, $5, to_timestamp($6), to_timestamp($7), $8, $9) \
         ON CONFLICT (domain_id, decision_id, scope_key) DO NOTHING",
    )
    .bind(notice.sequence)
    .bind(state.domain_id())
    .bind(&notice.decision_id)
    .bind(target_uuid)
    .bind(&notice.reason)
    .bind(notice.revoked_at)
    .bind(notice.expires_at)
    .bind(&envelope_json)
    .bind(revocation_scope(&notice.adapter_kinds))
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    if inserted.rows_affected() == 0 {
        transaction.rollback().await.map_err(ApiError::internal)?;
        return load_revocation(
            state,
            &notice.decision_id,
            &revocation_scope(&notice.adapter_kinds),
        )
        .await?
        .ok_or_else(|| ApiError::internal("conflicting revocation disappeared"));
    }
    if notice
        .adapter_kinds
        .contains(&AdapterGrantKindV1::MtlsClientCertificate)
    {
        authority_mtls_core::database::revoke_in(&mut transaction, &envelope)
            .await
            .map_err(ApiError::internal)?;
        sqlx::query("INSERT INTO policy.revocation_members(sequence,instance_id,lease_until) SELECT $1,instance_id,lease_until FROM policy.enforcement_instances WHERE domain_id=$2 AND target_node_id=$3 AND role='mtls-service' AND lease_until>clock_timestamp()")
            .bind(notice.sequence).bind(state.domain_id()).bind(target_uuid).execute(&mut *transaction).await.map_err(ApiError::internal)?;
    }
    if notice
        .adapter_kinds
        .contains(&AdapterGrantKindV1::WireGuardPeer)
        || notice.adapter_kinds.contains(&AdapterGrantKindV1::TcpPort)
    {
        sqlx::query(
            "INSERT INTO policy.adapter_deliveries(sequence,receiver_id,origin) VALUES($1,$2,$3)",
        )
        .bind(notice.sequence)
        .bind(format!("network:{target_uuid}"))
        .bind(state.network_agent_origin())
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::internal)?;
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
    scope_key: &str,
) -> Result<Option<SignedDecisionRevocationNoticeV2>, ApiError> {
    let value: Option<Value> = sqlx::query_scalar(
        "SELECT envelope FROM policy.revocation_notices \
         WHERE domain_id = $1 AND decision_id = $2 AND scope_key = $3 AND envelope->'notice' ? 'adapter_kinds'",
    )
    .bind(state.domain_id())
    .bind(decision_id)
    .bind(scope_key)
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?;
    value
        .map(serde_json::from_value)
        .transpose()
        .map_err(ApiError::internal)
}

async fn revocation_status(
    State(state): State<AppState>,
    Path(decision_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let session = authenticated_session(
        &state,
        &headers,
        "access.revoke_status",
        std::slice::from_ref(&decision_id),
    )
    .await?;
    let source = sqlx::query(REVOCABLE_DECISION_QUERY)
        .bind(&decision_id)
        .fetch_optional(state.pool())
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("authorization_not_found"))?;
    if revocable_decision(source.try_get("payload").map_err(ApiError::internal)?)?.subject
        != session.user_id.to_string()
    {
        return Err(ApiError::not_found("authorization_not_found"));
    }
    let rows = sqlx::query("SELECT n.sequence, NOT EXISTS(SELECT 1 FROM policy.revocation_members m WHERE m.sequence=n.sequence AND m.lease_until>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM policy.revocation_receipts r WHERE r.sequence=m.sequence AND r.instance_id=m.instance_id)) AS drained FROM policy.revocation_notices n WHERE n.domain_id=$1 AND n.decision_id=$2")
        .bind(state.domain_id()).bind(&decision_id).fetch_all(state.pool()).await.map_err(ApiError::internal)?;
    let notices = rows.iter().map(|row| Ok(json!({"sequence":row.try_get::<i64,_>("sequence")?,"sessions_drained":row.try_get::<bool,_>("drained")?}))).collect::<Result<Vec<_>,sqlx::Error>>().map_err(ApiError::internal)?;
    let drained = !notices.is_empty() && notices.iter().all(|n| n["sessions_drained"] == true);
    Ok(Json(
        json!({"decision_id":decision_id,"committed":!rows.is_empty(),"mtls_sessions_drained":drained,"notices":notices}),
    ))
}

#[derive(Deserialize)]
struct PullRevocationsQuery {
    target_node_id: Uuid,
    #[serde(default)]
    after: i64,
}

#[derive(Serialize)]
struct PullRevocationsResponse {
    notices: Vec<SignedDecisionRevocationNoticeV2>,
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
           AND expires_at > now() AND envelope->'notice' ? 'adapter_kinds' \
         ORDER BY sequence LIMIT 100",
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

fn required_contract<T>(contract: Option<T>, name: &str) -> Result<T, ApiError> {
    contract.ok_or_else(|| ApiError::internal(format!("authorized plan omitted {name}")))
}

fn lifetime_limits(state: &AppState) -> LifetimeLimits {
    LifetimeLimits {
        ssh_seconds: state.ssh_authorization_ttl_seconds(),
        network_seconds: state.network_grant_ttl_seconds(),
    }
}

fn authorization_denial(reason: &ScopeError) -> ApiError {
    ApiError::forbidden(match reason {
        ScopeError::Policy(_) => "policy_denied",
        _ => reason.code(),
    })
}

fn authorized_claims(state: &AppState, plan: &AuthorizedPlan) -> CommonDecisionClaims {
    let binding = plan.binding();
    CommonDecisionClaims {
        decision_id: Uuid::new_v4().simple().to_string(),
        issuer: authority_contracts_model::protocol::domain_issuer(state.domain_id()),
        domain_id: binding.domain_id.to_string(),
        subject_user_id: binding.subject_user_id.to_string(),
        device_id: binding.device_id.to_string(),
        target_node_id: binding.target_node_id.to_string(),
        policy_id: plan.policy_reference().to_owned(),
        issued_at: plan.issued_at(),
    }
}

fn build_access_bundle(
    state: &AppState,
    decision: &access_policy::AuthorizedAccess,
) -> Result<AccessAuthorizationResponse, ApiError> {
    let common = authorized_claims(state, &decision.plan);
    let decision_id = common.decision_id.clone();
    let projected = project_authorized(&common, &decision.plan).map_err(ApiError::internal)?;
    let ssh_authorization = sign_authorization(
        required_contract(projected.ssh_issuance, "SSH")?,
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let node_authorization = sign_authorization(
        required_contract(projected.ssh_node_install, "SSH installation")?,
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let network_grant = sign_network_grant(
        required_contract(projected.network_grant, "WireGuard")?,
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let mtls_authorization = sign_mtls_authorization(
        required_contract(projected.mtls_issuance, "mTLS")?,
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let mtls_node_authorization = sign_mtls_authorization(
        required_contract(projected.mtls_node_install, "mTLS installation")?,
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let bundle = AccessAuthorizationBundleV1 {
        version: authority_contracts_model::protocol::CONTRACT_VERSION_V1.to_owned(),
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
        mtls_authorization,
        mtls_node_authorization,
    })
}

struct DecisionAudit<'a> {
    decision: &'a str,
    denial_reason: Option<&'a str>,
    denied_capability: Option<&'a str>,
    evaluated: Option<&'a access_policy::AuthorizedAccess>,
    authorization: Option<&'a AccessAuthorizationResponse>,
    planning: Option<&'a PlanningEvidence>,
}

async fn record_access_decision(
    transaction: &mut Transaction<'_, Postgres>,
    domain_id: Uuid,
    user_id: Uuid,
    target_node_id: Uuid,
    audit: DecisionAudit<'_>,
) -> Result<(), ApiError> {
    let payload = if let Some((bundle, evaluated)) = audit.authorization.zip(audit.evaluated) {
        policy_decision_payload(
            &evaluated.decision,
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
                AdapterGrantV1 {
                    kind: AdapterGrantKindV1::MtlsClientCertificate,
                    audience: bundle
                        .mtls_authorization
                        .authorization
                        .service_audience
                        .clone(),
                    expires_at: bundle.mtls_authorization.authorization.expires_at,
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
    .bind(domain_id)
    .bind(user_id.to_string())
    .bind(target_node_id.to_string())
    .bind(audit.decision)
    .bind(
        (audit.decision == "deny")
            .then_some(audit.denial_reason.unwrap_or("policy_denied")),
    )
    .bind(&payload)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if let Some(bundle) = audit.authorization {
        insert_decision_outbox(transaction, &bundle.decision_id, &payload).await?;
        insert_access_bundle(transaction, bundle).await?;
    }
    if let Some(evidence) = audit
        .planning
        .or_else(|| audit.evaluated.map(|value| value.plan.evidence()))
    {
        let decision_id = audit.authorization.map_or_else(
            || Uuid::new_v4().simple().to_string(),
            |bundle| bundle.decision_id.clone(),
        );
        crate::planning_audit::insert(transaction, &decision_id, evidence, audit.denial_reason)
            .await
            .map_err(ApiError::database)?;
    }
    Ok(())
}

async fn insert_access_bundle(
    transaction: &mut Transaction<'_, Postgres>,
    bundle: &AccessAuthorizationResponse,
) -> Result<(), ApiError> {
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
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    Ok(())
}

fn policy_decision_payload(
    decision: &authority_policy_core::AccessDecision,
    decision_id: &str,
    adapter_grants: Vec<AdapterGrantV1>,
) -> Result<Value, ApiError> {
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
                    authority_policy_core::Outcome::MtlsService => PolicyOutcomeV1::MtlsService,
                    authority_policy_core::Outcome::TcpConnect => PolicyOutcomeV1::TcpConnect,
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
        authority_policy_core::Capability::MtlsIssue => PolicyCapabilityV1::MtlsIssue,
        authority_policy_core::Capability::TcpConnect => PolicyCapabilityV1::TcpConnect,
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
    .map_err(ApiError::database)?;
    Ok(())
}

fn policy_reference(decision: &authority_policy_core::AccessDecision) -> String {
    decision
        .policies()
        .into_iter()
        .map(|policy| format!("{}@{}", policy.policy_id, policy.revision))
        .collect::<Vec<_>>()
        .join(".")
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

async fn require_bootstrap_token(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = bootstrap_token_header(headers)?;
    if state
        .verify_bootstrap_token(supplied)
        .await
        .map_err(ApiError::internal)?
    {
        Ok(())
    } else {
        Err(ApiError::unauthorized("invalid_bootstrap_token"))
    }
}

async fn consume_bootstrap_token(
    state: &AppState,
    headers: &HeaderMap,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), ApiError> {
    let supplied = bootstrap_token_header(headers)?;
    if state
        .consume_bootstrap_token(supplied, transaction)
        .await
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

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    fn database(cause: sqlx::Error) -> Self {
        if matches!(&cause, sqlx::Error::Database(error)
            if error.code().as_deref() == Some("40P01"))
        {
            error!(%cause, "authorization transaction conflicted; no grant returned");
            return Self::unavailable("authorization_conflict");
        }
        Self::internal(cause)
    }

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

    #[tokio::test]
    #[ignore = "requires AUTHORITY_DB_HOST and LXC PostgreSQL"]
    async fn revocation_retention_includes_mtls_beyond_transport_expiry() {
        let pool = crate::access_policy::tests::lxc_pool(1).await;
        let mut transaction = pool.begin().await.unwrap();
        let payload: Value = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/access-authorization-bundle-v1/valid/basic.json"
        ))
        .unwrap();
        let transport_expiry = revocable_decision(payload.clone())
            .unwrap_or_else(|_| panic!("fixture must decode"))
            .expires_at;
        let mtls_expiry = transport_expiry + 600;
        let decision = Uuid::new_v4().simple().to_string();
        for (event, value) in [
            ("access.authorization.issued", payload),
            (
                "policy.decision.evaluated",
                json!({"adapter_grants":[{"kind":"mtls.client_certificate", "expires_at":mtls_expiry}]}),
            ),
        ] {
            sqlx::query("INSERT INTO outbox.events (id, owner_module, aggregate_type, aggregate_id, event_type, contract_version, payload, occurred_at) VALUES ($1,'policy','access_decision',$2,$3,1,$4,now())")
                .bind(Uuid::new_v4()).bind(&decision).bind(event).bind(value)
                .execute(&mut *transaction).await.unwrap();
        }
        let row = sqlx::query(REVOCABLE_DECISION_QUERY)
            .bind(&decision)
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        assert_eq!(
            row.get::<Option<i64>, _>("adapter_expires_at"),
            Some(mtls_expiry)
        );
        assert!(row.get::<Option<i64>, _>("adapter_expires_at").unwrap() > transport_expiry);
        transaction.rollback().await.unwrap();
    }

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
        let evaluated = AccessDecision {
            realization: authority_policy_core::realization::realize(
                &AccessIntent::ssh(Route::MeshRequired),
                authority_policy_core::realization::all_abilities(),
            )
            .expect("built-in SSH plan"),
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
    #[test]
    fn automatic_route_selection_is_bound_into_the_device_proof() {
        let mut request: IssueTcpAuthorizationRequest = serde_json::from_value(json!({
            "device_id": Uuid::from_u128(1), "target_node_id": Uuid::from_u128(2),
            "destination_ports": [8080], "include_network": false, "ttl_seconds": 20,
        }))
        .unwrap();
        let legacy = tcp_authorization_bindings(&request).unwrap();
        assert_eq!(
            legacy,
            vec![
                request.device_id.to_string(),
                request.target_node_id.to_string(),
                "[8080]".to_owned(),
                "false".to_owned(),
                "20".to_owned()
            ]
        );
        request.automatic_route = true;
        let automatic = tcp_authorization_bindings(&request).unwrap();
        assert_eq!(&automatic[..5], legacy);
        assert_eq!(automatic[5], "automatic");
        assert_ne!(
            session_request_preimage("session", "access.authorize_tcp", &legacy, "100", "nonce"),
            session_request_preimage(
                "session",
                "access.authorize_tcp",
                &automatic,
                "100",
                "nonce"
            ),
        );
    }
}

fn revocation_scope(kinds: &[AdapterGrantKindV1]) -> String {
    let mut names = kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>();
    names.sort_unstable();
    names.join(",")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueTcpAuthorizationRequest {
    device_id: Uuid,
    target_node_id: Uuid,
    destination_ports: Vec<u16>,
    #[serde(default)]
    include_network: bool,
    ttl_seconds: i64,
    #[serde(default)]
    automatic_route: bool,
}

#[derive(Serialize)]
struct TcpAuthorizationResponse {
    decision_id: String,
    tcp_grant: authority_contracts_model::SignedTcpAccessGrantV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_grant: Option<SignedNetworkAccessGrantV1>,
}

fn tcp_authorization_bindings(
    request: &IssueTcpAuthorizationRequest,
) -> Result<Vec<String>, ApiError> {
    let mut bindings = vec![
        request.device_id.to_string(),
        request.target_node_id.to_string(),
        serde_json::to_string(&request.destination_ports).map_err(ApiError::internal)?,
        request.include_network.to_string(),
        request.ttl_seconds.to_string(),
    ];
    if request.automatic_route {
        bindings.push("automatic".to_owned());
    }
    Ok(bindings)
}

fn tcp_selection(state: &AppState, request: &IssueTcpAuthorizationRequest) -> SelectionOptions {
    if !request.automatic_route {
        return SelectionOptions::exact(if request.include_network {
            Route::MeshRequired
        } else {
            Route::Direct
        });
    }
    let target = state.target_mesh_address().parse().ok();
    SelectionOptions {
        choice: RouteChoice::Automatic,
        availability: DeploymentAvailability {
            existing_route: state.existing_route_source_address().zip(target).map(
                |(source, destination)| ExistingRouteAvailability {
                    source,
                    destination,
                    registered_wireguard_key: state.client_wireguard_public_key().to_owned(),
                },
            ),
            wireguard_target: target,
        },
    }
}

async fn issue_tcp_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueTcpAuthorizationRequest>,
) -> Result<Json<TcpAuthorizationResponse>, ApiError> {
    let bindings = tcp_authorization_bindings(&request)?;
    let session =
        authenticated_session(&state, &headers, "access.authorize_tcp", &bindings).await?;
    if session.device_id != request.device_id {
        return Err(ApiError::forbidden("session_device_mismatch"));
    }
    if (request.automatic_route && request.include_network)
        || !(authority_contracts_model::protocol::MIN_TTL_SECONDS
            ..=state.network_grant_ttl_seconds())
            .contains(&request.ttl_seconds)
        || request.destination_ports.is_empty()
        || request.destination_ports.len() > authority_contracts_model::protocol::MAX_TCP_PORTS
        || request.destination_ports.contains(&0)
        || request
            .destination_ports
            .windows(2)
            .any(|ports| ports[0] >= ports[1])
    {
        return Err(ApiError::bad_request("invalid_tcp_request"));
    }
    let now = unix_timestamp()?;
    let mut transaction = access_policy::begin_authorization(state.pool())
        .await
        .map_err(ApiError::database)?;
    let outcome = access_policy::authorize(
        &mut transaction,
        access_policy::request(
            state.domain_id(),
            session.user_id,
            request.device_id,
            request.target_node_id,
            now,
            AccessIntent::tcp(if request.include_network {
                Route::MeshRequired
            } else {
                Route::Direct
            }),
        ),
        &RequestedAccess {
            tcp: Some(RequestedTcp {
                ports: request.destination_ports.iter().copied().collect(),
                ttl_seconds: request.ttl_seconds,
            }),
            network: (request.include_network || request.automatic_route).then(|| {
                RequestedNetwork {
                    wireguard_public_key: None,
                    ttl_seconds: state.network_grant_ttl_seconds(),
                }
            }),
            ..RequestedAccess::default()
        },
        lifetime_limits(&state),
        &tcp_selection(&state, &request),
    )
    .await
    .map_err(ApiError::database)?;
    let evaluated = match outcome {
        access_policy::AuthorizationOutcome::Allowed(value) => value,
        access_policy::AuthorizationOutcome::Denied(reason) => {
            record_access_decision(
                &mut transaction,
                state.domain_id(),
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
                    planning: Some(&reason.evidence),
                },
            )
            .await?;
            transaction.commit().await.map_err(ApiError::database)?;
            return Err(authorization_denial(&reason.reason));
        }
    };
    let (response, adapters) = build_tcp_response(&state, &evaluated)?;
    let trace = policy_decision_payload(&evaluated.decision, &response.decision_id, adapters)?;
    persist_tcp_authorization(
        &mut transaction,
        state.domain_id(),
        &session,
        request.target_node_id,
        &response,
        &trace,
        evaluated.plan.evidence(),
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(Json(response))
}

fn build_tcp_response(
    state: &AppState,
    evaluated: &access_policy::AuthorizedAccess,
) -> Result<(TcpAuthorizationResponse, Vec<AdapterGrantV1>), ApiError> {
    let common = authorized_claims(state, &evaluated.plan);
    let projected = project_authorized(&common, &evaluated.plan).map_err(ApiError::internal)?;
    let tcp_grant = authority_issuer_core::sign_tcp_grant(
        required_contract(projected.tcp_grant, "TCP admission")?,
        state.signer(),
    )
    .map_err(ApiError::internal)?;
    let network_grant = projected
        .network_grant
        .map(|grant| sign_network_grant(grant, state.signer()))
        .transpose()
        .map_err(ApiError::internal)?;
    let mut adapters = vec![AdapterGrantV1 {
        kind: AdapterGrantKindV1::TcpPort,
        audience: "network-agent".to_owned(),
        expires_at: tcp_grant.grant.expires_at,
    }];
    if let Some(network) = &network_grant {
        adapters.push(AdapterGrantV1 {
            kind: AdapterGrantKindV1::WireGuardPeer,
            audience: network.grant.audience.clone(),
            expires_at: network.grant.expires_at,
        });
    }
    let response = TcpAuthorizationResponse {
        decision_id: common.decision_id,
        tcp_grant,
        network_grant,
    };
    Ok((response, adapters))
}

async fn persist_tcp_authorization(
    transaction: &mut Transaction<'_, Postgres>,
    domain_id: Uuid,
    session: &AuthenticatedSession,
    target_node_id: Uuid,
    response: &TcpAuthorizationResponse,
    trace: &Value,
    planning: &PlanningEvidence,
) -> Result<(), ApiError> {
    insert_decision_outbox(transaction, &response.decision_id, trace).await?;
    sqlx::query(
        "INSERT INTO audit.events \
        (domain_id, actor_type, actor_id, action, target_type, target_id, decision, payload) \
        VALUES ($1, 'user', $2, 'access.authorize_tcp', 'node', $3, 'allow', $4)",
    )
    .bind(domain_id)
    .bind(session.user_id.to_string())
    .bind(target_node_id.to_string())
    .bind(trace)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    sqlx::query("INSERT INTO outbox.events \
        (id, owner_module, aggregate_type, aggregate_id, event_type, contract_version, payload, occurred_at) \
        VALUES ($1, 'policy', 'access_decision', $2, 'access.tcp_authorization.issued', 1, $3, now())")
        .bind(Uuid::new_v4()).bind(&response.decision_id).bind(serde_json::to_value(response).map_err(ApiError::internal)?)
        .execute(&mut **transaction).await.map_err(ApiError::database)?;
    crate::planning_audit::insert(transaction, &response.decision_id, planning, None)
        .await
        .map_err(ApiError::database)?;
    Ok(())
}

struct RevocableDecision {
    subject: String,
    target_node_id: String,
    expires_at: i64,
    issued_kinds: Vec<AdapterGrantKindV1>,
}

fn revocable_decision(payload: Value) -> Result<RevocableDecision, ApiError> {
    let (subject, target_node_id, expires_at, issued_kinds) = if payload.get("tcp_grant").is_some()
    {
        let grant: authority_contracts_model::SignedTcpAccessGrantV1 =
            serde_json::from_value(payload["tcp_grant"].clone()).map_err(ApiError::internal)?;
        let mut kinds = vec![AdapterGrantKindV1::TcpPort];
        let mut expiry = grant.grant.expires_at;
        if !payload["network_grant"].is_null() {
            let network: SignedNetworkAccessGrantV1 =
                serde_json::from_value(payload["network_grant"].clone())
                    .map_err(ApiError::internal)?;
            expiry = expiry.max(network.grant.expires_at);
            kinds.push(AdapterGrantKindV1::WireGuardPeer);
        }
        (
            grant.grant.subject_user_id,
            grant.grant.target_node_id,
            expiry,
            kinds,
        )
    } else {
        let bundle: AccessAuthorizationBundleV1 =
            serde_json::from_value(payload).map_err(ApiError::internal)?;
        (
            bundle.ssh_authorization.authorization.subject_user_id,
            bundle.network_grant.grant.target_node_id,
            bundle
                .ssh_authorization
                .authorization
                .expires_at
                .max(bundle.network_grant.grant.expires_at),
            vec![
                AdapterGrantKindV1::SshCertificate,
                AdapterGrantKindV1::SshSession,
                AdapterGrantKindV1::WireGuardPeer,
                AdapterGrantKindV1::MtlsClientCertificate,
            ],
        )
    };
    Ok(RevocableDecision {
        subject,
        target_node_id,
        expires_at,
        issued_kinds,
    })
}
