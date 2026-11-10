use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use authority_contracts_model::{
    IssuanceAuthorizationV1, NetworkAccessGrantV1, SignedIssuanceAuthorizationV1,
    SignedNetworkAccessGrantV1,
};
use authority_issuer_core::{sign_authorization, sign_network_grant};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use tracing::error;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::state::{AppState, PendingAuthentication, PendingRegistration, Session};
use crate::ui;

const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_mins(15);

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(ui::index))
        .route("/health", get(health))
        .route("/v1/bootstrap/users", post(create_user))
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
        .route("/v1/issuance-authorizations", post(issue_authorization))
        .route("/v1/network-access-grants", post(issue_network_grant))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
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
    wireguard_public_key: Option<String>,
}

#[derive(Serialize)]
struct DemoAccessResponse {
    device_id: Uuid,
    target_node_id: Uuid,
    principal: String,
}

async fn create_demo_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateDemoAccessRequest>,
) -> Result<(StatusCode, Json<DemoAccessResponse>), ApiError> {
    require_bootstrap_token(&state, &headers)?;
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

    let device_id = Uuid::new_v4();
    let target_device_id = Uuid::new_v4();
    let target_node_id = Uuid::new_v4();
    let policy_id = Uuid::new_v4();
    let address_seed = target_node_id.as_bytes();
    let mesh_address = format!(
        "10.42.{}.{}",
        address_seed[0],
        address_seed[1].clamp(1, 254)
    );
    let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
    for (id, label) in [(device_id, "client"), (target_device_id, "target")] {
        let wireguard_public_key = if label == "client" {
            request
                .wireguard_public_key
                .clone()
                .unwrap_or_else(|| format!("poc-{label}-wireguard-{id}"))
        } else {
            format!("poc-{label}-wireguard-{id}")
        };
        sqlx::query(
            "INSERT INTO device.devices \
             (id, domain_id, owner_user_id, device_public_key, wireguard_public_key, status, enrolled_at) \
             VALUES ($1, $2, $3, $4, $5, 'active', now())",
        )
        .bind(id)
        .bind(state.domain_id())
        .bind(request.user_id)
        .bind(format!("poc-{label}-device-{id}").into_bytes())
        .bind(wireguard_public_key.into_bytes())
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::internal)?;
    }
    sqlx::query(
        "INSERT INTO device.nodes \
         (id, device_id, hostname, mesh_address, ssh_principals, status) \
         VALUES ($1, $2, 'poc-target', $3::inet, ARRAY['deploy'], 'active')",
    )
    .bind(target_node_id)
    .bind(target_device_id)
    .bind(mesh_address)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::internal)?;
    sqlx::query(
        "INSERT INTO policy.access_policies \
         (id, domain_id, subject_user_id, required_device_id, target_node_id, ssh_principal) \
         VALUES ($1, $2, $3, $4, $5, 'deploy')",
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
        }),
    ))
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
    state
        .registrations()
        .lock()
        .map_err(ApiError::internal)?
        .insert(
            challenge_id,
            PendingRegistration {
                user_id: request.user_id,
                state: registration,
                expires_at: Instant::now() + CHALLENGE_TTL,
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
}

#[derive(Serialize)]
struct StartAuthenticationResponse {
    challenge_id: Uuid,
    options: RequestChallengeResponse,
}

async fn start_authentication(
    State(state): State<AppState>,
    Json(request): Json<StartAuthenticationRequest>,
) -> Result<Json<StartAuthenticationResponse>, ApiError> {
    let user = sqlx::query(
        "SELECT id FROM identity.users \
         WHERE domain_id = $1 AND username = $2 AND status = 'active'",
    )
    .bind(state.domain_id())
    .bind(&request.username)
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?
    .ok_or_else(|| ApiError::unauthorized("authentication_failed"))?;
    let user_id: Uuid = user.try_get("id").map_err(ApiError::internal)?;
    let passkeys = load_passkeys(&state, user_id).await?;
    if passkeys.is_empty() {
        return Err(ApiError::unauthorized("authentication_failed"));
    }

    let (options, authentication) = state
        .webauthn()
        .start_passkey_authentication(&passkeys)
        .map_err(ApiError::internal)?;
    let challenge_id = Uuid::new_v4();
    state
        .authentications()
        .lock()
        .map_err(ApiError::internal)?
        .insert(
            challenge_id,
            PendingAuthentication {
                user_id,
                state: authentication,
                expires_at: Instant::now() + CHALLENGE_TTL,
            },
        );

    Ok(Json(StartAuthenticationResponse {
        challenge_id,
        options,
    }))
}

#[derive(Deserialize)]
struct FinishAuthenticationRequest {
    challenge_id: Uuid,
    credential: PublicKeyCredential,
}

#[derive(Serialize)]
struct FinishAuthenticationResponse {
    session_token: Uuid,
    user_id: Uuid,
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

    let session_token = Uuid::new_v4();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(ApiError::internal)?
        .saturating_add(SESSION_TTL)
        .as_secs();
    state.sessions().lock().map_err(ApiError::internal)?.insert(
        session_token,
        Session {
            user_id: pending.user_id,
            expires_at: Instant::now() + SESSION_TTL,
            expires_at_unix: expires_at,
        },
    );

    Ok(Json(FinishAuthenticationResponse {
        session_token,
        user_id: pending.user_id,
        expires_at,
    }))
}

#[derive(Serialize)]
struct SessionResponse {
    user_id: Uuid,
    expires_at: u64,
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let session = authenticated_session(&state, &headers)?;
    Ok(Json(SessionResponse {
        user_id: session.user_id,
        expires_at: session.expires_at,
    }))
}

struct AuthenticatedSession {
    user_id: Uuid,
    expires_at: u64,
}

fn authenticated_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    let token = bearer_token(headers)?;
    let mut sessions = state.sessions().lock().map_err(ApiError::internal)?;
    let session = sessions
        .get(&token)
        .ok_or_else(|| ApiError::unauthorized("invalid_session"))?;
    if Instant::now() > session.expires_at {
        sessions.remove(&token);
        return Err(ApiError::unauthorized("expired_session"));
    }
    Ok(AuthenticatedSession {
        user_id: session.user_id,
        expires_at: session.expires_at_unix,
    })
}

#[derive(Deserialize)]
struct IssueAuthorizationRequest {
    device_id: Uuid,
    target_node_id: Uuid,
    ssh_public_key_fingerprint: String,
}

async fn issue_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueAuthorizationRequest>,
) -> Result<Json<SignedIssuanceAuthorizationV1>, ApiError> {
    let session = authenticated_session(&state, &headers)?;
    let policy = sqlx::query(
        "SELECT policy.id, policy.ssh_principal \
         FROM policy.access_policies AS policy \
         JOIN device.devices AS client \
           ON client.id = $3 AND client.domain_id = policy.domain_id \
          AND client.owner_user_id = policy.subject_user_id AND client.status = 'active' \
         JOIN device.nodes AS target \
           ON target.id = policy.target_node_id AND target.status = 'active' \
         WHERE policy.domain_id = $1 AND policy.subject_user_id = $2 \
           AND policy.target_node_id = $4 AND policy.enabled \
           AND (policy.required_device_id IS NULL OR policy.required_device_id = $3) \
           AND (policy.valid_from IS NULL OR policy.valid_from <= now()) \
           AND (policy.valid_until IS NULL OR policy.valid_until > now()) \
         ORDER BY policy.id LIMIT 1",
    )
    .bind(state.domain_id())
    .bind(session.user_id)
    .bind(request.device_id)
    .bind(request.target_node_id)
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?;

    let Some(policy) = policy else {
        let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
        record_audit(
            &mut transaction,
            state.domain_id(),
            session.user_id,
            "issuance.authorize",
            "node",
            request.target_node_id,
            "deny",
        )
        .await?;
        transaction.commit().await.map_err(ApiError::internal)?;
        return Err(ApiError::forbidden("policy_denied"));
    };

    let policy_id: Uuid = policy.try_get("id").map_err(ApiError::internal)?;
    let principal: String = policy
        .try_get("ssh_principal")
        .map_err(ApiError::internal)?;
    let issued_at = unix_timestamp()?;
    let authorization = IssuanceAuthorizationV1 {
        version: "1".to_owned(),
        issuer: format!("domain-authority:{}", state.domain_id()),
        domain_id: state.domain_id().to_string(),
        subject_user_id: session.user_id.to_string(),
        device_id: request.device_id.to_string(),
        target_node_id: request.target_node_id.to_string(),
        ssh_public_key_fingerprint: request.ssh_public_key_fingerprint,
        principals: vec![principal],
        policy_id: policy_id.to_string(),
        nonce: Uuid::new_v4().simple().to_string(),
        issued_at,
        not_before: issued_at,
        expires_at: issued_at + 300,
        audience: "credential-issuer".to_owned(),
    };
    let envelope = sign_authorization(authorization, state.signer()).map_err(ApiError::internal)?;

    let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
    record_audit(
        &mut transaction,
        state.domain_id(),
        session.user_id,
        "issuance.authorize",
        "node",
        request.target_node_id,
        "allow",
    )
    .await?;
    transaction.commit().await.map_err(ApiError::internal)?;
    Ok(Json(envelope))
}

#[derive(Deserialize)]
struct IssueNetworkGrantRequest {
    device_id: Uuid,
    target_node_id: Uuid,
    wireguard_public_key: String,
    mesh_address: String,
}

async fn issue_network_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueNetworkGrantRequest>,
) -> Result<Json<SignedNetworkAccessGrantV1>, ApiError> {
    let session = authenticated_session(&state, &headers)?;
    let policy = sqlx::query(
        "SELECT policy.id, client.wireguard_public_key \
         FROM policy.access_policies AS policy \
         JOIN device.devices AS client \
           ON client.id = $3 AND client.domain_id = policy.domain_id \
          AND client.owner_user_id = policy.subject_user_id AND client.status = 'active' \
         JOIN device.nodes AS target \
           ON target.id = policy.target_node_id AND target.status = 'active' \
         WHERE policy.domain_id = $1 AND policy.subject_user_id = $2 \
           AND policy.target_node_id = $4 AND policy.enabled \
           AND (policy.required_device_id IS NULL OR policy.required_device_id = $3) \
           AND (policy.valid_from IS NULL OR policy.valid_from <= now()) \
           AND (policy.valid_until IS NULL OR policy.valid_until > now()) \
         ORDER BY policy.id LIMIT 1",
    )
    .bind(state.domain_id())
    .bind(session.user_id)
    .bind(request.device_id)
    .bind(request.target_node_id)
    .fetch_optional(state.pool())
    .await
    .map_err(ApiError::internal)?;

    let Some(policy) = policy else {
        return Err(ApiError::forbidden("policy_denied"));
    };
    let policy_id: Uuid = policy.try_get("id").map_err(ApiError::internal)?;
    let registered_key: Vec<u8> = policy
        .try_get("wireguard_public_key")
        .map_err(ApiError::internal)?;
    if registered_key != request.wireguard_public_key.as_bytes() {
        return Err(ApiError::forbidden("wireguard_key_mismatch"));
    }
    let issued_at = unix_timestamp()?;
    let grant = NetworkAccessGrantV1 {
        version: "1".to_owned(),
        issuer: format!("domain-authority:{}", state.domain_id()),
        domain_id: state.domain_id().to_string(),
        subject_user_id: session.user_id.to_string(),
        device_id: request.device_id.to_string(),
        target_node_id: request.target_node_id.to_string(),
        wireguard_public_key: request.wireguard_public_key,
        mesh_address: request.mesh_address,
        policy_id: policy_id.to_string(),
        nonce: Uuid::new_v4().simple().to_string(),
        issued_at,
        not_before: issued_at,
        expires_at: issued_at + state.network_grant_ttl_seconds(),
        audience: "node-agent".to_owned(),
    };
    let envelope = sign_network_grant(grant, state.signer()).map_err(|cause| {
        error!(%cause, "invalid network access grant request");
        ApiError::bad_request("invalid_network_grant")
    })?;

    let mut transaction = state.pool().begin().await.map_err(ApiError::internal)?;
    record_audit(
        &mut transaction,
        state.domain_id(),
        session.user_id,
        "network.authorize",
        "node",
        request.target_node_id,
        "allow",
    )
    .await?;
    transaction.commit().await.map_err(ApiError::internal)?;
    Ok(Json(envelope))
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
    let supplied = headers
        .get("x-authority-bootstrap-token")
        .and_then(|value| value.to_str().ok());
    if supplied == Some(state.bootstrap_token()) {
        Ok(())
    } else {
        Err(ApiError::unauthorized("invalid_bootstrap_token"))
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<Uuid, ApiError> {
    let value = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("invalid_session"))?;
    value
        .parse()
        .map_err(|_| ApiError::unauthorized("invalid_session"))
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
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.code }))).into_response()
    }
}
