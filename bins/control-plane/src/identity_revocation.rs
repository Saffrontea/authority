//! Root-authenticated management; identity fences, PKI events and outbox co-commit.
use crate::{api::ApiError, state::AppState};
use authority_contracts_model::{
    AdapterGrantKindV1 as Kind, DecisionRevocationNoticeV2,
    administration::{IdentitySelector, SignedIdentityRevocationCommandV1},
    fence::{RevocationSelector, ScopedRevocationNoticeV3},
};
use authority_issuer_core::sign_revocation_notice_v2;
use axum::{Json, extract::State};
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

type Tx<'a> = Transaction<'a, Postgres>;

#[allow(clippy::too_many_lines)] // One publication transaction owns the complete identity mutation.
pub async fn revoke(
    State(state): State<AppState>,
    Json(envelope): Json<SignedIdentityRevocationCommandV1>,
) -> Result<Json<Value>, ApiError> {
    let now = authority_mtls_core::unix_timestamp().map_err(ApiError::internal)?;
    authority_issuer_core::fence::verify_command(
        &envelope,
        state.operator_verifier(),
        &state.domain_id().to_string(),
        now,
    )
    .map_err(|e| ApiError::unauthorized_with_log("invalid_operator_command", e))?;
    let command = &envelope.command;
    let mut tx = crate::access_policy::begin_authorization(state.pool())
        .await
        .map_err(ApiError::database)?;
    let encoded = serde_json::to_value(&envelope).map_err(ApiError::internal)?;
    sqlx::query("INSERT INTO policy.identity_revocation_commands(domain_id,nonce,command) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(state.domain_id()).bind(&command.nonce).bind(&encoded).execute(&mut *tx).await.map_err(ApiError::database)?;
    let row=sqlx::query("SELECT command,response FROM policy.identity_revocation_commands WHERE domain_id=$1 AND nonce=$2 FOR UPDATE")
        .bind(state.domain_id()).bind(&command.nonce).fetch_one(&mut *tx).await.map_err(ApiError::database)?;
    let previous: SignedIdentityRevocationCommandV1 =
        serde_json::from_value(row.try_get("command").map_err(ApiError::database)?)
            .map_err(ApiError::internal)?;
    if previous.key_id != envelope.key_id
        || previous.command.selector != command.selector
        || previous.command.reason != command.reason
    {
        return Err(ApiError::conflict("operation_nonce_reused"));
    }
    let existing: Value = row.try_get("response").map_err(ApiError::database)?;
    if existing.get("selector").is_some() {
        tx.commit().await.map_err(ApiError::database)?;
        return status(&state, &command.nonce, existing).await.map(Json);
    }
    let (selector, subject, device) = freeze(&mut tx, state.domain_id(), &command.selector).await?;
    // Sequence order remains publication commit order across precise and bulk notices.
    sqlx::query("SELECT id FROM policy.revocation_stream FOR UPDATE")
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;
    let now: i64 =
        sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::database)?;
    let targets=sqlx::query("SELECT DISTINCT target_node_id FROM policy.issued_ability_grants WHERE domain_id=$1 AND ($2::uuid IS NULL OR subject_user_id=$2) AND ($3::uuid IS NULL OR device_id=$3) AND expires_at>$4")
        .bind(state.domain_id()).bind(subject).bind(device).bind(now).fetch_all(&mut *tx).await.map_err(ApiError::database)?;
    let decisions=sqlx::query("SELECT DISTINCT target_node_id,decision_id,MAX(expires_at) AS expiry FROM policy.issued_ability_grants WHERE domain_id=$1 AND ($2::uuid IS NULL OR subject_user_id=$2) AND ($3::uuid IS NULL OR device_id=$3) AND ability_kind='mtls_credential' AND expires_at>$4 GROUP BY target_node_id,decision_id")
        .bind(state.domain_id()).bind(subject).bind(device).bind(now).fetch_all(&mut *tx).await.map_err(ApiError::database)?;
    sqlx::query("UPDATE policy.issued_ability_grants SET revoked_at=COALESCE(revoked_at,$4) WHERE domain_id=$1 AND ($2::uuid IS NULL OR subject_user_id=$2) AND ($3::uuid IS NULL OR device_id=$3)")
        .bind(state.domain_id()).bind(subject).bind(device).bind(now).execute(&mut *tx).await.map_err(ApiError::database)?;
    sqlx::query("UPDATE issuer.ssh_certificates SET revoked_at=COALESCE(revoked_at,$4) WHERE domain_id=$1 AND ($2::text IS NULL OR subject_user_id=$2) AND ($3::text IS NULL OR device_id=$3)")
        .bind(state.domain_id().to_string()).bind(subject.map(|id|id.to_string())).bind(device.map(|id|id.to_string())).bind(now).execute(&mut *tx).await.map_err(ApiError::database)?;
    let mut notices = Vec::new();
    for target in targets {
        let target: Uuid = target
            .try_get("target_node_id")
            .map_err(ApiError::database)?;
        let sequence = next_sequence(&mut tx).await?;
        let notice = authority_issuer_core::fence::sign(
            ScopedRevocationNoticeV3 {
                version: 3,
                issuer: authority_contracts_model::protocol::domain_issuer(state.domain_id()),
                domain_id: state.domain_id().to_string(),
                target_node_id: target.to_string(),
                selector: selector.clone(),
                reason: command.reason.clone(),
                sequence,
                revoked_at: now,
                expires_at: now + 86400,
                adapter_kinds: vec![
                    Kind::WireGuardPeer,
                    Kind::TcpPort,
                    Kind::SshCertificate,
                    Kind::SshSession,
                    Kind::MtlsClientCertificate,
                ],
            },
            state.signer(),
        )
        .map_err(ApiError::internal)?;
        let value = serde_json::to_value(&notice).map_err(ApiError::internal)?;
        sqlx::query("INSERT INTO policy.scoped_revocation_notices(sequence,domain_id,operation_nonce,target_node_id,envelope,expires_at) VALUES($1,$2,$3,$4,$5,to_timestamp($6))")
            .bind(sequence).bind(state.domain_id()).bind(&command.nonce).bind(target).bind(&value).bind(now+86400).execute(&mut *tx).await.map_err(ApiError::database)?;
        notices.push(notice);
    }
    for decision in decisions {
        let target: Uuid = decision
            .try_get("target_node_id")
            .map_err(ApiError::database)?;
        let id: String = decision
            .try_get("decision_id")
            .map_err(ApiError::database)?;
        let expiry: i64 = decision.try_get("expiry").map_err(ApiError::database)?;
        publish_pki(
            &mut tx,
            &state,
            &command.nonce,
            target,
            &id,
            expiry,
            now,
            &command.reason,
        )
        .await?;
    }
    let response = json!({"operation_nonce":command.nonce,"selector":selector,"notices":notices,"revoked_at":now});
    sqlx::query("UPDATE policy.identity_revocation_commands SET response=$3 WHERE domain_id=$1 AND nonce=$2")
        .bind(state.domain_id()).bind(&command.nonce).bind(&response).execute(&mut *tx).await.map_err(ApiError::database)?;
    sqlx::query("INSERT INTO audit.events(domain_id,actor_type,actor_id,action,target_type,target_id,decision,reason,payload) VALUES($1,'operator',$2,'identity.revoke','identity',$3,'allow',$4,$5)")
        .bind(state.domain_id()).bind(&envelope.key_id).bind(&command.nonce).bind(&command.reason).bind(json!({"command":envelope,"result":response})).execute(&mut *tx).await.map_err(ApiError::database)?;
    sqlx::query("INSERT INTO outbox.events(id,owner_module,aggregate_type,aggregate_id,event_type,contract_version,payload,occurred_at) VALUES($1,'policy','identity',$2,'identity.revoked.v1',1,$3,clock_timestamp())")
        .bind(Uuid::new_v4()).bind(&command.nonce).bind(&response).execute(&mut *tx).await.map_err(ApiError::database)?;
    tx.commit().await.map_err(ApiError::database)?;
    status(&state, &command.nonce, response).await.map(Json)
}

async fn freeze(
    tx: &mut Tx<'_>,
    domain: Uuid,
    selector: &IdentitySelector,
) -> Result<(RevocationSelector, Option<Uuid>, Option<Uuid>), ApiError> {
    match selector {
        IdentitySelector::Subject { subject_user_id } => {
            let id = subject_user_id
                .parse::<Uuid>()
                .map_err(|_| ApiError::bad_request("invalid_subject"))?;
            let generation: Option<i64> = sqlx::query_scalar(
                "SELECT generation FROM identity.users WHERE id=$1 AND domain_id=$2 FOR UPDATE",
            )
            .bind(id)
            .bind(domain)
            .fetch_optional(&mut **tx)
            .await
            .map_err(ApiError::database)?;
            let next = generation
                .ok_or_else(|| ApiError::bad_request("unknown_subject"))?
                .checked_add(1)
                .ok_or_else(|| ApiError::conflict("generation_exhausted"))?;
            sqlx::query("UPDATE identity.users SET status='disabled',generation=$3 WHERE id=$1 AND domain_id=$2").bind(id).bind(domain).bind(next).execute(&mut **tx).await.map_err(ApiError::database)?;
            Ok((
                RevocationSelector::Subject {
                    subject_user_id: id.to_string(),
                    minimum_generation: next,
                },
                Some(id),
                None,
            ))
        }
        IdentitySelector::Device { device_id } => {
            let id = device_id
                .parse::<Uuid>()
                .map_err(|_| ApiError::bad_request("invalid_device"))?;
            let owner: Option<Option<Uuid>> = sqlx::query_scalar(
                "SELECT owner_user_id FROM device.devices WHERE id=$1 AND domain_id=$2",
            )
            .bind(id)
            .bind(domain)
            .fetch_optional(&mut **tx)
            .await
            .map_err(ApiError::database)?;
            let owner = owner
                .flatten()
                .ok_or_else(|| ApiError::bad_request("client_device_required"))?;
            sqlx::query("SELECT id FROM identity.users WHERE id=$1 AND domain_id=$2 FOR SHARE")
                .bind(owner)
                .bind(domain)
                .execute(&mut **tx)
                .await
                .map_err(ApiError::database)?;
            let row=sqlx::query("SELECT generation,owner_user_id FROM device.devices WHERE id=$1 AND domain_id=$2 FOR UPDATE").bind(id).bind(domain).fetch_one(&mut **tx).await.map_err(ApiError::database)?;
            if row
                .try_get::<Option<Uuid>, _>("owner_user_id")
                .map_err(ApiError::database)?
                != Some(owner)
            {
                return Err(ApiError::conflict("device_owner_changed"));
            }
            let next = row
                .try_get::<i64, _>("generation")
                .map_err(ApiError::database)?
                .checked_add(1)
                .ok_or_else(|| ApiError::conflict("generation_exhausted"))?;
            sqlx::query("UPDATE device.devices SET status='disabled',generation=$3 WHERE id=$1 AND domain_id=$2").bind(id).bind(domain).bind(next).execute(&mut **tx).await.map_err(ApiError::database)?;
            Ok((
                RevocationSelector::Device {
                    device_id: id.to_string(),
                    minimum_generation: next,
                },
                None,
                Some(id),
            ))
        }
    }
}

async fn next_sequence(tx: &mut Tx<'_>) -> Result<i64, ApiError> {
    sqlx::query_scalar("SELECT nextval('policy.revocation_notice_sequence')")
        .fetch_one(&mut **tx)
        .await
        .map_err(ApiError::database)
}

#[allow(clippy::too_many_arguments)]
async fn publish_pki(
    tx: &mut Tx<'_>,
    state: &AppState,
    nonce: &str,
    target: Uuid,
    decision: &str,
    expires: i64,
    now: i64,
    reason: &str,
) -> Result<(), ApiError> {
    let scope = "mtls.client_certificate";
    let existing:Option<i64>=sqlx::query_scalar("SELECT sequence FROM policy.revocation_notices WHERE domain_id=$1 AND target_node_id=$2 AND decision_id=$3 AND scope_key=$4")
        .bind(state.domain_id()).bind(target).bind(decision).bind(scope).fetch_optional(&mut **tx).await.map_err(ApiError::database)?;
    let sequence = if let Some(sequence) = existing {
        sequence
    } else {
        let sequence = next_sequence(tx).await?;
        let envelope = sign_revocation_notice_v2(
            DecisionRevocationNoticeV2 {
                version: "2".into(),
                issuer: authority_contracts_model::protocol::domain_issuer(state.domain_id()),
                domain_id: state.domain_id().to_string(),
                target_node_id: target.to_string(),
                decision_id: decision.into(),
                reason: reason.into(),
                sequence,
                revoked_at: now,
                expires_at: expires,
                adapter_kinds: vec![Kind::MtlsClientCertificate],
            },
            state.signer(),
        )
        .map_err(ApiError::internal)?;
        sqlx::query("INSERT INTO policy.revocation_notices(sequence,domain_id,decision_id,target_node_id,reason,revoked_at,expires_at,envelope,scope_key) VALUES($1,$2,$3,$4,$5,to_timestamp($6),to_timestamp($7),$8,$9)")
            .bind(sequence).bind(state.domain_id()).bind(decision).bind(target).bind(reason).bind(now).bind(expires).bind(serde_json::to_value(&envelope).map_err(ApiError::internal)?).bind(scope).execute(&mut **tx).await.map_err(ApiError::database)?;
        authority_mtls_core::database::revoke_in(tx, &envelope)
            .await
            .map_err(ApiError::database)?;
        sqlx::query("INSERT INTO policy.revocation_members(sequence,instance_id,lease_until) SELECT $1,instance_id,lease_until FROM policy.enforcement_instances WHERE domain_id=$2 AND target_node_id=$3 AND role='mtls-service' AND lease_until>clock_timestamp()")
            .bind(sequence).bind(state.domain_id()).bind(target).execute(&mut **tx).await.map_err(ApiError::database)?;
        sequence
    };
    sqlx::query("INSERT INTO policy.identity_revocation_children(domain_id,operation_nonce,sequence) VALUES($1,$2,$3)").bind(state.domain_id()).bind(nonce).bind(sequence).execute(&mut **tx).await.map_err(ApiError::database)?;
    Ok(())
}

async fn status(state: &AppState, nonce: &str, mut value: Value) -> Result<Value, ApiError> {
    let pending:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM policy.scoped_revocation_notices WHERE domain_id=$1 AND operation_nonce=$2 AND completed_at IS NULL)+(SELECT count(*) FROM policy.identity_revocation_children c JOIN policy.revocation_members m USING(sequence) LEFT JOIN policy.revocation_receipts r ON r.sequence=m.sequence AND r.instance_id=m.instance_id WHERE c.domain_id=$1 AND c.operation_nonce=$2 AND r.instance_id IS NULL AND m.lease_until>clock_timestamp())")
        .bind(state.domain_id()).bind(nonce).fetch_one(state.pool()).await.map_err(ApiError::database)?;
    let rows = sqlx::query("SELECT r.sequence,r.target_node_id,r.expires_at::text AS expires_at,CASE WHEN r.completed_at IS NOT NULL THEN 'completed' WHEN r.expires_at<=clock_timestamp() THEN 'expired' WHEN n.id IS NULL THEN 'missing_target' WHEN n.enforcement_origin IS NULL THEN 'missing_origin' ELSE 'pending' END AS status FROM policy.scoped_revocation_notices r LEFT JOIN device.nodes n ON n.id=r.target_node_id WHERE r.domain_id=$1 AND r.operation_nonce=$2 ORDER BY r.sequence")
        .bind(state.domain_id()).bind(nonce).fetch_all(state.pool()).await.map_err(ApiError::database)?;
    let mut blocked = 0;
    let mut deliveries = Vec::new();
    for row in rows {
        let status: String = row.try_get("status").map_err(ApiError::database)?;
        if matches!(
            status.as_str(),
            "expired" | "missing_target" | "missing_origin"
        ) {
            blocked += 1;
        }
        deliveries.push(json!({"sequence":row.try_get::<i64,_>("sequence").map_err(ApiError::database)?, "target_node_id":row.try_get::<Uuid,_>("target_node_id").map_err(ApiError::database)?, "status":status,"expires_at":row.try_get::<String,_>("expires_at").map_err(ApiError::database)?}));
    }
    value["blocked_receivers"] = json!(blocked);
    value["deliveries"] = json!(deliveries);
    value["completed"] = json!(pending == 0);
    value["pending_receivers"] = json!(pending);
    Ok(value)
}
