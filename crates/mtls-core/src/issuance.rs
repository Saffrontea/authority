//! Credential redemption shares the same identity guards as policy issuance.
use crate::{
    AccessError,
    database::{AuthorityDb, begin},
};
use authority_contracts_model::{
    SignedDecisionRevocationNoticeV2, SignedIssuanceAuthorizationV2, fence::GenerationBinding,
};
use sqlx::{Postgres, Row, Transaction};

/// # Errors
/// Acquires subject -> device guards and checks active ownership and exact epochs.
pub async fn lock_generations(
    tx: &mut Transaction<'_, Postgres>,
    binding: &GenerationBinding,
) -> Result<bool, sqlx::Error> {
    if binding.validate().is_err() {
        return Ok(false);
    }
    let (Ok(domain), Ok(subject), Ok(device)) = (
        binding.domain_id.parse::<uuid::Uuid>(),
        binding.subject_user_id.parse::<uuid::Uuid>(),
        binding.device_id.parse::<uuid::Uuid>(),
    ) else {
        return Ok(false);
    };
    let user = sqlx::query(
        "SELECT generation,status FROM identity.users WHERE id=$1 AND domain_id=$2 FOR SHARE",
    )
    .bind(subject)
    .bind(domain)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(user) = user else {
        return Ok(false);
    };
    if user.try_get::<i64, _>("generation")? != binding.subject_generation
        || user.try_get::<String, _>("status")? != "active"
    {
        return Ok(false);
    }
    let device = sqlx::query("SELECT generation,status,owner_user_id FROM device.devices WHERE id=$1 AND domain_id=$2 FOR SHARE")
        .bind(device).bind(domain).fetch_optional(&mut **tx).await?;
    Ok(match device {
        Some(device) => {
            device.try_get::<i64, _>("generation")? == binding.device_generation
                && device.try_get::<String, _>("status")? == "active"
                && device.try_get::<Option<uuid::Uuid>, _>("owner_user_id")? == Some(subject)
        }
        None => false,
    })
}

fn storage(error: &sqlx::Error) -> AccessError {
    AccessError::Storage(error.to_string())
}

impl AuthorityDb {
    /// # Errors
    /// Reserves/signs/records an SSH certificate under identity and decision locks.
    /// Failed signing or persistence rolls back nonce consumption and serial use.
    pub async fn issue_ssh<T>(
        &self,
        signed: &SignedIssuanceAuthorizationV2,
        operation: impl FnOnce(u64) -> Result<(T, String, String), String>,
    ) -> Result<T, AccessError> {
        signed
            .validate()
            .map_err(|e| AccessError::Operation(e.to_string()))?;
        let a = &signed.authorization;
        let mut tx = begin(self.pool()).await.map_err(|error| storage(&error))?;
        if !lock_generations(&mut tx, &signed.generation)
            .await
            .map_err(|error| storage(&error))?
        {
            return Err(AccessError::Revoked);
        }
        sqlx::query("INSERT INTO issuer.ssh_decision_state(domain_id,target_node_id,decision_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(domain_id,target_node_id,decision_id) DO UPDATE SET expires_at=GREATEST(issuer.ssh_decision_state.expires_at,excluded.expires_at)")
            .bind(&a.domain_id).bind(&a.target_node_id).bind(&a.decision_id).bind(a.expires_at).execute(&mut *tx).await.map_err(|error| storage(&error))?;
        let row = sqlx::query("SELECT revoked_at,FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint AS now FROM issuer.ssh_decision_state WHERE domain_id=$1 AND target_node_id=$2 AND decision_id=$3 FOR UPDATE")
            .bind(&a.domain_id).bind(&a.target_node_id).bind(&a.decision_id).fetch_one(&mut *tx).await.map_err(|error| storage(&error))?;
        let now: i64 = row.try_get("now").map_err(|error| storage(&error))?;
        if now < a.not_before || now >= a.expires_at {
            return Err(AccessError::NotActive);
        }
        if row
            .try_get::<Option<i64>, _>("revoked_at")
            .map_err(|error| storage(&error))?
            .is_some()
        {
            return Err(AccessError::Revoked);
        }
        if !super::database::consume_in(&mut tx, "ssh.certificate", &a.nonce, a.expires_at)
            .await
            .map_err(|error| storage(&error))?
        {
            return Err(AccessError::Replay);
        }
        let serial: i64 = sqlx::query_scalar("SELECT nextval('issuer.certificate_serial')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| storage(&error))?;
        let (value, certificate, ca) =
            operation(u64::try_from(serial).map_err(|e| AccessError::Operation(e.to_string()))?)
                .map_err(AccessError::Operation)?;
        sqlx::query("INSERT INTO issuer.ssh_certificates(serial,domain_id,target_node_id,subject_user_id,device_id,subject_generation,device_generation,decision_id,certificate_openssh,ca_fingerprint,not_before,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
            .bind(serial).bind(&a.domain_id).bind(&a.target_node_id).bind(&a.subject_user_id).bind(&a.device_id).bind(signed.generation.subject_generation).bind(signed.generation.device_generation).bind(&a.decision_id).bind(certificate).bind(ca).bind(a.not_before).bind(a.expires_at).execute(&mut *tx).await.map_err(|error| storage(&error))?;
        tx.commit().await.map_err(|error| storage(&error))?;
        Ok(value)
    }
}

/// # Errors
/// Shares the publication transaction and credential-redemption decision guard.
pub async fn revoke_ssh_in(
    tx: &mut Transaction<'_, Postgres>,
    envelope: &SignedDecisionRevocationNoticeV2,
) -> Result<(), sqlx::Error> {
    let n = &envelope.notice;
    sqlx::query("INSERT INTO issuer.ssh_decision_state(domain_id,target_node_id,decision_id,revoked_at,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(domain_id,target_node_id,decision_id) DO UPDATE SET revoked_at=COALESCE(issuer.ssh_decision_state.revoked_at,excluded.revoked_at),expires_at=GREATEST(issuer.ssh_decision_state.expires_at,excluded.expires_at)")
        .bind(&n.domain_id).bind(&n.target_node_id).bind(&n.decision_id).bind(n.revoked_at).bind(n.expires_at).execute(&mut **tx).await?;
    sqlx::query("UPDATE issuer.ssh_certificates SET revoked_at=COALESCE(revoked_at,$4) WHERE domain_id=$1 AND target_node_id=$2 AND decision_id=$3")
        .bind(&n.domain_id).bind(&n.target_node_id).bind(&n.decision_id).bind(n.revoked_at).execute(&mut **tx).await?;
    Ok(())
}
