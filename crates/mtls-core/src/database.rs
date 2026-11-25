//! Shared authority with READ COMMITTED and per-decision row locks.
use crate::AccessError;
use authority_contracts_model::{MtlsIssuanceAuthorizationV1, SignedDecisionRevocationNoticeV2};
use openssl::x509::{X509, X509Ref};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};

#[derive(Clone)]
pub struct AuthorityDb {
    pool: PgPool,
}
impl AuthorityDb {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// # Errors
    /// Fails if explicit DB configuration or the shared database is unavailable.
    pub async fn from_env() -> Result<Self, String> {
        let host =
            std::env::var("AUTHORITY_DB_HOST").map_err(|_| "AUTHORITY_DB_HOST is required")?;
        let password = match std::env::var("AUTHORITY_DB_PASSWORD") {
            Ok(value) => value,
            Err(_) => std::fs::read_to_string(
                std::env::var("AUTHORITY_DB_PASSWORD_FILE")
                    .map_err(|_| "AUTHORITY_DB_PASSWORD_FILE is required")?,
            )
            .map_err(|e| e.to_string())?
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
        };
        let options = PgConnectOptions::new()
            .host(&host)
            .port(
                std::env::var("AUTHORITY_DB_PORT")
                    .unwrap_or_else(|_| "5432".into())
                    .parse::<u16>()
                    .map_err(|e| e.to_string())?,
            )
            .username(&std::env::var("AUTHORITY_DB_USER").unwrap_or_else(|_| "authority".into()))
            .password(&password)
            .database(&std::env::var("AUTHORITY_DB_NAME").unwrap_or_else(|_| "authority".into()))
            .ssl_mode(
                std::env::var("AUTHORITY_DB_SSLMODE")
                    .unwrap_or_else(|_| "disable".into())
                    .parse::<PgSslMode>()
                    .map_err(|e| e.to_string())?,
            );
        PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map(Self::new)
            .map_err(|e| e.to_string())
    }

    /// # Errors
    /// Rejects a CA identifier whose immutable signing material differs.
    pub async fn register_ca(&self, ca_id: &str, certificate: &X509Ref) -> Result<(), String> {
        let der = certificate.to_der().map_err(|e| e.to_string())?;
        let public_key = certificate
            .public_key()
            .and_then(|key| key.public_key_to_der())
            .map_err(|e| e.to_string())?;
        sqlx::query("INSERT INTO issuer.ca_registry(ca_id,certificate_der,public_key_der) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(ca_id).bind(&der).bind(&public_key).execute(&self.pool).await.map_err(|e|e.to_string())?;
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT certificate_der FROM issuer.ca_registry WHERE ca_id=$1")
                .bind(ca_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| e.to_string())?;
        if stored != der {
            return Err("CA material differs across replicas".into());
        }
        Ok(())
    }

    /// # Errors
    /// Binds one configured CA slot to immutable material across all replicas.
    pub async fn bind_ca(&self, slot: &str, ca_id: &str) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO issuer.ca_bindings(slot,ca_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(slot)
        .bind(ca_id)
        .execute(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        let stored: String =
            sqlx::query_scalar("SELECT ca_id FROM issuer.ca_bindings WHERE slot=$1")
                .bind(slot)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| e.to_string())?;
        if stored != ca_id {
            return Err("CA slot already bound to different material; provision the same CA on every replica".into());
        }
        Ok(())
    }

    /// # Errors
    /// Rejects revoked/replayed/expired authority; rolls back failed signing/storage.
    pub async fn issue(
        &self,
        ca_id: &str,
        authorization: &MtlsIssuanceAuthorizationV1,
        generation: &authority_contracts_model::fence::GenerationBinding,
        operation: impl FnOnce(u64) -> Result<X509, String>,
    ) -> Result<X509, AccessError> {
        let mut tx = begin(&self.pool).await.map_err(|e| storage(&e))?;
        generation
            .check_identity(
                &authorization.domain_id,
                &authorization.subject_user_id,
                &authorization.device_id,
            )
            .map_err(|_| AccessError::Revoked)?;
        if !crate::issuance::lock_generations(&mut tx, generation)
            .await
            .map_err(|e| storage(&e))?
        {
            return Err(AccessError::Revoked);
        }
        sqlx::query("INSERT INTO issuer.decision_state(domain_id,target_node_id,decision_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(domain_id,target_node_id,decision_id) DO UPDATE SET expires_at=GREATEST(issuer.decision_state.expires_at,excluded.expires_at)")
            .bind(&authorization.domain_id).bind(&authorization.target_node_id).bind(&authorization.decision_id).bind(authorization.expires_at).execute(&mut *tx).await.map_err(|e| storage(&e))?;
        let row = sqlx::query("SELECT revoked_at, FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint AS now FROM issuer.decision_state WHERE domain_id=$1 AND target_node_id=$2 AND decision_id=$3 FOR UPDATE")
            .bind(&authorization.domain_id).bind(&authorization.target_node_id).bind(&authorization.decision_id).fetch_one(&mut *tx).await.map_err(|e| storage(&e))?;
        let now: i64 = row.try_get("now").map_err(|e| storage(&e))?;
        if now < authorization.not_before || now >= authorization.expires_at {
            return Err(AccessError::NotActive);
        }
        if row
            .try_get::<Option<i64>, _>("revoked_at")
            .map_err(|e| storage(&e))?
            .is_some()
        {
            return Err(AccessError::Revoked);
        }
        if !consume_in(
            &mut tx,
            authority_contracts_model::AdapterGrantKindV1::MtlsClientCertificate.as_str(),
            &authorization.nonce,
            authorization.expires_at,
        )
        .await
        .map_err(|e| storage(&e))?
        {
            return Err(AccessError::Replay);
        }
        let serial: i64 = sqlx::query_scalar("SELECT nextval('issuer.certificate_serial')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| storage(&e))?;
        let certificate =
            operation(u64::try_from(serial).map_err(|e| AccessError::Operation(e.to_string()))?)
                .map_err(AccessError::Operation)?;
        sqlx::query("INSERT INTO issuer.certificates(ca_id,serial,domain_id,target_node_id,decision_id,authorization_nonce,certificate_der,not_before,expires_at,subject_user_id,device_id,subject_generation,device_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(ca_id).bind(serial).bind(&authorization.domain_id).bind(&authorization.target_node_id).bind(&authorization.decision_id).bind(&authorization.nonce)
            .bind(certificate.to_der().map_err(|e|AccessError::Operation(e.to_string()))?).bind(authorization.not_before).bind(authorization.expires_at)
            .bind(&generation.subject_user_id).bind(&generation.device_id).bind(generation.subject_generation).bind(generation.device_generation).execute(&mut *tx).await.map_err(|e| storage(&e))?;
        tx.commit().await.map_err(|e| storage(&e))?;
        Ok(certificate)
    }

    /// # Errors
    /// Atomically reserves a unique serial and consumes one shared issuer nonce.
    pub async fn consume_serial(
        &self,
        issuer_id: &str,
        nonce: &str,
        expires_at: i64,
    ) -> Result<Option<u64>, String> {
        let mut tx = begin(&self.pool).await.map_err(|e| e.to_string())?;
        if !consume_in(&mut tx, issuer_id, nonce, expires_at)
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(None);
        }
        let serial: i64 = sqlx::query_scalar("SELECT nextval('issuer.certificate_serial')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(Some(u64::try_from(serial).map_err(|e| e.to_string())?))
    }

    /// # Errors
    /// An unavailable DB, unknown, revoked or expired certificate is never admitted.
    pub async fn certificate_active(&self, ca_id: &str, serial: i64) -> Result<bool, String> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuer.certificates c JOIN issuer.decision_state d USING(domain_id,target_node_id,decision_id) JOIN identity.users u ON u.id=c.subject_user_id::uuid AND u.domain_id=c.domain_id::uuid AND u.generation=c.subject_generation AND u.status='active' JOIN device.devices v ON v.id=c.device_id::uuid AND v.domain_id=u.domain_id AND v.owner_user_id=u.id AND v.generation=c.device_generation AND v.status='active' WHERE c.ca_id=$1 AND c.serial=$2 AND c.revoked_at IS NULL AND d.revoked_at IS NULL AND c.not_before<=FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint AND c.expires_at>FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint)")
            .bind(ca_id).bind(serial).fetch_one(&self.pool).await.map_err(|e|e.to_string())
    }
}

fn storage(error: &sqlx::Error) -> AccessError {
    AccessError::Storage(error.to_string())
}

/// # Errors
/// Starts every authority mutation with the explicitly selected isolation level.
pub async fn begin(pool: &PgPool) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

pub(crate) async fn consume_in(
    tx: &mut Transaction<'_, Postgres>,
    issuer_id: &str,
    nonce: &str,
    expires_at: i64,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("INSERT INTO issuer.consumed_authorizations(issuer_id,nonce,expires_at) SELECT $1,$2,$3 WHERE $3>FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint ON CONFLICT DO NOTHING")
        .bind(issuer_id).bind(nonce).bind(expires_at).execute(&mut **tx).await?.rows_affected()==1)
}

/// Shares the caller's publication transaction and decision lock with issuance.
/// # Errors
/// Propagates SQL failures; no decision/serial can become partly revoked.
pub async fn revoke_in(
    tx: &mut Transaction<'_, Postgres>,
    envelope: &SignedDecisionRevocationNoticeV2,
) -> Result<(), sqlx::Error> {
    let n = &envelope.notice;
    sqlx::query("INSERT INTO issuer.decision_state(domain_id,target_node_id,decision_id,expires_at,revoked_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(domain_id,target_node_id,decision_id) DO UPDATE SET revoked_at=COALESCE(issuer.decision_state.revoked_at,excluded.revoked_at), expires_at=GREATEST(issuer.decision_state.expires_at,excluded.expires_at)")
        .bind(&n.domain_id).bind(&n.target_node_id).bind(&n.decision_id).bind(n.expires_at).bind(n.revoked_at).execute(&mut **tx).await?;
    sqlx::query("UPDATE issuer.certificates SET revoked_at=COALESCE(revoked_at,$4) WHERE domain_id=$1 AND target_node_id=$2 AND decision_id=$3")
        .bind(&n.domain_id).bind(&n.target_node_id).bind(&n.decision_id).bind(n.revoked_at).execute(&mut **tx).await?;
    Ok(())
}

/// # Errors
/// Fails if the CA certificate cannot be encoded.
pub fn ca_id(cert: &X509Ref) -> Result<String, String> {
    Ok(openssl::base64::encode_block(&openssl::sha::sha256(
        &cert.to_der().map_err(|e| e.to_string())?,
    ))
    .trim_end_matches('=')
    .replace('+', "-")
    .replace('/', "_"))
}

impl AuthorityDb {
    /// # Errors
    /// Compatibility delivery may act only on the exact committed envelope.
    pub async fn committed_notice(
        &self,
        notice: &SignedDecisionRevocationNoticeV2,
    ) -> Result<bool, String> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM policy.revocation_notices WHERE sequence=$1 AND envelope=$2)").bind(notice.notice.sequence).bind(serde_json::to_value(notice).map_err(|e|e.to_string())?).fetch_one(&self.pool).await.map_err(|e|e.to_string())
    }
    /// # Errors
    /// Registers a new process epoch without initially granting an enforcement lease.
    pub async fn register_instance(
        &self,
        instance: uuid::Uuid,
        domain: uuid::Uuid,
        target: uuid::Uuid,
    ) -> Result<(), String> {
        sqlx::query("INSERT INTO policy.enforcement_instances(instance_id,domain_id,target_node_id,role,lease_until) VALUES($1,$2,$3,'mtls-service',clock_timestamp())")
            .bind(instance).bind(domain).bind(target).execute(&self.pool).await.map_err(|e|e.to_string())?;
        Ok(())
    }
    /// # Errors
    /// Loads committed events after one process's durable cursor.
    pub async fn events(
        &self,
        instance: uuid::Uuid,
    ) -> Result<Vec<SignedDecisionRevocationNoticeV2>, String> {
        let values: Vec<serde_json::Value> = sqlx::query_scalar("SELECT n.envelope FROM policy.enforcement_instances i JOIN policy.revocation_notices n ON n.domain_id=i.domain_id AND n.target_node_id=i.target_node_id WHERE i.instance_id=$1 AND n.sequence>i.last_sequence AND n.envelope->'notice'->'adapter_kinds' ? 'mtls.client_certificate' ORDER BY n.sequence LIMIT 100")
            .bind(instance).fetch_all(&self.pool).await.map_err(|e|e.to_string())?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())
    }
    /// # Errors
    /// Advances only after local socket drain. A lease is granted only when all
    /// relevant committed events have been applied; publication takes an exclusive
    /// stream lock, so a concurrent commit cannot be skipped by a new cursor.
    pub async fn acknowledge_and_renew(
        &self,
        instance: uuid::Uuid,
        applied: &[i64],
    ) -> Result<bool, String> {
        let mut tx = begin(&self.pool).await.map_err(|e| e.to_string())?;
        sqlx::query("SELECT id FROM policy.revocation_stream FOR SHARE")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        let row = sqlx::query("SELECT domain_id,target_node_id,last_sequence FROM policy.enforcement_instances WHERE instance_id=$1 FOR UPDATE")
            .bind(instance).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
        let domain: uuid::Uuid = row.try_get("domain_id").map_err(|e| e.to_string())?;
        let target: uuid::Uuid = row.try_get("target_node_id").map_err(|e| e.to_string())?;
        let mut cursor: i64 = row.try_get("last_sequence").map_err(|e| e.to_string())?;
        // Do not trust a caller-supplied watermark to skip an earlier event.
        let expected: Vec<i64> = sqlx::query_scalar("SELECT sequence FROM policy.revocation_notices WHERE domain_id=$1 AND target_node_id=$2 AND sequence>$3 AND envelope->'notice'->'adapter_kinds' ? 'mtls.client_certificate' ORDER BY sequence LIMIT 100")
            .bind(domain).bind(target).bind(cursor).fetch_all(&mut *tx).await.map_err(|e|e.to_string())?;
        if !applied.is_empty() && expected.get(..applied.len()) != Some(applied) {
            return Err("event acknowledgement is not the exact next page".into());
        }
        for &sequence in applied {
            sqlx::query("INSERT INTO policy.revocation_receipts(sequence,instance_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
                .bind(sequence).bind(instance).execute(&mut *tx).await.map_err(|e|e.to_string())?;
            cursor = sequence;
        }
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM policy.revocation_notices WHERE domain_id=$1 AND target_node_id=$2 AND sequence>$3 AND envelope->'notice'->'adapter_kinds' ? 'mtls.client_certificate')")
            .bind(domain).bind(target).bind(cursor).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
        if pending {
            sqlx::query(
                "UPDATE policy.enforcement_instances SET last_sequence=$2 WHERE instance_id=$1",
            )
            .bind(instance)
            .bind(cursor)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        } else {
            let watermark: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(sequence),0) FROM policy.revocation_notices",
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
            sqlx::query("UPDATE policy.enforcement_instances SET last_sequence=$2,lease_until=clock_timestamp()+make_interval(secs=>$3::integer) WHERE instance_id=$1")
                .bind(instance).bind(watermark).bind(i32::try_from(crate::ENFORCEMENT_LEASE_SECONDS).map_err(|e|e.to_string())?).execute(&mut *tx).await.map_err(|e|e.to_string())?;
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(!pending)
    }
}

#[cfg(test)]
#[path = "database_tests.rs"]
mod tests;
