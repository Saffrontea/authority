//! Shared per-subject limits: one known account must not occupy the whole domain.
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub const MAX_PENDING_PER_USER: i64 = 4;
pub const MAX_PENDING_PER_DOMAIN: i64 = 4096;
pub const CHALLENGES_PER_WINDOW: i32 = 8;
pub const CHALLENGE_WINDOW_SECONDS: i32 = 30;
pub const MAX_SESSIONS_PER_USER: i64 = 8;
pub const MAX_SESSIONS_PER_DOMAIN: i64 = 4096;

/// Caller holds the domain row lock until challenge insertion commits.
pub async fn reserve_challenge_slot(
    tx: &mut Transaction<'_, Postgres>,
    domain: Uuid,
    user: Uuid,
    kind: &str,
) -> Result<bool, sqlx::Error> {
    let allowed: bool = sqlx::query_scalar("INSERT INTO identity.challenge_rate_limits(domain_id,kind,subject_user_id,window_start,attempts) VALUES($1,$2,$3,clock_timestamp(),1) ON CONFLICT(domain_id,kind,subject_user_id) DO UPDATE SET window_start=CASE WHEN identity.challenge_rate_limits.window_start+make_interval(secs=>$4)<=EXCLUDED.window_start THEN EXCLUDED.window_start ELSE identity.challenge_rate_limits.window_start END, attempts=CASE WHEN identity.challenge_rate_limits.window_start+make_interval(secs=>$4)<=EXCLUDED.window_start THEN 1 ELSE LEAST(identity.challenge_rate_limits.attempts+1,$5+1) END RETURNING attempts <= $5")
        .bind(domain).bind(kind).bind(user).bind(CHALLENGE_WINDOW_SECONDS).bind(CHALLENGES_PER_WINDOW)
        .fetch_one(&mut **tx).await?;
    if !allowed {
        return Ok(false);
    }
    // Only this subject's oldest challenges are evicted, never another user's.
    sqlx::query("DELETE FROM identity.pending_challenges WHERE domain_id=$1 AND kind=$2 AND subject_user_id=$3 AND id IN (SELECT id FROM identity.pending_challenges WHERE domain_id=$1 AND kind=$2 AND subject_user_id=$3 ORDER BY expires_at DESC,id DESC OFFSET $4)")
        .bind(domain).bind(kind).bind(user).bind(MAX_PENDING_PER_USER-1).execute(&mut **tx).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity.pending_challenges WHERE domain_id=$1 AND kind=$2",
    )
    .bind(domain)
    .bind(kind)
    .fetch_one(&mut **tx)
    .await?;
    Ok(count < MAX_PENDING_PER_DOMAIN)
}

/// Serialize issuance across replicas, evict only this user's oldest sessions.
/// Call only after successful credential verification, inside its transaction.
pub async fn reserve_session_slot(
    tx: &mut Transaction<'_, Postgres>,
    domain: Uuid,
    user: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query("SELECT domain_id FROM identity.auth_domains WHERE domain_id=$1 FOR UPDATE")
        .bind(domain)
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query(
        "DELETE FROM identity.sessions WHERE domain_id=$1 AND expires_at<=clock_timestamp()",
    )
    .bind(domain)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM identity.sessions WHERE domain_id=$1 AND user_id=$2 AND token_digest IN (SELECT token_digest FROM identity.sessions WHERE domain_id=$1 AND user_id=$2 ORDER BY expires_at DESC,token_digest DESC OFFSET $3)")
        .bind(domain).bind(user).bind(MAX_SESSIONS_PER_USER-1).execute(&mut **tx).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.sessions WHERE domain_id=$1")
            .bind(domain)
            .fetch_one(&mut **tx)
            .await?;
    Ok(count < MAX_SESSIONS_PER_DOMAIN)
}
