use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use authority_credential_crypto_openssl::OpenSslEd25519Signer;
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn,
    prelude::{PasskeyAuthentication, PasskeyRegistration},
};

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    pool: PgPool,
    webauthn: Webauthn,
    domain_id: Uuid,
    bootstrap_digest: [u8; 32],
    signer: OpenSslEd25519Signer,
    enrollment: EnrollmentConfig,
    network_grant_ttl_seconds: i64,
    ssh_authorization_ttl_seconds: i64,
}

pub struct EnrollmentConfig {
    pub target_identity_file: PathBuf,
    pub client_wireguard_public_key: String,
    pub network_agent_origin: String,
    pub target_mesh_address: String,
    pub existing_route_source_address: Option<std::net::Ipv4Addr>,
}

#[derive(Serialize, Deserialize)]
pub struct PendingRegistration {
    pub user_id: Uuid,
    pub state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
pub struct PendingAuthentication {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_public_key: [u8; 32],
    pub device_challenge: String,
    pub state: PasskeyAuthentication,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        webauthn: Webauthn,
        domain_id: Uuid,
        bootstrap_token: &str,
        signer: OpenSslEd25519Signer,
        enrollment: EnrollmentConfig,
        authorization_ttls: (i64, i64),
    ) -> Self {
        let (network_grant_ttl_seconds, ssh_authorization_ttl_seconds) = authorization_ttls;
        Self(Arc::new(Inner {
            pool,
            webauthn,
            domain_id,
            bootstrap_digest: openssl::sha::sha256(bootstrap_token.as_bytes()),
            signer,
            enrollment,
            network_grant_ttl_seconds,
            ssh_authorization_ttl_seconds,
        }))
    }

    pub fn pool(&self) -> &PgPool {
        &self.0.pool
    }

    pub fn webauthn(&self) -> &Webauthn {
        &self.0.webauthn
    }

    pub fn domain_id(&self) -> Uuid {
        self.0.domain_id
    }

    pub fn target_identity_file(&self) -> &Path {
        &self.0.enrollment.target_identity_file
    }

    pub fn client_wireguard_public_key(&self) -> &str {
        &self.0.enrollment.client_wireguard_public_key
    }

    pub fn target_mesh_address(&self) -> &str {
        &self.0.enrollment.target_mesh_address
    }

    pub fn existing_route_source_address(&self) -> Option<std::net::Ipv4Addr> {
        self.0.enrollment.existing_route_source_address
    }

    pub fn network_agent_origin(&self) -> &str {
        &self.0.enrollment.network_agent_origin
    }

    pub fn signer(&self) -> &OpenSslEd25519Signer {
        &self.0.signer
    }

    pub fn network_grant_ttl_seconds(&self) -> i64 {
        self.0.network_grant_ttl_seconds
    }

    pub fn ssh_authorization_ttl_seconds(&self) -> i64 {
        self.0.ssh_authorization_ttl_seconds
    }
}

impl AppState {
    pub async fn initialize_auth(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO identity.auth_domains(domain_id) VALUES($1) ON CONFLICT DO NOTHING",
        )
        .bind(self.domain_id())
        .execute(self.pool())
        .await?;
        sqlx::query("INSERT INTO identity.bootstrap_tokens(domain_id,token_digest) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(self.domain_id()).bind(self.0.bootstrap_digest.as_slice()).execute(self.pool()).await?;
        Ok(())
    }
    pub async fn verify_bootstrap_token(&self, supplied: &str) -> Result<bool, sqlx::Error> {
        let digest = openssl::sha::sha256(supplied.as_bytes());
        if !openssl::memcmp::eq(&digest, &self.0.bootstrap_digest) {
            return Ok(false);
        }
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identity.bootstrap_tokens WHERE domain_id=$1 AND token_digest=$2 AND consumed_at IS NULL)").bind(self.domain_id()).bind(digest.as_slice()).fetch_one(self.pool()).await
    }
    pub async fn consume_bootstrap_token(
        &self,
        supplied: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<bool, sqlx::Error> {
        let digest = openssl::sha::sha256(supplied.as_bytes());
        if !openssl::memcmp::eq(&digest, &self.0.bootstrap_digest) {
            return Ok(false);
        }
        Ok(sqlx::query("UPDATE identity.bootstrap_tokens SET consumed_at=clock_timestamp() WHERE domain_id=$1 AND token_digest=$2 AND consumed_at IS NULL").bind(self.domain_id()).bind(digest.as_slice()).execute(&mut **tx).await?.rows_affected() == 1)
    }
    pub async fn put_challenge<T: Serialize>(
        &self,
        id: Uuid,
        kind: &str,
        subject_user_id: Uuid,
        payload: &T,
        ttl: i64,
    ) -> Result<bool, String> {
        let mut tx = crate::access_policy::begin_authorization(self.pool())
            .await
            .map_err(|e| e.to_string())?;
        sqlx::query("SELECT domain_id FROM identity.auth_domains WHERE domain_id=$1 FOR UPDATE")
            .bind(self.domain_id())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        sqlx::query("DELETE FROM identity.pending_challenges WHERE domain_id=$1 AND expires_at<=clock_timestamp()").bind(self.domain_id()).execute(&mut *tx).await.map_err(|e| e.to_string())?;
        if !crate::auth_limits::reserve_challenge_slot(
            &mut tx,
            self.domain_id(),
            subject_user_id,
            kind,
        )
        .await
        .map_err(|error| error.to_string())?
        {
            tx.commit().await.map_err(|error| error.to_string())?;
            return Ok(false);
        }
        sqlx::query("INSERT INTO identity.pending_challenges(domain_id,id,kind,subject_user_id,payload,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+make_interval(secs=>$6::integer))")
            .bind(self.domain_id()).bind(id).bind(kind).bind(subject_user_id)
            .bind(serde_json::to_value(payload).map_err(|e|e.to_string())?).bind(i32::try_from(ttl).map_err(|e|e.to_string())?)
            .execute(&mut *tx).await.map_err(|e|e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(true)
    }
    pub async fn take_challenge<T: serde::de::DeserializeOwned>(
        &self,
        id: Uuid,
        kind: &str,
    ) -> Result<Option<T>, String> {
        let value: Option<serde_json::Value> = sqlx::query_scalar("DELETE FROM identity.pending_challenges WHERE domain_id=$1 AND id=$2 AND kind=$3 AND expires_at>clock_timestamp() RETURNING payload").bind(self.domain_id()).bind(id).bind(kind).fetch_optional(self.pool()).await.map_err(|e| e.to_string())?;
        value
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| e.to_string())
    }
}
