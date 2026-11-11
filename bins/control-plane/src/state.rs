use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
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
    bootstrap_token: Mutex<Option<String>>,
    registrations: Mutex<HashMap<Uuid, PendingRegistration>>,
    authentications: Mutex<HashMap<Uuid, PendingAuthentication>>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    signer: OpenSslEd25519Signer,
    target_identity_file: PathBuf,
    network_grant_ttl_seconds: i64,
    ssh_authorization_ttl_seconds: i64,
}

pub struct PendingRegistration {
    pub user_id: Uuid,
    pub state: PasskeyRegistration,
    pub expires_at: Instant,
}

pub struct PendingAuthentication {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_public_key: [u8; 32],
    pub device_challenge: String,
    pub state: PasskeyAuthentication,
    pub expires_at: Instant,
}

pub struct Session {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_public_key: [u8; 32],
    pub consumed_nonces: HashSet<String>,
    pub expires_at: Instant,
    pub expires_at_unix: u64,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        webauthn: Webauthn,
        domain_id: Uuid,
        bootstrap_token: String,
        signer: OpenSslEd25519Signer,
        target_identity_file: PathBuf,
        authorization_ttls: (i64, i64),
    ) -> Self {
        let (network_grant_ttl_seconds, ssh_authorization_ttl_seconds) = authorization_ttls;
        Self(Arc::new(Inner {
            pool,
            webauthn,
            domain_id,
            bootstrap_token: Mutex::new(Some(bootstrap_token)),
            registrations: Mutex::new(HashMap::new()),
            authentications: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            signer,
            target_identity_file,
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
        &self.0.target_identity_file
    }

    pub fn verify_bootstrap_token(&self, supplied: &str) -> Result<bool, String> {
        let token = self
            .0
            .bootstrap_token
            .lock()
            .map_err(|error| error.to_string())?;
        Ok(token
            .as_deref()
            .is_some_and(|expected| constant_time_eq(expected.as_bytes(), supplied.as_bytes())))
    }

    pub fn consume_bootstrap_token(&self, supplied: &str) -> Result<bool, String> {
        let mut token = self
            .0
            .bootstrap_token
            .lock()
            .map_err(|error| error.to_string())?;
        if token
            .as_deref()
            .is_some_and(|expected| constant_time_eq(expected.as_bytes(), supplied.as_bytes()))
        {
            token.take();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn registrations(&self) -> &Mutex<HashMap<Uuid, PendingRegistration>> {
        &self.0.registrations
    }

    pub fn authentications(&self) -> &Mutex<HashMap<Uuid, PendingAuthentication>> {
        &self.0.authentications
    }

    pub fn sessions(&self) -> &Mutex<HashMap<[u8; 32], Session>> {
        &self.0.sessions
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}
