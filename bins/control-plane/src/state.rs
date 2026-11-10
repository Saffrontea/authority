use std::{
    collections::HashMap,
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
    bootstrap_token: String,
    registrations: Mutex<HashMap<Uuid, PendingRegistration>>,
    authentications: Mutex<HashMap<Uuid, PendingAuthentication>>,
    sessions: Mutex<HashMap<Uuid, Session>>,
    signer: OpenSslEd25519Signer,
    network_grant_ttl_seconds: i64,
}

pub struct PendingRegistration {
    pub user_id: Uuid,
    pub state: PasskeyRegistration,
    pub expires_at: Instant,
}

pub struct PendingAuthentication {
    pub user_id: Uuid,
    pub state: PasskeyAuthentication,
    pub expires_at: Instant,
}

pub struct Session {
    pub user_id: Uuid,
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
        network_grant_ttl_seconds: i64,
    ) -> Self {
        Self(Arc::new(Inner {
            pool,
            webauthn,
            domain_id,
            bootstrap_token,
            registrations: Mutex::new(HashMap::new()),
            authentications: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            signer,
            network_grant_ttl_seconds,
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

    pub fn bootstrap_token(&self) -> &str {
        &self.0.bootstrap_token
    }

    pub fn registrations(&self) -> &Mutex<HashMap<Uuid, PendingRegistration>> {
        &self.0.registrations
    }

    pub fn authentications(&self) -> &Mutex<HashMap<Uuid, PendingAuthentication>> {
        &self.0.authentications
    }

    pub fn sessions(&self) -> &Mutex<HashMap<Uuid, Session>> {
        &self.0.sessions
    }

    pub fn signer(&self) -> &OpenSslEd25519Signer {
        &self.0.signer
    }

    pub fn network_grant_ttl_seconds(&self) -> i64 {
        self.0.network_grant_ttl_seconds
    }
}
