#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard};

use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
#[cfg(test)]
use authority_mtls_core::AccessStore;
use authority_mtls_core::database::AuthorityDb;
#[cfg(test)]
use authority_replay_ledger::ReplayLedger;
use ssh_key::PrivateKey;

use crate::mtls_ca::MtlsCa;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    verifier: OpenSslEd25519Verifier,
    ca_key: RwLock<PrivateKey>,
    database: Option<AuthorityDb>,
    pki_origin: String,
    #[cfg(test)]
    access: Option<AccessStore>,
    #[cfg(test)]
    next_serial: AtomicU64,
    mtls_ca: RwLock<Option<MtlsCa>>,
}

impl AppState {
    #[cfg(test)]
    pub fn new(
        verifier: OpenSslEd25519Verifier,
        ca_key: PrivateKey,
        replay_ledger: ReplayLedger,
        initial_serial: u64,
    ) -> Self {
        Self(Arc::new(Inner {
            verifier,
            ca_key: RwLock::new(ca_key),
            database: None,
            pki_origin: "http://authority.test".into(),
            access: Some(AccessStore::new(replay_ledger)),
            next_serial: AtomicU64::new(initial_serial),
            mtls_ca: RwLock::new(None),
        }))
    }

    pub fn from_database(
        verifier: OpenSslEd25519Verifier,
        ca_key: PrivateKey,
        database: AuthorityDb,
        pki_origin: String,
    ) -> Self {
        Self(Arc::new(Inner {
            verifier,
            ca_key: RwLock::new(ca_key),
            database: Some(database),
            pki_origin,
            #[cfg(test)]
            access: None,
            #[cfg(test)]
            next_serial: AtomicU64::new(0),
            mtls_ca: RwLock::new(None),
        }))
    }
    pub fn database(&self) -> Result<&AuthorityDb, String> {
        self.0
            .database
            .as_ref()
            .ok_or_else(|| "shared authority database required".into())
    }
    pub fn pki_origin(&self) -> &str {
        &self.0.pki_origin
    }
    pub fn mtls_ca_id(&self) -> Result<String, String> {
        self.with_mtls_ca(|ca| authority_mtls_core::database::ca_id(&ca.certificate))
    }

    pub fn verifier(&self) -> &OpenSslEd25519Verifier {
        &self.0.verifier
    }

    pub fn ca_key(&self) -> Result<RwLockReadGuard<'_, PrivateKey>, String> {
        self.0.ca_key.read().map_err(|error| error.to_string())
    }

    pub fn rotate_ca(&self, ca_key: PrivateKey) -> Result<(), String> {
        *self.0.ca_key.write().map_err(|error| error.to_string())? = ca_key;
        Ok(())
    }

    #[cfg(test)]
    pub fn consume_nonce(&self, nonce: &str, expires_at: i64, now: i64) -> Result<bool, String> {
        self.access().consume_nonce(nonce, expires_at, now)
    }

    #[cfg(test)]
    pub fn access(&self) -> &AccessStore {
        self.0.access.as_ref().expect("native test fixture")
    }

    #[cfg(test)]
    pub fn next_serial(&self) -> u64 {
        self.0.next_serial.fetch_add(1, Ordering::Relaxed)
    }

    pub fn install_mtls_ca(&self, ca: MtlsCa) -> Result<(), String> {
        *self.0.mtls_ca.write().map_err(|error| error.to_string())? = Some(ca);
        Ok(())
    }

    pub fn with_mtls_ca<T>(
        &self,
        operation: impl FnOnce(&MtlsCa) -> Result<T, String>,
    ) -> Result<T, String> {
        let guard = self.0.mtls_ca.read().map_err(|error| error.to_string())?;
        operation(
            guard
                .as_ref()
                .ok_or_else(|| "mTLS CA is not initialized".to_owned())?,
        )
    }
}
