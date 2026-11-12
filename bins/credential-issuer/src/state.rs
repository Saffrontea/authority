use std::sync::{
    Arc, Mutex, RwLock, RwLockReadGuard,
    atomic::{AtomicU64, Ordering},
};

use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use authority_replay_ledger::ReplayLedger;
use ssh_key::PrivateKey;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    verifier: OpenSslEd25519Verifier,
    ca_key: RwLock<PrivateKey>,
    replay_ledger: Mutex<ReplayLedger>,
    next_serial: AtomicU64,
}

impl AppState {
    pub fn new(
        verifier: OpenSslEd25519Verifier,
        ca_key: PrivateKey,
        replay_ledger: ReplayLedger,
        initial_serial: u64,
    ) -> Self {
        Self(Arc::new(Inner {
            verifier,
            ca_key: RwLock::new(ca_key),
            replay_ledger: Mutex::new(replay_ledger),
            next_serial: AtomicU64::new(initial_serial),
        }))
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

    pub fn consume_nonce(&self, nonce: &str, expires_at: i64, now: i64) -> Result<bool, String> {
        self.0
            .replay_ledger
            .lock()
            .map_err(|error| error.to_string())?
            .consume(nonce, expires_at, now)
    }

    pub fn next_serial(&self) -> u64 {
        self.0.next_serial.fetch_add(1, Ordering::Relaxed)
    }
}
