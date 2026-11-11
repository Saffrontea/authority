use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ::ssh_key::{PrivateKey, PublicKey};
use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use axum::http::HeaderValue;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    private_key: PrivateKey,
    trusted_ca: PublicKey,
    private_key_path: PathBuf,
    certificate_path: PathBuf,
    known_hosts_path: PathBuf,
    ssh_target: Option<IpAddr>,
    browser_origins: Vec<HeaderValue>,
    terminal_slots: Arc<Semaphore>,
    verifier: OpenSslEd25519Verifier,
    terminal_lease: Mutex<Option<TerminalLease>>,
}

pub struct TerminalLease {
    pub token_hash: String,
    pub expires_at: i64,
}

pub struct AgentPaths {
    pub private_key: PathBuf,
    pub certificate: PathBuf,
    pub known_hosts: PathBuf,
}

impl AppState {
    pub fn new(
        private_key: PrivateKey,
        trusted_ca: PublicKey,
        paths: AgentPaths,
        ssh_target: Option<IpAddr>,
        browser_origins: Vec<HeaderValue>,
        verifier: OpenSslEd25519Verifier,
    ) -> Self {
        Self(Arc::new(Inner {
            private_key,
            trusted_ca,
            private_key_path: paths.private_key,
            certificate_path: paths.certificate,
            known_hosts_path: paths.known_hosts,
            ssh_target,
            browser_origins,
            terminal_slots: Arc::new(Semaphore::new(4)),
            verifier,
            terminal_lease: Mutex::new(None),
        }))
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.0.private_key
    }

    pub fn trusted_ca(&self) -> &PublicKey {
        &self.0.trusted_ca
    }

    pub fn private_key_path(&self) -> &PathBuf {
        &self.0.private_key_path
    }

    pub fn certificate_path(&self) -> &PathBuf {
        &self.0.certificate_path
    }

    pub fn known_hosts_path(&self) -> &PathBuf {
        &self.0.known_hosts_path
    }

    pub fn ssh_target(&self) -> Option<IpAddr> {
        self.0.ssh_target
    }

    pub fn browser_origin_allowed(&self, origin: &HeaderValue) -> bool {
        self.0.browser_origins.contains(origin)
    }

    pub fn terminal_slots(&self) -> Arc<Semaphore> {
        Arc::clone(&self.0.terminal_slots)
    }

    pub fn verifier(&self) -> &OpenSslEd25519Verifier {
        &self.0.verifier
    }

    pub fn install_terminal_lease(&self, lease: TerminalLease) -> Result<(), String> {
        *self
            .0
            .terminal_lease
            .lock()
            .map_err(|error| error.to_string())? = Some(lease);
        Ok(())
    }

    pub fn terminal_authorized(&self, token_hash: &str, now: i64) -> Result<bool, String> {
        let lease = self
            .0
            .terminal_lease
            .lock()
            .map_err(|error| error.to_string())?;
        Ok(lease.as_ref().is_some_and(|lease| {
            lease.expires_at > now
                && constant_time_eq(lease.token_hash.as_bytes(), token_hash.as_bytes())
        }))
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
