use std::{net::IpAddr, path::PathBuf, sync::Arc};

use ::ssh_key::{PrivateKey, PublicKey};
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
}

impl AppState {
    pub fn new(
        private_key: PrivateKey,
        trusted_ca: PublicKey,
        private_key_path: PathBuf,
        certificate_path: PathBuf,
        known_hosts_path: PathBuf,
        ssh_target: Option<IpAddr>,
        browser_origins: Vec<HeaderValue>,
    ) -> Self {
        Self(Arc::new(Inner {
            private_key,
            trusted_ca,
            private_key_path,
            certificate_path,
            known_hosts_path,
            ssh_target,
            browser_origins,
            terminal_slots: Arc::new(Semaphore::new(4)),
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
}
