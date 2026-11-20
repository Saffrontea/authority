use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use ::ssh_key::{PrivateKey, PublicKey};
use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use axum::http::HeaderValue;
use openssl::pkey::{PKey, Private};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    private_key: PrivateKey,
    trusted_cas: Vec<PublicKey>,
    private_key_path: PathBuf,
    certificate_path: PathBuf,
    known_hosts_path: PathBuf,
    ssh_target: Option<IpAddr>,
    ssh_target_port: u16,
    browser_origins: Vec<HeaderValue>,
    terminal_slots: Arc<Semaphore>,
    verifier: OpenSslEd25519Verifier,
    terminal_lease: Mutex<Option<TerminalSnapshot>>,
    mtls_private_key: PKey<Private>,
}

pub struct TerminalLease {
    pub token_hash: String,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct TerminalSnapshot {
    pub certificate: Arc<str>,
    pub expires_at: i64,
    token_hash: String,
}

pub struct AgentPaths {
    pub private_key: PathBuf,
    pub certificate: PathBuf,
    pub known_hosts: PathBuf,
}

pub struct AgentCredentials {
    pub ssh_private_key: PrivateKey,
    pub mtls_private_key: PKey<Private>,
}

impl AppState {
    pub fn new(
        credentials: AgentCredentials,
        trusted_cas: Vec<PublicKey>,
        paths: AgentPaths,
        ssh_target: Option<IpAddr>,
        ssh_target_port: u16,
        browser_origins: Vec<HeaderValue>,
        verifier: OpenSslEd25519Verifier,
    ) -> Self {
        Self(Arc::new(Inner {
            private_key: credentials.ssh_private_key,
            trusted_cas,
            private_key_path: paths.private_key,
            certificate_path: paths.certificate,
            known_hosts_path: paths.known_hosts,
            ssh_target,
            ssh_target_port,
            browser_origins,
            terminal_slots: Arc::new(Semaphore::new(4)),
            verifier,
            terminal_lease: Mutex::new(None),
            mtls_private_key: credentials.mtls_private_key,
        }))
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.0.private_key
    }

    pub fn trusted_cas(&self) -> &[PublicKey] {
        &self.0.trusted_cas
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

    pub fn ssh_target(&self) -> Option<(IpAddr, u16)> {
        self.0
            .ssh_target
            .map(|target| (target, self.0.ssh_target_port))
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

    pub fn mtls_private_key(&self) -> &PKey<Private> {
        &self.0.mtls_private_key
    }

    pub fn install_certificate(
        &self,
        certificate: &str,
        lease: TerminalLease,
    ) -> Result<(), String> {
        use std::io::Write;
        let mut installed = self
            .0
            .terminal_lease
            .lock()
            .map_err(|error| error.to_string())?;
        let parent = self
            .certificate_path()
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
        temporary
            .write_all(certificate.as_bytes())
            .map_err(|error| error.to_string())?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| error.to_string())?;
        temporary
            .persist(self.certificate_path())
            .map_err(|error| error.to_string())?;
        *installed = Some(TerminalSnapshot {
            certificate: Arc::from(certificate),
            token_hash: lease.token_hash,
            expires_at: lease.expires_at,
        });
        Ok(())
    }

    #[cfg(test)]
    pub fn install_terminal_lease(&self, lease: TerminalLease) -> Result<(), String> {
        let certificate =
            std::fs::read_to_string(self.certificate_path()).map_err(|error| error.to_string())?;
        self.install_certificate(&certificate, lease)
    }

    #[cfg(test)]
    pub fn terminal_authorized(&self, token_hash: &str, now: i64) -> Result<bool, String> {
        Ok(self.terminal_snapshot(token_hash, now)?.is_some())
    }

    pub fn terminal_snapshot(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<TerminalSnapshot>, String> {
        let lease = self
            .0
            .terminal_lease
            .lock()
            .map_err(|error| error.to_string())?;
        Ok(lease
            .as_ref()
            .filter(|lease| {
                lease.expires_at > now
                    && constant_time_eq(lease.token_hash.as_bytes(), token_hash.as_bytes())
            })
            .cloned())
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
