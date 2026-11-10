use std::{path::PathBuf, sync::Arc};

use ::ssh_key::{PrivateKey, PublicKey};

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    private_key: PrivateKey,
    trusted_ca: PublicKey,
    private_key_path: PathBuf,
    certificate_path: PathBuf,
}

impl AppState {
    pub fn new(
        private_key: PrivateKey,
        trusted_ca: PublicKey,
        private_key_path: PathBuf,
        certificate_path: PathBuf,
    ) -> Self {
        Self(Arc::new(Inner {
            private_key,
            trusted_ca,
            private_key_path,
            certificate_path,
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
}
