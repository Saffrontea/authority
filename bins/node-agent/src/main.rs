mod api;
mod config;
mod ssh_key;
mod state;

use std::{fs, path::Path};

use ::ssh_key::{HashAlg, PublicKey};
use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use config::Config;
use state::{AgentPaths, AppState};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let config = Config::from_env().map_err(|error| format!("configuration error: {error}"))?;
    let private_key = ssh_key::load_or_generate(&config.ssh_private_key_file)
        .map_err(|error| format!("SSH key error: {error}"))?;
    let trusted_cas = load_trusted_cas(&config.trusted_ca_public_keys_file)?;
    let browser_origins = config.browser_origins.clone();
    let verifier = OpenSslEd25519Verifier::from_pem_file(
        config.control_plane_key_id,
        config.control_plane_public_key_file,
    )?;
    let state = AppState::new(
        private_key,
        trusted_cas,
        AgentPaths {
            private_key: config.ssh_private_key_file,
            certificate: config.ssh_certificate_file,
            known_hosts: config.ssh_known_hosts_file,
        },
        config.ssh_target,
        config.ssh_target_port,
        browser_origins,
        verifier,
    );
    let listener = tokio::net::TcpListener::bind(config.bind).await?;

    info!(address = %config.bind, "node agent listening");
    axum::serve(listener, api::router(state, config.browser_origins))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn load_trusted_cas(path: &Path) -> Result<Vec<PublicKey>, Box<dyn std::error::Error>> {
    let mut keys = Vec::<PublicKey>::new();
    for line in fs::read_to_string(path)?.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = PublicKey::from_openssh(line)?;
        let fingerprint = key.fingerprint(HashAlg::Sha256);
        if !keys
            .iter()
            .any(|existing| existing.fingerprint(HashAlg::Sha256) == fingerprint)
        {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        return Err("trusted SSH CA bundle contains no public keys".into());
    }
    Ok(keys)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use ssh_key::{Algorithm, PrivateKey, rand_core::OsRng};

    use super::load_trusted_cas;

    #[test]
    fn loads_deduplicated_overlap_ca_bundle() {
        let old = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("old CA");
        let new = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("new CA");
        let path = std::env::temp_dir().join(format!(
            "authority-ca-bundle-{}-{:?}",
            std::process::id(),
            SystemTime::now()
        ));
        fs::write(
            &path,
            format!(
                "# overlap\n{}\n{}\n{}\n",
                old.public_key().to_openssh().expect("old public key"),
                new.public_key().to_openssh().expect("new public key"),
                old.public_key().to_openssh().expect("duplicate old key"),
            ),
        )
        .expect("write bundle");
        let keys = load_trusted_cas(&path).expect("load bundle");
        fs::remove_file(path).expect("remove bundle");
        assert_eq!(keys.len(), 2);
    }
}
