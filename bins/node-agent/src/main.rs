mod api;
mod config;
mod ssh_key;
mod state;

use std::fs;

use ::ssh_key::PublicKey;
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
    let trusted_ca =
        PublicKey::from_openssh(&fs::read_to_string(&config.trusted_ca_public_key_file)?)?;
    let browser_origins = config.browser_origins.clone();
    let verifier = OpenSslEd25519Verifier::from_pem_file(
        config.control_plane_key_id,
        config.control_plane_public_key_file,
    )?;
    let state = AppState::new(
        private_key,
        trusted_ca,
        AgentPaths {
            private_key: config.ssh_private_key_file,
            certificate: config.ssh_certificate_file,
            known_hosts: config.ssh_known_hosts_file,
        },
        config.ssh_target,
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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
