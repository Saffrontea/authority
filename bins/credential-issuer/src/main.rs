mod api;
mod config;
mod ssh_ca;
mod state;

use std::time::{SystemTime, UNIX_EPOCH};

use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use authority_replay_ledger::ReplayLedger;
use config::Config;
use state::AppState;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let config = Config::from_env().map_err(|error| format!("configuration error: {error}"))?;
    let verifier = OpenSslEd25519Verifier::from_pem_file(
        config.control_plane_key_id,
        config.control_plane_public_key_file,
    )?;
    let ca_key = ssh_ca::load_or_generate(&config.ssh_ca_key_file, &config.ssh_ca_public_key_file)
        .map_err(|error| format!("SSH CA error: {error}"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let replay_ledger = ReplayLedger::open(
        config.replay_ledger_file,
        i64::try_from(now).map_err(|error| error.to_string())?,
    )?;
    let initial_serial = now << 20;
    let state = AppState::new(verifier, ca_key, replay_ledger, initial_serial);
    let listener = tokio::net::TcpListener::bind(config.bind).await?;

    info!(address = %config.bind, "credential issuer listening");
    axum::serve(listener, api::router(state, config.browser_origins))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
