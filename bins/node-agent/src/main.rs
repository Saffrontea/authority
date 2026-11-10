mod api;
mod config;
mod ssh_key;
mod state;

use std::fs;

use ::ssh_key::PublicKey;
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
    let private_key = ssh_key::load_or_generate(&config.ssh_private_key_file)
        .map_err(|error| format!("SSH key error: {error}"))?;
    let trusted_ca =
        PublicKey::from_openssh(&fs::read_to_string(&config.trusted_ca_public_key_file)?)?;
    let state = AppState::new(
        private_key,
        trusted_ca,
        config.ssh_private_key_file,
        config.ssh_certificate_file,
    );
    let listener = tokio::net::TcpListener::bind(config.bind).await?;

    info!(address = %config.bind, "node agent listening");
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
