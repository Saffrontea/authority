mod api;
mod config;
mod state;
mod ui;

use authority_credential_crypto_openssl::OpenSslEd25519Signer;
use config::Config;
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use tracing::info;
use tracing_subscriber::EnvFilter;
use webauthn_rs::WebauthnBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env().map_err(|error| format!("configuration error: {error}"))?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(config.database.clone())
        .await?;
    let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)?
        .rp_name(&config.rp_name)
        .build()?;
    let signer = load_or_generate_signer(&config.signing_key_id, &config.signing_key_file)?;
    write_public_key(&signer, &config.signing_public_key_file)?;
    let state = AppState::new(
        pool,
        webauthn,
        config.domain_id,
        config.bootstrap_token,
        signer,
        config.network_grant_ttl_seconds,
    );
    let listener = tokio::net::TcpListener::bind(config.bind).await?;

    info!(address = %config.bind, origin = %config.rp_origin, "control plane listening");
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn load_or_generate_signer(
    key_id: &str,
    path: &Path,
) -> Result<OpenSslEd25519Signer, Box<dyn std::error::Error>> {
    match OpenSslEd25519Signer::from_pem_file(key_id, path) {
        Ok(signer) => Ok(signer),
        Err(_) if !path.exists() => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let signer = OpenSslEd25519Signer::generate(key_id)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&signer.private_key_to_pem()?)?;
            info!(key_id, path = %path.display(), "generated control-plane signing key");
            Ok(signer)
        }
        Err(error) => Err(error.into()),
    }
}

fn write_public_key(
    signer: &OpenSslEd25519Signer,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, signer.public_key_to_pem()?)?;
    Ok(())
}
