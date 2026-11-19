mod api;
mod config;
mod mtls_ca;
mod ssh_ca;
mod state;

use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use authority_mtls_core::database::AuthorityDb;
use config::Config;
use state::AppState;
use tracing::{error, info};
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
    let database = AuthorityDb::from_env().await?;
    let state = AppState::from_database(verifier, ca_key, database, config.pki_origin);
    state.install_mtls_ca(mtls_ca::load_or_generate(
        &config.mtls_ca_key_file,
        &config.mtls_ca_certificate_file,
    )?)?;
    let ca_id = state.mtls_ca_id()?;
    let ca_cert = state.with_mtls_ca(|ca| Ok(ca.certificate.clone()))?;
    state.database()?.register_ca(&ca_id, &ca_cert).await?;
    state.database()?.bind_ca("mtls-client", &ca_id).await?;
    spawn_ca_reload(state.clone(), config.ssh_ca_key_file.clone())?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;

    info!(address = %config.bind, "credential issuer listening");
    axum::serve(listener, api::router(state, config.browser_origins))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn spawn_ca_reload(state: AppState, key_file: std::path::PathBuf) -> Result<(), std::io::Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            match ssh_ca::load(&key_file).and_then(|key| state.rotate_ca(key)) {
                Ok(()) => info!(path = %key_file.display(), "reloaded active SSH CA"),
                Err(cause) => error!(%cause, path = %key_file.display(), "failed to reload SSH CA"),
            }
        }
    });
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
