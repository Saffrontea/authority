use std::{env, net::SocketAddr, path::PathBuf};

use axum::http::HeaderValue;

pub struct Config {
    pub bind: SocketAddr,
    pub control_plane_key_id: String,
    pub control_plane_public_key_file: PathBuf,
    pub ssh_ca_key_file: PathBuf,
    pub ssh_ca_public_key_file: PathBuf,
    pub replay_ledger_file: PathBuf,
    pub browser_origins: Vec<HeaderValue>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            bind: value("AUTHORITY_ISSUER_BIND", "127.0.0.1:3001")?
                .parse()
                .map_err(|error| format!("AUTHORITY_ISSUER_BIND is invalid: {error}"))?,
            control_plane_key_id: value("AUTHORITY_CONTROL_PLANE_KEY_ID", "control-plane-key-1")?,
            control_plane_public_key_file: PathBuf::from(required(
                "AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE",
            )?),
            ssh_ca_key_file: PathBuf::from(required("AUTHORITY_SSH_CA_KEY_FILE")?),
            ssh_ca_public_key_file: PathBuf::from(required("AUTHORITY_SSH_CA_PUBLIC_KEY_FILE")?),
            replay_ledger_file: PathBuf::from(required("AUTHORITY_ISSUER_REPLAY_LEDGER_FILE")?),
            browser_origins: origins("AUTHORITY_BROWSER_ORIGINS", "http://localhost:3000")?,
        })
    }
}

fn origins(name: &str, default: &str) -> Result<Vec<HeaderValue>, String> {
    let raw = value(name, default)?;
    let parsed = raw
        .split(',')
        .map(str::trim)
        .map(|origin| {
            if origin.is_empty() || origin == "*" {
                return Err(format!("{name} contains an invalid origin"));
            }
            origin
                .parse::<HeaderValue>()
                .map_err(|error| format!("{name} contains an invalid origin: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.is_empty() {
        Err(format!("{name} must contain at least one origin"))
    } else {
        Ok(parsed)
    }
}

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} must be set"))
}

fn value(name: &str, default: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if value.is_empty() => Err(format!("{name} must not be empty")),
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(error) => Err(format!("cannot read {name}: {error}")),
    }
}
