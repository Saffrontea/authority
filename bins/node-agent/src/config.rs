use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use axum::http::HeaderValue;

pub struct Config {
    pub bind: SocketAddr,
    pub ssh_private_key_file: PathBuf,
    pub ssh_certificate_file: PathBuf,
    pub trusted_ca_public_key_file: PathBuf,
    pub browser_origins: Vec<HeaderValue>,
    pub ssh_known_hosts_file: PathBuf,
    pub ssh_target: Option<IpAddr>,
    pub control_plane_public_key_file: PathBuf,
    pub control_plane_key_id: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            bind: value("AUTHORITY_NODE_AGENT_BIND", "127.0.0.1:3002")?
                .parse()
                .map_err(|error| format!("AUTHORITY_NODE_AGENT_BIND is invalid: {error}"))?,
            ssh_private_key_file: PathBuf::from(required("AUTHORITY_NODE_SSH_KEY_FILE")?),
            ssh_certificate_file: PathBuf::from(required("AUTHORITY_NODE_SSH_CERT_FILE")?),
            trusted_ca_public_key_file: PathBuf::from(required(
                "AUTHORITY_SSH_CA_PUBLIC_KEY_FILE",
            )?),
            browser_origins: origins("AUTHORITY_BROWSER_ORIGINS", "http://localhost:3000")?,
            ssh_known_hosts_file: PathBuf::from(required("AUTHORITY_SSH_KNOWN_HOSTS_FILE")?),
            ssh_target: optional("AUTHORITY_SSH_TARGET")?
                .map(|target| {
                    target
                        .parse::<IpAddr>()
                        .map_err(|error| format!("AUTHORITY_SSH_TARGET is invalid: {error}"))
                })
                .transpose()?,
            control_plane_public_key_file: PathBuf::from(required(
                "AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE",
            )?),
            control_plane_key_id: value("AUTHORITY_SIGNING_KEY_ID", "control-plane-key-1")?,
        })
    }
}

fn optional(name: &str) -> Result<Option<String>, String> {
    match env::var(name) {
        Ok(value) if value.is_empty() => Err(format!("{name} must not be empty")),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(format!("cannot read {name}: {error}")),
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
