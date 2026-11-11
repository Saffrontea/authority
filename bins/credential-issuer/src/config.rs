use std::{env, net::SocketAddr, path::PathBuf};

pub struct Config {
    pub bind: SocketAddr,
    pub control_plane_key_id: String,
    pub control_plane_public_key_file: PathBuf,
    pub ssh_ca_key_file: PathBuf,
    pub ssh_ca_public_key_file: PathBuf,
    pub replay_ledger_file: PathBuf,
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
        })
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
