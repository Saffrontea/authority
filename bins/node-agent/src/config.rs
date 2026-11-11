use std::{env, net::SocketAddr, path::PathBuf};

pub struct Config {
    pub bind: SocketAddr,
    pub ssh_private_key_file: PathBuf,
    pub ssh_certificate_file: PathBuf,
    pub trusted_ca_public_key_file: PathBuf,
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
