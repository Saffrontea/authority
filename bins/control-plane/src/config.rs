use std::{env, fs, net::SocketAddr, path::PathBuf};

use sqlx::postgres::{PgConnectOptions, PgSslMode};
use uuid::Uuid;
use webauthn_rs::prelude::Url;

pub struct Config {
    pub bind: SocketAddr,
    pub database: PgConnectOptions,
    pub domain_id: Uuid,
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: Url,
    pub bootstrap_token: String,
    pub signing_key_id: String,
    pub signing_key_file: PathBuf,
    pub signing_public_key_file: PathBuf,
    pub target_identity_file: PathBuf,
    pub client_wireguard_public_key: String,
    pub network_agent_origin: String,
    pub network_grant_ttl_seconds: i64,
    pub ssh_authorization_ttl_seconds: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind = value("AUTHORITY_BIND", "127.0.0.1:3000")?
            .parse()
            .map_err(|error| format!("AUTHORITY_BIND is not a socket address: {error}"))?;
        let domain_id = value(
            "AUTHORITY_DOMAIN_ID",
            "019a6e6d-4b01-7c31-bb4c-f83220bec001",
        )?
        .parse()
        .map_err(|error| format!("AUTHORITY_DOMAIN_ID is not a UUID: {error}"))?;
        let rp_id = value("AUTHORITY_RP_ID", "localhost")?;
        let rp_name = value("AUTHORITY_RP_NAME", "Authority PoC")?;
        let rp_origin = Url::parse(&value("AUTHORITY_RP_ORIGIN", "http://localhost:3000")?)
            .map_err(|error| format!("AUTHORITY_RP_ORIGIN is not a URL: {error}"))?;

        let password = secret("AUTHORITY_DB_PASSWORD", "AUTHORITY_DB_PASSWORD_FILE")?;
        let bootstrap_token = secret(
            "AUTHORITY_BOOTSTRAP_TOKEN",
            "AUTHORITY_BOOTSTRAP_TOKEN_FILE",
        )?;
        let signing_key_id = value("AUTHORITY_SIGNING_KEY_ID", "control-plane-key-1")?;
        let signing_key_file = PathBuf::from(required("AUTHORITY_SIGNING_KEY_FILE")?);
        let signing_public_key_file = PathBuf::from(required("AUTHORITY_SIGNING_PUBLIC_KEY_FILE")?);
        let target_identity_file = PathBuf::from(required("AUTHORITY_TARGET_IDENTITY_FILE")?);
        let client_wireguard_public_key = required("AUTHORITY_CLIENT_WIREGUARD_PUBLIC_KEY")?;
        let network_agent_origin = required("AUTHORITY_NETWORK_AGENT_ORIGIN")?;
        let network_grant_ttl_seconds = value("AUTHORITY_NETWORK_GRANT_TTL_SECONDS", "300")?
            .parse::<i64>()
            .map_err(|error| format!("AUTHORITY_NETWORK_GRANT_TTL_SECONDS is invalid: {error}"))?;
        if !(1..=600).contains(&network_grant_ttl_seconds) {
            return Err("AUTHORITY_NETWORK_GRANT_TTL_SECONDS must be between 1 and 600".to_owned());
        }
        let ssh_authorization_ttl_seconds =
            value("AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS", "300")?
                .parse::<i64>()
                .map_err(|error| {
                    format!("AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS is invalid: {error}")
                })?;
        if !(5..=600).contains(&ssh_authorization_ttl_seconds) {
            return Err(
                "AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS must be between 5 and 600".to_owned(),
            );
        }
        if network_grant_ttl_seconds < ssh_authorization_ttl_seconds {
            return Err(
                "AUTHORITY_NETWORK_GRANT_TTL_SECONDS must cover AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS"
                    .to_owned(),
            );
        }
        let database = PgConnectOptions::new()
            .host(&required("AUTHORITY_DB_HOST")?)
            .port(
                value("AUTHORITY_DB_PORT", "5432")?
                    .parse()
                    .map_err(|error| format!("AUTHORITY_DB_PORT is not a port number: {error}"))?,
            )
            .username(&value("AUTHORITY_DB_USER", "authority")?)
            .password(&password)
            .database(&value("AUTHORITY_DB_NAME", "authority")?)
            .ssl_mode(PgSslMode::Disable);

        Ok(Self {
            bind,
            database,
            domain_id,
            rp_id,
            rp_name,
            rp_origin,
            bootstrap_token,
            signing_key_id,
            signing_key_file,
            signing_public_key_file,
            target_identity_file,
            client_wireguard_public_key,
            network_agent_origin,
            network_grant_ttl_seconds,
            ssh_authorization_ttl_seconds,
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

fn secret(value_name: &str, file_name: &str) -> Result<String, String> {
    if let Ok(value) = env::var(value_name) {
        return nonempty_one_line(value_name, value);
    }
    let path = PathBuf::from(required(file_name)?);
    let value = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {} at {}: {error}", file_name, path.display()))?;
    nonempty_one_line(file_name, value.trim_end_matches(['\r', '\n']).to_owned())
}

fn nonempty_one_line(name: &str, value: String) -> Result<String, String> {
    if value.is_empty() || value.contains(['\r', '\n']) {
        Err(format!("{name} must contain exactly one non-empty line"))
    } else {
        Ok(value)
    }
}
