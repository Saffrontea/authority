use std::{env, fs, net::SocketAddr, path::PathBuf};

use authority_contracts_model::protocol::{MAX_TTL_SECONDS, MIN_TTL_SECONDS, valid_ttl_seconds};

use sqlx::postgres::{PgConnectOptions, PgSslMode};
use uuid::Uuid;
use webauthn_rs::prelude::Url;

const DEFAULT_NETWORK_TTL_SECONDS: &str = "300";
const DEFAULT_SSH_TTL_SECONDS: &str = "300";
const MIN_SSH_TTL_SECONDS: i64 = 5;
pub const DEMO_SERVICE_AUDIENCE: &str = "demo-api";

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
    pub target_mesh_address: String,
    pub existing_route_source_address: Option<std::net::Ipv4Addr>,
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
        validate_network_agent_origin(&network_agent_origin)?;
        let target_mesh_address = value("AUTHORITY_TARGET_MESH_ADDRESS", "10.77.0.2")?;
        let target_address = target_mesh_address
            .parse::<std::net::Ipv4Addr>()
            .map_err(|error| format!("invalid target mesh address: {error}"))?;
        if target_address.is_unspecified()
            || target_address.is_multicast()
            || target_address.is_broadcast()
        {
            return Err("invalid target mesh address".to_owned());
        }
        let existing_route_source_address = existing_route_source()?;
        let network_grant_ttl_seconds = value(
            "AUTHORITY_NETWORK_GRANT_TTL_SECONDS",
            DEFAULT_NETWORK_TTL_SECONDS,
        )?
        .parse::<i64>()
        .map_err(|error| format!("AUTHORITY_NETWORK_GRANT_TTL_SECONDS is invalid: {error}"))?;
        if !valid_ttl_seconds(network_grant_ttl_seconds) {
            return Err(format!(
                "AUTHORITY_NETWORK_GRANT_TTL_SECONDS must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
            ));
        }
        let ssh_authorization_ttl_seconds = value(
            "AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS",
            DEFAULT_SSH_TTL_SECONDS,
        )?
        .parse::<i64>()
        .map_err(|error| format!("AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS is invalid: {error}"))?;
        if !(MIN_SSH_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ssh_authorization_ttl_seconds) {
            return Err(format!(
                "AUTHORITY_SSH_AUTHORIZATION_TTL_SECONDS must be between {MIN_SSH_TTL_SECONDS} and {MAX_TTL_SECONDS}"
            ));
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
            .ssl_mode(
                value("AUTHORITY_DB_SSLMODE", "disable")?
                    .parse::<PgSslMode>()
                    .map_err(|error| format!("AUTHORITY_DB_SSLMODE is invalid: {error}"))?,
            );

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
            target_mesh_address,
            existing_route_source_address,
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

fn existing_route_source() -> Result<Option<std::net::Ipv4Addr>, String> {
    match env::var("AUTHORITY_EXISTING_ROUTE_SOURCE_ADDRESS") {
        Ok(address) => {
            let address = address
                .parse::<std::net::Ipv4Addr>()
                .map_err(|cause| format!("invalid existing route source: {cause}"))?;
            if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
                return Err("invalid existing route source".to_owned());
            }
            Ok(Some(address))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(cause) => Err(format!("cannot read existing route source: {cause}")),
    }
}

pub(crate) fn validate_network_agent_origin(origin: &str) -> Result<(), String> {
    Url::parse(origin)
        .map_err(|_| "AUTHORITY_NETWORK_AGENT_ORIGIN must be an HTTP(S) origin".to_owned())?;
    let uri = origin
        .parse::<axum::http::Uri>()
        .map_err(|_| "AUTHORITY_NETWORK_AGENT_ORIGIN must be an HTTP(S) origin".to_owned())?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
        || origin.bytes().any(|b| {
            b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b';' | b'@' | b'#')
        })
    {
        return Err("AUTHORITY_NETWORK_AGENT_ORIGIN must be an HTTP(S) origin".into());
    }
    Ok(())
}

#[cfg(test)]
mod origin_tests {
    use super::validate_network_agent_origin;
    #[test]
    fn only_http_origins_are_accepted() {
        for origin in [
            "http://127.0.0.1:3002",
            "https://example.org",
            "http://[::1]:3002/",
        ] {
            assert!(validate_network_agent_origin(origin).is_ok(), "{origin}");
        }
        for origin in [
            "http://localhost\n",
            "http://localhost;script-src",
            "http://localhost unsafe",
            "http://user@localhost",
            "http://localhost/path",
            "http://localhost?x",
            "http://localhost#x",
            "ws://localhost",
            "http://",
        ] {
            assert!(validate_network_agent_origin(origin).is_err(), "{origin}");
        }
    }
}
