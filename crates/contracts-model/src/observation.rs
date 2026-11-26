//! Fresh target observations are evidence about the environment, never authority.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr};

pub const MAX_CLOCK_SKEW: i64 = 2;
pub const CHALLENGE_TTL: i64 = 30;
pub const OBSERVATION_TTL: i64 = 600;
pub const OBSERVATION_AUDIENCE: &str = "authority.endpoint.observe.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointFact {
    SshCaTrusted,
    MtlsCaTrusted,
    TcpEnforcement,
    MeshRouteConfigured,
    ExistingRouteConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationResources {
    pub source: Ipv4Addr,
    pub target: Ipv4Addr,
    pub principal: String,
    #[serde(deserialize_with = "unique_set")]
    pub ssh_ca_fingerprints: BTreeSet<String>,
    pub mtls_ca_sha256: String,
    pub service_audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointChallengeV1 {
    pub version: u8,
    pub audience: String,
    pub domain_id: String,
    pub target_node_id: String,
    pub nonce: String,
    pub revision: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub resources: ObservationResources,
}
impl EndpointChallengeV1 {
    /// Checks the bounded wire representation. Cryptographic verification is separate.
    ///
    /// # Errors
    /// Rejects unknown versions, invalid bindings, bounds or timestamps.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.audience != OBSERVATION_AUDIENCE
            || !super::valid_identifier(&self.domain_id)
            || !super::valid_identifier(&self.target_node_id)
            || self.nonce.len() != 43
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || self.revision < 1
            || self.issued_at < 0
            || self.expires_at.checked_sub(self.issued_at) != Some(CHALLENGE_TTL)
            || !super::valid_identifier(&self.resources.principal)
            || !super::valid_identifier(&self.resources.service_audience)
            || self.resources.ssh_ca_fingerprints.is_empty()
            || self.resources.ssh_ca_fingerprints.len() > 8
            || self
                .resources
                .ssh_ca_fingerprints
                .iter()
                .any(|f| f.len() != 50 || !super::valid_sha256_fingerprint(f) || f.contains('='))
            || !hex_digest(&self.resources.mtls_ca_sha256)
        {
            return Err("invalid_endpoint_challenge".into());
        }
        Ok(())
    }
    #[must_use]
    pub fn active(&self, now: i64) -> bool {
        self.validate().is_ok()
            && self.issued_at <= now.saturating_add(MAX_CLOCK_SKEW)
            && now < self.expires_at
    }
    /// Builds the domain-separated canonical representation.
    ///
    /// # Errors
    /// Rejects invalid contracts or serialization failures.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        preimage(b"AUTHORITY-ENDPOINT-CHALLENGE-V1\0", self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEndpointChallengeV1 {
    pub challenge: EndpointChallengeV1,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointObservationV3 {
    pub challenge: EndpointChallengeV1,
    pub boot_id: String,
    pub observed_at: i64,
    pub expires_at: i64,
    pub configuration_sha256: String,
    pub probe_sha256: String,
    #[serde(deserialize_with = "unique_set")]
    pub facts: BTreeSet<EndpointFact>,
    pub tcp_resources: crate::resources::TcpResourcesV1,
}
impl EndpointObservationV3 {
    /// Checks the bounded wire representation. Cryptographic verification is separate.
    ///
    /// # Errors
    /// Rejects unknown versions, invalid bindings, bounds or timestamps.
    pub fn validate(&self) -> Result<(), String> {
        self.challenge.validate()?;
        if (if self.facts.contains(&EndpointFact::TcpEnforcement) {
            self.tcp_resources.validate().is_err()
                || !self
                    .tcp_resources
                    .source_addresses
                    .contains_point(u64::from(u32::from(self.challenge.resources.source)))
                || !self
                    .tcp_resources
                    .destination_addresses
                    .contains_point(u64::from(u32::from(self.challenge.resources.target)))
        } else {
            !self.tcp_resources.source_addresses.is_empty()
                || !self.tcp_resources.destination_addresses.is_empty()
                || !self.tcp_resources.destination_ports.is_empty()
        }) || self.observed_at < 0
            || !hex_digest(&self.probe_sha256)
            || !super::valid_identifier(&self.boot_id)
            || !hex_digest(&self.configuration_sha256)
            || self.observed_at < self.challenge.issued_at - MAX_CLOCK_SKEW
            || self.observed_at >= self.challenge.expires_at
            || self.expires_at.checked_sub(self.observed_at) != Some(OBSERVATION_TTL)
        {
            return Err("invalid_endpoint_observation".into());
        }
        Ok(())
    }
    #[must_use]
    pub fn active(&self, now: i64) -> bool {
        self.validate().is_ok()
            && self.observed_at <= now.saturating_add(MAX_CLOCK_SKEW)
            && now < self.expires_at
    }
    /// Builds the domain-separated canonical representation.
    ///
    /// # Errors
    /// Rejects invalid contracts or serialization failures.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        preimage(b"AUTHORITY-ENDPOINT-OBSERVATION-V3\0", self)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEndpointObservationV3 {
    pub observation: EndpointObservationV3,
    pub signature: String,
}
fn hex_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn preimage(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut result = domain.to_vec();
    result.extend(serde_json::to_vec(value).map_err(|e| e.to_string())?);
    Ok(result)
}

fn unique_set<'de, D, T>(deserializer: D) -> Result<BTreeSet<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Ord,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    let count = values.len();
    let set: BTreeSet<_> = values.into_iter().collect();
    if set.len() != count {
        return Err(serde::de::Error::custom("duplicate observation value"));
    }
    Ok(set)
}
impl SignedEndpointChallengeV1 {
    /// Checks the bounded wire representation. Cryptographic verification is separate.
    ///
    /// # Errors
    /// Rejects unknown versions, invalid bindings, bounds or timestamps.
    pub fn validate(&self) -> Result<(), String> {
        self.challenge.validate()?;
        if !super::valid_identifier(&self.key_id) || !signature(&self.signature) {
            return Err("invalid_challenge_envelope".into());
        }
        Ok(())
    }
}
impl SignedEndpointObservationV3 {
    /// Checks the bounded wire representation. Cryptographic verification is separate.
    ///
    /// # Errors
    /// Rejects unknown versions, invalid bindings, bounds or timestamps.
    pub fn validate(&self) -> Result<(), String> {
        self.observation.validate()?;
        if !signature(&self.signature) {
            return Err("invalid_observation_envelope".into());
        }
        Ok(())
    }
}
fn signature(value: &str) -> bool {
    value.len() == 86
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
