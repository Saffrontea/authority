//! Port-scoped TCP admission, independent of mesh membership.
use super::{
    ContractError, push_string, valid_identifier, validate_envelope, validate_nonce_and_time,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpAccessGrantV1 {
    pub version: String,
    pub issuer: String,
    pub domain_id: String,
    pub subject_user_id: String,
    pub device_id: String,
    pub target_node_id: String,
    pub source_address: String,
    pub destination_address: String,
    pub destination_ports: Vec<u16>,
    pub policy_id: String,
    pub decision_id: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTcpAccessGrantV1 {
    pub grant: TcpAccessGrantV1,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

impl TcpAccessGrantV1 {
    /// Checks bounded, canonical addresses, ports, identity, and lifetime.
    ///
    /// # Errors
    /// Returns an error for invalid or unbounded admission claims.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != "1" {
            return Err(ContractError::UnsupportedVersion);
        }
        for (name, value) in [
            ("issuer", &self.issuer),
            ("domain_id", &self.domain_id),
            ("subject_user_id", &self.subject_user_id),
            ("device_id", &self.device_id),
            ("target_node_id", &self.target_node_id),
            ("policy_id", &self.policy_id),
            ("audience", &self.audience),
        ] {
            if !valid_identifier(value) {
                return Err(ContractError::InvalidIdentifier(name));
            }
        }
        for address in [&self.source_address, &self.destination_address] {
            let parsed = address
                .parse::<Ipv4Addr>()
                .map_err(|_| ContractError::InvalidMeshAddress)?;
            if parsed.is_unspecified()
                || parsed.is_multicast()
                || parsed.is_broadcast()
                || parsed.to_string() != *address
            {
                return Err(ContractError::InvalidMeshAddress);
            }
        }
        if self.destination_ports.is_empty()
            || self.destination_ports.len() > 64
            || self.destination_ports.contains(&0)
            || self
                .destination_ports
                .windows(2)
                .any(|ports| ports[0] >= ports[1])
        {
            return Err(ContractError::InvalidTcpPorts);
        }
        validate_nonce_and_time(
            &self.decision_id,
            self.issued_at,
            self.not_before,
            self.expires_at,
        )
    }

    /// Stable, domain-separated preimage including every admission constraint.
    ///
    /// # Errors
    /// Returns an error if the grant is invalid.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut output = b"AUTHORITY-TCP-ACCESS-GRANT-V1\0".to_vec();
        for value in [
            &self.version,
            &self.issuer,
            &self.domain_id,
            &self.subject_user_id,
            &self.device_id,
            &self.target_node_id,
            &self.source_address,
            &self.destination_address,
            &self.policy_id,
            &self.decision_id,
        ] {
            push_string(&mut output, value);
        }
        super::push_u32(&mut output, self.destination_ports.len());
        for port in &self.destination_ports {
            output.extend_from_slice(&port.to_be_bytes());
        }
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.not_before.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        push_string(&mut output, &self.audience);
        Ok(output)
    }
}

impl SignedTcpAccessGrantV1 {
    /// Validates both the TCP claims and signature envelope.
    ///
    /// # Errors
    /// Returns an error for invalid claims, algorithm, key id, or encoding.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.grant.validate()?;
        validate_envelope(&self.algorithm, &self.key_id, &self.signature)
    }
}
