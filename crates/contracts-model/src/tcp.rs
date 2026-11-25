//! Port-scoped TCP admission, independent of mesh membership.
use super::{
    ContractError, push_string, valid_identifier, validate_envelope, validate_nonce_and_time,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpAccessGrantV2 {
    pub version: String,
    pub issuer: String,
    pub domain_id: String,
    pub subject_user_id: String,
    pub device_id: String,
    pub target_node_id: String,
    pub resources: crate::resources::TcpResourcesV1,
    pub policy_id: String,
    pub decision_id: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTcpAccessGrantV2 {
    pub generation: crate::fence::GenerationBinding,
    pub grant: TcpAccessGrantV2,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

impl TcpAccessGrantV2 {
    /// Checks bounded, canonical addresses, ports, identity, and lifetime.
    ///
    /// # Errors
    /// Returns an error for invalid or unbounded admission claims.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != "2" {
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
        self.resources.validate()?;
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
        let mut output = b"AUTHORITY-TCP-ACCESS-GRANT-V2\0".to_vec();
        for value in [
            &self.version,
            &self.issuer,
            &self.domain_id,
            &self.subject_user_id,
            &self.device_id,
            &self.target_node_id,
            &self.policy_id,
            &self.decision_id,
        ] {
            push_string(&mut output, value);
        }
        output.extend_from_slice(&self.resources.signing_preimage()?);
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.not_before.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        push_string(&mut output, &self.audience);
        Ok(output)
    }
}

impl SignedTcpAccessGrantV2 {
    /// Validates both the TCP claims and signature envelope.
    ///
    /// # Errors
    /// Returns an error for invalid claims, algorithm, key id, or encoding.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.grant.validate()?;
        self.generation.check_identity(
            &self.grant.domain_id,
            &self.grant.subject_user_id,
            &self.grant.device_id,
        )?;
        validate_envelope(&self.algorithm, &self.key_id, &self.signature)
    }
    /// # Errors
    /// Rejects invalid claims or identity generation bindings.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, crate::ContractError> {
        self.validate()?;
        self.generation
            .envelope_preimage(&self.grant.signing_preimage()?)
    }
}
