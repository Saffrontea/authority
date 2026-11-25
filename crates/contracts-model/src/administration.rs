//! Explicit operator commands authenticated by the existing control-plane root.
use crate::{ContractError, push_string, valid_identifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentitySelector {
    Subject { subject_user_id: String },
    Device { device_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRevocationCommandV1 {
    pub version: u8,
    pub domain_id: String,
    pub selector: IdentitySelector,
    pub nonce: String,
    pub reason: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl IdentityRevocationCommandV1 {
    /// # Errors
    /// Rejects unknown versions, ambiguous selectors, invalid nonce/time/bindings.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != 1 {
            return Err(ContractError::UnsupportedVersion);
        }
        for (name, value) in [("domain_id", &self.domain_id), ("reason", &self.reason)] {
            if !valid_identifier(value) {
                return Err(ContractError::InvalidIdentifier(name));
            }
        }
        let id = match &self.selector {
            IdentitySelector::Subject { subject_user_id } => subject_user_id,
            IdentitySelector::Device { device_id } => device_id,
        };
        if !valid_identifier(id) {
            return Err(ContractError::InvalidIdentifier("selector"));
        }
        if self.nonce.len() != 43
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(ContractError::InvalidNonce);
        }
        if self.issued_at < 0 || self.expires_at.checked_sub(self.issued_at) != Some(30) {
            return Err(ContractError::InvalidTimeRange);
        }
        Ok(())
    }
    /// # Errors
    /// Canonical domain-separated encoding of every command claim.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut result = b"AUTHORITY-IDENTITY-REVOCATION-COMMAND-V1\0".to_vec();
        for field in [&self.domain_id, &self.nonce, &self.reason] {
            push_string(&mut result, field);
        }
        match &self.selector {
            IdentitySelector::Subject { subject_user_id } => {
                push_string(&mut result, "subject");
                push_string(&mut result, subject_user_id);
            }
            IdentitySelector::Device { device_id } => {
                push_string(&mut result, "device");
                push_string(&mut result, device_id);
            }
        }
        result.extend_from_slice(&self.issued_at.to_be_bytes());
        result.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIdentityRevocationCommandV1 {
    pub command: IdentityRevocationCommandV1,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}
impl SignedIdentityRevocationCommandV1 {
    /// # Errors
    /// Checks structure only; callers must verify the configured root signature.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.command.validate()?;
        crate::validate_envelope(&self.algorithm, &self.key_id, &self.signature)
    }
}
