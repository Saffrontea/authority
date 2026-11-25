//! Identity generations are monotone authority fences, not expiring deny entries.
//! These contracts do not by themselves attest that a receiver applied a fence.

use serde::{Deserialize, Serialize};

use crate::{AdapterGrantKindV1, ContractError, push_string, valid_identifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityGenerations {
    pub subject: i64,
    pub device: i64,
}

impl IdentityGenerations {
    #[must_use]
    pub fn bind(self, domain: &str, subject: &str, device: &str) -> GenerationBinding {
        GenerationBinding {
            domain_id: domain.into(),
            subject_user_id: subject.into(),
            device_id: device.into(),
            subject_generation: self.subject,
            device_generation: self.device,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBinding {
    pub domain_id: String,
    pub subject_user_id: String,
    pub device_id: String,
    pub subject_generation: i64,
    pub device_generation: i64,
}

/// CA-signed SSH key-ID metadata. The authenticated principal command verifies
/// it at the actual sshd boundary; the epoch lease also covers established SSH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshCertificateIdentityV2 {
    pub version: u8,
    pub generation: GenerationBinding,
    pub target_node_id: String,
    pub decision_id: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
}
impl SshCertificateIdentityV2 {
    /// # Errors
    /// Rejects malformed identities, decision IDs and expired/overflowing lifetimes.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.generation.validate()?;
        if self.version != 2 {
            return Err(ContractError::UnsupportedVersion);
        }
        for (name, value) in [
            ("target_node_id", &self.target_node_id),
            ("decision_id", &self.decision_id),
        ] {
            if !valid_identifier(value) {
                return Err(ContractError::InvalidIdentifier(name));
            }
        }
        super::validate_nonce_and_time(
            &self.decision_id,
            self.issued_at,
            self.not_before,
            self.expires_at,
        )
    }
}

impl GenerationBinding {
    /// # Errors
    /// Rejects a binding transplanted onto another grant's identity.
    pub fn check_identity(
        &self,
        domain: &str,
        subject: &str,
        device: &str,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if self.domain_id != domain || self.subject_user_id != subject || self.device_id != device {
            return Err(ContractError::InvalidIdentifier("generation_binding"));
        }
        Ok(())
    }

    /// # Errors
    /// Validates generations and constructs a domain-separated V2 envelope.
    pub fn envelope_preimage(&self, claims: &[u8]) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut result = b"AUTHORITY-GENERATION-BOUND-ENVELOPE-V2\0".to_vec();
        super::push_u32(&mut result, claims.len());
        result.extend_from_slice(claims);
        for field in [&self.domain_id, &self.subject_user_id, &self.device_id] {
            push_string(&mut result, field);
        }
        result.extend_from_slice(&self.subject_generation.to_be_bytes());
        result.extend_from_slice(&self.device_generation.to_be_bytes());
        Ok(result)
    }
    /// # Errors
    /// Rejects missing identity bindings and nonpositive generations.
    pub fn validate(&self) -> Result<(), ContractError> {
        for (name, value) in [
            ("domain_id", &self.domain_id),
            ("subject_user_id", &self.subject_user_id),
            ("device_id", &self.device_id),
        ] {
            if !valid_identifier(value) {
                return Err(ContractError::InvalidIdentifier(name));
            }
        }
        if self.subject_generation < 1 || self.device_generation < 1 {
            return Err(ContractError::InvalidSequence);
        }
        Ok(())
    }
}

/// The minimum acceptable generation is inclusive. Once installed it remains in
/// force after the notice's transport delivery window has elapsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationSelector {
    Decision {
        decision_id: String,
    },
    Subject {
        subject_user_id: String,
        minimum_generation: i64,
    },
    Device {
        device_id: String,
        minimum_generation: i64,
    },
}

impl RevocationSelector {
    /// # Errors
    /// Rejects malformed identity selectors and invalid generations.
    pub fn validate(&self) -> Result<(), ContractError> {
        let (name, value, generation) = match self {
            Self::Decision { decision_id } => ("decision_id", decision_id, 1),
            Self::Subject {
                subject_user_id,
                minimum_generation,
            } => ("subject_user_id", subject_user_id, *minimum_generation),
            Self::Device {
                device_id,
                minimum_generation,
            } => ("device_id", device_id, *minimum_generation),
        };
        if !valid_identifier(value) {
            return Err(ContractError::InvalidIdentifier(name));
        }
        if generation < 1 {
            return Err(ContractError::InvalidSequence);
        }
        Ok(())
    }

    /// Scope matching is separate from freshness/signature verification. The
    /// caller must first authenticate both the grant's binding and the notice.
    #[must_use]
    pub fn rejects(&self, domain: &str, binding: &GenerationBinding, decision: &str) -> bool {
        if domain != binding.domain_id {
            return false;
        }
        match self {
            Self::Decision { decision_id } => decision_id == decision,
            Self::Subject {
                subject_user_id,
                minimum_generation,
            } => {
                subject_user_id == &binding.subject_user_id
                    && binding.subject_generation < *minimum_generation
            }
            Self::Device {
                device_id,
                minimum_generation,
            } => device_id == &binding.device_id && binding.device_generation < *minimum_generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedRevocationNoticeV3 {
    pub version: u8,
    pub issuer: String,
    pub domain_id: String,
    pub target_node_id: String,
    pub selector: RevocationSelector,
    pub reason: String,
    pub sequence: i64,
    pub revoked_at: i64,
    pub expires_at: i64,
    pub adapter_kinds: Vec<AdapterGrantKindV1>,
}

impl ScopedRevocationNoticeV3 {
    /// # Errors
    /// Rejects unbounded or ambiguous selectors, adapters and delivery windows.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != 3 {
            return Err(ContractError::UnsupportedVersion);
        }
        for (name, value) in [
            ("issuer", &self.issuer),
            ("domain_id", &self.domain_id),
            ("target_node_id", &self.target_node_id),
            ("reason", &self.reason),
        ] {
            if !valid_identifier(value) {
                return Err(ContractError::InvalidIdentifier(name));
            }
        }
        self.selector.validate()?;
        if self.sequence < 1 {
            return Err(ContractError::InvalidSequence);
        }
        if self.revoked_at < 0 || self.revoked_at >= self.expires_at {
            return Err(ContractError::InvalidTimeRange);
        }
        let unique: std::collections::HashSet<_> = self.adapter_kinds.iter().collect();
        if unique.is_empty() || unique.len() != self.adapter_kinds.len() {
            return Err(ContractError::InvalidAdapterKinds);
        }
        Ok(())
    }

    /// All selectors use distinct explicit tags and length-prefixed UTF-8 fields;
    /// the adapter list is sorted in lexical protocol order for canonical signing.
    ///
    /// # Errors
    /// Rejects invalid claims. No JSON object ordering enters this preimage.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut result = b"AUTHORITY-SCOPED-REVOCATION-NOTICE-V3\0".to_vec();
        for field in [
            &self.issuer,
            &self.domain_id,
            &self.target_node_id,
            &self.reason,
        ] {
            push_string(&mut result, field);
        }
        match &self.selector {
            RevocationSelector::Decision { decision_id } => {
                push_string(&mut result, "decision");
                push_string(&mut result, decision_id);
            }
            RevocationSelector::Subject {
                subject_user_id,
                minimum_generation,
            } => {
                push_string(&mut result, "subject");
                push_string(&mut result, subject_user_id);
                result.extend_from_slice(&minimum_generation.to_be_bytes());
            }
            RevocationSelector::Device {
                device_id,
                minimum_generation,
            } => {
                push_string(&mut result, "device");
                push_string(&mut result, device_id);
                result.extend_from_slice(&minimum_generation.to_be_bytes());
            }
        }
        for number in [self.sequence, self.revoked_at, self.expires_at] {
            result.extend_from_slice(&number.to_be_bytes());
        }
        let mut kinds: Vec<_> = self
            .adapter_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect();
        kinds.sort_unstable();
        super::push_u32(&mut result, kinds.len());
        for kind in kinds {
            push_string(&mut result, kind);
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedScopedRevocationNoticeV3 {
    pub notice: ScopedRevocationNoticeV3,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

impl SignedScopedRevocationNoticeV3 {
    /// # Errors
    /// Checks envelope structure; the caller must verify its signature separately.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.notice.validate()?;
        super::validate_envelope(&self.algorithm, &self.key_id, &self.signature)
    }
}
