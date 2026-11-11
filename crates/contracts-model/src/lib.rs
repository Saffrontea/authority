//! Versioned wire contracts shared across process boundaries.
//!
//! This crate contains no database, HTTP, CA, or policy-engine adapters.

use std::{collections::HashSet, net::IpAddr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const VERSION: &str = "1";
const MAX_TTL_SECONDS: i64 = 600;
const DOMAIN_SEPARATOR: &[u8] = b"AUTHORITY-ISSUANCE-AUTHORIZATION-V1\0";
const NETWORK_GRANT_DOMAIN_SEPARATOR: &[u8] = b"AUTHORITY-NETWORK-ACCESS-GRANT-V1\0";
const SIGNATURE_ALGORITHM: &str = "Ed25519";

/// Control-plane authorization consumed by the isolated credential issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceAuthorizationV1 {
    pub version: String,
    pub issuer: String,
    pub domain_id: String,
    pub subject_user_id: String,
    pub device_id: String,
    pub target_node_id: String,
    pub ssh_public_key_fingerprint: String,
    pub principals: Vec<String>,
    pub policy_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub audience: String,
}

/// Signed transport envelope passed from the control plane to an issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIssuanceAuthorizationV1 {
    pub authorization: IssuanceAuthorizationV1,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

/// Short-lived permission for a target node to admit one `WireGuard` peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAccessGrantV1 {
    pub version: String,
    pub issuer: String,
    pub domain_id: String,
    pub subject_user_id: String,
    pub device_id: String,
    pub target_node_id: String,
    pub wireguard_public_key: String,
    pub mesh_address: String,
    pub policy_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNetworkAccessGrantV1 {
    pub grant: NetworkAccessGrantV1,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

/// One policy decision projected into two independently consumable contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessAuthorizationBundleV1 {
    pub version: String,
    pub decision_id: String,
    pub ssh_authorization: SignedIssuanceAuthorizationV1,
    pub network_grant: SignedNetworkAccessGrantV1,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unsupported contract version")]
    UnsupportedVersion,
    #[error("{0} must be a non-empty identifier")]
    InvalidIdentifier(&'static str),
    #[error("SSH public key fingerprint must use the SHA256 format")]
    InvalidFingerprint,
    #[error("at least one unique principal is required")]
    InvalidPrincipals,
    #[error("nonce must be a base64url value between 32 and 128 characters")]
    InvalidNonce,
    #[error("credential timestamps are inconsistent")]
    InvalidTimeRange,
    #[error("credential lifetime exceeds {MAX_TTL_SECONDS} seconds")]
    LifetimeTooLong,
    #[error("signature algorithm must be Ed25519")]
    InvalidSignatureAlgorithm,
    #[error("signature must be an unpadded base64url value")]
    InvalidSignature,
    #[error("WireGuard public key must be a 32-byte padded base64 value")]
    InvalidWireGuardPublicKey,
    #[error("mesh_address must be an IPv4 address")]
    InvalidMeshAddress,
    #[error("access authorization bundle field does not match: {0}")]
    BundleMismatch(&'static str),
}

impl IssuanceAuthorizationV1 {
    /// Enforces semantics that cannot be expressed by shape validation alone.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when a field violates the v1 identity,
    /// audience, nonce, fingerprint, principal, or lifetime rules.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != VERSION {
            return Err(ContractError::UnsupportedVersion);
        }

        for (name, value) in [
            ("issuer", self.issuer.as_str()),
            ("domain_id", self.domain_id.as_str()),
            ("subject_user_id", self.subject_user_id.as_str()),
            ("device_id", self.device_id.as_str()),
            ("target_node_id", self.target_node_id.as_str()),
            ("policy_id", self.policy_id.as_str()),
            ("audience", self.audience.as_str()),
        ] {
            if !valid_identifier(value) {
                return Err(ContractError::InvalidIdentifier(name));
            }
        }

        if !self.ssh_public_key_fingerprint.starts_with("SHA256:")
            || self.ssh_public_key_fingerprint.len() <= "SHA256:".len()
            || !self.ssh_public_key_fingerprint["SHA256:".len()..]
                .bytes()
                .all(is_base64_character)
        {
            return Err(ContractError::InvalidFingerprint);
        }

        let unique: HashSet<&str> = self.principals.iter().map(String::as_str).collect();
        if self.principals.is_empty()
            || unique.len() != self.principals.len()
            || self.principals.iter().any(|value| !valid_identifier(value))
        {
            return Err(ContractError::InvalidPrincipals);
        }

        if !(32..=128).contains(&self.nonce.len())
            || !self.nonce.bytes().all(is_base64url_character)
        {
            return Err(ContractError::InvalidNonce);
        }

        if self.issued_at > self.not_before || self.not_before >= self.expires_at {
            return Err(ContractError::InvalidTimeRange);
        }
        if self.expires_at - self.not_before > MAX_TTL_SECONDS {
            return Err(ContractError::LifetimeTooLong);
        }

        Ok(())
    }

    /// Stable, length-prefixed signing preimage for the v1 contract.
    ///
    /// JSON bytes are deliberately not signed because whitespace and key order
    /// are not a stable cryptographic representation.
    ///
    /// # Errors
    ///
    /// Returns the same [`ContractError`] values as [`Self::validate`] and
    /// emits no bytes for an invalid authorization.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(DOMAIN_SEPARATOR);
        for value in [
            self.version.as_str(),
            self.issuer.as_str(),
            self.domain_id.as_str(),
            self.subject_user_id.as_str(),
            self.device_id.as_str(),
            self.target_node_id.as_str(),
            self.ssh_public_key_fingerprint.as_str(),
        ] {
            push_string(&mut output, value);
        }
        push_u32(&mut output, self.principals.len());
        for principal in &self.principals {
            push_string(&mut output, principal);
        }
        push_string(&mut output, &self.policy_id);
        push_string(&mut output, &self.nonce);
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.not_before.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        push_string(&mut output, &self.audience);
        Ok(output)
    }
}

impl SignedIssuanceAuthorizationV1 {
    /// Validates envelope shape and the embedded authorization semantics.
    ///
    /// This does not cryptographically verify the signature.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid authorization, algorithm,
    /// key identifier, or base64url signature representation.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.authorization.validate()?;
        if self.algorithm != SIGNATURE_ALGORITHM {
            return Err(ContractError::InvalidSignatureAlgorithm);
        }
        if !valid_identifier(&self.key_id) {
            return Err(ContractError::InvalidIdentifier("key_id"));
        }
        if !(80..=128).contains(&self.signature.len())
            || !self.signature.bytes().all(is_base64url_character)
        {
            return Err(ContractError::InvalidSignature);
        }
        Ok(())
    }
}

impl NetworkAccessGrantV1 {
    /// Validates identifiers, peer material, audience, nonce, and lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when any signed field violates the v1 rules.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != VERSION {
            return Err(ContractError::UnsupportedVersion);
        }
        for (name, value) in [
            ("issuer", self.issuer.as_str()),
            ("domain_id", self.domain_id.as_str()),
            ("subject_user_id", self.subject_user_id.as_str()),
            ("device_id", self.device_id.as_str()),
            ("target_node_id", self.target_node_id.as_str()),
            ("policy_id", self.policy_id.as_str()),
            ("audience", self.audience.as_str()),
        ] {
            if !valid_identifier(value) {
                return Err(ContractError::InvalidIdentifier(name));
            }
        }
        if self.wireguard_public_key.len() != 44
            || !self.wireguard_public_key.ends_with('=')
            || !self.wireguard_public_key.bytes().all(is_base64_character)
        {
            return Err(ContractError::InvalidWireGuardPublicKey);
        }
        if !matches!(self.mesh_address.parse::<IpAddr>(), Ok(IpAddr::V4(_))) {
            return Err(ContractError::InvalidMeshAddress);
        }
        validate_nonce_and_time(
            self.nonce.as_str(),
            self.issued_at,
            self.not_before,
            self.expires_at,
        )
    }

    /// Builds the stable, domain-separated byte representation to sign.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the grant is invalid.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(NETWORK_GRANT_DOMAIN_SEPARATOR);
        for value in [
            self.version.as_str(),
            self.issuer.as_str(),
            self.domain_id.as_str(),
            self.subject_user_id.as_str(),
            self.device_id.as_str(),
            self.target_node_id.as_str(),
            self.wireguard_public_key.as_str(),
            self.mesh_address.as_str(),
            self.policy_id.as_str(),
            self.nonce.as_str(),
        ] {
            push_string(&mut output, value);
        }
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.not_before.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        push_string(&mut output, &self.audience);
        Ok(output)
    }
}

impl SignedNetworkAccessGrantV1 {
    /// Validates the embedded grant and signature envelope shape.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the grant or envelope is invalid.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.grant.validate()?;
        validate_envelope(&self.algorithm, &self.key_id, &self.signature)
    }
}

impl AccessAuthorizationBundleV1 {
    /// Validates both consumer contracts and their shared decision bindings.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an inner contract is invalid or when the
    /// two signed projections do not describe the same policy decision.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != VERSION {
            return Err(ContractError::UnsupportedVersion);
        }
        self.ssh_authorization.validate()?;
        self.network_grant.validate()?;
        let ssh = &self.ssh_authorization.authorization;
        let network = &self.network_grant.grant;
        if self.decision_id != ssh.nonce || self.decision_id != network.nonce {
            return Err(ContractError::BundleMismatch("decision_id"));
        }
        for (field, left, right) in [
            ("issuer", ssh.issuer.as_str(), network.issuer.as_str()),
            (
                "domain_id",
                ssh.domain_id.as_str(),
                network.domain_id.as_str(),
            ),
            (
                "subject_user_id",
                ssh.subject_user_id.as_str(),
                network.subject_user_id.as_str(),
            ),
            (
                "device_id",
                ssh.device_id.as_str(),
                network.device_id.as_str(),
            ),
            (
                "target_node_id",
                ssh.target_node_id.as_str(),
                network.target_node_id.as_str(),
            ),
            (
                "policy_id",
                ssh.policy_id.as_str(),
                network.policy_id.as_str(),
            ),
        ] {
            if left != right {
                return Err(ContractError::BundleMismatch(field));
            }
        }
        if ssh.issued_at != network.issued_at {
            return Err(ContractError::BundleMismatch("issued_at"));
        }
        if ssh.not_before != network.not_before {
            return Err(ContractError::BundleMismatch("not_before"));
        }
        Ok(())
    }
}

fn validate_nonce_and_time(
    nonce: &str,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
) -> Result<(), ContractError> {
    if !(32..=128).contains(&nonce.len()) || !nonce.bytes().all(is_base64url_character) {
        return Err(ContractError::InvalidNonce);
    }
    if issued_at > not_before || not_before >= expires_at {
        return Err(ContractError::InvalidTimeRange);
    }
    if expires_at - not_before > MAX_TTL_SECONDS {
        return Err(ContractError::LifetimeTooLong);
    }
    Ok(())
}

fn validate_envelope(algorithm: &str, key_id: &str, signature: &str) -> Result<(), ContractError> {
    if algorithm != SIGNATURE_ALGORITHM {
        return Err(ContractError::InvalidSignatureAlgorithm);
    }
    if !valid_identifier(key_id) {
        return Err(ContractError::InvalidIdentifier("key_id"));
    }
    if !(80..=128).contains(&signature.len()) || !signature.bytes().all(is_base64url_character) {
        return Err(ContractError::InvalidSignature);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
}

fn is_base64_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
}

fn is_base64url_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn push_u32(output: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("contract field count fits in u32");
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    push_u32(output, value.len());
    output.extend_from_slice(value.as_bytes());
}
