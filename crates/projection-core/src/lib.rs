//! Pure projection of one policy decision into protocol adapter contracts.

use authority_contracts_model::protocol::valid_ttl_seconds;
use authority_contracts_model::protocol::{
    CREDENTIAL_ISSUER_AUDIENCE, NETWORK_AGENT_AUDIENCE, NODE_AGENT_AUDIENCE,
};
mod selection;
pub use selection::{ProjectionInputs, SelectedProjections, project_plan};
mod scoped;
pub use scoped::project_authorized;

use authority_contracts_model::{
    ContractError, IssuanceAuthorizationV2, MtlsIssuanceAuthorizationV1, NetworkAccessGrantV1,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonDecisionClaims {
    pub decision_id: String,
    pub issuer: String,
    pub domain_id: String,
    pub subject_user_id: String,
    pub device_id: String,
    pub target_node_id: String,
    pub policy_id: String,
    pub issued_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshProjectionRequest {
    pub public_key_fingerprint: String,
    pub principals: Vec<String>,
    pub terminal_token_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProjectionRequest {
    pub wireguard_public_key: String,
    pub mesh_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsProjectionRequest {
    pub client_spki_sha256: String,
    pub identity_uri: String,
    pub service_audience: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionLifetimes {
    pub ssh_seconds: i64,
    pub network_seconds: i64,
    pub mtls_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionSet {
    pub ssh_issuance: IssuanceAuthorizationV2,
    pub ssh_node_install: IssuanceAuthorizationV2,
    pub network_grant: NetworkAccessGrantV1,
    pub mtls_issuance: MtlsIssuanceAuthorizationV1,
    pub mtls_node_install: MtlsIssuanceAuthorizationV1,
}

#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("projection claims differ from the authorized scope")]
    ScopeMismatch,
    #[error("selected mechanism requires {0} projection input")]
    MissingInput(&'static str),
    #[error("projection lifetime must be between {min} and {max} seconds", min = authority_contracts_model::protocol::MIN_TTL_SECONDS, max = authority_contracts_model::protocol::MAX_TTL_SECONDS)]
    InvalidLifetime,
    #[error(transparent)]
    Contract(#[from] ContractError),
}

// One checked lifetime kernel for every contract constructor. Verified from this
// exact body; even the legacy all-adapter entry point must fail without overflow.
fn projection_expiry(issued_at: i64, ttl_seconds: i64) -> Option<i64> {
    if !valid_ttl_seconds(ttl_seconds) {
        return None;
    }
    issued_at.checked_add(ttl_seconds)
}

/// Projects one decision into adapter-specific unsigned contracts.
///
/// # Errors
///
/// Returns [`ProjectionError`] if a lifetime or resulting contract is invalid.
pub fn project(
    common: &CommonDecisionClaims,
    ssh: &SshProjectionRequest,
    network: &NetworkProjectionRequest,
    mtls: &MtlsProjectionRequest,
    lifetimes: ProjectionLifetimes,
) -> Result<ProjectionSet, ProjectionError> {
    let ssh_issuance = ssh_contract(
        common,
        ssh,
        &common.decision_id,
        CREDENTIAL_ISSUER_AUDIENCE,
        lifetimes.ssh_seconds,
    )?;
    let ssh_node_install = ssh_contract(
        common,
        ssh,
        &ssh.terminal_token_hash,
        NODE_AGENT_AUDIENCE,
        lifetimes.ssh_seconds,
    )?;
    let network_grant = project_network(common, network, lifetimes.network_seconds)?;
    let mtls_issuance = mtls_contract(
        common,
        mtls,
        CREDENTIAL_ISSUER_AUDIENCE,
        lifetimes.mtls_seconds,
    )?;
    let mtls_node_install =
        mtls_contract(common, mtls, NODE_AGENT_AUDIENCE, lifetimes.mtls_seconds)?;
    ssh_issuance.validate()?;
    ssh_node_install.validate()?;
    network_grant.validate()?;
    mtls_issuance.validate()?;
    mtls_node_install.validate()?;
    Ok(ProjectionSet {
        ssh_issuance,
        ssh_node_install,
        network_grant,
        mtls_issuance,
        mtls_node_install,
    })
}

fn ssh_contract(
    common: &CommonDecisionClaims,
    ssh: &SshProjectionRequest,
    nonce: &str,
    audience: &str,
    ttl: i64,
) -> Result<IssuanceAuthorizationV2, ProjectionError> {
    Ok(IssuanceAuthorizationV2 {
        version: authority_contracts_model::protocol::CONTRACT_VERSION_V2.to_owned(),
        issuer: common.issuer.clone(),
        domain_id: common.domain_id.clone(),
        subject_user_id: common.subject_user_id.clone(),
        device_id: common.device_id.clone(),
        target_node_id: common.target_node_id.clone(),
        ssh_public_key_fingerprint: ssh.public_key_fingerprint.clone(),
        principals: ssh.principals.clone(),
        policy_id: common.policy_id.clone(),
        decision_id: common.decision_id.clone(),
        nonce: nonce.to_owned(),
        issued_at: common.issued_at,
        not_before: common.issued_at,
        expires_at: projection_expiry(common.issued_at, ttl)
            .ok_or(ProjectionError::InvalidLifetime)?,
        audience: audience.to_owned(),
    })
}

fn mtls_contract(
    common: &CommonDecisionClaims,
    mtls: &MtlsProjectionRequest,
    audience: &str,
    ttl: i64,
) -> Result<MtlsIssuanceAuthorizationV1, ProjectionError> {
    Ok(MtlsIssuanceAuthorizationV1 {
        version: authority_contracts_model::protocol::CONTRACT_VERSION_V1.to_owned(),
        issuer: common.issuer.clone(),
        domain_id: common.domain_id.clone(),
        subject_user_id: common.subject_user_id.clone(),
        device_id: common.device_id.clone(),
        target_node_id: common.target_node_id.clone(),
        client_spki_sha256: mtls.client_spki_sha256.clone(),
        identity_uri: mtls.identity_uri.clone(),
        service_audience: mtls.service_audience.clone(),
        policy_id: common.policy_id.clone(),
        decision_id: common.decision_id.clone(),
        nonce: format!("{}_mtls_{}", common.decision_id, audience.replace('-', "_")),
        issued_at: common.issued_at,
        not_before: common.issued_at,
        expires_at: projection_expiry(common.issued_at, ttl)
            .ok_or(ProjectionError::InvalidLifetime)?,
        audience: audience.to_owned(),
    })
}

/// TCP is an independently selectable projection. No SSH, CA, or peer key
/// material is needed to derive a TCP grant from an authorized decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpProjectionRequest {
    pub resources: authority_contracts_model::resources::TcpResourcesV1,
}

/// Projects just TCP admission from the shared decision claims.
///
/// # Errors
/// Returns an error for invalid claims, ports, or lifetime.
pub fn project_tcp(
    common: &CommonDecisionClaims,
    tcp: &TcpProjectionRequest,
    ttl_seconds: i64,
) -> Result<authority_contracts_model::TcpAccessGrantV2, ProjectionError> {
    let grant = authority_contracts_model::TcpAccessGrantV2 {
        version: authority_contracts_model::protocol::CONTRACT_VERSION_V2.to_owned(),
        issuer: common.issuer.clone(),
        domain_id: common.domain_id.clone(),
        subject_user_id: common.subject_user_id.clone(),
        device_id: common.device_id.clone(),
        target_node_id: common.target_node_id.clone(),
        policy_id: common.policy_id.clone(),
        decision_id: common.decision_id.clone(),
        resources: tcp.resources.clone(),
        issued_at: common.issued_at,
        not_before: common.issued_at,
        expires_at: projection_expiry(common.issued_at, ttl_seconds)
            .ok_or(ProjectionError::InvalidLifetime)?,
        audience: NETWORK_AGENT_AUDIENCE.to_owned(),
    };
    grant.validate()?;
    Ok(grant)
}

/// Projects only mesh membership; callers select it independently of TCP.
///
/// # Errors
/// Returns an error for invalid claims, peer material, or lifetime.
pub fn project_network(
    common: &CommonDecisionClaims,
    network: &NetworkProjectionRequest,
    ttl_seconds: i64,
) -> Result<NetworkAccessGrantV1, ProjectionError> {
    let grant = NetworkAccessGrantV1 {
        version: authority_contracts_model::protocol::CONTRACT_VERSION_V1.to_owned(),
        issuer: common.issuer.clone(),
        domain_id: common.domain_id.clone(),
        subject_user_id: common.subject_user_id.clone(),
        device_id: common.device_id.clone(),
        target_node_id: common.target_node_id.clone(),
        policy_id: common.policy_id.clone(),
        wireguard_public_key: network.wireguard_public_key.clone(),
        mesh_address: network.mesh_address.clone(),
        nonce: common.decision_id.clone(),
        issued_at: common.issued_at,
        not_before: common.issued_at,
        expires_at: projection_expiry(common.issued_at, ttl_seconds)
            .ok_or(ProjectionError::InvalidLifetime)?,
        audience: NODE_AGENT_AUDIENCE.to_owned(),
    };
    grant.validate()?;
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_common_decision_projects_into_three_protocols() {
        let common = CommonDecisionClaims {
            decision_id: "0123456789abcdef0123456789abcdef".to_owned(),
            issuer: "domain-authority:example".to_owned(),
            domain_id: "domain_example".to_owned(),
            subject_user_id: "user_01".to_owned(),
            device_id: "device_01".to_owned(),
            target_node_id: "node_01".to_owned(),
            policy_id: "policy_01@1".to_owned(),
            issued_at: 1_700_000_000,
        };
        let projected = project(
            &common,
            &SshProjectionRequest {
                public_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_owned(),
                principals: vec!["deploy".to_owned()],
                terminal_token_hash: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
            },
            &NetworkProjectionRequest {
                wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                mesh_address: "10.77.0.1".to_owned(),
            },
            &MtlsProjectionRequest {
                client_spki_sha256: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_owned(),
                identity_uri: "spiffe://authority.example/user/user_01/device/device_01".to_owned(),
                service_audience: "demo-api".to_owned(),
            },
            ProjectionLifetimes {
                ssh_seconds: 60,
                network_seconds: 90,
                mtls_seconds: 120,
            },
        )
        .expect("project decision");

        assert_eq!(projected.ssh_issuance.nonce, common.decision_id);
        assert_eq!(projected.network_grant.nonce, common.decision_id);
        assert_eq!(projected.mtls_issuance.decision_id, common.decision_id);
        assert_ne!(projected.mtls_issuance.nonce, projected.ssh_issuance.nonce);
        assert_eq!(
            projected.ssh_issuance.policy_id,
            projected.mtls_issuance.policy_id
        );
        assert_eq!(
            projected.network_grant.target_node_id,
            projected.mtls_issuance.target_node_id
        );
    }
}
