use authority_contracts_model::{
    IssuanceAuthorizationV1, MtlsIssuanceAuthorizationV1, NetworkAccessGrantV1, TcpAccessGrantV1,
};
use authority_policy_core::realization::{AccessMechanism, AccessPlan};

use crate::{
    CommonDecisionClaims, MtlsProjectionRequest, NetworkProjectionRequest, ProjectionError,
    SshProjectionRequest, TcpProjectionRequest, mtls_contract, project_network, project_tcp,
    ssh_contract,
};

#[derive(Clone, Copy, Default)]
pub struct ProjectionInputs<'a> {
    pub ssh: Option<(&'a SshProjectionRequest, i64)>,
    pub network: Option<(&'a NetworkProjectionRequest, i64)>,
    pub mtls: Option<(&'a MtlsProjectionRequest, i64)>,
    pub tcp: Option<(&'a TcpProjectionRequest, i64)>,
}

#[derive(Debug, Default)]
pub struct SelectedProjections {
    pub ssh_issuance: Option<IssuanceAuthorizationV1>,
    pub ssh_node_install: Option<IssuanceAuthorizationV1>,
    pub network_grant: Option<NetworkAccessGrantV1>,
    pub mtls_issuance: Option<MtlsIssuanceAuthorizationV1>,
    pub mtls_node_install: Option<MtlsIssuanceAuthorizationV1>,
    pub tcp_grant: Option<TcpAccessGrantV1>,
}

fn lifetime(common: &CommonDecisionClaims, seconds: i64) -> Result<(), ProjectionError> {
    if !(1..=600).contains(&seconds) || common.issued_at.checked_add(seconds).is_none() {
        return Err(ProjectionError::InvalidLifetime);
    }
    Ok(())
}

/// Materializes exactly the mechanisms selected by the policy planner.
///
/// The caller must supply an authorized plan and already scope-checked inputs.
/// This function does not perform policy evaluation or expand its authority.
/// Unselected adapters need no key material and emit no contracts.
///
/// # Errors
/// Returns an error if any selected adapter lacks input or produces an invalid
/// contract. Partial results are never returned.
pub fn project_plan(
    common: &CommonDecisionClaims,
    plan: &AccessPlan,
    inputs: ProjectionInputs<'_>,
) -> Result<SelectedProjections, ProjectionError> {
    let mut result = SelectedProjections::default();
    for mechanism in &plan.mechanisms {
        match mechanism {
            AccessMechanism::NetworkRoute => {}
            AccessMechanism::WireGuardPeer => {
                let (request, ttl) = inputs
                    .network
                    .ok_or(ProjectionError::MissingInput("network"))?;
                result.network_grant = Some(project_network(common, request, ttl)?);
            }
            AccessMechanism::TcpAdmission => {
                let (request, ttl) = inputs.tcp.ok_or(ProjectionError::MissingInput("tcp"))?;
                result.tcp_grant = Some(project_tcp(common, request, ttl)?);
            }
            AccessMechanism::SshCertificate => {
                let (request, ttl) = inputs.ssh.ok_or(ProjectionError::MissingInput("ssh"))?;
                lifetime(common, ttl)?;
                let issuance = ssh_contract(
                    common,
                    request,
                    &common.decision_id,
                    "credential-issuer",
                    ttl,
                );
                let install = ssh_contract(
                    common,
                    request,
                    &request.terminal_token_hash,
                    "node-agent",
                    ttl,
                );
                issuance.validate()?;
                install.validate()?;
                result.ssh_issuance = Some(issuance);
                result.ssh_node_install = Some(install);
            }
            AccessMechanism::MtlsCertificate => {
                let (request, ttl) = inputs.mtls.ok_or(ProjectionError::MissingInput("mtls"))?;
                lifetime(common, ttl)?;
                let issuance = mtls_contract(common, request, "credential-issuer", ttl);
                let install = mtls_contract(common, request, "node-agent", ttl);
                issuance.validate()?;
                install.validate()?;
                result.mtls_issuance = Some(issuance);
                result.mtls_node_install = Some(install);
            }
        }
    }
    Ok(result)
}
