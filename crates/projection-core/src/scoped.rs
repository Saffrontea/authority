use authority_policy_core::{
    realization::AccessPlan,
    scoped::{AbilityScope, AuthorizedPlan},
};

use crate::{
    CommonDecisionClaims, MtlsProjectionRequest, NetworkProjectionRequest, ProjectionError,
    ProjectionInputs, SelectedProjections, SshProjectionRequest, TcpProjectionRequest,
    project_plan,
};

/// Projects only the immutable scopes approved by policy evaluation. Caller
/// supplied keys, ports, principals and lifetimes cannot be substituted here.
///
/// # Errors
/// Rejects mismatched subject/device/target/domain, issuer, policy provenance or
/// issuance time, and any invalid resulting adapter contract.
pub fn project_authorized(
    common: &CommonDecisionClaims,
    plan: &AuthorizedPlan,
) -> Result<SelectedProjections, ProjectionError> {
    let binding = plan.binding();
    if common.domain_id != binding.domain_id.to_string()
        || common.subject_user_id != binding.subject_user_id.to_string()
        || common.device_id != binding.device_id.to_string()
        || common.target_node_id != binding.target_node_id.to_string()
        || common.issued_at != plan.issued_at()
        || common.policy_id != plan.policy_reference()
        || common.issuer != authority_contracts_model::protocol::domain_issuer(binding.domain_id)
    {
        return Err(ProjectionError::ScopeMismatch);
    }
    let (mut ssh, mut mtls, mut network, mut tcp) = (None, None, None, None);
    for ability in &plan.realization().abilities {
        let ttl = ability
            .validity
            .expires_at
            .checked_sub(common.issued_at)
            .ok_or(ProjectionError::InvalidLifetime)?;
        match &ability.scope {
            AbilityScope::MeshMembership {
                wireguard_public_key,
                address,
            } => {
                network = Some((
                    NetworkProjectionRequest {
                        wireguard_public_key: wireguard_public_key.clone(),
                        mesh_address: address.to_string(),
                    },
                    ttl,
                ));
            }
            AbilityScope::NetworkReachability { .. } => {}
            AbilityScope::SshSession {
                public_key_fingerprint,
                principals,
                terminal_token_hash,
            } => {
                ssh = Some((
                    SshProjectionRequest {
                        public_key_fingerprint: public_key_fingerprint.clone(),
                        principals: principals.iter().cloned().collect(),
                        terminal_token_hash: terminal_token_hash.clone(),
                    },
                    ttl,
                ));
            }
            AbilityScope::ServiceIdentity {
                client_spki_sha256,
                identity_uri,
                service_audience,
            } => {
                mtls = Some((
                    MtlsProjectionRequest {
                        client_spki_sha256: client_spki_sha256.clone(),
                        identity_uri: identity_uri.clone(),
                        service_audience: service_audience.clone(),
                    },
                    ttl,
                ));
            }
            AbilityScope::TcpConnection {
                source,
                destination,
                ports,
            } => {
                tcp = Some((
                    TcpProjectionRequest {
                        source_address: source.to_string(),
                        destination_address: destination.to_string(),
                        destination_ports: ports.iter().copied().collect(),
                    },
                    ttl,
                ));
            }
        }
    }
    let selection = AccessPlan {
        mechanisms: plan.realization().mechanisms.clone(),
        abilities: plan
            .realization()
            .abilities
            .iter()
            .map(|ability| ability.scope.kind())
            .collect(),
    };
    project_plan(
        common,
        &selection,
        ProjectionInputs {
            ssh: ssh.as_ref().map(|(input, ttl)| (input, *ttl)),
            mtls: mtls.as_ref().map(|(input, ttl)| (input, *ttl)),
            network: network.as_ref().map(|(input, ttl)| (input, *ttl)),
            tcp: tcp.as_ref().map(|(input, ttl)| (input, *ttl)),
        },
    )
}
