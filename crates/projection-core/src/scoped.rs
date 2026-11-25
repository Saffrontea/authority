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
        let ttl = authority_contracts_model::protocol::lifetime_seconds(
            common.issued_at,
            ability.validity.expires_at,
        )
        .ok_or(ProjectionError::InvalidLifetime)?;
        match project_scope(&ability.scope) {
            ScopeProjection::None => {}
            ScopeProjection::Network(request) => network = Some((request, ttl)),
            ScopeProjection::Ssh(request) => ssh = Some((request, ttl)),
            ScopeProjection::Mtls(request) => mtls = Some((request, ttl)),
            ScopeProjection::Tcp(request) => tcp = Some((request, ttl)),
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

// The only conversion from an approved ability to protocol request material.
// Keep this pure: lifetime validation and mechanism selection happen in the
// caller, while these fields must come solely from the immutable approved scope.
enum ScopeProjection {
    None,
    Network(NetworkProjectionRequest),
    Ssh(SshProjectionRequest),
    Mtls(MtlsProjectionRequest),
    Tcp(TcpProjectionRequest),
}

fn project_scope(scope: &AbilityScope) -> ScopeProjection {
    match scope {
        AbilityScope::MeshMembership {
            wireguard_public_key,
            address,
        } => ScopeProjection::Network(NetworkProjectionRequest {
            wireguard_public_key: wireguard_public_key.clone(),
            mesh_address: address.to_string(),
        }),
        AbilityScope::NetworkReachability { .. }
        | AbilityScope::NetworkRouteAuthorization { .. }
        | AbilityScope::SshSession { .. }
        | AbilityScope::ServiceIdentity { .. }
        | AbilityScope::TcpConnection { .. } => ScopeProjection::None,
        AbilityScope::SshCredential {
            public_key_fingerprint,
            principals,
            terminal_token_hash,
        } => ScopeProjection::Ssh(SshProjectionRequest {
            public_key_fingerprint: public_key_fingerprint.clone(),
            principals: principals.iter().cloned().collect(),
            terminal_token_hash: terminal_token_hash.clone(),
        }),
        AbilityScope::MtlsCredential {
            client_spki_sha256,
            identity_uri,
            service_audience,
        } => ScopeProjection::Mtls(MtlsProjectionRequest {
            client_spki_sha256: client_spki_sha256.clone(),
            identity_uri: identity_uri.clone(),
            service_audience: service_audience.clone(),
        }),
        AbilityScope::TcpAdmission {
            source,
            destination,
            ports,
        } => ScopeProjection::Tcp(TcpProjectionRequest {
            resources: authority_contracts_model::resources::TcpResourcesV1 {
                source_addresses: source.clone(),
                destination_addresses: destination.clone(),
                destination_ports: ports.clone(),
            },
        }),
    }
}
