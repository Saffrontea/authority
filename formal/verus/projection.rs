// Appended to the generated scope model; the same logical data declarations and
// atom semantics are used on both sides of the field mapping.
verus! {
/* PRODUCTION_PROJECTION_TYPES */

pub uninterp spec fn ip_text(address: u32) -> Seq<char>;
pub uninterp spec fn uuid_text(identity: u128) -> Seq<char>;
pub uninterp spec fn domain_issuer(domain: u128) -> Seq<char>;

pub open spec fn common_matches(common: CommonDecisionClaims, binding: AccessBinding,
    authorized_at: i64, policy_reference: Seq<char>) -> bool {
    /* PRODUCTION_COMMON_MATCHES */
}

pub proof fn common_binding_preserved(common: CommonDecisionClaims, binding: AccessBinding,
    authorized_at: i64, policy_reference: Seq<char>)
    requires common_matches(common, binding, authorized_at, policy_reference),
    ensures
        common.domain_id == uuid_text(binding.domain_id),
        common.subject_user_id == uuid_text(binding.subject_user_id),
        common.device_id == uuid_text(binding.device_id),
        common.target_node_id == uuid_text(binding.target_node_id),
        common.issued_at == authorized_at,
        common.policy_id == policy_reference,
        common.issuer == domain_issuer(binding.domain_id),
{}


pub open spec fn project_scope(scope: AbilityScope) -> ScopeProjection {
    /* PRODUCTION_PROJECT_SCOPE */
}

pub open spec fn material_agrees(scope: AbilityScope, material: ScopeProjection) -> bool {
    match (scope, material) {
        (AbilityScope::MeshMembership { wireguard_public_key, address }, ScopeProjection::Network(request)) =>
            request.wireguard_public_key == wireguard_public_key && request.mesh_address == ip_text(address),
        (AbilityScope::NetworkReachability { .. }, ScopeProjection::None) => true,
        (AbilityScope::SshSession { public_key_fingerprint, principals, terminal_token_hash }, ScopeProjection::Ssh(request)) =>
            request.public_key_fingerprint == public_key_fingerprint && request.terminal_token_hash == terminal_token_hash
                && request.principals.to_set() == principals && request.principals.len() == principals.len()
                && request.principals.no_duplicates(),
        (AbilityScope::ServiceIdentity { client_spki_sha256, identity_uri, service_audience }, ScopeProjection::Mtls(request)) =>
            request.client_spki_sha256 == client_spki_sha256 && request.identity_uri == identity_uri
                && request.service_audience == service_audience,
        (AbilityScope::TcpConnection { source, destination, ports }, ScopeProjection::Tcp(request)) =>
            request.source_address == ip_text(source) && request.destination_address == ip_text(destination)
                && request.destination_ports.to_set() == ports && request.destination_ports.len() == ports.len()
                && request.destination_ports.no_duplicates(),
        _ => false,
    }
}

pub proof fn scope_materialization_refines_authorized_scope(scope: AbilityScope)
    ensures material_agrees(scope, project_scope(scope)),
{
    match scope {
        AbilityScope::SshSession { principals, .. } => {
            principals.lemma_to_seq_to_set_id();
            principals.lemma_to_seq_no_duplicates();
            principals.lemma_to_seq_len();
        },
        AbilityScope::TcpConnection { ports, .. } => {
            ports.lemma_to_seq_to_set_id();
            ports.lemma_to_seq_no_duplicates();
            ports.lemma_to_seq_len();
        },
        _ => {},
    }
}
} // verus!
