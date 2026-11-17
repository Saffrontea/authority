#[allow(unused_macros)]
macro_rules! propagate {
    ($expression:expr) => { match $expression { Ok(value) => value, Err(cause) => return Err(cause) } };
}
#[allow(unused_macros)]
macro_rules! require_some {
    ($expression:expr, $cause:expr) => { match $expression { Some(value) => value, None => return Err($cause) } };
}

verus! {
/* PRODUCTION_CONTRACT_TYPES */
pub enum ProjectionError { InvalidLifetime, MissingInput(Seq<char>), ScopeMismatch, Contract }

pub open spec fn version_v1() -> Seq<char> { /* CONTRACT_VERSION_V1 */ }
pub open spec fn credential_audience() -> Seq<char> { /* CREDENTIAL_ISSUER_AUDIENCE */ }
pub open spec fn node_audience() -> Seq<char> { /* NODE_AGENT_AUDIENCE */ }
pub open spec fn network_audience() -> Seq<char> { /* NETWORK_AGENT_AUDIENCE */ }
pub uninterp spec fn mtls_nonce(decision: Seq<char>, audience: Seq<char>) -> Seq<char>;

// Opaque validators: no assumption that validation succeeds, and no validation
// fact is needed to establish consistency of a successfully returned contract.
pub uninterp spec fn ssh_valid(c: IssuanceAuthorizationV1) -> bool;
pub uninterp spec fn mtls_valid(c: MtlsIssuanceAuthorizationV1) -> bool;
pub uninterp spec fn network_valid(c: NetworkAccessGrantV1) -> bool;
pub uninterp spec fn tcp_valid(c: TcpAccessGrantV1) -> bool;

impl IssuanceAuthorizationV1 {
    pub proof fn validate(self) -> (r: Result<(), ProjectionError>)
        ensures r.is_ok() == ssh_valid(self),
    { if ssh_valid(self) { Ok(()) } else { Err(ProjectionError::Contract) } }
}
impl MtlsIssuanceAuthorizationV1 {
    pub proof fn validate(self) -> (r: Result<(), ProjectionError>)
        ensures r.is_ok() == mtls_valid(self),
    { if mtls_valid(self) { Ok(()) } else { Err(ProjectionError::Contract) } }
}
impl NetworkAccessGrantV1 {
    pub proof fn validate(self) -> (r: Result<(), ProjectionError>)
        ensures r.is_ok() == network_valid(self),
    { if network_valid(self) { Ok(()) } else { Err(ProjectionError::Contract) } }
}
impl TcpAccessGrantV1 {
    pub proof fn validate(self) -> (r: Result<(), ProjectionError>)
        ensures r.is_ok() == tcp_valid(self),
    { if tcp_valid(self) { Ok(()) } else { Err(ProjectionError::Contract) } }
}

// Independent common-binding specification; each contract is viewed through
// the same required identity, policy provenance and validity fields.
pub struct BindingView {
    pub version: Seq<char>, pub issuer: Seq<char>, pub domain: Seq<char>,
    pub user: Seq<char>, pub device: Seq<char>, pub target: Seq<char>, pub policy: Seq<char>,
    pub issued_at: i64, pub not_before: i64, pub expires_at: i64,
}
pub open spec fn binding_agrees(v: BindingView, common: CommonDecisionClaims, ttl: i64) -> bool {
    v.version == version_v1() && v.issuer == common.issuer && v.domain == common.domain_id
        && v.user == common.subject_user_id && v.device == common.device_id
        && v.target == common.target_node_id && v.policy == common.policy_id
        && v.issued_at == common.issued_at && v.not_before == common.issued_at
        && expiry_spec(common.issued_at, ttl) == Some(v.expires_at)
}

pub open spec fn ssh_binding(c: IssuanceAuthorizationV1) -> BindingView {
    BindingView { version: c.version, issuer: c.issuer, domain: c.domain_id, user: c.subject_user_id,
        device: c.device_id, target: c.target_node_id, policy: c.policy_id,
        issued_at: c.issued_at, not_before: c.not_before, expires_at: c.expires_at }
}
pub open spec fn mtls_binding(c: MtlsIssuanceAuthorizationV1) -> BindingView {
    BindingView { version: c.version, issuer: c.issuer, domain: c.domain_id, user: c.subject_user_id,
        device: c.device_id, target: c.target_node_id, policy: c.policy_id,
        issued_at: c.issued_at, not_before: c.not_before, expires_at: c.expires_at }
}
pub open spec fn network_binding(c: NetworkAccessGrantV1) -> BindingView {
    BindingView { version: c.version, issuer: c.issuer, domain: c.domain_id, user: c.subject_user_id,
        device: c.device_id, target: c.target_node_id, policy: c.policy_id,
        issued_at: c.issued_at, not_before: c.not_before, expires_at: c.expires_at }
}
pub open spec fn tcp_binding(c: TcpAccessGrantV1) -> BindingView {
    BindingView { version: c.version, issuer: c.issuer, domain: c.domain_id, user: c.subject_user_id,
        device: c.device_id, target: c.target_node_id, policy: c.policy_id,
        issued_at: c.issued_at, not_before: c.not_before, expires_at: c.expires_at }
}

pub open spec fn ssh_agrees(common: CommonDecisionClaims, request: SshProjectionRequest,
    nonce: Seq<char>, audience: Seq<char>, ttl: i64, c: IssuanceAuthorizationV1) -> bool {
    binding_agrees(ssh_binding(c), common, ttl) && c.ssh_public_key_fingerprint == request.public_key_fingerprint
        && c.principals == request.principals && c.nonce == nonce && c.audience == audience
}
pub open spec fn mtls_agrees(common: CommonDecisionClaims, request: MtlsProjectionRequest,
    audience: Seq<char>, ttl: i64, c: MtlsIssuanceAuthorizationV1) -> bool {
    binding_agrees(mtls_binding(c), common, ttl) && c.client_spki_sha256 == request.client_spki_sha256
        && c.identity_uri == request.identity_uri && c.service_audience == request.service_audience
        && c.decision_id == common.decision_id && c.nonce == mtls_nonce(common.decision_id, audience)
        && c.audience == audience
}
pub open spec fn network_agrees(common: CommonDecisionClaims, request: NetworkProjectionRequest,
    ttl: i64, c: NetworkAccessGrantV1) -> bool {
    binding_agrees(network_binding(c), common, ttl) && c.wireguard_public_key == request.wireguard_public_key
        && c.mesh_address == request.mesh_address && c.nonce == common.decision_id && c.audience == node_audience()
}
pub open spec fn tcp_agrees(common: CommonDecisionClaims, request: TcpProjectionRequest,
    ttl: i64, c: TcpAccessGrantV1) -> bool {
    binding_agrees(tcp_binding(c), common, ttl) && c.source_address == request.source_address
        && c.destination_address == request.destination_address && c.destination_ports == request.destination_ports
        && c.decision_id == common.decision_id && c.audience == network_audience()
}

pub proof fn ssh_contract(common: CommonDecisionClaims, ssh: SshProjectionRequest,
    nonce: Seq<char>, audience: Seq<char>, ttl: i64) -> (r: Result<IssuanceAuthorizationV1, ProjectionError>)
    ensures match r { Ok(c) => ssh_agrees(common, ssh, nonce, audience, ttl, c), Err(_) => true },
{ /* PRODUCTION_SSH_CONTRACT */ }

pub proof fn mtls_contract(common: CommonDecisionClaims, mtls: MtlsProjectionRequest,
    audience: Seq<char>, ttl: i64) -> (r: Result<MtlsIssuanceAuthorizationV1, ProjectionError>)
    ensures match r { Ok(c) => mtls_agrees(common, mtls, audience, ttl, c), Err(_) => true },
{ /* PRODUCTION_MTLS_CONTRACT */ }

pub proof fn project_network(common: CommonDecisionClaims, network: NetworkProjectionRequest,
    ttl_seconds: i64) -> (r: Result<NetworkAccessGrantV1, ProjectionError>)
    ensures match r { Ok(c) => network_agrees(common, network, ttl_seconds, c) && network_valid(c), Err(_) => true },
{ /* PRODUCTION_PROJECT_NETWORK */ }

pub proof fn project_tcp(common: CommonDecisionClaims, tcp: TcpProjectionRequest,
    ttl_seconds: i64) -> (r: Result<TcpAccessGrantV1, ProjectionError>)
    ensures match r { Ok(c) => tcp_agrees(common, tcp, ttl_seconds, c) && tcp_valid(c), Err(_) => true },
{ /* PRODUCTION_PROJECT_TCP */ }

} // verus!
