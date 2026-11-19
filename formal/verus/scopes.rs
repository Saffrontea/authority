use vstd::prelude::*;

verus! {

/* PRODUCTION_TYPES */
pub const MAX_TCP_PORTS: usize = /* MAX_TCP_PORTS */;

impl Validity {
    pub open spec fn contains(self, other: Self) -> bool {
        /* PRODUCTION_VALIDITY */
    }
}
impl AbilityScope {
    pub open spec fn kind(self) -> Ability {
        /* PRODUCTION_SCOPE_KIND */
    }
    pub open spec fn contains(self, requested: Self) -> bool {
        /* PRODUCTION_SCOPE_CONTAINS */
    }
}
impl ScopedAbility {
    pub open spec fn contains(self, requested: Self) -> bool {
        /* PRODUCTION_SCOPED_CONTAINS */
    }
}

// A single exercise of authority, independent of the production containment
// predicate: one peer, route, SSH principal, service identity or TCP port.
pub enum Atom {
    Peer { key: Seq<char>, address: u32 },
    RouteInstalled { source: u32, destination: u32 },
    CredentialSsh { key: Seq<char>, principal: Seq<char>, token: Seq<char> },
    CredentialMtls { key: Seq<char>, uri: Seq<char>, audience: Seq<char> },
    AdmissionTcp { source: u32, destination: u32, port: u16 },
    Route { source: u32, destination: u32 },
    Ssh { key: Seq<char>, principal: Seq<char>, token: Seq<char> },
    Identity { key: Seq<char>, uri: Seq<char>, audience: Seq<char> },
    Tcp { source: u32, destination: u32, port: u16 },
}

pub open spec fn allows(scope: AbilityScope, atom: Atom) -> bool {
    match (scope, atom) {
        (AbilityScope::MeshMembership { wireguard_public_key, address }, Atom::Peer { key, address: at }) =>
            wireguard_public_key == key && address == at,
        (AbilityScope::NetworkReachability { source, destination }, Atom::Route { source: from, destination: to }) =>
            source == from && destination == to,

        (AbilityScope::NetworkRouteAuthorization { source, destination }, Atom::RouteInstalled { source: from, destination: to }) =>
            source == from && destination == to,
        (AbilityScope::SshSession { public_key_fingerprint, principals, terminal_token_hash },
            Atom::Ssh { key, principal, token }) =>
            public_key_fingerprint == key && terminal_token_hash == token && principals.contains(principal),

        (AbilityScope::SshCredential { public_key_fingerprint, principals, terminal_token_hash },
            Atom::CredentialSsh { key, principal, token }) =>
            public_key_fingerprint == key && terminal_token_hash == token && principals.contains(principal),
        (AbilityScope::ServiceIdentity { client_spki_sha256, identity_uri, service_audience },
            Atom::Identity { key, uri, audience }) =>
            client_spki_sha256 == key && identity_uri == uri && service_audience == audience,

        (AbilityScope::MtlsCredential { client_spki_sha256, identity_uri, service_audience },
            Atom::CredentialMtls { key, uri, audience }) =>
            client_spki_sha256 == key && identity_uri == uri && service_audience == audience,
        (AbilityScope::TcpConnection { source, destination, ports }, Atom::Tcp { source: from, destination: to, port }) =>
            source == from && destination == to && ports.contains(port),

        (AbilityScope::TcpAdmission { source, destination, ports }, Atom::AdmissionTcp { source: from, destination: to, port }) =>
            source == from && destination == to && ports.contains(port),
        _ => false,
    }
}

pub open spec fn valid_request(scope: AbilityScope) -> bool {
    match scope {
        AbilityScope::SshCredential { principals, .. } | AbilityScope::SshSession { principals, .. } => principals.len() > 0
            && forall|principal: Seq<char>| principals.contains(principal) ==> principal.len() > 0,
        AbilityScope::TcpAdmission { ports, .. } | AbilityScope::TcpConnection { ports, .. } => ports.len() > 0
            && ports.len() <= MAX_TCP_PORTS && !ports.contains(0),
        _ => true,
    }
}

pub proof fn scope_nonexpansion(grant: AbilityScope, requested: AbilityScope, atom: Atom)
    requires grant.contains(requested), allows(requested, atom),
    ensures allows(grant, atom),
{
    match (grant, requested) {
        (AbilityScope::SshSession { .. }, AbilityScope::SshSession { .. }) => {},
        (AbilityScope::SshCredential { .. }, AbilityScope::SshCredential { .. }) => {},
        (AbilityScope::TcpConnection { .. }, AbilityScope::TcpConnection { .. }) => {},
        (AbilityScope::TcpAdmission { .. }, AbilityScope::TcpAdmission { .. }) => {},
        _ => {},
    }
}

pub proof fn scope_kind_preserved(grant: AbilityScope, requested: AbilityScope)
    requires grant.contains(requested),
    ensures grant.kind() == requested.kind(), valid_request(requested),
{
    match (grant, requested) {
        (AbilityScope::SshSession { .. }, AbilityScope::SshSession { .. }) => {},
        (AbilityScope::SshCredential { .. }, AbilityScope::SshCredential { .. }) => {},
        (AbilityScope::TcpConnection { .. }, AbilityScope::TcpConnection { .. }) => {},
        (AbilityScope::TcpAdmission { .. }, AbilityScope::TcpAdmission { .. }) => {},
        _ => {},
    }
}

pub proof fn scope_transitive(a: AbilityScope, b: AbilityScope, c: AbilityScope)
    requires a.contains(b), b.contains(c),
    ensures a.contains(c),
{
    scope_kind_preserved(a, b);
    scope_kind_preserved(b, c);
    match (a, b, c) {
        (AbilityScope::SshSession { .. }, AbilityScope::SshSession { .. }, AbilityScope::SshSession { .. }) => {},
        (AbilityScope::SshCredential { .. }, AbilityScope::SshCredential { .. }, AbilityScope::SshCredential { .. }) => {},
        (AbilityScope::TcpConnection { .. }, AbilityScope::TcpConnection { .. }, AbilityScope::TcpConnection { .. }) => {},
        (AbilityScope::TcpAdmission { .. }, AbilityScope::TcpAdmission { .. }, AbilityScope::TcpAdmission { .. }) => {},
        _ => {},
    }
}

pub open spec fn allows_at(ability: ScopedAbility, binding: AccessBinding, at: int, atom: Atom) -> bool {
    ability.binding == binding && ability.validity.not_before <= at < ability.validity.expires_at
        && allows(ability.scope, atom)
}

pub proof fn scoped_authority_nonexpansion(grant: ScopedAbility, requested: ScopedAbility,
    binding: AccessBinding, at: int, atom: Atom)
    requires grant.contains(requested), allows_at(requested, binding, at, atom),
    ensures allows_at(grant, binding, at, atom),
{
    scope_nonexpansion(grant.scope, requested.scope, atom);
}

pub proof fn scoped_transitive(a: ScopedAbility, b: ScopedAbility, c: ScopedAbility)
    requires a.contains(b), b.contains(c),
    ensures a.contains(c),
{
    scope_transitive(a.scope, b.scope, c.scope);
}

pub proof fn scoped_binding_and_ttl(grant: ScopedAbility, requested: ScopedAbility)
    requires grant.contains(requested),
    ensures
        grant.binding.domain_id == requested.binding.domain_id,
        grant.binding.subject_user_id == requested.binding.subject_user_id,
        grant.binding.device_id == requested.binding.device_id,
        grant.binding.target_node_id == requested.binding.target_node_id,
        requested.validity.not_before >= 0,
        requested.validity.not_before < requested.validity.expires_at,
        requested.validity.expires_at as int - requested.validity.not_before as int
            <= grant.validity.expires_at as int - grant.validity.not_before as int,
{}

} // verus!
