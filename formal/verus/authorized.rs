verus! {
// Projection-facing view of the private AuthorizedPlan. Evidence is not read by
// projection. Set enumeration abstracts BTreeSet order without adding effects.
pub struct ScopedPlan { pub mechanisms: Seq<AccessMechanism>, pub abilities: Set<ScopedAbility> }
pub struct AuthorizedPlan {
    pub binding: AccessBinding, pub issued_at: i64, pub policy_reference: Seq<char>,
    pub realization: ScopedPlan,
}
impl AuthorizedPlan {
    pub open spec fn binding(self) -> AccessBinding { self.binding }
    pub open spec fn issued_at(self) -> i64 { self.issued_at }
    pub open spec fn policy_reference(self) -> Seq<char> { self.policy_reference }
    pub open spec fn realization(self) -> ScopedPlan { self.realization }
}

pub open spec fn material_origin(common: CommonDecisionClaims, abilities: Seq<ScopedAbility>,
    material: ScopeProjection, ttl: i64) -> bool {
    exists|i: int| 0 <= i < abilities.len()
        && material_agrees(abilities[i].scope, material)
        && lifetime_spec(common.issued_at, abilities[i].validity.expires_at) == Some(ttl)
}
pub open spec fn inputs_origin(common: CommonDecisionClaims, abilities: Seq<ScopedAbility>, inputs: ProjectionInputs) -> bool {
    (match inputs.network { Some((r, ttl)) => material_origin(common, abilities, ScopeProjection::Network(r), ttl), None => true })
    && (match inputs.tcp { Some((r, ttl)) => material_origin(common, abilities, ScopeProjection::Tcp(r), ttl), None => true })
    && (match inputs.ssh { Some((r, ttl)) => material_origin(common, abilities, ScopeProjection::Ssh(r), ttl), None => true })
    && (match inputs.mtls { Some((r, ttl)) => material_origin(common, abilities, ScopeProjection::Mtls(r), ttl), None => true })
}

pub proof fn gather_step(common: CommonDecisionClaims, prefix: Seq<ScopedAbility>, ability: ScopedAbility,
    previous: ProjectionInputs) -> (r: Result<ProjectionInputs, ProjectionError>)
    requires inputs_origin(common, prefix, previous),
    ensures match r { Ok(inputs) => inputs_origin(common, prefix.push(ability), inputs), Err(_) => true },
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let (mut ssh, mut mtls, mut network, mut tcp) = (previous.ssh, previous.mtls, previous.network, previous.tcp);
    scope_materialization_refines_authorized_scope(ability.scope);
    /* PRODUCTION_GATHER_STEP */
    let inputs = ProjectionInputs { ssh, mtls, network, tcp };
    assert forall|material: ScopeProjection, ttl: i64| material_origin(common, prefix, material, ttl)
        implies material_origin(common, prefix.push(ability), material, ttl) by {
        let i = choose|i: int| 0 <= i < prefix.len() && material_agrees(prefix[i].scope, material)
            && lifetime_spec(common.issued_at, prefix[i].validity.expires_at) == Some(ttl);
        assert(prefix.push(ability)[i] == prefix[i]);
    };
    assert(prefix.push(ability)[prefix.len() as int] == ability);
    assert(lifetime_spec(common.issued_at, ability.validity.expires_at) == Some(ttl));
    assert(material_agrees(ability.scope, project_scope(ability.scope)));
    assert(material_origin(common, prefix.push(ability), project_scope(ability.scope), ttl));
    Ok(inputs)
}

pub proof fn gather_prefix(common: CommonDecisionClaims, abilities: Seq<ScopedAbility>, length: nat)
    -> (r: Result<ProjectionInputs, ProjectionError>)
    requires length <= abilities.len(),
    ensures match r { Ok(inputs) => inputs_origin(common, abilities.take(length as int), inputs), Err(_) => true },
    decreases length,
{
    broadcast use vstd::seq_lib::group_seq_properties;
    if length == 0 {
        Ok(ProjectionInputs { ssh: None, mtls: None, network: None, tcp: None })
    } else {
        let previous_length = (length - 1) as nat;
        let prefix = abilities.take(previous_length as int);
        let previous = propagate!(gather_prefix(common, abilities, previous_length));
        let ability = abilities[(length - 1) as int];
        let result = propagate!(gather_step(common, prefix, ability, previous));
        assert(abilities.take(length as int) =~= prefix.push(ability));
        Ok(result)
    }
}

pub open spec fn plan_bindings_valid(plan: AuthorizedPlan) -> bool {
    plan.issued_at >= 0 && forall|ability: ScopedAbility| plan.realization.abilities.contains(ability) ==>
        ability.binding == plan.binding && ability.validity.not_before == plan.issued_at
}

pub open spec fn network_scope(c: NetworkAccessGrantV1, s: AbilityScope) -> bool {
    match s { AbilityScope::MeshMembership { wireguard_public_key, address } =>
        c.wireguard_public_key == wireguard_public_key && c.mesh_address == ip_text(address), _ => false }
}
pub open spec fn tcp_scope(c: TcpAccessGrantV1, s: AbilityScope) -> bool {
    match s { AbilityScope::TcpConnection { source, destination, ports } =>
        c.source_address == ip_text(source) && c.destination_address == ip_text(destination)
            && c.destination_ports.to_set() == ports && c.destination_ports.no_duplicates(), _ => false }
}
pub open spec fn ssh_scope(c: IssuanceAuthorizationV1, s: AbilityScope) -> bool {
    match s { AbilityScope::SshSession { public_key_fingerprint, principals, .. } =>
        c.ssh_public_key_fingerprint == public_key_fingerprint && c.principals.to_set() == principals
            && c.principals.no_duplicates(), _ => false }
}
pub open spec fn ssh_install_scope(c: IssuanceAuthorizationV1, s: AbilityScope) -> bool {
    ssh_scope(c, s) && match s { AbilityScope::SshSession { terminal_token_hash, .. } => c.nonce == terminal_token_hash, _ => false }
}
pub open spec fn mtls_scope(c: MtlsIssuanceAuthorizationV1, s: AbilityScope) -> bool {
    match s { AbilityScope::ServiceIdentity { client_spki_sha256, identity_uri, service_audience } =>
        c.client_spki_sha256 == client_spki_sha256 && c.identity_uri == identity_uri && c.service_audience == service_audience, _ => false }
}

pub open spec fn temporal_origin(common: CommonDecisionClaims, ability: ScopedAbility,
    start: i64, end: i64) -> bool {
    start == ability.validity.not_before && end == ability.validity.expires_at
        && common.domain_id == uuid_text(ability.binding.domain_id)
        && common.subject_user_id == uuid_text(ability.binding.subject_user_id)
        && common.device_id == uuid_text(ability.binding.device_id)
        && common.target_node_id == uuid_text(ability.binding.target_node_id)
}

pub open spec fn outputs_origin(common: CommonDecisionClaims, abilities: Seq<ScopedAbility>, result: SelectedProjections) -> bool {
    (match result.network_grant { Some(c) => exists|i: int| 0 <= i < abilities.len()
        && network_scope(c, abilities[i].scope) && temporal_origin(common, abilities[i], c.not_before, c.expires_at), None => true })
    && (match result.tcp_grant { Some(c) => exists|i: int| 0 <= i < abilities.len()
        && tcp_scope(c, abilities[i].scope) && temporal_origin(common, abilities[i], c.not_before, c.expires_at), None => true })
    && (match result.ssh_issuance { Some(c) => exists|i: int| 0 <= i < abilities.len()
        && ssh_scope(c, abilities[i].scope) && temporal_origin(common, abilities[i], c.not_before, c.expires_at), None => true })
    && (match result.ssh_node_install { Some(c) => exists|i: int| 0 <= i < abilities.len()
        && ssh_install_scope(c, abilities[i].scope) && temporal_origin(common, abilities[i], c.not_before, c.expires_at), None => true })
    && (match result.mtls_issuance { Some(c) => exists|i: int| 0 <= i < abilities.len()
        && mtls_scope(c, abilities[i].scope) && temporal_origin(common, abilities[i], c.not_before, c.expires_at), None => true })
    && (match result.mtls_node_install { Some(c) => exists|i: int| 0 <= i < abilities.len()
        && mtls_scope(c, abilities[i].scope) && temporal_origin(common, abilities[i], c.not_before, c.expires_at), None => true })
}

pub proof fn expiry_origin(common: CommonDecisionClaims, ability: ScopedAbility, ttl: i64, start: i64, end: i64)
    requires ability.validity.not_before == common.issued_at,
        lifetime_spec(common.issued_at, ability.validity.expires_at) == Some(ttl),
        start == common.issued_at, expiry_spec(common.issued_at, ttl) == Some(end),
    ensures start == ability.validity.not_before, end == ability.validity.expires_at,
{
    expiry_round_trip(common.issued_at, ability.validity.expires_at);
}

pub proof fn final_contracts_have_origin(common: CommonDecisionClaims, plan: AuthorizedPlan,
    abilities: Seq<ScopedAbility>, inputs: ProjectionInputs, result: SelectedProjections)
    requires plan_bindings_valid(plan), abilities.to_set() == plan.realization.abilities,
        common_matches(common, plan.binding, plan.issued_at, plan.policy_reference),
        inputs_origin(common, abilities, inputs), selected_agrees(common, inputs, plan.realization.mechanisms, result),
    ensures outputs_origin(common, abilities, result),
{
    broadcast use vstd::seq_lib::group_seq_properties;
    common_binding_preserved(common, plan.binding, plan.issued_at, plan.policy_reference);
    if let Some(c) = result.network_grant {
        if let Some((request, ttl)) = inputs.network {
            let material = ScopeProjection::Network(request);
            let i = choose|i: int| 0 <= i < abilities.len()
                && material_agrees(abilities[i].scope, material)
                && lifetime_spec(common.issued_at, abilities[i].validity.expires_at) == Some(ttl);
            let ability = abilities[i];
            assert(plan.realization.abilities.contains(ability));
            assert(ability.binding == plan.binding);
            assert(ability.validity.not_before == common.issued_at);
            expiry_origin(common, ability, ttl, c.not_before, c.expires_at);
            assert(network_scope(c, ability.scope));
            assert(temporal_origin(common, ability, c.not_before, c.expires_at));
        } else { assert(false); }
    }
    if let Some(c) = result.tcp_grant {
        if let Some((request, ttl)) = inputs.tcp {
            let material = ScopeProjection::Tcp(request);
            let i = choose|i: int| 0 <= i < abilities.len()
                && material_agrees(abilities[i].scope, material)
                && lifetime_spec(common.issued_at, abilities[i].validity.expires_at) == Some(ttl);
            let ability = abilities[i];
            assert(plan.realization.abilities.contains(ability));
            assert(ability.binding == plan.binding);
            assert(ability.validity.not_before == common.issued_at);
            expiry_origin(common, ability, ttl, c.not_before, c.expires_at);
            assert(tcp_scope(c, ability.scope));
            assert(temporal_origin(common, ability, c.not_before, c.expires_at));
        } else { assert(false); }
    }
    if let Some(c) = result.ssh_issuance {
        if let Some((request, ttl)) = inputs.ssh {
            let material = ScopeProjection::Ssh(request);
            let i = choose|i: int| 0 <= i < abilities.len()
                && material_agrees(abilities[i].scope, material)
                && lifetime_spec(common.issued_at, abilities[i].validity.expires_at) == Some(ttl);
            let ability = abilities[i];
            assert(plan.realization.abilities.contains(ability));
            assert(ability.binding == plan.binding);
            assert(ability.validity.not_before == common.issued_at);
            expiry_origin(common, ability, ttl, c.not_before, c.expires_at);
            assert(ssh_scope(c, ability.scope));
            assert(temporal_origin(common, ability, c.not_before, c.expires_at));
        } else { assert(false); }
    }
    if let Some(c) = result.ssh_node_install {
        if let Some((request, ttl)) = inputs.ssh {
            let material = ScopeProjection::Ssh(request);
            let i = choose|i: int| 0 <= i < abilities.len()
                && material_agrees(abilities[i].scope, material)
                && lifetime_spec(common.issued_at, abilities[i].validity.expires_at) == Some(ttl);
            let ability = abilities[i];
            assert(plan.realization.abilities.contains(ability));
            assert(ability.binding == plan.binding);
            assert(ability.validity.not_before == common.issued_at);
            expiry_origin(common, ability, ttl, c.not_before, c.expires_at);
            assert(ssh_install_scope(c, ability.scope));
            assert(temporal_origin(common, ability, c.not_before, c.expires_at));
        } else { assert(false); }
    }
    if let Some(c) = result.mtls_issuance {
        if let Some((request, ttl)) = inputs.mtls {
            let material = ScopeProjection::Mtls(request);
            let i = choose|i: int| 0 <= i < abilities.len()
                && material_agrees(abilities[i].scope, material)
                && lifetime_spec(common.issued_at, abilities[i].validity.expires_at) == Some(ttl);
            let ability = abilities[i];
            assert(plan.realization.abilities.contains(ability));
            assert(ability.binding == plan.binding);
            assert(ability.validity.not_before == common.issued_at);
            expiry_origin(common, ability, ttl, c.not_before, c.expires_at);
            assert(mtls_scope(c, ability.scope));
            assert(temporal_origin(common, ability, c.not_before, c.expires_at));
        } else { assert(false); }
    }
    if let Some(c) = result.mtls_node_install {
        if let Some((request, ttl)) = inputs.mtls {
            let material = ScopeProjection::Mtls(request);
            let i = choose|i: int| 0 <= i < abilities.len()
                && material_agrees(abilities[i].scope, material)
                && lifetime_spec(common.issued_at, abilities[i].validity.expires_at) == Some(ttl);
            let ability = abilities[i];
            assert(plan.realization.abilities.contains(ability));
            assert(ability.binding == plan.binding);
            assert(ability.validity.not_before == common.issued_at);
            expiry_origin(common, ability, ttl, c.not_before, c.expires_at);
            assert(mtls_scope(c, ability.scope));
            assert(temporal_origin(common, ability, c.not_before, c.expires_at));
        } else { assert(false); }
    }
}

pub proof fn project_authorized(common: CommonDecisionClaims, plan: AuthorizedPlan)
    -> (r: Result<SelectedProjections, ProjectionError>)
    requires plan_bindings_valid(plan),
    ensures match r {
        Ok(result) => common_matches(common, plan.binding, plan.issued_at, plan.policy_reference)
            && (exists|inputs: ProjectionInputs| selected_agrees(common, inputs, plan.realization.mechanisms, result))
            && outputs_origin(common, plan.realization.abilities.to_seq(), result),
        Err(_) => true,
    },
{
    broadcast use vstd::seq_lib::group_seq_properties;
    /* PRODUCTION_AUTHORIZED_GUARD */
    let abilities = plan.realization.abilities.to_seq();
    plan.realization.abilities.lemma_to_seq_to_set_id();
    let inputs = propagate!(gather_prefix(common, abilities, abilities.len()));
    assert(abilities.take(abilities.len() as int) =~= abilities);
    /* PRODUCTION_AUTHORIZED_SELECTION */
    let projected = /* PRODUCTION_AUTHORIZED_CALL */;
    match projected {
        Ok(result) => { final_contracts_have_origin(common, plan, abilities, inputs, result); },
        Err(_) => {},
    }
    projected
}

} // verus!
