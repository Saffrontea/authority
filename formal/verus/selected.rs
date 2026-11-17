verus! {
/* PRODUCTION_SELECTED_TYPES */

pub open spec fn empty_selected() -> SelectedProjections {
    SelectedProjections { ssh_issuance: None, ssh_node_install: None, network_grant: None,
        mtls_issuance: None, mtls_node_install: None, tcp_grant: None }
}

pub open spec fn ssh_pair_agrees(common: CommonDecisionClaims, input: Option<(SshProjectionRequest, i64)>,
    issue: Option<IssuanceAuthorizationV1>, install: Option<IssuanceAuthorizationV1>) -> bool {
    match (input, issue, install) {
        (Some((request, ttl)), Some(a), Some(b)) =>
            ssh_agrees(common, request, common.decision_id, credential_audience(), ttl, a)
            && ssh_agrees(common, request, request.terminal_token_hash, node_audience(), ttl, b)
            && ssh_valid(a) && ssh_valid(b),
        (_, None, None) => true,
        _ => false,
    }
}
pub open spec fn mtls_pair_agrees(common: CommonDecisionClaims, input: Option<(MtlsProjectionRequest, i64)>,
    issue: Option<MtlsIssuanceAuthorizationV1>, install: Option<MtlsIssuanceAuthorizationV1>) -> bool {
    match (input, issue, install) {
        (Some((request, ttl)), Some(a), Some(b)) =>
            mtls_agrees(common, request, credential_audience(), ttl, a)
            && mtls_agrees(common, request, node_audience(), ttl, b)
            && mtls_valid(a) && mtls_valid(b),
        (_, None, None) => true,
        _ => false,
    }
}
pub open spec fn network_option_agrees(common: CommonDecisionClaims, input: Option<(NetworkProjectionRequest, i64)>,
    output: Option<NetworkAccessGrantV1>) -> bool {
    match (input, output) {
        (Some((request, ttl)), Some(c)) => network_agrees(common, request, ttl, c) && network_valid(c),
        (_, None) => true,
        _ => false,
    }
}
pub open spec fn tcp_option_agrees(common: CommonDecisionClaims, input: Option<(TcpProjectionRequest, i64)>,
    output: Option<TcpAccessGrantV1>) -> bool {
    match (input, output) {
        (Some((request, ttl)), Some(c)) => tcp_agrees(common, request, ttl, c) && tcp_valid(c),
        (_, None) => true,
        _ => false,
    }
}

pub open spec fn selected_agrees(common: CommonDecisionClaims, inputs: ProjectionInputs,
    mechanisms: Seq<AccessMechanism>, result: SelectedProjections) -> bool {
    result.network_grant.is_some() == mechanisms.contains(AccessMechanism::WireGuardPeer)
        && result.tcp_grant.is_some() == mechanisms.contains(AccessMechanism::TcpAdmission)
        && result.ssh_issuance.is_some() == mechanisms.contains(AccessMechanism::SshCertificate)
        && result.ssh_node_install.is_some() == mechanisms.contains(AccessMechanism::SshCertificate)
        && result.mtls_issuance.is_some() == mechanisms.contains(AccessMechanism::MtlsCertificate)
        && result.mtls_node_install.is_some() == mechanisms.contains(AccessMechanism::MtlsCertificate)
        && network_option_agrees(common, inputs.network, result.network_grant)
        && tcp_option_agrees(common, inputs.tcp, result.tcp_grant)
        && ssh_pair_agrees(common, inputs.ssh, result.ssh_issuance, result.ssh_node_install)
        && mtls_pair_agrees(common, inputs.mtls, result.mtls_issuance, result.mtls_node_install)
}

// The complete production match is checked as a state transition. The source
// adapter checks initialization, Vec iteration and return shape; induction below
// establishes the same ordered fold over the full finite mechanism sequence.
pub proof fn project_step(common: CommonDecisionClaims, inputs: ProjectionInputs,
    prefix: Seq<AccessMechanism>, mechanism: AccessMechanism, previous: SelectedProjections)
    -> (r: Result<SelectedProjections, ProjectionError>)
    requires selected_agrees(common, inputs, prefix, previous),
    ensures match r { Ok(result) => selected_agrees(common, inputs, prefix.push(mechanism), result), Err(_) => true },
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let mut result = previous;
    /* PRODUCTION_SELECTED_LOOP */
    Ok(result)
}

pub proof fn project_prefix(common: CommonDecisionClaims, plan: AccessPlan,
    inputs: ProjectionInputs, length: nat) -> (r: Result<SelectedProjections, ProjectionError>)
    requires length <= plan.mechanisms.len(),
    ensures match r { Ok(result) => selected_agrees(common, inputs, plan.mechanisms.take(length as int), result), Err(_) => true },
    decreases length,
{
    broadcast use vstd::seq_lib::group_seq_properties;
    if length == 0 {
        Ok(empty_selected())
    } else {
        let previous_length = (length - 1) as nat;
        let prefix = plan.mechanisms.take(previous_length as int);
        let previous = propagate!(project_prefix(common, plan, inputs, previous_length));
        let mechanism = plan.mechanisms[(length - 1) as int];
        let result = propagate!(project_step(common, inputs, prefix, mechanism, previous));
        assert(plan.mechanisms.take(length as int) =~=
            plan.mechanisms.take((length - 1) as int).push(mechanism));
        Ok(result)
    }
}

pub proof fn project_plan(common: CommonDecisionClaims, plan: AccessPlan, inputs: ProjectionInputs)
    -> (r: Result<SelectedProjections, ProjectionError>)
    ensures match r { Ok(result) => selected_agrees(common, inputs, plan.mechanisms, result), Err(_) => true },
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let result = propagate!(project_prefix(common, plan, inputs, plan.mechanisms.len()));
    assert(plan.mechanisms.take(plan.mechanisms.len() as int) =~= plan.mechanisms);
    Ok(result)
}

} // verus!
