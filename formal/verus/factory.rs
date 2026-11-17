verus! {
pub enum ScopeError { InvalidLifetime, InvalidRequest }

// Exact checked-constructor body under the same field/collection value views.
// No invariant is required of the candidate solver output.
pub proof fn new_authorized_plan(binding: AccessBinding, issued_at: i64, policy_reference: Seq<char>,
    realization: ScopedPlan, evidence: Seq<char>) -> (r: Result<AuthorizedPlan, ScopeError>)
    ensures match r {
        Ok(plan) => plan_bindings_valid(plan) && plan.binding == binding && plan.issued_at == issued_at
            && plan.policy_reference == policy_reference && plan.realization == realization && plan.evidence == evidence,
        Err(_) => !(issued_at >= 0 && forall|ability: ScopedAbility| realization.abilities.contains(ability) ==>
            ability.binding == binding && ability.validity.not_before == issued_at),
    },
{
    /* PRODUCTION_PLAN_CONSTRUCTOR */
}

// Discharges the consumer's input invariant by composition with construction.
// A failure at either stage produces no contract result; no solver assumption
// or plan_bindings_valid precondition is introduced here.
pub proof fn checked_factory_then_projection(common: CommonDecisionClaims, binding: AccessBinding,
    issued_at: i64, policy_reference: Seq<char>, realization: ScopedPlan, evidence: Seq<char>)
    -> (r: Option<SelectedProjections>)
    ensures match r {
        Some(result) => common_matches(common, binding, issued_at, policy_reference)
            && (exists|inputs: ProjectionInputs| selected_agrees(common, inputs, realization.mechanisms, result))
            && outputs_origin(common, realization.abilities.to_seq(), result),
        None => true,
    },
{
    let plan = match new_authorized_plan(binding, issued_at, policy_reference, realization, evidence) {
        Ok(plan) => plan,
        Err(_) => return None,
    };
    match project_authorized(common, plan) {
        Ok(result) => Some(result),
        Err(_) => None,
    }
}

} // verus!
