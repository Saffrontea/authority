//! Selection between trusted deployment implementations and durable evidence.
//!
//! Automatic selection never treats client assertions as route availability.
//! Existing-route plans reuse an externally provided transport; they do not grant
//! mesh membership. `WireGuard` plans explicitly authorize and project that membership.

use authority_contracts_model::protocol::valid_ttl_seconds;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use authority_planning_core::{Model, Plan};
use serde::{Deserialize, Serialize};

use crate::{
    AccessDecision, AccessRequest, DenialReason, Outcome, PolicyRef, PolicySnapshot, Route,
    realization::{Ability, AccessMechanism},
    scoped::{
        AccessBinding, AuthorizedPlan, LifetimeLimits, NetworkResources, PolicyScope,
        RequestedAccess, ScopeError, ScopedAbility, binding, evaluate_scoped,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "route",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RouteChoice {
    Exact(Route),
    Automatic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateId {
    ExistingRoute,
    #[serde(rename = "wireguard_mesh")]
    WireGuardMesh,
}

impl CandidateId {
    const fn route(self) -> Route {
        match self {
            Self::ExistingRoute => Route::Direct,
            Self::WireGuardMesh => Route::MeshRequired,
        }
    }

    const fn from_route(route: Route) -> Self {
        match route {
            Route::Direct => Self::ExistingRoute,
            Route::MeshRequired => Self::WireGuardMesh,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingRouteAvailability {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub registered_wireguard_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAvailability {
    /// Trusted deployment facts, matched to this request's concrete resources.
    pub existing_route: Option<ExistingRouteAvailability>,
    pub wireguard_target: Option<Ipv4Addr>,
}

#[derive(Debug, Clone)]
pub struct SelectionOptions {
    pub choice: RouteChoice,
    pub availability: DeploymentAvailability,
}

impl SelectionOptions {
    #[must_use]
    pub const fn exact(route: Route) -> Self {
        Self {
            choice: RouteChoice::Exact(route),
            availability: DeploymentAvailability {
                existing_route: None,
                wireguard_target: None,
            },
        }
    }

    fn candidates(&self, resources: &NetworkResources) -> Vec<(CandidateId, bool)> {
        match self.choice {
            // An exact request retains the existing explicit route assumption.
            RouteChoice::Exact(route) => vec![(CandidateId::from_route(route), true)],
            RouteChoice::Automatic => vec![
                (
                    CandidateId::ExistingRoute,
                    self.availability
                        .existing_route
                        .as_ref()
                        .is_some_and(|route| {
                            route.source == resources.source_address
                                && route.destination == resources.target_address
                                && route.registered_wireguard_key
                                    == resources.registered_wireguard_key
                        }),
                ),
                (
                    CandidateId::WireGuardMesh,
                    self.availability.wireguard_target == Some(resources.target_address),
                ),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateResult {
    Authorized {
        mechanism_count: usize,
    },
    Rejected {
        reason: String,
        capability: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvaluation {
    pub candidate: CandidateId,
    pub result: CandidateResult,
}

impl CandidateEvaluation {
    fn rejected(candidate: CandidateId, error: &ScopeError) -> Self {
        Self {
            candidate,
            result: CandidateResult::Rejected {
                reason: error.code().to_owned(),
                capability: error.capability().map(|cap| cap.as_str().to_owned()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbilityEvidence {
    pub ability: ScopedAbility,
    pub permitted: ScopedAbility,
    pub policy: PolicyRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepEvidence {
    pub mechanism: AccessMechanism,
    /// Indices into PlanEvidence.abilities, in executable step order.
    pub requires: Vec<usize>,
    pub provides: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEvidence {
    pub abilities: Vec<AbilityEvidence>,
    pub goals: Vec<usize>,
    pub steps: Vec<StepEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derivations: Vec<DerivedEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedEvidence {
    pub after_mechanisms: usize,
    pub requires: Vec<usize>,
    pub provides: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningEvidence {
    pub version: u8,
    pub binding: AccessBinding,
    pub evaluated_at: i64,
    pub outcomes: BTreeSet<Outcome>,
    pub route_choice: RouteChoice,
    pub resources: Option<NetworkResources>,
    pub deployment: Option<DeploymentAvailability>,
    pub selection_rule: String,
    pub candidates: Vec<CandidateEvaluation>,
    pub selected: Option<CandidateId>,
    pub plan: Option<PlanEvidence>,
}

impl PlanningEvidence {
    /// Checks the recorded graph, scope containment and selection rule. This is
    /// evidence replay, not authorization against current policy or live routing.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        if ![
            authority_contracts_model::protocol::PLANNING_EVIDENCE_VERSION_V1,
            authority_contracts_model::protocol::PLANNING_EVIDENCE_VERSION_V2,
        ]
        .contains(&self.version)
            || self.evaluated_at < 0
            || self.outcomes.is_empty()
            || self.selection_rule != authority_contracts_model::protocol::PLAN_SELECTION_RULE_V1
        {
            return false;
        }
        if !self.availability_consistent() {
            return false;
        }
        let expected = match self.route_choice {
            RouteChoice::Exact(route) => vec![CandidateId::from_route(route)],
            RouteChoice::Automatic => vec![CandidateId::ExistingRoute, CandidateId::WireGuardMesh],
        };
        if self
            .candidates
            .iter()
            .map(|candidate| candidate.candidate)
            .collect::<Vec<_>>()
            != expected
        {
            return false;
        }
        let mut authorized = Vec::new();
        for evaluation in &self.candidates {
            match &evaluation.result {
                CandidateResult::Authorized { mechanism_count } => {
                    if !(1..=authority_contracts_model::protocol::MAX_PLAN_MECHANISMS_V1)
                        .contains(mechanism_count)
                    {
                        return false;
                    }
                    authorized.push((*mechanism_count, evaluation.candidate));
                }
                CandidateResult::Rejected { reason, capability } => {
                    if reason.is_empty()
                        || capability.as_ref().is_some_and(|capability| {
                            !crate::realization::all_abilities()
                                .iter()
                                .any(|ability| ability.permission().as_str() == capability)
                        })
                    {
                        return false;
                    }
                }
            }
        }
        match (self.selected, &self.plan) {
            (None, None) => authorized.is_empty(),
            (Some(selected), Some(plan)) => {
                authorized.into_iter().min() == Some((plan.steps.len(), selected))
                    && self.resources.as_ref().is_some_and(|resources| {
                        plan.consistent(
                            self.binding,
                            self.evaluated_at,
                            selected,
                            &self.outcomes,
                            resources,
                            self.version,
                        )
                    })
            }
            _ => false,
        }
    }

    fn availability_consistent(&self) -> bool {
        if self.selected.is_some() && self.resources.is_none() {
            return false;
        }
        match self.route_choice {
            RouteChoice::Exact(_) => self.deployment.is_none(),
            RouteChoice::Automatic => {
                let Some(deployment) = &self.deployment else {
                    return false;
                };
                let Some(resources) = &self.resources else {
                    return self.selected.is_none();
                };
                let options = SelectionOptions {
                    choice: self.route_choice,
                    availability: deployment.clone(),
                };
                options.candidates(resources).iter().zip(&self.candidates).all(|((id, available), evaluation)| {
                    *id == evaluation.candidate && (*available || matches!(&evaluation.result,
                        CandidateResult::Rejected { reason, .. } if reason == "no_available_implementation"))
                })
            }
        }
    }

    fn base(request: &AccessRequest, choice: RouteChoice) -> Self {
        Self {
            version: authority_contracts_model::protocol::PLANNING_EVIDENCE_VERSION_V2,
            binding: binding(request),
            evaluated_at: request.evaluated_at,
            outcomes: request.intent.outcomes.clone(),
            route_choice: choice,
            resources: None,
            deployment: None,
            selection_rule: authority_contracts_model::protocol::PLAN_SELECTION_RULE_V1.to_owned(),
            candidates: Vec::new(),
            selected: None,
            plan: None,
        }
    }

    pub(crate) fn authorized(
        request: &AccessRequest,
        plan: PlanEvidence,
        resources: &NetworkResources,
    ) -> Self {
        let candidate = CandidateId::from_route(request.intent.route);
        Self {
            candidates: vec![CandidateEvaluation {
                candidate,
                result: CandidateResult::Authorized {
                    mechanism_count: plan.steps.len(),
                },
            }],
            selected: Some(candidate),
            resources: Some(resources.clone()),
            plan: Some(plan),
            ..Self::base(request, RouteChoice::Exact(request.intent.route))
        }
    }
}

impl PlanEvidence {
    fn consistent(
        &self,
        binding: AccessBinding,
        evaluated_at: i64,
        selected: CandidateId,
        outcomes: &BTreeSet<Outcome>,
        resources: &NetworkResources,
        version: u8,
    ) -> bool {
        let mut kinds = BTreeSet::new();
        for record in &self.abilities {
            if record.ability.binding != binding
                || record.ability.validity.not_before != evaluated_at
                || !record.permitted.contains(&record.ability)
                || !scope_matches_resources(&record.ability.scope, resources, binding)
                || !scope_matches_resources(&record.permitted.scope, resources, binding)
                || record.policy.revision < 1
                || !kinds.insert(record.ability.scope.kind())
                || !record
                    .ability
                    .validity
                    .expires_at
                    .checked_sub(evaluated_at)
                    .is_some_and(valid_ttl_seconds)
            {
                return false;
            }
        }
        let index_kinds = |indices: &[usize]| -> Option<BTreeSet<Ability>> {
            if indices.iter().copied().collect::<BTreeSet<_>>().len() != indices.len() {
                return None;
            }
            indices
                .iter()
                .map(|index| {
                    self.abilities
                        .get(*index)
                        .map(|record| record.ability.scope.kind())
                })
                .collect()
        };
        let goals = outcomes
            .iter()
            .map(|outcome| match outcome {
                Outcome::Ssh => Ability::SshSession,
                Outcome::NetworkReachability => Ability::NetworkReachability,
                Outcome::MtlsService => Ability::ServiceIdentity,
                Outcome::TcpConnect => Ability::TcpConnection,
            })
            .collect();
        if index_kinds(&self.goals) != Some(goals) {
            return false;
        }
        if version == authority_contracts_model::protocol::PLANNING_EVIDENCE_VERSION_V2 {
            return self.consistent_derived(binding, evaluated_at, selected, outcomes, resources);
        }
        if !self.derivations.is_empty() || !resources.environment.is_empty() {
            return false;
        }
        let model = crate::realization::legacy_catalog(selected.route());
        let mut executed = BTreeSet::new();
        let mut available = BTreeSet::new();
        for step in &self.steps {
            let Some(mechanism) = model
                .mechanisms
                .iter()
                .find(|mechanism| mechanism.id == step.mechanism)
            else {
                return false;
            };
            if !executed.insert(step.mechanism)
                || !step.requires.iter().all(|index| available.contains(index))
                || index_kinds(&step.requires) != Some(mechanism.requires.clone())
                || index_kinds(&step.provides) != Some(mechanism.provides.clone())
            {
                return false;
            }
            available.extend(step.provides.iter().copied());
        }
        available.len() == self.abilities.len()
            && self.goals.iter().all(|index| available.contains(index))
    }
}

fn scope_matches_resources(
    scope: &crate::scoped::AbilityScope,
    resources: &NetworkResources,
    binding: AccessBinding,
) -> bool {
    use crate::scoped::AbilityScope;
    if matches!(
        scope.kind(),
        Ability::NetworkRouteAuthorization
            | Ability::SshCredential
            | Ability::MtlsCredential
            | Ability::TcpAdmission
    ) {
        return scope_matches_resources(&scope.effective(), resources, binding);
    }
    match scope {
        AbilityScope::MeshMembership {
            wireguard_public_key,
            address,
        } => {
            *address == resources.source_address
                && *wireguard_public_key == resources.registered_wireguard_key
        }
        AbilityScope::NetworkReachability {
            source,
            destination,
        }
        | AbilityScope::NetworkRouteAuthorization {
            source,
            destination,
        }
        | AbilityScope::TcpAdmission {
            source,
            destination,
            ..
        }
        | AbilityScope::TcpConnection {
            source,
            destination,
            ..
        } => *source == resources.source_address && *destination == resources.target_address,
        AbilityScope::ServiceIdentity {
            identity_uri,
            service_audience,
            ..
        } => {
            *service_audience == resources.service_audience
                && *identity_uri == binding.identity_uri()
        }
        AbilityScope::SshSession { .. } => true,
        AbilityScope::SshCredential { .. } | AbilityScope::MtlsCredential { .. } => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionFailure {
    pub reason: ScopeError,
    pub evidence: Box<PlanningEvidence>,
}

impl SelectionFailure {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.reason.code()
    }

    #[must_use]
    pub const fn capability(&self) -> Option<crate::Capability> {
        self.reason.capability()
    }

    /// Records a policy lookup failure before identity/rules can be loaded.
    #[must_use]
    pub fn policy(
        request: &AccessRequest,
        options: &SelectionOptions,
        reason: DenialReason,
    ) -> Self {
        Self::rejected(request, options, ScopeError::Policy(reason))
    }

    fn rejected(request: &AccessRequest, options: &SelectionOptions, reason: ScopeError) -> Self {
        let mut evidence = PlanningEvidence::base(request, options.choice);
        evidence.deployment =
            (options.choice == RouteChoice::Automatic).then(|| options.availability.clone());
        let candidates = match options.choice {
            RouteChoice::Exact(route) => vec![CandidateId::from_route(route)],
            RouteChoice::Automatic => vec![CandidateId::ExistingRoute, CandidateId::WireGuardMesh],
        };
        evidence.candidates = candidates
            .into_iter()
            .map(|candidate| CandidateEvaluation::rejected(candidate, &reason))
            .collect();
        Self {
            reason,
            evidence: Box::new(evidence),
        }
    }
}

pub(crate) fn plan_evidence(
    plan: &Plan<ScopedAbility, AccessMechanism>,
    model: &Model<ScopedAbility, AccessMechanism>,
    goals: &BTreeSet<ScopedAbility>,
    permissions: &BTreeMap<Ability, (ScopedAbility, PolicyRef)>,
) -> Result<PlanEvidence, ScopeError> {
    let index: BTreeMap<_, _> = plan
        .abilities
        .iter()
        .enumerate()
        .map(|(id, ability)| (ability, id))
        .collect();
    let indices = |values: &BTreeSet<ScopedAbility>| {
        values
            .iter()
            .map(|ability| {
                index
                    .get(ability)
                    .copied()
                    .ok_or(ScopeError::InvalidRequest)
            })
            .collect::<Result<Vec<_>, _>>()
    };
    let abilities = plan
        .abilities
        .iter()
        .map(|ability| {
            let (permitted, policy) = permissions
                .get(&ability.scope.kind())
                .ok_or(ScopeError::InvalidRequest)?;
            Ok(AbilityEvidence {
                ability: ability.clone(),
                permitted: permitted.clone(),
                policy: *policy,
            })
        })
        .collect::<Result<_, ScopeError>>()?;
    let steps = plan
        .mechanisms
        .iter()
        .map(|id| {
            let mechanism = model
                .mechanisms
                .iter()
                .find(|mechanism| mechanism.id == *id)
                .ok_or(ScopeError::InvalidRequest)?;
            Ok(StepEvidence {
                mechanism: *id,
                requires: indices(&mechanism.requires)?,
                provides: indices(&mechanism.provides)?,
            })
        })
        .collect::<Result<_, ScopeError>>()?;
    let derivations = authority_planning_core::explain(model, &BTreeSet::new(), plan)
        .map_err(|_| ScopeError::InvalidRequest)?
        .into_iter()
        .map(|step| {
            let rule = &model.derivations[step.rule];
            Ok(DerivedEvidence {
                after_mechanisms: step.after_mechanisms,
                requires: indices(&rule.requires)?,
                provides: indices(&rule.provides)?,
            })
        })
        .collect::<Result<_, ScopeError>>()?;
    Ok(PlanEvidence {
        derivations,
        abilities,
        goals: indices(goals)?,
        steps,
    })
}

fn candidate_inputs(
    request: &AccessRequest,
    requested: &RequestedAccess,
    candidate: CandidateId,
    choice: RouteChoice,
) -> (AccessRequest, RequestedAccess) {
    let mut request = request.clone();
    request.intent.route = candidate.route();
    let mut requested = requested.clone();
    if choice == RouteChoice::Automatic
        && candidate == CandidateId::ExistingRoute
        && !request
            .intent
            .outcomes
            .contains(&Outcome::NetworkReachability)
    {
        requested.network = None;
    }
    (request, requested)
}

/// Evaluates every available candidate independently against the same immutable
/// policy snapshot, then chooses the smallest authorized plan deterministically.
/// Exact selections retain the existing route constraints and never fall back.
///
/// # Errors
/// Returns all candidate reasons on denial. Availability cannot grant authority;
/// every chosen candidate must independently pass scoped policy evaluation.
pub fn evaluate_selection(
    request: &AccessRequest,
    snapshot: &PolicySnapshot,
    scopes: &BTreeMap<PolicyRef, PolicyScope>,
    requested: &RequestedAccess,
    resources: &NetworkResources,
    limits: LifetimeLimits,
    options: &SelectionOptions,
) -> Result<(AccessDecision, AuthorizedPlan), SelectionFailure> {
    if matches!(options.choice, RouteChoice::Exact(route) if route != request.intent.route) {
        return Err(SelectionFailure::rejected(
            request,
            options,
            ScopeError::InvalidRequest,
        ));
    }
    let mut evaluations = Vec::new();
    let mut authorized = Vec::new();
    let mut failures = Vec::new();
    for (candidate, available) in options.candidates(resources) {
        if !available {
            evaluations.push(CandidateEvaluation::rejected(
                candidate,
                &ScopeError::NoAvailableImplementation,
            ));
            continue;
        }
        let (candidate_request, inputs) =
            candidate_inputs(request, requested, candidate, options.choice);
        match evaluate_scoped(
            &candidate_request,
            snapshot,
            scopes,
            &inputs,
            resources,
            limits,
        ) {
            Ok((decision, plan)) => {
                let count = plan.realization().mechanisms.len();
                evaluations.push(CandidateEvaluation {
                    candidate,
                    result: CandidateResult::Authorized {
                        mechanism_count: count,
                    },
                });
                authorized.push(((count, candidate), decision, plan));
            }
            Err(reason) => {
                evaluations.push(CandidateEvaluation::rejected(candidate, &reason));
                failures.push(reason);
            }
        }
    }
    if let Some((_, decision, mut plan)) = authorized.into_iter().min_by_key(|(key, _, _)| *key) {
        plan.set_selection(options, evaluations);
        return Ok((decision, plan));
    }
    let reason = failures
        .first()
        .map_or(ScopeError::NoAvailableImplementation, |first| {
            if failures.iter().all(|reason| reason == first) {
                first.clone()
            } else {
                ScopeError::NoAuthorizedImplementation
            }
        });
    let mut evidence = PlanningEvidence::base(request, options.choice);
    evidence.resources = Some(resources.clone());
    evidence.deployment =
        (options.choice == RouteChoice::Automatic).then(|| options.availability.clone());
    evidence.candidates = evaluations;
    Err(SelectionFailure {
        reason,
        evidence: Box::new(evidence),
    })
}

impl PlanEvidence {
    fn consistent_derived(
        &self,
        binding: AccessBinding,
        evaluated_at: i64,
        selected: CandidateId,
        outcomes: &BTreeSet<Outcome>,
        resources: &NetworkResources,
    ) -> bool {
        let kind_model = crate::realization::conditional_catalog(selected.route())
            .instantiate(&resources.environment);
        let kind_plan = Plan {
            mechanisms: self.steps.iter().map(|step| step.mechanism).collect(),
            abilities: self
                .abilities
                .iter()
                .map(|entry| entry.ability.scope.kind())
                .collect(),
        };
        if authority_planning_core::explain(&kind_model, &BTreeSet::new(), &kind_plan).is_err() {
            return false;
        }
        let abilities: BTreeMap<_, _> = self
            .abilities
            .iter()
            .map(|entry| (entry.ability.scope.kind(), entry.ability.clone()))
            .collect();
        let request = AccessRequest {
            domain_id: binding.domain_id,
            subject_user_id: binding.subject_user_id,
            device_id: binding.device_id,
            target_node_id: binding.target_node_id,
            evaluated_at,
            intent: crate::AccessIntent {
                outcomes: outcomes.clone(),
                route: selected.route(),
            },
        };
        let model = crate::scoped::instantiate(&request, &abilities, resources);
        let plan = Plan {
            mechanisms: self.steps.iter().map(|step| step.mechanism).collect(),
            abilities: abilities.values().cloned().collect(),
        };
        let permissions = self
            .abilities
            .iter()
            .map(|entry| {
                (
                    entry.ability.scope.kind(),
                    (entry.permitted.clone(), entry.policy),
                )
            })
            .collect();
        let goals = self
            .goals
            .iter()
            .map(|index| {
                self.abilities
                    .get(*index)
                    .map(|entry| entry.ability.clone())
            })
            .collect::<Option<BTreeSet<_>>>();
        let Some(goals) = goals else {
            return false;
        };
        plan_evidence(&plan, &model, &goals, &permissions).is_ok_and(|expected| expected == *self)
    }
}
