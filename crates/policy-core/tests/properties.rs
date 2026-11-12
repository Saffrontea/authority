use std::collections::BTreeSet;

use authority_policy_core::{
    AccessIntent, AccessRequest, Capability, DenialReason, Effect, IdentityFacts, Outcome,
    PolicyRule, PolicySnapshot, Route, evaluate, plan,
};
use proptest::prelude::*;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct RuleSpec {
    deny: bool,
    priority: i16,
    revision: u16,
    capabilities: u8,
    enabled: bool,
    applicable: bool,
}

fn intent(outcomes: u8, mesh: bool) -> AccessIntent {
    let mut selected = BTreeSet::new();
    if outcomes & 1 != 0 {
        selected.insert(Outcome::Ssh);
    }
    if outcomes & 2 != 0 {
        selected.insert(Outcome::NetworkReachability);
    }
    AccessIntent {
        outcomes: selected,
        route: if mesh {
            Route::MeshRequired
        } else {
            Route::Direct
        },
    }
}

fn capability_set(mask: u8) -> BTreeSet<Capability> {
    let mut capabilities = BTreeSet::new();
    if mask & 1 != 0 {
        capabilities.insert(Capability::MeshJoin);
    }
    if mask & 2 != 0 {
        capabilities.insert(Capability::NetworkReach);
    }
    if mask & 4 != 0 {
        capabilities.insert(Capability::SshIssue);
    }
    capabilities
}

fn request_and_identity(access_intent: AccessIntent) -> (AccessRequest, IdentityFacts) {
    let domain_id = Uuid::from_u128(1);
    let subject_user_id = Uuid::from_u128(2);
    let device_id = Uuid::from_u128(3);
    let target_node_id = Uuid::from_u128(4);
    (
        AccessRequest {
            domain_id,
            subject_user_id,
            device_id,
            target_node_id,
            evaluated_at: 100,
            intent: access_intent,
        },
        IdentityFacts {
            device_domain_id: domain_id,
            device_owner_user_id: subject_user_id,
            device_active: true,
            target_active: true,
        },
    )
}

fn rule_from_spec(index: usize, spec: &RuleSpec, request: &AccessRequest) -> PolicyRule {
    PolicyRule {
        policy_id: Uuid::from_u128(u128::try_from(index).expect("index fits u128") + 10),
        domain_id: request.domain_id,
        subject_user_id: request.subject_user_id,
        required_device_id: Some(request.device_id),
        target_node_id: if spec.applicable {
            request.target_node_id
        } else {
            Uuid::from_u128(5)
        },
        enabled: spec.enabled,
        effect: if spec.deny {
            Effect::Deny
        } else {
            Effect::Allow
        },
        priority: i32::from(spec.priority),
        revision: i64::from(spec.revision) + 1,
        grants: capability_set(spec.capabilities),
        revoked_at: None,
        valid_from: None,
        valid_until: None,
    }
}

fn rule_strategy() -> impl Strategy<Value = RuleSpec> {
    (
        any::<bool>(),
        any::<i16>(),
        any::<u16>(),
        0_u8..8,
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(deny, priority, revision, capabilities, enabled, applicable)| RuleSpec {
                deny,
                priority,
                revision,
                capabilities,
                enabled,
                applicable,
            },
        )
}

proptest! {
    #[test]
    fn policy_result_is_invariant_under_rule_order(
        outcomes in 0_u8..4,
        mesh in any::<bool>(),
        specs in prop::collection::vec(rule_strategy(), 0..40),
    ) {
        let (request, identity) = request_and_identity(intent(outcomes, mesh));
        let rules = specs
            .iter()
            .enumerate()
            .map(|(index, spec)| rule_from_spec(index, spec, &request))
            .collect::<Vec<_>>();
        let mut reversed = rules.clone();
        reversed.reverse();

        let forward = evaluate(
            &request,
            &PolicySnapshot { identity: identity.clone(), rules },
        );
        let backward = evaluate(
            &request,
            &PolicySnapshot { identity, rules: reversed },
        );
        prop_assert_eq!(forward, backward);
    }

    #[test]
    fn a_higher_priority_deny_rejects_its_required_capability(
        outcomes in 1_u8..4,
        mesh in any::<bool>(),
        selected in any::<usize>(),
        priority in -10_000_i32..10_000,
    ) {
        let (request, identity) = request_and_identity(intent(outcomes, mesh));
        let required = plan(&request.intent);
        prop_assume!(!required.is_empty());
        let capability = *required.iter().nth(selected % required.len()).expect("nonempty");
        let allow = PolicyRule {
            policy_id: Uuid::from_u128(10),
            domain_id: request.domain_id,
            subject_user_id: request.subject_user_id,
            required_device_id: Some(request.device_id),
            target_node_id: request.target_node_id,
            enabled: true,
            effect: Effect::Allow,
            priority,
            revision: 1,
            grants: required,
            revoked_at: None,
            valid_from: None,
            valid_until: None,
        };
        let deny = PolicyRule {
            policy_id: Uuid::from_u128(11),
            effect: Effect::Deny,
            priority: priority + 1,
            grants: BTreeSet::from([capability]),
            ..allow.clone()
        };
        let result = evaluate(&request, &PolicySnapshot { identity, rules: vec![allow, deny] });
        prop_assert_eq!(result, Err(DenialReason::ExplicitDeny(capability)));
    }

    #[test]
    fn planned_capabilities_obey_dependency_closure(
        outcomes in 0_u8..4,
        mesh in any::<bool>(),
    ) {
        let access_intent = intent(outcomes, mesh);
        let required = plan(&access_intent);
        prop_assert_eq!(
            required.contains(&Capability::SshIssue),
            access_intent.outcomes.contains(&Outcome::Ssh),
        );
        if required.contains(&Capability::NetworkReach) && access_intent.route == Route::MeshRequired {
            prop_assert!(required.contains(&Capability::MeshJoin));
        }
        if required.contains(&Capability::MeshJoin) {
            prop_assert!(required.contains(&Capability::NetworkReach));
            prop_assert_eq!(access_intent.route, Route::MeshRequired);
        }
    }
}
