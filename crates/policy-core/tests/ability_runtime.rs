use std::collections::BTreeSet;

use authority_policy_core::{
    AccessIntent, AccessRequest, Effect, IdentityFacts, PolicyRef, Route,
    ability_policy::{
        AbilityPolicySnapshot, AbilitySelector, StoredAbilityPolicy, evaluate_selection,
    },
    realization::{Ability, endpoint_facts},
    scoped::{LifetimeLimits, NetworkResources, RequestedAccess, RequestedTcp, Validity},
    selection::SelectionOptions,
};
use uuid::Uuid;

fn policy(id: u128, kind: Ability, ports: &[u16], start: i64, end: i64) -> StoredAbilityPolicy {
    let source = [10, 77, 0, 1].into();
    let destination = [10, 77, 0, 2].into();
    let ports = ports.iter().copied().collect();
    let selector = match kind {
        Ability::TcpAdmission => AbilitySelector::TcpAdmission {
            source,
            destination,
            ports,
        },
        Ability::TcpConnection => AbilitySelector::TcpConnection {
            source,
            destination,
            ports,
        },
        _ => unreachable!(),
    };
    StoredAbilityPolicy {
        policy: PolicyRef {
            policy_id: Uuid::from_u128(id),
            revision: 1,
        },
        domain_id: Uuid::from_u128(1),
        subject_user_id: Uuid::from_u128(2),
        required_device_id: Some(Uuid::from_u128(3)),
        target_node_id: Uuid::from_u128(4),
        enabled: true,
        revoked: false,
        priority: 0,
        effect: Effect::Allow,
        validity: Validity {
            not_before: start,
            expires_at: end,
        },
        selector,
    }
}

fn run(
    rules: Vec<StoredAbilityPolicy>,
    ports: &[u16],
) -> Result<
    (
        authority_policy_core::ability_policy::AbilityDecision,
        authority_policy_core::scoped::AuthorizedPlan,
    ),
    authority_policy_core::selection::SelectionFailure,
> {
    let request = AccessRequest {
        domain_id: Uuid::from_u128(1),
        subject_user_id: Uuid::from_u128(2),
        device_id: Uuid::from_u128(3),
        target_node_id: Uuid::from_u128(4),
        evaluated_at: 100,
        intent: AccessIntent::tcp(Route::Direct),
    };
    evaluate_selection(
        &request,
        &AbilityPolicySnapshot {
            identity: IdentityFacts {
                device_domain_id: request.domain_id,
                device_owner_user_id: Some(request.subject_user_id),
                device_active: true,
                target_active: true,
            },
            rules,
        },
        &RequestedAccess {
            tcp: Some(RequestedTcp {
                ports: ports.iter().copied().collect(),
                ttl_seconds: 10,
            }),
            ..RequestedAccess::default()
        },
        &NetworkResources {
            source_address: [10, 77, 0, 1].into(),
            target_address: [10, 77, 0, 2].into(),
            registered_wireguard_key: "registered".to_owned(),
            service_audience: "service".to_owned(),
            environment: endpoint_facts(),
        },
        LifetimeLimits {
            ssh_seconds: 30,
            network_seconds: 30,
        },
        &SelectionOptions::exact(Route::Direct),
    )
}

#[test]
fn direct_permission_cannot_hide_a_denied_mandatory_derived_effect() {
    let direct = policy(10, Ability::TcpAdmission, &[8080, 8081], 0, 200);
    let allow = policy(11, Ability::TcpConnection, &[8080, 8081], 0, 200);
    let mut deny = policy(12, Ability::TcpConnection, &[8081], 105, 106);
    deny.effect = Effect::Deny;
    let rules = vec![direct, allow, deny];
    assert!(run(rules.clone(), &[8080]).is_ok());
    assert_eq!(
        run(rules, &[8080, 8081]).unwrap_err().code(),
        "explicit_ability_deny"
    );
}

#[test]
fn each_ability_requires_its_own_permission() {
    let direct = policy(10, Ability::TcpAdmission, &[8080], 0, 200);
    let derived = policy(11, Ability::TcpConnection, &[8080], 0, 200);
    assert_eq!(
        run(vec![direct], &[8080]).unwrap_err().code(),
        "missing_ability"
    );
    assert_eq!(
        run(vec![derived], &[8080]).unwrap_err().code(),
        "missing_ability"
    );
}

#[test]
fn combined_policy_provenance_survives_audit_replay() {
    let rules = vec![
        policy(10, Ability::TcpAdmission, &[8080, 8081], 0, 200),
        policy(11, Ability::TcpConnection, &[8080], 100, 105),
        policy(12, Ability::TcpConnection, &[8080], 105, 110),
        policy(13, Ability::TcpConnection, &[8081], 100, 110),
    ];
    let (decision, plan) = run(rules, &[8080, 8081]).unwrap();
    assert_eq!(
        decision.sources[&Ability::TcpConnection],
        BTreeSet::from([
            PolicyRef {
                policy_id: Uuid::from_u128(11),
                revision: 1
            },
            PolicyRef {
                policy_id: Uuid::from_u128(12),
                revision: 1
            },
            PolicyRef {
                policy_id: Uuid::from_u128(13),
                revision: 1
            },
        ])
    );
    assert_eq!(plan.policy_reference(), decision.policy_reference());
    assert!(plan.policy_reference().len() <= 128);
    let mut changed = decision.clone();
    changed
        .sources
        .get_mut(&Ability::TcpConnection)
        .unwrap()
        .insert(PolicyRef {
            policy_id: Uuid::from_u128(99),
            revision: 1,
        });
    assert_ne!(decision.policy_reference(), changed.policy_reference());
    assert!(plan.evidence().is_consistent());
    let derived = plan
        .evidence()
        .plan
        .as_ref()
        .unwrap()
        .abilities
        .iter()
        .find(|entry| entry.ability.scope.kind() == Ability::TcpConnection)
        .unwrap();
    assert_eq!(derived.policies.len(), 3);
    let mut forged = plan.evidence().clone();
    forged.plan.as_mut().unwrap().abilities[0].policies.clear();
    assert!(!forged.is_consistent());
}

#[test]
fn ownership_revocation_and_expiry_cannot_be_reused_as_permissions() {
    for change in 0..4 {
        let direct = policy(10, Ability::TcpAdmission, &[8080], 0, 200);
        let mut derived = policy(11, Ability::TcpConnection, &[8080], 0, 200);
        match change {
            0 => derived.revoked = true,
            1 => derived.required_device_id = Some(Uuid::from_u128(9)),
            2 => derived.subject_user_id = Uuid::from_u128(9),
            _ => derived.validity.expires_at = 100,
        }
        assert!(run(vec![direct, derived], &[8080]).is_err());
    }
}
