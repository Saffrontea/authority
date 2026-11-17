use std::collections::{BTreeMap, BTreeSet};

use authority_policy_core::{
    AccessDecision, AccessIntent, AccessRequest, Capability, DenialReason, Effect, IdentityFacts,
    PolicyRef, PolicyRule, PolicySnapshot,
    scoped::{AuthorizedPlan, LifetimeLimits, NetworkResources, PolicyScope, RequestedAccess},
    selection::{SelectionFailure, SelectionOptions, evaluate_selection},
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub struct AuthorizedAccess {
    pub decision: AccessDecision,
    pub plan: AuthorizedPlan,
}

pub enum AuthorizationOutcome {
    Allowed(Box<AuthorizedAccess>),
    Denied(Box<SelectionFailure>),
}

struct StoredRule {
    rule: PolicyRule,
    scope: PolicyScope,
}

/// Extracts an immutable snapshot from PostgreSQL, then delegates all policy
/// semantics to the pure policy-core evaluator.
pub async fn authorize(
    pool: &PgPool,
    request: AccessRequest,
    requested: &RequestedAccess,
    limits: LifetimeLimits,
    selection: &SelectionOptions,
) -> Result<AuthorizationOutcome, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT policy.id, policy.domain_id, policy.subject_user_id, \
                policy.required_device_id, policy.target_node_id, policy.enabled, \
                policy.effect, policy.priority, policy.revision, policy.capabilities, \
                EXTRACT(EPOCH FROM policy.revoked_at)::bigint AS revoked_at, \
                CEIL(EXTRACT(EPOCH FROM policy.valid_from))::bigint AS valid_from, \
                FLOOR(EXTRACT(EPOCH FROM policy.valid_until))::bigint AS valid_until, \
                policy.ssh_principal, policy.tcp_ports, host(target.mesh_address) AS target_mesh_address, client.domain_id AS device_domain_id, \
                client.owner_user_id AS device_owner_user_id, \
                client.status = 'active' AS device_active, \
                target.status = 'active' AND target_device.status = 'active' \
                    AND target_device.domain_id = policy.domain_id AS target_active, \
                client.wireguard_public_key, \
                host(client.mesh_address) AS device_mesh_address \
         FROM policy.access_policies AS policy \
         JOIN device.devices AS client ON client.id = $3 \
         JOIN device.nodes AS target ON target.id = $4 \
         JOIN device.devices AS target_device ON target_device.id = target.device_id \
         WHERE policy.domain_id = $1 AND policy.subject_user_id = $2 \
           AND policy.target_node_id = $4 \
         ORDER BY policy.id, policy.revision",
    )
    .bind(request.domain_id)
    .bind(request.subject_user_id)
    .bind(request.device_id)
    .bind(request.target_node_id)
    .fetch_all(pool)
    .await?;

    let Some(first) = rows.first() else {
        return Ok(AuthorizationOutcome::Denied(Box::new(
            SelectionFailure::policy(&request, selection, DenialReason::NoApplicablePolicy),
        )));
    };
    let identity = IdentityFacts {
        device_domain_id: first.try_get("device_domain_id")?,
        device_owner_user_id: first.try_get("device_owner_user_id")?,
        device_active: first.try_get("device_active")?,
        target_active: first.try_get("target_active")?,
    };
    let resources = NetworkResources {
        registered_wireguard_key: String::from_utf8(first.try_get("wireguard_public_key")?)
            .map_err(|cause| sqlx::Error::Decode(Box::new(cause)))?,
        source_address: first
            .try_get::<String, _>("device_mesh_address")?
            .parse()
            .map_err(|cause| sqlx::Error::Decode(Box::new(cause)))?,
        target_address: first
            .try_get::<String, _>("target_mesh_address")?
            .parse()
            .map_err(|cause| sqlx::Error::Decode(Box::new(cause)))?,
        service_audience: "demo-api".to_owned(),
    };
    let stored = rows
        .iter()
        .map(stored_rule)
        .collect::<Result<Vec<_>, _>>()?;
    let scopes: BTreeMap<_, _> = stored
        .iter()
        .map(|item| {
            (
                PolicyRef {
                    policy_id: item.rule.policy_id,
                    revision: item.rule.revision,
                },
                item.scope.clone(),
            )
        })
        .collect();
    let snapshot = PolicySnapshot {
        identity,
        rules: stored.into_iter().map(|item| item.rule).collect(),
    };
    match evaluate_selection(
        &request, &snapshot, &scopes, requested, &resources, limits, selection,
    ) {
        Ok((decision, plan)) => Ok(AuthorizationOutcome::Allowed(Box::new(AuthorizedAccess {
            decision,
            plan,
        }))),
        Err(reason) => Ok(AuthorizationOutcome::Denied(Box::new(reason))),
    }
}

fn stored_rule(row: &sqlx::postgres::PgRow) -> Result<StoredRule, sqlx::Error> {
    let effect = match row.try_get::<String, _>("effect")?.as_str() {
        "allow" => Effect::Allow,
        _ => Effect::Deny,
    };
    let capabilities: Vec<String> = row.try_get("capabilities")?;
    let mut grants = BTreeSet::new();
    for capability in capabilities {
        match capability.as_str() {
            "ssh" | "ssh.issue" => {
                grants.insert(Capability::SshIssue);
            }
            "tcp.connect" => {
                grants.insert(Capability::TcpConnect);
            }
            "mtls.issue" => {
                grants.insert(Capability::MtlsIssue);
            }
            // `wireguard` is the legacy PoC aggregate. New writes persist
            // atomic capabilities and dependency closure stays in policy-core.
            "wireguard" => {
                grants.insert(Capability::MeshJoin);
                grants.insert(Capability::NetworkReach);
            }
            "mesh.join" => {
                grants.insert(Capability::MeshJoin);
            }
            "network.reach" => {
                grants.insert(Capability::NetworkReach);
            }
            _ => {}
        }
    }
    let tcp_ports: Vec<i32> = row.try_get("tcp_ports")?;
    let tcp_ports = tcp_ports
        .into_iter()
        .map(u16::try_from)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|cause| sqlx::Error::Decode(Box::new(cause)))?;
    Ok(StoredRule {
        rule: PolicyRule {
            policy_id: row.try_get("id")?,
            domain_id: row.try_get("domain_id")?,
            subject_user_id: row.try_get("subject_user_id")?,
            required_device_id: row.try_get("required_device_id")?,
            target_node_id: row.try_get("target_node_id")?,
            enabled: row.try_get("enabled")?,
            effect,
            priority: row.try_get("priority")?,
            revision: row.try_get("revision")?,
            grants,
            revoked_at: row.try_get("revoked_at")?,
            valid_from: row.try_get("valid_from")?,
            valid_until: row.try_get("valid_until")?,
        },
        scope: PolicyScope {
            ssh_principals: BTreeSet::from([row.try_get("ssh_principal")?]),
            tcp_ports,
        },
    })
}

pub fn request(
    domain_id: Uuid,
    subject_user_id: Uuid,
    device_id: Uuid,
    target_node_id: Uuid,
    evaluated_at: i64,
    intent: AccessIntent,
) -> AccessRequest {
    AccessRequest {
        domain_id,
        subject_user_id,
        device_id,
        target_node_id,
        evaluated_at,
        intent,
    }
}
