use std::collections::{BTreeMap, BTreeSet};

use authority_policy_core::{
    AccessDecision, AccessIntent, AccessRequest, DenialReason, Effect, IdentityFacts, PolicyRef,
    PolicyRule, PolicySnapshot,
    capabilities::{CapabilityParseError, parse_capabilities},
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

#[derive(Debug)]
enum PolicyReadError {
    Storage(sqlx::Error),
    InvalidCapabilities {
        policy_id: Uuid,
        cause: CapabilityParseError,
    },
}

impl From<sqlx::Error> for PolicyReadError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error)
    }
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
    let stored = match rows.iter().map(stored_rule).collect::<Result<Vec<_>, _>>() {
        Ok(stored) => stored,
        Err(PolicyReadError::Storage(cause)) => return Err(cause),
        Err(PolicyReadError::InvalidCapabilities { policy_id, cause }) => {
            tracing::warn!(%policy_id, %cause, "invalid stored policy capabilities; refusing authorization");
            return Ok(AuthorizationOutcome::Denied(Box::new(
                SelectionFailure::policy(&request, selection, DenialReason::InvalidPolicy),
            )));
        }
    };
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

fn stored_rule(row: &sqlx::postgres::PgRow) -> Result<StoredRule, PolicyReadError> {
    let effect = match row.try_get::<String, _>("effect")?.as_str() {
        "allow" => Effect::Allow,
        _ => Effect::Deny,
    };
    let policy_id = row.try_get("id")?;
    let capabilities: Vec<String> = row.try_get("capabilities")?;
    let grants = parse_capabilities(capabilities.iter().map(String::as_str))
        .map_err(|cause| PolicyReadError::InvalidCapabilities { policy_id, cause })?;
    let tcp_ports: Vec<i32> = row.try_get("tcp_ports")?;
    let tcp_ports = tcp_ports
        .into_iter()
        .map(u16::try_from)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|cause| sqlx::Error::Decode(Box::new(cause)))?;
    Ok(StoredRule {
        rule: PolicyRule {
            policy_id,
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

#[cfg(test)]
mod tests {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

    use super::*;

    #[tokio::test]
    #[ignore = "requires AUTHORITY_DB_HOST and the LXC PostgreSQL development credentials"]
    async fn stored_policy_capabilities_fail_closed_in_postgres() {
        let host = std::env::var("AUTHORITY_DB_HOST").expect("set AUTHORITY_DB_HOST for LXC");
        let password = std::env::var("AUTHORITY_DB_PASSWORD").unwrap_or_else(|_| {
            let path = std::env::var_os("AUTHORITY_DB_PASSWORD_FILE").map_or_else(
                || {
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../.secrets/authority-db-password")
                },
                std::path::PathBuf::from,
            );
            std::fs::read_to_string(path)
                .expect("read local development credential")
                .trim()
                .to_owned()
        });
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(
                PgConnectOptions::new()
                    .host(&host)
                    .username("authority")
                    .password(&password)
                    .database("authority")
                    .ssl_mode(PgSslMode::Disable),
            )
            .await
            .expect("connect to LXC PostgreSQL");
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let query = "SELECT $1::text AS effect, $2::text[] AS capabilities, \
            ARRAY[8080]::integer[] AS tcp_ports, 'deploy'::text AS ssh_principal, \
            '00000000-0000-0000-0000-000000000001'::uuid AS id, \
            '00000000-0000-0000-0000-000000000002'::uuid AS domain_id, \
            '00000000-0000-0000-0000-000000000003'::uuid AS subject_user_id, \
            '00000000-0000-0000-0000-000000000004'::uuid AS required_device_id, \
            '00000000-0000-0000-0000-000000000005'::uuid AS target_node_id, \
            true AS enabled, 100::integer AS priority, 1::bigint AS revision, \
            NULL::bigint AS revoked_at, NULL::bigint AS valid_from, NULL::bigint AS valid_until";
        let allow = sqlx::query(query)
            .bind("allow")
            .bind(vec!["ssh.issue".to_owned()])
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        assert!(stored_rule(&allow).is_ok());
        for effect in ["allow", "deny"] {
            for capabilities in [
                vec!["ssh.isssue"],
                vec!["ssh.issue", "unknown.capability"],
                vec![],
            ] {
                let values = capabilities
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let invalid = sqlx::query(query)
                    .bind(effect)
                    .bind(values)
                    .fetch_one(&mut *transaction)
                    .await
                    .unwrap();
                // The same atomic collection used by authorize must reject an
                // invalid deny even in the presence of a valid allow rule.
                for rows in [[&allow, &invalid], [&invalid, &allow]] {
                    let parsed = rows
                        .into_iter()
                        .map(stored_rule)
                        .collect::<Result<Vec<_>, _>>();
                    assert!(matches!(
                        parsed,
                        Err(PolicyReadError::InvalidCapabilities { .. })
                    ));
                }
            }
        }
        transaction.rollback().await.unwrap();
    }
}
