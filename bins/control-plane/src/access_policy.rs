use std::collections::{BTreeMap, BTreeSet};

use authority_policy_core::{
    AccessDecision, AccessIntent, AccessRequest, DenialReason, Effect, IdentityFacts, PolicyRef,
    PolicyRule, PolicySnapshot,
    capabilities::{CapabilityParseError, parse_capabilities},
    scoped::{AuthorizedPlan, LifetimeLimits, NetworkResources, PolicyScope, RequestedAccess},
    selection::{SelectionFailure, SelectionOptions, evaluate_selection},
};
use sqlx::{PgPool, Postgres, Row, Transaction};
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

/// Owns the complete read/evaluate/write boundary. Callers must commit only after
/// decision, planning evidence and issued contracts have all been persisted.
pub async fn begin_authorization(pool: &PgPool) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

/// Extracts an immutable snapshot from PostgreSQL, then delegates all policy
/// semantics to the pure policy-core evaluator.
pub async fn authorize(
    transaction: &mut Transaction<'_, Postgres>,
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
         ORDER BY policy.id, policy.revision \
         FOR SHARE OF policy, client, target, target_device",
    )
    .bind(request.domain_id)
    .bind(request.subject_user_id)
    .bind(request.device_id)
    .bind(request.target_node_id)
    .fetch_all(&mut **transaction)
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
        service_audience: crate::config::DEMO_SERVICE_AUDIENCE.to_owned(),
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
    use authority_policy_core::{Capability, Route, scoped::RequestedTcp};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
    use std::time::Duration;

    use super::*;

    async fn lxc_pool(max_connections: u32) -> PgPool {
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
                .trim_end_matches(['\r', '\n'])
                .to_owned()
        });
        PgPoolOptions::new()
            .max_connections(max_connections)
            .connect_with(
                PgConnectOptions::new()
                    .host(&host)
                    .username("authority")
                    .password(&password)
                    .database("authority")
                    .ssl_mode(PgSslMode::Disable),
            )
            .await
            .expect("connect to LXC PostgreSQL")
    }

    #[tokio::test]
    #[ignore = "requires AUTHORITY_DB_HOST and the LXC PostgreSQL development credentials"]
    async fn stored_policy_capabilities_fail_closed_in_postgres() {
        let pool = lxc_pool(1).await;
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

    async fn writer_waits(
        pool: &PgPool,
        query: &'static str,
        id: Uuid,
    ) -> tokio::task::JoinHandle<()> {
        let pool = pool.clone();
        let observer = pool.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            let mut transaction = pool.begin().await.unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *transaction)
                .await
                .unwrap();
            sender.send(pid).unwrap();
            sqlx::query(query)
                .bind(id)
                .execute(&mut *transaction)
                .await
                .unwrap();
            transaction.rollback().await.unwrap();
        });
        let pid = receiver.await.unwrap();
        let blocked = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock')"
                ).bind(pid).fetch_one(&observer).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        assert!(
            blocked.is_ok(),
            "concurrent policy/identity writer must wait for the authorization transaction"
        );
        writer
    }

    async fn live_tcp_request(pool: &PgPool) -> (AccessRequest, Uuid) {
        let row = sqlx::query(
            "SELECT p.domain_id, p.subject_user_id, p.required_device_id, p.target_node_id, n.device_id AS target_device_id \
             FROM policy.access_policies p JOIN device.devices d ON d.id = p.required_device_id \
             JOIN device.nodes n ON n.id = p.target_node_id \
             WHERE p.enabled AND p.effect = 'allow' AND 'tcp.connect' = ANY(p.capabilities) \
               AND d.owner_user_id = p.subject_user_id AND d.status = 'active' \
             ORDER BY p.id DESC LIMIT 1"
        ).fetch_one(pool).await.expect("run poc:e2e to bootstrap a policy first");
        let request = request(
            row.get("domain_id"),
            row.get("subject_user_id"),
            row.get("required_device_id"),
            row.get("target_node_id"),
            i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap(),
            AccessIntent::tcp(Route::Direct),
        );
        (request, row.get("target_device_id"))
    }

    #[tokio::test]
    #[ignore = "requires LXC PostgreSQL and a bootstrapped poc:e2e policy"]
    async fn authorization_transaction_locks_and_rolls_back_in_postgres() {
        let pool = lxc_pool(4).await;
        let (request, target_device_id) = live_tcp_request(&pool).await;
        let inputs = RequestedAccess {
            tcp: Some(RequestedTcp {
                ports: BTreeSet::from([8080]),
                ttl_seconds: 10,
            }),
            ..RequestedAccess::default()
        };
        let updates = [
            "UPDATE policy.access_policies SET enabled = enabled WHERE id = $1",
            "UPDATE device.devices SET status = status WHERE id = $1",
            "UPDATE device.nodes SET status = status WHERE id = $1",
            "UPDATE device.devices SET status = status WHERE id = $1",
        ];
        for (index, update) in updates.into_iter().enumerate() {
            let mut transaction = begin_authorization(&pool).await.unwrap();
            let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
                .fetch_one(&mut *transaction)
                .await
                .unwrap();
            assert_eq!(isolation, "serializable");
            let result = authorize(
                &mut transaction,
                request.clone(),
                &inputs,
                LifetimeLimits {
                    ssh_seconds: 60,
                    network_seconds: 300,
                },
                &SelectionOptions::exact(Route::Direct),
            )
            .await
            .unwrap();
            let AuthorizationOutcome::Allowed(authorized) = result else {
                panic!("expected valid demo authorization");
            };
            let id = match index {
                0 => authorized.decision.sources[&Capability::TcpConnect].policy_id,
                1 => request.device_id,
                2 => request.target_node_id,
                _ => target_device_id,
            };
            let writer = writer_waits(&pool, update, id).await;
            let decision_id = Uuid::new_v4().simple().to_string();
            crate::planning_audit::insert(
                &mut transaction,
                &decision_id,
                authorized.plan.evidence(),
                None,
            )
            .await
            .unwrap();
            let visible: i64 =
                sqlx::query_scalar("SELECT count(*) FROM outbox.events WHERE aggregate_id = $1")
                    .bind(&decision_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(
                visible, 0,
                "uncommitted decision must not escape to another connection"
            );
            // Force a real outbox constraint failure after both audit/outbox writes.
            let failure = sqlx::query(
                "INSERT INTO outbox.events SELECT * FROM outbox.events WHERE aggregate_id = $1",
            )
            .bind(&decision_id)
            .execute(&mut *transaction)
            .await
            .unwrap_err();
            assert!(
                matches!(failure, sqlx::Error::Database(error) if error.code().as_deref() == Some("23505"))
            );
            transaction.rollback().await.unwrap();
            writer.await.unwrap();
            let remaining: i64 = sqlx::query_scalar(
                "SELECT (SELECT count(*) FROM outbox.events WHERE aggregate_id = $1) + \
                    (SELECT count(*) FROM audit.events WHERE payload->>'decision_id' = $1)",
            )
            .bind(&decision_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                remaining, 0,
                "failed decision must leave neither audit nor outbox behind"
            );
        }
    }
}
