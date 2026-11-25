#[cfg(test)]
use std::collections::BTreeSet;

use authority_policy_core::{
    AccessIntent, AccessRequest, DenialReason, Effect, IdentityFacts, PolicyRef,
    ability_policy::{
        AbilityDecision, AbilityPolicySnapshot, StoredAbilityPolicy, evaluate_selection,
    },
    scoped::{AuthorizedPlan, LifetimeLimits, NetworkResources, RequestedAccess, Validity},
    selection::{SelectionFailure, SelectionOptions},
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub struct AuthorizedAccess {
    pub decision: AbilityDecision,
    pub plan: AuthorizedPlan,
    pub generations: authority_contracts_model::fence::IdentityGenerations,
}

pub enum AuthorizationOutcome {
    Allowed(Box<AuthorizedAccess>),
    Denied(Box<SelectionFailure>),
}

#[derive(Debug)]
enum PolicyReadError {
    Storage(sqlx::Error),
    InvalidPolicy { policy_id: Uuid, cause: String },
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
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
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
    let rows = snapshot_rows(transaction, &request).await?;

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
    if identity.device_domain_id != request.domain_id
        || identity.device_owner_user_id != Some(request.subject_user_id)
    {
        return Ok(AuthorizationOutcome::Denied(Box::new(
            SelectionFailure::policy(&request, selection, DenialReason::DeviceMismatch),
        )));
    }
    let checked = crate::endpoint_observation::snapshot(first, &request);
    let envelope = match checked {
        Ok(envelope) => envelope,
        Err(cause) => {
            tracing::warn!(%cause,"endpoint observation refused");
            return Ok(AuthorizationOutcome::Denied(Box::new(
                SelectionFailure::policy(
                    &request,
                    selection,
                    DenialReason::EndpointObservationUnavailable,
                ),
            )));
        }
    };
    let environment = envelope.observation.facts.clone();
    let remaining = envelope.observation.expires_at - request.evaluated_at;
    let limits = LifetimeLimits {
        ssh_seconds: limits.ssh_seconds.min(remaining),
        network_seconds: limits.network_seconds.min(remaining),
    };
    let resources = NetworkResources {
        observation: Some(Box::new(envelope)),
        environment,
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
        Err(PolicyReadError::InvalidPolicy { policy_id, cause }) => {
            tracing::warn!(%policy_id, %cause, "invalid stored ability policy; refusing authorization");
            return Ok(AuthorizationOutcome::Denied(Box::new(
                SelectionFailure::policy(&request, selection, DenialReason::InvalidPolicy),
            )));
        }
    };
    let snapshot = AbilityPolicySnapshot {
        identity,
        rules: stored,
    };
    match evaluate_selection(
        &request, &snapshot, requested, &resources, limits, selection,
    ) {
        Ok((decision, plan)) => Ok(AuthorizationOutcome::Allowed(Box::new(AuthorizedAccess {
            decision,
            plan,
            generations: authority_contracts_model::fence::IdentityGenerations {
                subject: first.try_get("subject_generation")?,
                device: first.try_get("device_generation")?,
            },
        }))),
        Err(reason) => Ok(AuthorizationOutcome::Denied(Box::new(reason))),
    }
}

/// Only API entry point: a failed refresh never falls back to an older report.
pub async fn authorize_with_refresh(
    transaction: &mut Transaction<'_, Postgres>,
    refresh: &Result<i64, String>,
    request: AccessRequest,
    requested: &RequestedAccess,
    limits: LifetimeLimits,
    selection: &SelectionOptions,
) -> Result<AuthorizationOutcome, sqlx::Error> {
    if let Err(cause) = refresh {
        tracing::warn!(%cause,node=%request.target_node_id,"fresh endpoint observation unavailable");
    }
    let outcome = authorize(transaction, request.clone(), requested, limits, selection).await?;
    if let AuthorizationOutcome::Allowed(ref allowed) = outcome {
        let revision = allowed
            .plan
            .evidence()
            .resources
            .as_ref()
            .and_then(|r| r.observation.as_ref())
            .map(|o| o.observation.challenge.revision);
        if refresh
            .as_ref()
            .ok()
            .zip(revision)
            .is_none_or(|(required, actual)| actual < *required)
        {
            return Ok(AuthorizationOutcome::Denied(Box::new(
                SelectionFailure::policy(
                    &request,
                    selection,
                    DenialReason::EndpointObservationUnavailable,
                ),
            )));
        }
    }
    Ok(outcome)
}

async fn snapshot_rows(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AccessRequest,
) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    // Every issuance/redemption path takes subject -> device before policy/node
    // guards. Revocation takes the corresponding exclusive identity guard.
    sqlx::query("SELECT id FROM identity.users WHERE id=$1 AND domain_id=$2 FOR SHARE")
        .bind(request.subject_user_id)
        .bind(request.domain_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT id FROM device.devices WHERE id=$1 AND domain_id=$2 FOR SHARE")
        .bind(request.device_id)
        .bind(request.domain_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(policy.ability_policy_lock_key($1, $2, $3))")
        .bind(request.domain_id)
        .bind(request.subject_user_id)
        .bind(request.target_node_id)
        .execute(&mut **transaction)
        .await?;
    // Lock BEFORE reading the joined observation: a SELECT that waits for a
    // row lock otherwise retains the statement's older READ COMMITTED snapshot.
    sqlx::query("SELECT n.id FROM device.nodes n JOIN device.devices d ON d.id=n.device_id WHERE n.id=$1 AND d.domain_id=$2 FOR SHARE OF n,d")
        .bind(request.target_node_id).bind(request.domain_id)
        .execute(&mut **transaction)
        .await?;
    let rows = sqlx::query(
        "SELECT policy.id, policy.domain_id, policy.subject_user_id, \
                policy.required_device_id, policy.target_node_id, policy.enabled, \
                policy.effect, policy.priority, policy.revision, policy.selector, \
                EXTRACT(EPOCH FROM policy.revoked_at)::bigint AS revoked_at, \
                CEIL(EXTRACT(EPOCH FROM policy.valid_from))::bigint AS valid_from, \
                FLOOR(EXTRACT(EPOCH FROM policy.valid_until))::bigint AS valid_until, \
                host(target.mesh_address) AS target_mesh_address, client.domain_id AS device_domain_id, \
                client.owner_user_id AS device_owner_user_id, \
                client.status = 'active' AND subject.status = 'active' AS device_active, subject.generation AS subject_generation, client.generation AS device_generation, \
                target.status = 'active' AND target_device.status = 'active' \
                    AND target_device.domain_id = policy.domain_id AS target_active, \
                target_device.device_public_key AS target_public_key, obs.envelope AS observation, obs.pending_challenge, obs.consumed, obs.revision AS observation_revision, client.wireguard_public_key, \
                host(client.mesh_address) AS device_mesh_address \
         FROM policy.ability_policies AS policy \
         JOIN device.devices AS client ON client.id = $3 \
         JOIN identity.users AS subject ON subject.id = $2 AND subject.domain_id = $1 \
         JOIN device.nodes AS target ON target.id = $4 \
         JOIN device.devices AS target_device ON target_device.id = target.device_id \
         LEFT JOIN device.endpoint_observations obs ON obs.node_id = target.id AND obs.domain_id = policy.domain_id \
         WHERE policy.domain_id = $1 AND policy.subject_user_id = $2 \
           AND policy.target_node_id = $4 \
         ORDER BY policy.id, policy.revision \
         FOR SHARE OF client, target, target_device",
    )
    .bind(request.domain_id)
    .bind(request.subject_user_id)
    .bind(request.device_id)
    .bind(request.target_node_id)
    .fetch_all(&mut **transaction)
    .await?;

    Ok(rows)
}

fn stored_rule(row: &sqlx::postgres::PgRow) -> Result<StoredAbilityPolicy, PolicyReadError> {
    let policy_id = row.try_get("id")?;
    let invalid = |cause: &str| PolicyReadError::InvalidPolicy {
        policy_id,
        cause: cause.to_owned(),
    };
    let effect = match row.try_get::<String, _>("effect")?.as_str() {
        "allow" => Effect::Allow,
        "deny" => Effect::Deny,
        _ => return Err(invalid("unknown effect")),
    };
    let selector = serde_json::from_value(row.try_get("selector")?).map_err(|cause| {
        PolicyReadError::InvalidPolicy {
            policy_id,
            cause: cause.to_string(),
        }
    })?;
    let rule = StoredAbilityPolicy {
        policy: PolicyRef {
            policy_id,
            revision: row.try_get("revision")?,
        },
        domain_id: row.try_get("domain_id")?,
        subject_user_id: row.try_get("subject_user_id")?,
        required_device_id: row.try_get("required_device_id")?,
        target_node_id: row.try_get("target_node_id")?,
        enabled: row.try_get("enabled")?,
        revoked: row.try_get::<Option<i64>, _>("revoked_at")?.is_some(),
        effect,
        priority: row.try_get("priority")?,
        selector,
        validity: Validity {
            not_before: row.try_get::<Option<i64>, _>("valid_from")?.unwrap_or(0),
            expires_at: row
                .try_get::<Option<i64>, _>("valid_until")?
                .unwrap_or(i64::MAX),
        },
    };
    if !rule.selector.is_valid()
        || !rule.validity.contains(rule.validity)
        || rule.policy.revision < 1
    {
        return Err(invalid("invalid selector, revision or validity"));
    }
    Ok(rule)
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
pub(crate) mod tests {
    use authority_policy_core::{Route, realization::Ability, scoped::RequestedTcp};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
    use std::time::Duration;

    use super::*;

    pub(crate) async fn lxc_pool(max_connections: u32) -> PgPool {
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
    async fn stored_ability_policies_fail_closed_in_postgres() {
        let pool = lxc_pool(1).await;
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let query = "SELECT $1::text AS effect, $2::jsonb AS selector, \
            '00000000-0000-0000-0000-000000000001'::uuid AS id, \
            '00000000-0000-0000-0000-000000000002'::uuid AS domain_id, \
            '00000000-0000-0000-0000-000000000003'::uuid AS subject_user_id, \
            '00000000-0000-0000-0000-000000000004'::uuid AS required_device_id, \
            '00000000-0000-0000-0000-000000000005'::uuid AS target_node_id, \
            true AS enabled, 100::integer AS priority, 1::bigint AS revision, \
            NULL::bigint AS revoked_at, NULL::bigint AS valid_from, NULL::bigint AS valid_until";
        let allow = sqlx::query(query)
            .bind("allow")
            .bind(serde_json::json!({"kind":"tcp_connection", "source":"10.0.0.1", "destination":"10.0.0.2", "ports":[8080]}))
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        assert!(stored_rule(&allow).is_ok());
        for effect in ["allow", "deny"] {
            for selector in [
                serde_json::json!({"kind":"unknown"}),
                serde_json::json!({"kind":"tcp_connection", "source":"10.0.0.1", "destination":"10.0.0.2", "ports":[]}),
                serde_json::json!({"kind":"tcp_connection", "source":"10.0.0.1", "destination":"10.0.0.2", "ports":[8080], "future":"ignored"}),
            ] {
                let invalid = sqlx::query(query)
                    .bind(effect)
                    .bind(selector)
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
                    assert!(matches!(parsed, Err(PolicyReadError::InvalidPolicy { .. })));
                }
            }
        }
        transaction.rollback().await.unwrap();
    }

    async fn wait_for_lock(pool: &PgPool, pid: i32) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock')",
                ).bind(pid).fetch_one(pool).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("concurrent transaction must wait on the authority guard");
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
        wait_for_lock(&observer, pid).await;
        writer
    }

    #[tokio::test]
    #[ignore = "requires LXC PostgreSQL and a bootstrapped poc:e2e policy"]
    async fn waiting_authorization_reads_the_committed_deny_under_read_committed() {
        let pool = lxc_pool(4).await;
        let (request, _) = live_tcp_request(&pool).await;
        let mut writer = begin_authorization(&pool).await.unwrap();
        let deny_id = Uuid::new_v4();
        sqlx::query("INSERT INTO policy.ability_policies (id,domain_id,subject_user_id,required_device_id,target_node_id,selector,effect,priority) SELECT $1,domain_id,subject_user_id,required_device_id,target_node_id,selector,'deny',100 FROM policy.ability_policies WHERE domain_id=$2 AND subject_user_id=$3 AND target_node_id=$4 AND selector->>'kind' IN ('tcp_connection','tcp_connection_range') LIMIT 1")
            .bind(deny_id).bind(request.domain_id).bind(request.subject_user_id).bind(request.target_node_id)
            .execute(&mut *writer).await.unwrap();
        let reader_pool = pool.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(async move {
            let mut tx = begin_authorization(&reader_pool).await.unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            sender.send(pid).unwrap();
            let outcome = authorize(
                &mut tx,
                request,
                &RequestedAccess {
                    tcp: Some(RequestedTcp {
                        source_addresses: None,
                        destination_addresses: None,
                        ports: authority_contracts_model::resources::PortSet::from_ports(
                            &BTreeSet::from([8080]),
                        )
                        .unwrap(),
                        ttl_seconds: 10,
                    }),
                    ..RequestedAccess::default()
                },
                LifetimeLimits {
                    ssh_seconds: 60,
                    network_seconds: 300,
                },
                &SelectionOptions::exact(Route::Direct),
            )
            .await;
            tx.rollback().await.unwrap();
            outcome
        });
        wait_for_lock(&pool, receiver.await.unwrap()).await;
        writer.commit().await.unwrap();
        let outcome = reader.await.unwrap();
        // Remove this test's committed deny before inspecting the result.
        sqlx::query("DELETE FROM policy.ability_policies WHERE id=$1")
            .bind(deny_id)
            .execute(&pool)
            .await
            .unwrap();
        let AuthorizationOutcome::Denied(reason) = outcome.unwrap() else {
            panic!("a reader waiting behind a committed deny must not use an older snapshot");
        };
        assert_eq!(reason.code(), "explicit_ability_deny");
    }

    pub(crate) async fn live_tcp_request(pool: &PgPool) -> (AccessRequest, Uuid) {
        let row = sqlx::query(
            "SELECT p.domain_id, p.subject_user_id, p.required_device_id, p.target_node_id, n.device_id AS target_device_id \
             FROM policy.ability_policies p JOIN device.devices d ON d.id = p.required_device_id \
             JOIN device.nodes n ON n.id = p.target_node_id \
             WHERE p.enabled AND p.effect = 'allow' AND p.selector->>'kind' IN ('tcp_connection','tcp_connection_range') \
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
                source_addresses: None,
                destination_addresses: None,
                ports: authority_contracts_model::resources::PortSet::from_ports(&BTreeSet::from(
                    [8080],
                ))
                .unwrap(),
                ttl_seconds: 10,
            }),
            ..RequestedAccess::default()
        };
        let updates = [
            "UPDATE policy.ability_policies SET enabled = enabled WHERE id = $1",
            "UPDATE device.devices SET status = status WHERE id = $1",
            "UPDATE device.nodes SET status = status WHERE id = $1",
            "UPDATE device.nodes SET endpoint_facts = endpoint_facts WHERE id = $1",
            "UPDATE device.devices SET status = status WHERE id = $1",
            "INSERT INTO policy.ability_policies (id,domain_id,subject_user_id,required_device_id,target_node_id,selector,effect) SELECT md5(random()::text)::uuid,domain_id,subject_user_id,required_device_id,target_node_id,selector,'deny' FROM policy.ability_policies WHERE id = $1",
        ];
        for (index, update) in updates.into_iter().enumerate() {
            let mut transaction = begin_authorization(&pool).await.unwrap();
            let isolation: String = sqlx::query_scalar("SHOW transaction_isolation")
                .fetch_one(&mut *transaction)
                .await
                .unwrap();
            assert_eq!(isolation, "read committed");
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
                0 | 5 => {
                    authorized.decision.sources[&Ability::TcpConnection]
                        .first()
                        .unwrap()
                        .policy_id
                }
                1 => request.device_id,
                2 | 3 => request.target_node_id,
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
    #[tokio::test]
    #[ignore = "requires LXC PostgreSQL and a bootstrapped poc:e2e policy"]
    async fn concrete_ability_denies_are_atomic_and_scope_specific_in_postgres() {
        let pool = lxc_pool(2).await;
        let (request, _) = live_tcp_request(&pool).await;
        let mut tx = begin_authorization(&pool).await.unwrap();
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO policy.ability_policies (id,domain_id,subject_user_id,required_device_id,target_node_id,selector,effect,priority) SELECT $1,domain_id,subject_user_id,required_device_id,target_node_id,jsonb_set(selector,'{ports}', CASE WHEN selector->>'kind'='tcp_connection_range' THEN '[{\"start\":8081,\"end\":8082}]'::jsonb ELSE '[8081]'::jsonb END),'deny',100 FROM policy.ability_policies WHERE domain_id=$2 AND subject_user_id=$3 AND target_node_id=$4 AND selector->>'kind' IN ('tcp_connection','tcp_connection_range') LIMIT 1")
            .bind(id).bind(request.domain_id).bind(request.subject_user_id).bind(request.target_node_id)
            .execute(&mut *tx).await.unwrap();
        for (ports, allowed) in [
            (BTreeSet::from([8080]), true),
            (BTreeSet::from([8081]), false),
            (BTreeSet::from([8080, 8081]), false),
        ] {
            let result = authorize(
                &mut tx,
                request.clone(),
                &RequestedAccess {
                    tcp: Some(RequestedTcp {
                        source_addresses: None,
                        destination_addresses: None,
                        ports: authority_contracts_model::resources::PortSet::from_ports(&ports)
                            .unwrap(),
                        ttl_seconds: 10,
                    }),
                    ..RequestedAccess::default()
                },
                LifetimeLimits {
                    ssh_seconds: 60,
                    network_seconds: 300,
                },
                &SelectionOptions::exact(Route::Direct),
            )
            .await
            .unwrap();
            match result {
                AuthorizationOutcome::Allowed(_) => assert!(allowed),
                AuthorizationOutcome::Denied(reason) => {
                    assert!(!allowed);
                    assert_eq!(reason.code(), "explicit_ability_deny");
                }
            }
        }
        sqlx::query("UPDATE policy.ability_policies SET selector = '{\"kind\":\"future_ability\"}'::jsonb WHERE id=$1")
            .bind(id).execute(&mut *tx).await.unwrap();
        let outcome = authorize(
            &mut tx,
            request,
            &RequestedAccess {
                tcp: Some(RequestedTcp {
                    source_addresses: None,
                    destination_addresses: None,
                    ports: authority_contracts_model::resources::PortSet::from_ports(
                        &BTreeSet::from([8080]),
                    )
                    .unwrap(),
                    ttl_seconds: 10,
                }),
                ..RequestedAccess::default()
            },
            LifetimeLimits {
                ssh_seconds: 60,
                network_seconds: 300,
            },
            &SelectionOptions::exact(Route::Direct),
        )
        .await
        .unwrap();
        let AuthorizationOutcome::Denied(reason) = outcome else {
            panic!("unknown deny must reject the whole snapshot");
        };
        assert_eq!(reason.code(), "invalid_policy");
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires LXC PostgreSQL and a bootstrapped poc:e2e policy"]
    async fn unsigned_manifests_cannot_override_signed_endpoint_evidence() {
        let pool = lxc_pool(2).await;
        let (request, _) = live_tcp_request(&pool).await;
        let inputs = RequestedAccess {
            tcp: Some(RequestedTcp {
                source_addresses: None,
                destination_addresses: None,
                ports: authority_contracts_model::resources::PortSet::from_ports(&BTreeSet::from(
                    [8080],
                ))
                .unwrap(),
                ttl_seconds: 10,
            }),
            ..RequestedAccess::default()
        };
        for mutation in 0..6 {
            let mut tx = begin_authorization(&pool).await.unwrap();
            sqlx::query("UPDATE device.nodes SET endpoint_facts=ARRAY['future.fact','tcp_enforcement','existing_route_configured'] WHERE id=$1").bind(request.target_node_id).execute(&mut *tx).await.unwrap();
            let query = match mutation {
                0 => None,
                1 => Some("UPDATE device.endpoint_observations SET envelope=NULL WHERE node_id=$1"),
                2 => {
                    Some("UPDATE device.endpoint_observations SET consumed=false WHERE node_id=$1")
                }
                3 => Some(
                    "UPDATE device.endpoint_observations SET envelope=jsonb_set(envelope,'{observation,facts}','[\"future.fact\"]') WHERE node_id=$1",
                ),
                4 => Some(
                    "UPDATE device.endpoint_observations SET envelope=jsonb_set(envelope,'{observation,expires_at}','1') WHERE node_id=$1",
                ),
                _ => Some(
                    "UPDATE device.endpoint_observations SET envelope=jsonb_set(envelope,'{observation,challenge,resources,source}','\"10.77.0.99\"') WHERE node_id=$1",
                ),
            };
            if let Some(query) = query {
                sqlx::query(query)
                    .bind(request.target_node_id)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let result = authorize(
                &mut tx,
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
            if mutation == 0 {
                assert!(
                    matches!(result, AuthorizationOutcome::Allowed(_)),
                    "unsigned manifest must be ignored"
                );
            } else {
                assert!(
                    matches!(result, AuthorizationOutcome::Denied(_)),
                    "mutation {mutation} must deny"
                );
            }
            tx.rollback().await.unwrap();
        }
    }
}
