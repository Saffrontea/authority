//! Issuance provenance, committed with signing/audit/outbox. These records are
//! deliberately not installed-ability observations and never seed the solver.

use authority_contracts_model::{AdapterGrantKindV1, DecisionRevocationNoticeV2};
use authority_policy_core::{realization::Ability, scoped::AuthorizedPlan};
use sqlx::{Postgres, Transaction};

fn stored_kind(ability: Ability) -> Option<&'static str> {
    match ability {
        Ability::MeshMembership => Some("mesh_membership"),
        Ability::SshCredential => Some("ssh_credential"),
        Ability::MtlsCredential => Some("mtls_credential"),
        Ability::TcpAdmission => Some("tcp_admission"),
        _ => None,
    }
}

pub async fn record(
    transaction: &mut Transaction<'_, Postgres>,
    decision_id: &str,
    plan: &AuthorizedPlan,
) -> Result<(), sqlx::Error> {
    let evidence = plan.evidence().plan.as_ref().ok_or_else(|| {
        sqlx::Error::Protocol("authorized plan is missing issuance evidence".into())
    })?;
    let issued: std::collections::BTreeSet<_> = evidence
        .steps
        .iter()
        .flat_map(|step| step.provides.iter().copied())
        .collect();
    for index in issued {
        let record = evidence.abilities.get(index).ok_or_else(|| {
            sqlx::Error::Protocol("issuance step refers to an unknown ability".into())
        })?;
        let Some(kind) = stored_kind(record.ability.scope.kind()) else {
            continue;
        };
        let ability = &record.ability;
        sqlx::query("INSERT INTO policy.issued_ability_grants (domain_id,subject_user_id,device_id,target_node_id,decision_id,ability_kind,ability,policy_refs,not_before,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(ability.binding.domain_id).bind(ability.binding.subject_user_id)
            .bind(ability.binding.device_id).bind(ability.binding.target_node_id)
            .bind(decision_id).bind(kind)
            .bind(serde_json::to_value(ability).map_err(|cause| sqlx::Error::Encode(Box::new(cause)))?)
            .bind(serde_json::to_value(&record.policies).map_err(|cause| sqlx::Error::Encode(Box::new(cause)))?)
            .bind(ability.validity.not_before).bind(ability.validity.expires_at)
            .execute(&mut **transaction).await?;
    }
    Ok(())
}

/// Must run in the same transaction that publishes the signed notice.
pub async fn revoke(
    transaction: &mut Transaction<'_, Postgres>,
    notice: &DecisionRevocationNoticeV2,
) -> Result<(), sqlx::Error> {
    let domain: uuid::Uuid = notice
        .domain_id
        .parse()
        .map_err(|cause| sqlx::Error::Decode(Box::new(cause)))?;
    let target: uuid::Uuid = notice
        .target_node_id
        .parse()
        .map_err(|cause| sqlx::Error::Decode(Box::new(cause)))?;
    let kinds: Vec<_> = notice
        .adapter_kinds
        .iter()
        .map(|kind| match kind {
            AdapterGrantKindV1::WireGuardPeer => "mesh_membership",
            AdapterGrantKindV1::SshCertificate | AdapterGrantKindV1::SshSession => "ssh_credential",
            AdapterGrantKindV1::MtlsClientCertificate => "mtls_credential",
            AdapterGrantKindV1::TcpPort => "tcp_admission",
        })
        .collect();
    sqlx::query("UPDATE policy.issued_ability_grants SET revoked_at=LEAST(COALESCE(revoked_at,$5),$5) WHERE domain_id=$1 AND target_node_id=$2 AND decision_id=$3 AND ability_kind=ANY($4)")
        .bind(domain).bind(target).bind(&notice.decision_id).bind(kinds).bind(notice.revoked_at)
        .execute(&mut **transaction).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_policy::{
        self, AuthorizationOutcome,
        tests::{live_tcp_request, lxc_pool},
    };
    use authority_policy_core::{
        Route,
        scoped::{LifetimeLimits, RequestedAccess, RequestedTcp},
        selection::SelectionOptions,
    };
    use sqlx::Row;
    use std::collections::BTreeSet;
    use uuid::Uuid;

    async fn plan(pool: &sqlx::PgPool) -> AuthorizedPlan {
        let (request, _) = live_tcp_request(pool).await;
        let mut tx = access_policy::begin_authorization(pool).await.unwrap();
        let outcome = access_policy::authorize(
            &mut tx,
            request,
            &RequestedAccess {
                tcp: Some(RequestedTcp {
                    ports: BTreeSet::from([8080]),
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
        tx.rollback().await.unwrap();
        let AuthorizationOutcome::Allowed(authorized) = outcome else {
            panic!("fixture must authorize");
        };
        authorized.plan
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL and an ability policy fixture"]
    async fn issued_abilities_and_audit_rollback_together() {
        let pool = lxc_pool(2).await;
        let plan = plan(&pool).await;
        let decision = Uuid::new_v4().simple().to_string();
        let mut tx = access_policy::begin_authorization(&pool).await.unwrap();
        record(&mut tx, &decision, &plan).await.unwrap();
        crate::planning_audit::insert(&mut tx, &decision, plan.evidence(), None)
            .await
            .unwrap();
        let row = sqlx::query("SELECT ability,policy_refs,revoked_at FROM policy.issued_ability_grants WHERE decision_id=$1")
            .bind(&decision).fetch_one(&mut *tx).await.unwrap();
        let ability: authority_policy_core::scoped::ScopedAbility =
            serde_json::from_value(row.get("ability")).unwrap();
        assert_eq!(ability.scope.kind(), Ability::TcpAdmission);
        assert_eq!(ability.binding, plan.binding());
        assert_eq!(ability.validity.not_before, plan.issued_at());
        assert!(row.get::<Option<i64>, _>("revoked_at").is_none());
        assert!(
            !row.get::<serde_json::Value, _>("policy_refs")
                .as_array()
                .unwrap()
                .is_empty()
        );
        let invisible: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM policy.issued_ability_grants WHERE decision_id=$1",
        )
        .bind(&decision)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(invisible, 0);
        assert!(
            sqlx::query(
                "INSERT INTO outbox.events SELECT * FROM outbox.events WHERE aggregate_id=$1"
            )
            .bind(&decision)
            .execute(&mut *tx)
            .await
            .is_err()
        );
        tx.rollback().await.unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM policy.issued_ability_grants WHERE decision_id=$1) + (SELECT count(*) FROM outbox.events WHERE aggregate_id=$1) + (SELECT count(*) FROM audit.events WHERE payload->>'decision_id'=$1)")
            .bind(&decision).fetch_one(&pool).await.unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL and an ability policy fixture"]
    async fn revocation_is_scoped_and_transactional_for_issued_abilities() {
        let pool = lxc_pool(2).await;
        let plan = plan(&pool).await;
        let decision = Uuid::new_v4().simple().to_string();
        let mut tx = access_policy::begin_authorization(&pool).await.unwrap();
        record(&mut tx, &decision, &plan).await.unwrap();
        tx.commit().await.unwrap();
        let binding = plan.binding();
        let mut notice = DecisionRevocationNoticeV2 {
            version: "2".into(),
            issuer: authority_contracts_model::protocol::domain_issuer(binding.domain_id),
            domain_id: binding.domain_id.to_string(),
            target_node_id: binding.target_node_id.to_string(),
            decision_id: decision.clone(),
            reason: "test".into(),
            sequence: 1,
            revoked_at: plan.issued_at(),
            expires_at: plan.issued_at() + 10,
            adapter_kinds: vec![AdapterGrantKindV1::WireGuardPeer],
        };
        let mut tx = access_policy::begin_authorization(&pool).await.unwrap();
        revoke(&mut tx, &notice).await.unwrap();
        let untouched: Option<i64> = sqlx::query_scalar(
            "SELECT revoked_at FROM policy.issued_ability_grants WHERE decision_id=$1",
        )
        .bind(&decision)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(untouched.is_none());
        notice.adapter_kinds = vec![AdapterGrantKindV1::TcpPort];
        revoke(&mut tx, &notice).await.unwrap();
        let invisible: Option<i64> = sqlx::query_scalar(
            "SELECT revoked_at FROM policy.issued_ability_grants WHERE decision_id=$1",
        )
        .bind(&decision)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(invisible.is_none());
        tx.rollback().await.unwrap();
        let mut tx = access_policy::begin_authorization(&pool).await.unwrap();
        revoke(&mut tx, &notice).await.unwrap();
        tx.commit().await.unwrap();
        let revoked: Option<i64> = sqlx::query_scalar(
            "SELECT revoked_at FROM policy.issued_ability_grants WHERE decision_id=$1",
        )
        .bind(&decision)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM policy.issued_ability_grants WHERE decision_id=$1")
            .bind(&decision)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(revoked, Some(notice.revoked_at));
    }
}
