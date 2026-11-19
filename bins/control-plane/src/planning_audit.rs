use authority_policy_core::selection::PlanningEvidence;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

fn payload(decision_id: &str, evidence: &PlanningEvidence) -> Result<Value, sqlx::Error> {
    if decision_id.is_empty() || decision_id.len() > 128 || !evidence.is_consistent() {
        return Err(sqlx::Error::Protocol(
            "inconsistent planning evidence".to_owned(),
        ));
    }
    Ok(json!({ "decision_id": decision_id, "planning": evidence }))
}

/// The planning audit and its outbox event share the authorization transaction.
/// Existing policy.decision.evaluated v1 payloads remain unchanged.
pub async fn insert(
    transaction: &mut Transaction<'_, Postgres>,
    decision_id: &str,
    evidence: &PlanningEvidence,
    denial_reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    let payload = payload(decision_id, evidence)?;
    let decision = if evidence.selected.is_some() {
        "allow"
    } else {
        "deny"
    };
    sqlx::query(
        "INSERT INTO audit.events \
         (domain_id, actor_type, actor_id, action, target_type, target_id, decision, reason, payload) \
         VALUES ($1, 'user', $2, 'access.plan', 'node', $3, $4, $5, $6)",
    )
    .bind(evidence.binding.domain_id)
    .bind(evidence.binding.subject_user_id.to_string())
    .bind(evidence.binding.target_node_id.to_string())
    .bind(decision)
    .bind(denial_reason)
    .bind(&payload)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO outbox.events \
         (id, owner_module, aggregate_type, aggregate_id, event_type, contract_version, payload, occurred_at) \
         VALUES ($1, 'policy', 'access_decision', $2, 'policy.plan.evaluated', $4, $3, now())",
    )
    .bind(Uuid::new_v4())
    .bind(decision_id)
    .bind(payload)
    .bind(i16::from(evidence.version))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_payload_preserves_allow_and_deny_evidence_and_rejects_inconsistency() {
        for vector in [
            include_str!(
                "../../../contracts/test-vectors/policy-plan-evaluated-v2/valid/existing-route.json"
            ),
            include_str!(
                "../../../contracts/test-vectors/policy-plan-evaluated-v2/valid/no-implementation.json"
            ),
        ] {
            let value: Value = serde_json::from_str(vector).unwrap();
            let evidence: PlanningEvidence =
                serde_json::from_value(value["planning"].clone()).unwrap();
            assert_eq!(
                payload(value["decision_id"].as_str().unwrap(), &evidence).unwrap(),
                value
            );
        }
        let value: Value = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/policy-plan-evaluated-v2/invalid/rebound-credential.json"
        ))
        .unwrap();
        let evidence: PlanningEvidence = serde_json::from_value(value["planning"].clone()).unwrap();
        assert!(payload("denied", &evidence).is_err());
    }
}
