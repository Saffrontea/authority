use authority_policy_core::{AccessDecision, AccessRequest, PolicyCandidate, evaluate};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub async fn authorize(
    pool: &PgPool,
    request: AccessRequest,
) -> Result<Option<AccessDecision>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT policy.id, policy.domain_id, policy.subject_user_id, \
                policy.required_device_id, policy.target_node_id, policy.enabled, \
                EXTRACT(EPOCH FROM policy.valid_from)::bigint AS valid_from, \
                EXTRACT(EPOCH FROM policy.valid_until)::bigint AS valid_until, \
                policy.ssh_principal, client.domain_id AS device_domain_id, \
                client.owner_user_id AS device_owner_user_id, \
                client.status = 'active' AS device_active, \
                target.status = 'active' AS target_active, client.wireguard_public_key \
                , host(client.mesh_address) AS device_mesh_address \
         FROM policy.access_policies AS policy \
         JOIN device.devices AS client ON client.id = $3 \
         JOIN device.nodes AS target ON target.id = $4 \
         WHERE policy.domain_id = $1 AND policy.subject_user_id = $2 \
           AND policy.target_node_id = $4 \
         ORDER BY policy.id LIMIT 1",
    )
    .bind(request.domain_id)
    .bind(request.subject_user_id)
    .bind(request.device_id)
    .bind(request.target_node_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let candidate = PolicyCandidate {
        policy_id: row.try_get("id")?,
        domain_id: row.try_get("domain_id")?,
        subject_user_id: row.try_get("subject_user_id")?,
        required_device_id: row.try_get("required_device_id")?,
        target_node_id: row.try_get("target_node_id")?,
        enabled: row.try_get("enabled")?,
        valid_from: row.try_get("valid_from")?,
        valid_until: row.try_get("valid_until")?,
        ssh_principal: row.try_get("ssh_principal")?,
        device_domain_id: row.try_get("device_domain_id")?,
        device_owner_user_id: row.try_get("device_owner_user_id")?,
        device_active: row.try_get("device_active")?,
        target_active: row.try_get("target_active")?,
        wireguard_public_key: row.try_get("wireguard_public_key")?,
        device_mesh_address: row.try_get("device_mesh_address")?,
    };
    Ok(evaluate(&request, candidate).ok())
}

pub fn request(
    domain_id: Uuid,
    subject_user_id: Uuid,
    device_id: Uuid,
    target_node_id: Uuid,
    evaluated_at: i64,
) -> AccessRequest {
    AccessRequest {
        domain_id,
        subject_user_id,
        device_id,
        target_node_id,
        evaluated_at,
    }
}
