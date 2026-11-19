//! Independent connection pools exercise PostgreSQL authority, not local fixtures.
use super::*;
use authority_contracts_model::{AdapterGrantKindV1, DecisionRevocationNoticeV2};
use std::time::Duration;

fn authorization() -> MtlsIssuanceAuthorizationV1 {
    let now = crate::unix_timestamp().unwrap();
    MtlsIssuanceAuthorizationV1 {
        version: "1".into(),
        issuer: "test".into(),
        domain_id: uuid::Uuid::new_v4().to_string(),
        target_node_id: uuid::Uuid::new_v4().to_string(),
        subject_user_id: "subject".into(),
        device_id: "device".into(),
        client_spki_sha256: "fixture".into(),
        identity_uri: "spiffe://test/user/device".into(),
        service_audience: "test".into(),
        policy_id: "test".into(),
        decision_id: uuid::Uuid::new_v4().to_string(),
        nonce: uuid::Uuid::new_v4().to_string(),
        issued_at: now,
        not_before: now - 1,
        expires_at: now + 60,
        audience: "test".into(),
    }
}
fn notice(a: &MtlsIssuanceAuthorizationV1) -> SignedDecisionRevocationNoticeV2 {
    SignedDecisionRevocationNoticeV2 {
        notice: DecisionRevocationNoticeV2 {
            version: "2".into(),
            issuer: "test".into(),
            domain_id: a.domain_id.clone(),
            target_node_id: a.target_node_id.clone(),
            decision_id: a.decision_id.clone(),
            reason: "test".into(),
            sequence: 0,
            revoked_at: crate::unix_timestamp().unwrap(),
            expires_at: a.expires_at,
            adapter_kinds: vec![AdapterGrantKindV1::MtlsClientCertificate],
        },
        algorithm: "fixture".into(),
        key_id: "fixture".into(),
        signature: "fixture".into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires migrated LXC PostgreSQL, AUTHORITY_DB_HOST and password file"]
async fn independent_replicas_share_nonce_serial_and_revocation_locks() {
    let left = AuthorityDb::from_env().await.unwrap();
    let right = AuthorityDb::from_env().await.unwrap();
    let namespace = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let expires = crate::unix_timestamp().unwrap() + 60;
    let (a, b) = tokio::join!(
        left.consume_serial(&namespace, &nonce, expires),
        right.consume_serial(&namespace, &nonce, expires)
    );
    assert_eq!(
        usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
        1
    );
    let a = left
        .consume_serial(&namespace, "left", expires)
        .await
        .unwrap()
        .unwrap();
    let b = right
        .consume_serial(&namespace, "right", expires)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(a, b);

    let cert = X509::from_pem(&std::fs::read("../../.secrets/mtls-ca-cert.pem").unwrap()).unwrap();
    let ca = ca_id(&cert).unwrap();
    left.register_ca(&ca, &cert).await.unwrap();
    let auth = authorization();
    assert!(
        left.issue(&ca, &auth, |_| Err("signing failure".into()))
            .await
            .is_err()
    );
    // Failure rolls back consumption; a different process can retry.
    right.issue(&ca, &auth, |_| Ok(cert.clone())).await.unwrap();
    assert!(matches!(
        left.issue(&ca, &auth, |_| Ok(cert.clone())).await,
        Err(AccessError::Replay)
    ));

    let auth = authorization();
    let mut tx = begin(left.pool()).await.unwrap();
    revoke_in(&mut tx, &notice(&auth)).await.unwrap();
    let peer = right.clone();
    let ca_copy = ca.clone();
    let auth_copy = auth.clone();
    let mut issuing =
        tokio::spawn(async move { peer.issue(&ca_copy, &auth_copy, |_| Ok(cert)).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut issuing)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert!(matches!(issuing.await.unwrap(), Err(AccessError::Revoked)));
    assert!(!right.certificate_active(&ca, i64::MAX).await.unwrap());
}

async fn publish(db: &AuthorityDb, auth: &MtlsIssuanceAuthorizationV1) -> i64 {
    let mut tx = begin(db.pool()).await.unwrap();
    sqlx::query("SELECT id FROM policy.revocation_stream FOR UPDATE")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let sequence: i64 = sqlx::query_scalar("SELECT nextval('policy.revocation_notice_sequence')")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let mut envelope = notice(auth);
    envelope.notice.sequence = sequence;
    sqlx::query("INSERT INTO policy.revocation_notices(sequence,domain_id,target_node_id,decision_id,reason,revoked_at,expires_at,envelope,scope_key) VALUES($1,$2,$3,$4,'test',clock_timestamp(),clock_timestamp()+interval '60 seconds',$5,'mtls.client_certificate')")
        .bind(sequence).bind(auth.domain_id.parse::<uuid::Uuid>().unwrap()).bind(auth.target_node_id.parse::<uuid::Uuid>().unwrap()).bind(&auth.decision_id).bind(serde_json::to_value(envelope).unwrap()).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    sequence
}

#[tokio::test]
#[ignore = "requires migrated LXC PostgreSQL, AUTHORITY_DB_HOST and password file"]
async fn replica_cursors_require_contiguous_receipts_and_catchup_before_lease() {
    let left = AuthorityDb::from_env().await.unwrap();
    let right = AuthorityDb::from_env().await.unwrap();
    let mut auth = authorization();
    let instance = uuid::Uuid::new_v4();
    left.register_instance(
        instance,
        auth.domain_id.parse().unwrap(),
        auth.target_node_id.parse().unwrap(),
    )
    .await
    .unwrap();
    let first = publish(&left, &auth).await;
    assert!(!right.acknowledge_and_renew(instance, &[]).await.unwrap());
    assert!(
        right
            .acknowledge_and_renew(instance, &[first + 1])
            .await
            .is_err()
    );
    auth.decision_id = uuid::Uuid::new_v4().to_string();
    let second = publish(&left, &auth).await;
    // A commit between fetch and acknowledgement may extend the next page;
    // acknowledging the exact fetched prefix must not skip that new event.
    assert!(
        !right
            .acknowledge_and_renew(instance, &[first])
            .await
            .unwrap()
    );
    assert_eq!(
        left.events(instance).await.unwrap()[0].notice.sequence,
        second
    );
    assert!(
        left.acknowledge_and_renew(instance, &[second])
            .await
            .unwrap()
    );
    let restarted = uuid::Uuid::new_v4();
    right
        .register_instance(
            restarted,
            auth.domain_id.parse().unwrap(),
            auth.target_node_id.parse().unwrap(),
        )
        .await
        .unwrap();
    assert!(!right.acknowledge_and_renew(restarted, &[]).await.unwrap());
    assert_eq!(right.events(restarted).await.unwrap().len(), 2);
    assert!(
        right
            .acknowledge_and_renew(restarted, &[first, second])
            .await
            .unwrap()
    );
}
