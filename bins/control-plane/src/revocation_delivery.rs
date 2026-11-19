use std::time::Duration;

use authority_contracts_model::SignedDecisionRevocationNoticeV2;
use tracing::{info, warn};

use crate::state::AppState;

// The PoC has one configured target. Its origin is the LXC underlay address,
// independent of both the browser and the WireGuard peer being revoked.
pub fn client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
}

pub async fn run(state: AppState, client: reqwest::Client) {
    let worker = uuid::Uuid::new_v4();
    loop {
        if let Err(cause) = reconcile(&state, &client, worker).await {
            warn!(%cause, "revocation delivery reconciliation failed; will retry");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn reconcile(
    state: &AppState,
    client: &reqwest::Client,
    worker: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(delivery) = claim(state.pool(), worker).await? else {
        return Ok(());
    };
    let Delivery {
        sequence,
        receiver,
        origin,
        notice,
    } = delivery;
    match deliver(client, &origin, &notice).await {
        Ok(()) => {
            sqlx::query("UPDATE policy.adapter_deliveries SET completed_at=clock_timestamp() WHERE sequence=$1 AND receiver_id=$2 AND lease_owner=$3")
                .bind(sequence).bind(&receiver).bind(worker).execute(state.pool()).await?;
            info!(decision_id=%notice.notice.decision_id, %receiver, "revocation delivered to adapter");
        }
        Err(cause) => {
            sqlx::query("UPDATE policy.adapter_deliveries SET lease_until=clock_timestamp()+interval '1 second' WHERE sequence=$1 AND receiver_id=$2 AND lease_owner=$3")
                .bind(sequence).bind(&receiver).bind(worker).execute(state.pool()).await?;
            warn!(%cause, decision_id=%notice.notice.decision_id, %receiver, "revocation delivery failed; will retry");
        }
    }
    Ok(())
}

struct Delivery {
    sequence: i64,
    receiver: String,
    origin: String,
    notice: SignedDecisionRevocationNoticeV2,
}

async fn claim(
    pool: &sqlx::PgPool,
    worker: uuid::Uuid,
) -> Result<Option<Delivery>, Box<dyn std::error::Error + Send + Sync>> {
    use sqlx::Row;
    let mut tx = authority_mtls_core::database::begin(pool).await?;
    let row = sqlx::query("SELECT d.sequence,d.receiver_id,d.origin,n.envelope FROM policy.adapter_deliveries d JOIN policy.revocation_notices n USING(sequence) WHERE d.completed_at IS NULL AND (d.lease_until IS NULL OR d.lease_until<=clock_timestamp()) AND n.expires_at>clock_timestamp() ORDER BY d.sequence FOR UPDATE OF d SKIP LOCKED LIMIT 1")
        .fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let sequence: i64 = row.try_get("sequence")?;
    let receiver: String = row.try_get("receiver_id")?;
    let origin: String = row.try_get("origin")?;
    let notice: SignedDecisionRevocationNoticeV2 =
        serde_json::from_value(row.try_get("envelope")?)?;
    sqlx::query("UPDATE policy.adapter_deliveries SET lease_owner=$3,lease_until=clock_timestamp()+interval '15 seconds' WHERE sequence=$1 AND receiver_id=$2")
        .bind(sequence).bind(&receiver).bind(worker).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Some(Delivery {
        sequence,
        receiver,
        origin,
        notice,
    }))
}

async fn deliver(
    client: &reqwest::Client,
    origin: &str,
    notice: &SignedDecisionRevocationNoticeV2,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut response = client
        .post(format!("{}/v1/revocations", origin.trim_end_matches('/')))
        .json(notice)
        .send()
        .await?
        .error_for_status()?;
    if !response.status().is_success() {
        return Err(format!(
            "network agent did not acknowledge revocation: {}",
            response.status()
        )
        .into());
    }
    while response.chunk().await?.is_some() {}

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    async fn delivery_response_body(
        status: &str,
        response_body: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let notice: SignedDecisionRevocationNoticeV2 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/signed-decision-revocation-notice-v2/valid/basic.json"
        ))?;
        let body = serde_json::to_vec(&notice)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(offset) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    && request.len() >= offset + 4 + body.len()
                {
                    assert!(request.starts_with(b"POST /v1/revocations HTTP/1.1\r\n"));
                    assert_eq!(&request[offset + 4..], body);
                    break;
                }
            }
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let result = deliver(&client()?, &origin, &notice).await;
        server.await?;
        result
    }

    async fn delivery_response(
        status: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        delivery_response_body(status, "").await
    }

    #[tokio::test]
    async fn delivers_signed_notice_without_browser() {
        delivery_response("200 OK").await.unwrap();
    }

    #[tokio::test]
    async fn stalled_response_body_is_not_acknowledged() {
        let notice: SignedDecisionRevocationNoticeV2 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/signed-decision-revocation-notice-v2/valid/basic.json"
        ))
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let body_len = serde_json::to_vec(&notice).unwrap().len();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(offset) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    && request.len() >= offset + 4 + body_len
                {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(7),
            deliver(&client().unwrap(), &origin, &notice),
        )
        .await;
        server.abort();
        let error = result
            .expect("request deadline must include the response body")
            .unwrap_err();
        assert!(
            error.downcast_ref::<reqwest::Error>().unwrap().is_timeout(),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn redirects_are_not_acknowledgements() {
        assert!(delivery_response("302 Found").await.is_err());
    }

    #[tokio::test]
    async fn failed_delivery_remains_retryable() {
        assert!(delivery_response("503 Service Unavailable").await.is_err());
        delivery_response("200 OK").await.unwrap();
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires migrated LXC PostgreSQL; run without live PoC dispatchers"]
    async fn delivery_claims_are_shared_and_recovered_after_worker_lease_expiry() {
        let left = crate::access_policy::tests::lxc_pool(2).await;
        let right = crate::access_policy::tests::lxc_pool(2).await;
        let mut notice: SignedDecisionRevocationNoticeV2 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/signed-decision-revocation-notice-v2/valid/basic.json"
        ))
        .unwrap();
        let mut tx = authority_mtls_core::database::begin(&left).await.unwrap();
        sqlx::query("SELECT id FROM policy.revocation_stream FOR UPDATE")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let sequence: i64 =
            sqlx::query_scalar("SELECT nextval('policy.revocation_notice_sequence')")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        notice.notice.sequence = sequence;
        let domain = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO policy.revocation_notices(sequence,domain_id,target_node_id,decision_id,reason,revoked_at,expires_at,envelope,scope_key) VALUES($1,$2,$3,$4,'test',clock_timestamp(),clock_timestamp()+interval '60 seconds',$5,'wireguard.peer')")
            .bind(sequence).bind(domain).bind(uuid::Uuid::new_v4()).bind(uuid::Uuid::new_v4().to_string()).bind(serde_json::to_value(notice).unwrap()).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO policy.adapter_deliveries(sequence,receiver_id,origin) VALUES($1,'test','http://127.0.0.1:1')").bind(sequence).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let (a, b) = tokio::join!(claim(&left, first), claim(&right, second));
        let a = a.unwrap();
        let b = b.unwrap();
        assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
        assert_eq!(a.as_ref().or(b.as_ref()).unwrap().sequence, sequence);
        let old_owner = if a.is_some() { first } else { second };
        let new_owner = if a.is_some() { second } else { first };
        sqlx::query("UPDATE policy.adapter_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE sequence=$1").bind(sequence).execute(&left).await.unwrap();
        assert_eq!(
            claim(&right, new_owner).await.unwrap().unwrap().sequence,
            sequence
        );
        let stale=sqlx::query("UPDATE policy.adapter_deliveries SET completed_at=clock_timestamp() WHERE sequence=$1 AND lease_owner=$2").bind(sequence).bind(old_owner).execute(&left).await.unwrap();
        assert_eq!(stale.rows_affected(), 0);
        sqlx::query("DELETE FROM policy.adapter_deliveries WHERE sequence=$1")
            .bind(sequence)
            .execute(&left)
            .await
            .unwrap();
        sqlx::query("DELETE FROM policy.revocation_notices WHERE sequence=$1")
            .bind(sequence)
            .execute(&left)
            .await
            .unwrap();
    }
}
