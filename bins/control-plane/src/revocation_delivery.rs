use std::{collections::HashMap, time::Duration};

use authority_contracts_model::SignedDecisionRevocationNoticeV2;
use serde_json::Value;
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
    let mut delivered = HashMap::new();
    loop {
        if let Err(cause) = reconcile(&state, &client, &mut delivered).await {
            warn!(%cause, "revocation delivery reconciliation failed; will retry");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn reconcile(
    state: &AppState,
    client: &reqwest::Client,
    delivered: &mut HashMap<i64, i64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let identity: Value =
        serde_json::from_slice(&tokio::fs::read(state.target_identity_file()).await?)?;
    let target = identity["node_id"]
        .as_str()
        .ok_or("missing target node id")?
        .parse::<uuid::Uuid>()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let now = i64::try_from(now)?;
    delivered.retain(|_, expires_at| *expires_at > now);
    let values: Vec<Value> = sqlx::query_scalar(
        "SELECT envelope FROM policy.revocation_notices \
         WHERE domain_id = $1 AND target_node_id = $2 AND expires_at > now() \
           AND envelope->'notice' ? 'adapter_kinds' ORDER BY sequence",
    )
    .bind(state.domain_id())
    .bind(target)
    .fetch_all(state.pool())
    .await?;
    for value in values {
        let notice: SignedDecisionRevocationNoticeV2 = serde_json::from_value(value)?;
        if delivered.contains_key(&notice.notice.sequence) {
            continue;
        }
        match deliver(client, state.network_agent_origin(), &notice).await {
            Ok(()) => {
                delivered.insert(notice.notice.sequence, notice.notice.expires_at);
                info!(decision_id = %notice.notice.decision_id, "revocation delivered to network agent");
            }
            Err(cause) => {
                warn!(%cause, decision_id = %notice.notice.decision_id, "revocation delivery failed; will retry");
            }
        }
    }
    Ok(())
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
    // Drain the response within the request deadline so the connection can be reused.
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

    async fn delivery_response(
        status: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let notice: SignedDecisionRevocationNoticeV2 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/signed-decision-revocation-notice-v2/valid/basic.json"
        ))?;
        let body = serde_json::to_vec(&notice)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let response =
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
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
