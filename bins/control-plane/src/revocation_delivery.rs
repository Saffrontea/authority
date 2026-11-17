use std::{collections::HashMap, process::Stdio, time::Duration};

use authority_contracts_model::SignedDecisionRevocationNoticeV2;
use serde_json::Value;
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::{info, warn};

use crate::state::AppState;

// The PoC has one configured target. Its origin is the LXC underlay address,
// independent of both the browser and the WireGuard peer being revoked.
pub async fn run(state: AppState) {
    let mut delivered = HashMap::new();
    loop {
        if let Err(cause) = reconcile(&state, &mut delivered).await {
            warn!(%cause, "revocation delivery reconciliation failed; will retry");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn reconcile(
    state: &AppState,
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
        match deliver(state.network_agent_origin(), &notice).await {
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
    origin: &str,
    notice: &SignedDecisionRevocationNoticeV2,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = serde_json::to_vec(notice)?;
    let mut child = Command::new("curl")
        .args([
            "--disable",
            "--silent",
            "--show-error",
            "--fail",
            "--noproxy",
            "*",
            "--proto",
            "=http,https",
            "--connect-timeout",
            "2",
            "--max-time",
            "5",
            "--request",
            "POST",
            "--header",
            "content-type: application/json",
            "--data-binary",
            "@-",
            "--url",
            &format!("{}/v1/revocations", origin.trim_end_matches('/')),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("missing delivery stdin")?;
    stdin.write_all(&body).await?;
    drop(stdin);
    if !child.wait().await?.success() {
        return Err("network agent did not acknowledge revocation".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::AsyncReadExt, net::TcpListener};

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
        let result = deliver(&origin, &notice).await;
        server.await?;
        result
    }

    #[tokio::test]
    async fn delivers_signed_notice_without_browser() {
        delivery_response("200 OK").await.unwrap();
    }

    #[tokio::test]
    async fn failed_delivery_remains_retryable() {
        assert!(delivery_response("503 Service Unavailable").await.is_err());
        delivery_response("200 OK").await.unwrap();
    }
}
