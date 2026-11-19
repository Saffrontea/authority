use authority_contracts_model::SignedDecisionRevocationNoticeV2;
use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use authority_mtls_core::{
    AccessStore, certificate_lifetime, client_identity, unix_timestamp, wait_closed,
};
use authority_replay_ledger::ReplayLedger;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use http_body_util::Full;
use hyper::{Response, service::service_fn};
use hyper_util::rt::TokioIo;
use openssl::ssl::{
    Ssl, SslAcceptor, SslFiletype, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyMode,
};
use std::{convert::Infallible, env, pin::Pin, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;
use tracing::{info, warn};

#[derive(Clone)]
struct Service {
    store: AccessStore,
    verifier: Arc<OpenSslEd25519Verifier>,
    domain: String,
    target: String,
    audience: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();
    let service = Service {
        store: AccessStore::new(ReplayLedger::open(
            required("AUTHORITY_MTLS_SERVICE_LEDGER_FILE")?,
            unix_timestamp()?,
        )?),
        verifier: Arc::new(OpenSslEd25519Verifier::from_pem_file(
            env::var("AUTHORITY_SIGNING_KEY_ID").unwrap_or_else(|_| "control-plane-key-1".into()),
            required("AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE")?,
        )?),
        domain: required("AUTHORITY_DOMAIN_ID")?,
        target: required("AUTHORITY_TARGET_NODE_ID")?,
        audience: required("AUTHORITY_MTLS_SERVICE_AUDIENCE")?,
    };
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    acceptor.set_private_key_file(
        required("AUTHORITY_MTLS_SERVICE_KEY_FILE")?,
        SslFiletype::PEM,
    )?;
    acceptor.set_certificate_chain_file(required("AUTHORITY_MTLS_SERVICE_CERTIFICATE_FILE")?)?;
    acceptor.check_private_key()?;
    acceptor.set_ca_file(required("AUTHORITY_MTLS_CA_CERTIFICATE_FILE")?)?;
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    acceptor.set_options(SslOptions::NO_TICKET);
    acceptor.set_session_cache_mode(SslSessionCacheMode::OFF);
    acceptor.set_num_tickets(0)?;
    let acceptor = Arc::new(acceptor.build());
    let tls = TcpListener::bind(required("AUTHORITY_MTLS_SERVICE_TLS_BIND")?).await?;
    let listener = TcpListener::bind(required("AUTHORITY_MTLS_SERVICE_BIND")?).await?;
    let tls_service = service.clone();
    let slots = Arc::new(tokio::sync::Semaphore::new(64));
    tokio::spawn(async move {
        loop {
            let (stream, _) = match tls.accept().await {
                Ok(pair) => pair,
                Err(cause) => {
                    warn!(%cause, "TLS accept failed");
                    break;
                }
            };
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let acceptor = acceptor.clone();
            let service = tls_service.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(cause) = connection(stream, acceptor, service).await {
                    info!(%cause, "TLS connection closed");
                }
            });
        }
    });
    info!(address=%listener.local_addr()?, "mTLS service control listening");
    axum::serve(
        listener,
        Router::new()
            .route("/health", get(|| async { StatusCode::NO_CONTENT }))
            .route("/v1/revocations", post(revoke))
            .with_state(service),
    )
    .await?;
    Ok(())
}

async fn revoke(
    State(state): State<Service>,
    Json(envelope): Json<SignedDecisionRevocationNoticeV2>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let receivers = state
        .store
        .revoke(
            &envelope,
            &state.verifier,
            &state.target,
            Some(&state.domain),
        )
        .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    tokio::time::timeout(Duration::from_secs(5), wait_closed(receivers))
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "connection cleanup pending".into(),
            )
        })?
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e))?;
    Ok(Json(
        serde_json::json!({"decision_id":envelope.notice.decision_id,"sequence":envelope.notice.sequence,"adapter":"mtls.client_certificate"}),
    ))
}

async fn connection(
    tcp: TcpStream,
    acceptor: Arc<SslAcceptor>,
    state: Service,
) -> Result<(), String> {
    let ssl = Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
    let mut tls = SslStream::new(ssl, tcp).map_err(|e| e.to_string())?;
    tokio::time::timeout(Duration::from_secs(5), Pin::new(&mut tls).accept())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let certificate = tls
        .ssl()
        .peer_certificate()
        .ok_or("missing client certificate")?;
    let identity = client_identity(&certificate, &state.domain, &state.target, &state.audience)?;
    let clock = tokio::time::Instant::now();
    let lifetime = certificate_lifetime(identity.expires_at, std::time::SystemTime::now())?;
    let expires = clock
        .checked_add(lifetime)
        .ok_or("certificate expiry overflow")?;
    let mut session = state.store.register(&identity).map_err(|e| e.to_string())?;
    info!(decision_id=%identity.decision_id, lifetime_ms=lifetime.as_millis(), "mTLS connection admitted");
    let decision_id = identity.decision_id.clone();
    let response_identity =
        serde_json::json!({"decision_id":identity.decision_id,"service":state.audience})
            .to_string();
    {
        let mut http = hyper::server::conn::http1::Builder::new().serve_connection(
            TokioIo::new(tls),
            service_fn(move |request| {
                let body = response_identity.clone();
                async move {
                    let mut response = Response::new(Full::new(hyper::body::Bytes::from(body)));
                    if request.method() != hyper::Method::GET || request.uri().path() != "/whoami" {
                        *response.status_mut() = StatusCode::NOT_FOUND;
                    }
                    Ok::<_, Infallible>(response)
                }
            }),
        );
        tokio::select! { biased;
            _ = session.cancelled.changed() => { info!(%decision_id, "mTLS connection revoked"); },
            () = tokio::time::sleep_until(expires) => { info!(%decision_id, "mTLS connection expired"); },
            result = &mut http => { result.map_err(|e| e.to_string())?; },
        }
        // Cancellation discards any partially queued HTTP response. Send TLS
        // close_notify with a bound, then drop the socket before session ACK.
        let mut tls = http.into_parts().io.into_inner();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncWriteExt::shutdown(&mut tls),
        )
        .await;
    }
    drop(session);
    Ok(())
}

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}
