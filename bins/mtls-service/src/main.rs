use authority_contracts_model::SignedDecisionRevocationNoticeV2;
use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use authority_mtls_core::{certificate_lifetime, client_identity, wait_closed};
use authority_mtls_core::{connections::Connections, database::AuthorityDb};
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
    connections: Connections,
    database: AuthorityDb,
    lease: tokio::sync::watch::Receiver<Option<tokio::time::Instant>>,
    ca_id: String,
    ca: openssl::x509::X509,
    pki_origin: String,
    client: reqwest::Client,
    verifier: Arc<OpenSslEd25519Verifier>,
    domain: String,
    target: String,
    audience: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();
    let database = AuthorityDb::from_env().await?;
    let instance = uuid::Uuid::new_v4();
    let (lease_sender, lease) = tokio::sync::watch::channel(None);
    let ca = openssl::x509::X509::from_pem(&std::fs::read(required(
        "AUTHORITY_MTLS_CA_CERTIFICATE_FILE",
    )?)?)?;
    let service = Service {
        connections: Connections::default(),
        database,
        lease,
        ca_id: authority_mtls_core::database::ca_id(&ca)?,
        ca,
        pki_origin: required("AUTHORITY_PKI_PUBLIC_ORIGIN")?,
        client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()?,
        verifier: Arc::new(OpenSslEd25519Verifier::from_pem_file(
            env::var("AUTHORITY_SIGNING_KEY_ID").unwrap_or_else(|_| "control-plane-key-1".into()),
            required("AUTHORITY_CONTROL_PLANE_PUBLIC_KEY_FILE")?,
        )?),
        domain: required("AUTHORITY_DOMAIN_ID")?,
        target: required("AUTHORITY_TARGET_NODE_ID")?,
        audience: required("AUTHORITY_MTLS_SERVICE_AUDIENCE")?,
    };
    service
        .database
        .register_instance(instance, service.domain.parse()?, service.target.parse()?)
        .await?;
    let subscriber = service.clone();
    tokio::spawn(async move {
        subscribe(subscriber, instance, lease_sender).await;
    });
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
            .route("/health", get(health))
            .route("/v1/revocations", post(revoke))
            .with_state(service),
    )
    .await?;
    Ok(())
}

async fn health(State(state): State<Service>) -> StatusCode {
    if state
        .lease
        .borrow()
        .is_some_and(|deadline| deadline > tokio::time::Instant::now())
    {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn revoke(
    State(state): State<Service>,
    Json(envelope): Json<SignedDecisionRevocationNoticeV2>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    authority_issuer_core::verify_revocation_notice_v2_for_adapter(
        &envelope,
        state.verifier.as_ref(),
        &state.target,
        authority_contracts_model::AdapterGrantKindV1::MtlsClientCertificate,
        authority_mtls_core::unix_timestamp().map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e))?,
    )
    .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))?;
    if envelope.notice.domain_id != state.domain {
        return Err((StatusCode::FORBIDDEN, "domain mismatch".into()));
    }
    if !state
        .database
        .committed_notice(&envelope)
        .await
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e))?
    {
        return Err((StatusCode::FORBIDDEN, "revocation not committed".into()));
    }
    let receivers = state
        .connections
        .revoke(
            &state.domain,
            &state.target,
            &envelope.notice.decision_id,
            envelope.notice.expires_at,
        )
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e))?;
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
    let store = crl_store(&state).await?;
    let mut ssl = Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
    ssl.set_verify_cert_store(store)
        .map_err(|e| e.to_string())?;
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
    let serial = certificate
        .serial_number()
        .to_bn()
        .and_then(|n| n.to_dec_str())
        .map_err(|e| e.to_string())?
        .to_string()
        .parse::<i64>()
        .map_err(|e| e.to_string())?;
    if !tokio::time::timeout(
        Duration::from_secs(2),
        state.database.certificate_active(&state.ca_id, serial),
    )
    .await
    .map_err(|e| e.to_string())??
    {
        return Err("certificate is unknown, revoked or expired".into());
    }
    let mut lease = state.lease.clone();
    if lease
        .borrow()
        .is_none_or(|deadline| deadline <= tokio::time::Instant::now())
    {
        return Err("enforcement lease unavailable".into());
    }
    let mut session = state.connections.register(&identity)?;
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
        loop {
            let Some(lease_expiry) = *lease.borrow_and_update() else {
                break;
            };
            tokio::select! { biased;
                _ = session.cancelled.changed() => { info!(%decision_id, "mTLS connection revoked"); break; },
                () = tokio::time::sleep_until(expires.min(lease_expiry)) => { info!(%decision_id, "mTLS certificate or lease expired"); break; },
                changed = lease.changed() => { if changed.is_err() { break; } },
                result = &mut http => { result.map_err(|e|e.to_string())?; break; },
            }
        }
        // Cancellation discards any partially queued HTTP response. Send TLS
        // close_notify with a bound, then drop the socket before session ACK.
        let mut tls = http.into_parts().io.into_inner();
        let shutdown_budget = lease
            .borrow()
            .map_or(Duration::ZERO, |deadline| {
                deadline.saturating_duration_since(tokio::time::Instant::now())
            })
            .min(Duration::from_secs(1));
        let _ = tokio::time::timeout(
            shutdown_budget,
            tokio::io::AsyncWriteExt::shutdown(&mut tls),
        )
        .await;
    }
    drop(session);
    Ok(())
}

async fn subscribe(
    state: Service,
    instance: uuid::Uuid,
    lease: tokio::sync::watch::Sender<Option<tokio::time::Instant>>,
) {
    loop {
        let started = tokio::time::Instant::now();
        let result = async {
            let events = state.database.events(instance).await?;
            let mut applied = Vec::new();
            for envelope in events {
                let n = &envelope.notice;
                let receivers = state.connections.revoke(
                    &n.domain_id,
                    &n.target_node_id,
                    &n.decision_id,
                    n.expires_at,
                )?;
                wait_closed(receivers).await?;
                applied.push(n.sequence);
            }
            state
                .database
                .acknowledge_and_renew(instance, &applied)
                .await
        }
        .await;
        match result {
            Ok(true) => {
                lease.send_replace(Some(
                    started
                        + Duration::from_secs(u64::from(
                            authority_mtls_core::ENFORCEMENT_LEASE_SECONDS,
                        )),
                ));
            }
            Ok(false) => {}
            Err(cause) => warn!(%cause,%instance,"enforcement lease renewal failed"),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

// A derived CRL is never authoritative local state. OpenSSL checks its CA
// signature and thisUpdate/nextUpdate while verifying the client chain.
async fn crl_store(state: &Service) -> Result<openssl::x509::store::X509Store, String> {
    use openssl::x509::{
        store::{X509Lookup, X509StoreBuilder},
        verify::X509VerifyFlags,
    };
    use std::io::Write;
    struct Remove(std::path::PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let url = format!(
        "{}/v1/pki/{}/crl",
        state.pki_origin.trim_end_matches('/'),
        state.ca_id
    );
    let mut response = state
        .client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err("CRL exceeds size limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let path = std::env::temp_dir().join(format!("authority-crl-{}", uuid::Uuid::new_v4()));
    let _remove = Remove(path.clone());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
    store
        .add_cert(state.ca.clone())
        .map_err(|e| e.to_string())?;
    store
        .add_lookup(X509Lookup::file())
        .map_err(|e| e.to_string())?
        .load_crl_file(&path, SslFiletype::ASN1)
        .map_err(|e| e.to_string())?;
    store
        .set_flags(X509VerifyFlags::CRL_CHECK)
        .map_err(|e| e.to_string())?;
    Ok(store.build())
}
