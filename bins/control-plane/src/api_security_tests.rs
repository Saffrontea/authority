use super::*;
use crate::state::EnrollmentConfig;
use authority_credential_crypto_openssl::OpenSslEd25519Signer;
use authority_issuer_core::AuthorizationSigner;

struct SessionFixture {
    state: AppState,
    signer: OpenSslEd25519Signer,
    token: String,
    digest: [u8; 32],
    user: Uuid,
    device: Uuid,
}
impl SessionFixture {
    async fn new(pool: sqlx::PgPool) -> Self {
        Self::for_identity(pool, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()).await
    }
    async fn for_identity(pool: sqlx::PgPool, domain: Uuid, user: Uuid, device: Uuid) -> Self {
        let signer = OpenSslEd25519Signer::generate("test-device").unwrap();
        let token = generate_session_token().unwrap();
        let digest = session_token_digest(&token).unwrap();
        let webauthn = webauthn_rs::WebauthnBuilder::new(
            "localhost",
            &"http://localhost:3100".parse().unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
        let state = AppState::new(
            pool,
            webauthn,
            domain,
            "test-bootstrap",
            OpenSslEd25519Signer::generate("test-control").unwrap(),
            EnrollmentConfig {
                target_identity_file: "/unused/test-identity".into(),
                client_wireguard_public_key: "test-key".into(),
                network_agent_origin: "http://127.0.0.1:1".into(),
                target_mesh_address: "10.77.0.2".into(),
                existing_route_source_address: None,
            },
            (60, 60),
        );
        sqlx::query("INSERT INTO identity.sessions(domain_id,token_digest,user_id,device_id,device_public_key,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '15 minutes')")
            .bind(domain).bind(digest.as_slice()).bind(user).bind(device).bind(signer.public_key_raw().unwrap())
            .execute(state.pool()).await.unwrap();
        Self {
            state,
            signer,
            token,
            digest,
            user,
            device,
        }
    }
    fn headers(&self, action: &str, bindings: &[String], nonce: &str, timestamp: i64) -> HeaderMap {
        let timestamp = timestamp.to_string();
        let signature = self
            .signer
            .sign(&session_request_preimage(
                &self.token,
                action,
                bindings,
                &timestamp,
                nonce,
            ))
            .unwrap();
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("authorization", format!("Bearer {}", self.token)),
            ("x-authority-timestamp", timestamp),
            ("x-authority-nonce", nonce.to_owned()),
            ("x-authority-device-signature", encode_base64url(&signature)),
        ] {
            headers.insert(name, value.parse().unwrap());
        }
        headers
    }
    async fn cleanup(&self) {
        sqlx::query("DELETE FROM identity.sessions WHERE token_digest=$1")
            .bind(self.digest.as_slice())
            .execute(self.state.pool())
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL migrations"]
async fn nonce_window_prunes_expired_entries_but_keeps_live_replays_and_reports_rate_limit() {
    let fixture = SessionFixture::new(crate::access_policy::tests::lxc_pool(2).await).await;
    let now = unix_timestamp().unwrap();
    sqlx::query("INSERT INTO identity.session_nonces(token_digest,nonce,proof_expires_at) SELECT $1,'expired_'||n,$2 FROM generate_series(1,1024) n")
        .bind(fixture.digest.as_slice()).bind(now-1).execute(fixture.state.pool()).await.unwrap();
    let headers = fixture.headers("session.read", &[], "nonce_01234567890123456789", now);
    assert!(
        authenticated_session(&fixture.state, &headers, "session.read", &[])
            .await
            .is_ok()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.session_nonces WHERE token_digest=$1")
            .bind(fixture.digest.as_slice())
            .fetch_one(fixture.state.pool())
            .await
            .unwrap();
    assert_eq!(count, 1);
    let replay = authenticated_session(&fixture.state, &headers, "session.read", &[])
        .await
        .err()
        .unwrap();
    assert_eq!(replay.code, "device_proof_replayed");
    sqlx::query("INSERT INTO identity.session_nonces(token_digest,nonce,proof_expires_at) SELECT $1,'live_'||n,$2 FROM generate_series(1,1024) n")
        .bind(fixture.digest.as_slice()).bind(now+60).execute(fixture.state.pool()).await.unwrap();
    let fresh = fixture.headers("session.read", &[], "nonce_abcdefghijklmnopqrst", now);
    let capacity = authenticated_session(&fixture.state, &fresh, "session.read", &[])
        .await
        .err()
        .unwrap();
    fixture.cleanup().await;
    assert_eq!(capacity.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(capacity.code, "session_proof_capacity_reached");
}

async fn notice(fixture: &SessionFixture, target: Uuid, user: Uuid, device: Uuid) -> String {
    use authority_policy_core::scoped::{AbilityScope, AccessBinding, ScopedAbility, Validity};
    let decision = Uuid::new_v4().simple().to_string();
    let now = unix_timestamp().unwrap();
    let ability = ScopedAbility {
        binding: AccessBinding {
            domain_id: fixture.state.domain_id(),
            subject_user_id: user,
            device_id: device,
            target_node_id: target,
        },
        validity: Validity {
            not_before: now,
            expires_at: now + 60,
        },
        scope: AbilityScope::TcpAdmission {
            source: [10, 77, 0, 1].into(),
            destination: [10, 77, 0, 2].into(),
            ports: [8080].into(),
        },
    };
    sqlx::query("INSERT INTO policy.issued_ability_grants(domain_id,subject_user_id,device_id,target_node_id,decision_id,ability_kind,ability,policy_refs,not_before,expires_at) VALUES($1,$2,$3,$4,$5,'tcp_admission',$6,'[{\"policy_id\":\"test\",\"revision\":1}]',$7,$8)")
        .bind(fixture.state.domain_id()).bind(user).bind(device).bind(target).bind(&decision)
        .bind(serde_json::to_value(ability).unwrap()).bind(now).bind(now+60).execute(fixture.state.pool()).await.unwrap();
    let sequence: i64 = sqlx::query_scalar("SELECT nextval('policy.revocation_notice_sequence')")
        .fetch_one(fixture.state.pool())
        .await
        .unwrap();
    let envelope = sign_revocation_notice_v2(
        DecisionRevocationNoticeV2 {
            version: "2".into(),
            issuer: authority_contracts_model::protocol::domain_issuer(fixture.state.domain_id()),
            domain_id: fixture.state.domain_id().to_string(),
            target_node_id: target.to_string(),
            decision_id: decision.clone(),
            reason: "private_operation".into(),
            sequence,
            revoked_at: now,
            expires_at: now + 60,
            adapter_kinds: vec![AdapterGrantKindV1::TcpPort],
        },
        fixture.state.signer(),
    )
    .unwrap();
    sqlx::query("INSERT INTO policy.revocation_notices(sequence,domain_id,decision_id,target_node_id,reason,revoked_at,expires_at,envelope,scope_key) VALUES($1,$2,$3,$4,'private_operation',to_timestamp($5),to_timestamp($6),$7,'tcp.port')")
        .bind(sequence).bind(fixture.state.domain_id()).bind(&decision).bind(target).bind(now).bind(now + 60)
        .bind(serde_json::to_value(envelope).unwrap()).execute(fixture.state.pool()).await.unwrap();
    decision
}

#[tokio::test]
#[ignore = "requires PostgreSQL migrations"]
async fn revocation_pull_requires_bound_device_proof_and_filters_other_owners() {
    let fixture = SessionFixture::new(crate::access_policy::tests::lxc_pool(2).await).await;
    let target = Uuid::new_v4();
    let own = notice(&fixture, target, fixture.user, fixture.device).await;
    notice(&fixture, target, Uuid::new_v4(), fixture.device).await;
    notice(&fixture, target, fixture.user, Uuid::new_v4()).await;
    let query = || {
        Query(PullRevocationsQuery {
            target_node_id: target,
            after: 0,
        })
    };
    let anonymous = pull_revocations(State(fixture.state.clone()), query(), HeaderMap::new())
        .await
        .err()
        .unwrap();
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let bindings = [target.to_string(), "0".into()];
    let headers = fixture.headers(
        "revocations.read",
        &bindings,
        "pull_01234567890123456789",
        unix_timestamp().unwrap(),
    );
    let feed = pull_revocations(State(fixture.state.clone()), query(), headers.clone())
        .await
        .unwrap()
        .0;
    assert_eq!(feed.notices.len(), 1);
    assert_eq!(feed.notices[0].notice.decision_id, own);
    let replay = pull_revocations(State(fixture.state.clone()), query(), headers)
        .await
        .err()
        .unwrap();
    assert_eq!(replay.code, "device_proof_replayed");
    let tampered = fixture.headers(
        "revocations.read",
        &[Uuid::new_v4().to_string(), "0".into()],
        "pull_abcdefghijklmnopqrst",
        unix_timestamp().unwrap(),
    );
    let denied = pull_revocations(State(fixture.state.clone()), query(), tampered)
        .await
        .err()
        .unwrap();
    assert_eq!(denied.code, "invalid_device_proof");
    sqlx::query("DELETE FROM policy.revocation_notices WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM policy.issued_ability_grants WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL migrations"]
async fn device_allocation_skips_unreserved_target_address() {
    let pool = crate::access_policy::tests::lxc_pool(1).await;
    let mut tx = crate::access_policy::begin_authorization(&pool)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(617284901)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let occupied: Vec<String> =
        sqlx::query_scalar("SELECT host(address) FROM device.mesh_addresses")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    let reserved = (1..=254)
        .map(|last| format!("10.77.0.{last}"))
        .find(|address| !occupied.contains(address))
        .unwrap();
    let client = allocate_mesh_address(&mut tx, "device", Uuid::new_v4(), &reserved)
        .await
        .unwrap();
    let target = assign_target_mesh_address(&mut tx, Uuid::new_v4(), &reserved)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_ne!(client, reserved);
    assert_eq!(target, reserved);
}

#[tokio::test]
#[ignore = "requires PostgreSQL migrations"]
async fn challenge_flood_is_rate_limited_per_subject_and_preserves_other_users() {
    let fixture = SessionFixture::new(crate::access_policy::tests::lxc_pool(4).await).await;
    fixture.state.initialize_auth().await.unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let state = fixture.state.clone();
        let user = fixture.user;
        tasks.spawn(async move {
            state
                .put_challenge(
                    Uuid::new_v4(),
                    "authentication",
                    user,
                    &json!({"user_id":user}),
                    300,
                )
                .await
                .unwrap()
        });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        if result.unwrap() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, crate::auth_limits::CHALLENGES_PER_WINDOW);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity.pending_challenges WHERE domain_id=$1 AND subject_user_id=$2")
        .bind(fixture.state.domain_id()).bind(fixture.user).fetch_one(fixture.state.pool()).await.unwrap();
    assert_eq!(count, crate::auth_limits::MAX_PENDING_PER_USER);
    sqlx::query("UPDATE identity.challenge_rate_limits SET window_start=clock_timestamp()-interval '31 seconds' WHERE domain_id=$1 AND subject_user_id=$2")
        .bind(fixture.state.domain_id()).bind(fixture.user).execute(fixture.state.pool()).await.unwrap();
    assert!(
        fixture
            .state
            .put_challenge(
                Uuid::new_v4(),
                "authentication",
                fixture.user,
                &json!({"user_id":fixture.user}),
                300
            )
            .await
            .unwrap()
    );
    let other = Uuid::new_v4();
    let other_challenge = Uuid::new_v4();
    assert!(
        fixture
            .state
            .put_challenge(
                other_challenge,
                "authentication",
                other,
                &json!({"user_id":other}),
                300
            )
            .await
            .unwrap()
    );
    assert!(
        fixture
            .state
            .take_challenge::<Value>(other_challenge, "authentication")
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query("DELETE FROM identity.pending_challenges WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM identity.challenge_rate_limits WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM identity.bootstrap_tokens WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM identity.auth_domains WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL migrations"]
async fn session_pressure_evicts_only_the_authenticated_users_oldest_sessions() {
    let fixture = SessionFixture::new(crate::access_policy::tests::lxc_pool(2).await).await;
    fixture.state.initialize_auth().await.unwrap();
    let other_user = Uuid::new_v4();
    let other_digest = sha256(Uuid::new_v4().as_bytes());
    sqlx::query("INSERT INTO identity.sessions(domain_id,token_digest,user_id,device_id,device_public_key,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 minute')")
        .bind(fixture.state.domain_id()).bind(other_digest.as_slice()).bind(other_user).bind(Uuid::new_v4()).bind(fixture.signer.public_key_raw().unwrap())
        .execute(fixture.state.pool()).await.unwrap();
    for _ in 0..16 {
        let mut tx = crate::access_policy::begin_authorization(fixture.state.pool())
            .await
            .unwrap();
        assert!(
            crate::auth_limits::reserve_session_slot(
                &mut tx,
                fixture.state.domain_id(),
                fixture.user
            )
            .await
            .unwrap()
        );
        sqlx::query("INSERT INTO identity.sessions(domain_id,token_digest,user_id,device_id,device_public_key,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '15 minutes')")
            .bind(fixture.state.domain_id()).bind(sha256(Uuid::new_v4().as_bytes()).as_slice()).bind(fixture.user).bind(fixture.device).bind(fixture.signer.public_key_raw().unwrap())
            .execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
    }
    let own: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity.sessions WHERE domain_id=$1 AND user_id=$2",
    )
    .bind(fixture.state.domain_id())
    .bind(fixture.user)
    .fetch_one(fixture.state.pool())
    .await
    .unwrap();
    let other: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.sessions WHERE token_digest=$1")
            .bind(other_digest.as_slice())
            .fetch_one(fixture.state.pool())
            .await
            .unwrap();
    let original: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.sessions WHERE token_digest=$1")
            .bind(fixture.digest.as_slice())
            .fetch_one(fixture.state.pool())
            .await
            .unwrap();
    sqlx::query("DELETE FROM identity.sessions WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM identity.bootstrap_tokens WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM identity.auth_domains WHERE domain_id=$1")
        .bind(fixture.state.domain_id())
        .execute(fixture.state.pool())
        .await
        .unwrap();
    assert_eq!(own, crate::auth_limits::MAX_SESSIONS_PER_USER);
    assert_eq!(other, 1);
    assert_eq!(original, 0);
}

#[tokio::test]
#[ignore = "requires LXC PostgreSQL and a bootstrapped poc:e2e policy"]
async fn transferred_device_returns_forbidden_and_commits_a_deny_audit() {
    let pool = crate::access_policy::tests::lxc_pool(3).await;
    let (live, _) = crate::access_policy::tests::live_tcp_request(&pool).await;
    let fixture =
        SessionFixture::for_identity(pool, live.domain_id, live.subject_user_id, live.device_id)
            .await;
    let before: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(sequence),0) FROM audit.events")
        .fetch_one(fixture.state.pool())
        .await
        .unwrap();
    let grants_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM policy.issued_ability_grants WHERE domain_id=$1 AND device_id=$2",
    )
    .bind(live.domain_id)
    .bind(live.device_id)
    .fetch_one(fixture.state.pool())
    .await
    .unwrap();
    let request = IssueTcpAuthorizationRequest {
        device_id: live.device_id,
        target_node_id: live.target_node_id,
        destination_ports: vec![8080],
        include_network: false,
        ttl_seconds: 10,
        automatic_route: false,
    };
    let headers = fixture.headers(
        "access.authorize_tcp",
        &tcp_authorization_bindings(&request).unwrap(),
        "transferred_device_nonce_0123456789",
        unix_timestamp().unwrap(),
    );
    sqlx::query("UPDATE device.devices SET owner_user_id=NULL,owner_kind='domain',owner_domain_id=domain_id WHERE id=$1")
        .bind(live.device_id).execute(fixture.state.pool()).await.unwrap();
    let result =
        issue_tcp_authorization(State(fixture.state.clone()), headers, Json(request)).await;
    // Restore the live fixture before assertions so a failing regression cannot strand it.
    sqlx::query("UPDATE device.devices SET owner_user_id=$2,owner_kind='user',owner_domain_id=NULL WHERE id=$1")
        .bind(live.device_id).bind(live.subject_user_id).execute(fixture.state.pool()).await.unwrap();
    let audit: Vec<(String,Option<String>)> = sqlx::query_as("SELECT decision,reason FROM audit.events WHERE domain_id=$1 AND actor_id=$2 AND sequence>$3 AND action='access.authorize'")
        .bind(live.domain_id).bind(live.subject_user_id.to_string()).bind(before).fetch_all(fixture.state.pool()).await.unwrap();
    let grants_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM policy.issued_ability_grants WHERE domain_id=$1 AND device_id=$2",
    )
    .bind(live.domain_id)
    .bind(live.device_id)
    .fetch_one(fixture.state.pool())
    .await
    .unwrap();
    fixture.cleanup().await;
    let error = result.err().expect("a transferred device must be denied");
    assert_eq!(grants_before, grants_after);
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "policy_denied");
    assert_eq!(
        audit,
        vec![("deny".to_owned(), Some("device_mismatch".to_owned()))]
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL migrations"]
async fn malformed_access_identifiers_and_oversized_fingerprints_are_rejected_before_authentication()
 {
    let fixture = SessionFixture::new(crate::access_policy::tests::lxc_pool(1).await).await;
    for oversized_ssh in [false, true] {
        let normal = format!("SHA256:{}", "A".repeat(43));
        let huge = format!("SHA256:{}", "A".repeat(100_000));
        let request = IssueAccessAuthorizationRequest {
            device_id: fixture.device,
            target_node_id: Uuid::new_v4(),
            ssh_public_key_fingerprint: if oversized_ssh {
                huge.clone()
            } else {
                normal.clone()
            },
            mtls_client_spki_sha256: if oversized_ssh { normal } else { huge },
            wireguard_public_key: "unused".into(),
            terminal_token_hash: "unused".into(),
        };
        let error = issue_access_authorization(
            State(fixture.state.clone()),
            HeaderMap::new(),
            Json(request),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "invalid_key_fingerprint");
    }
    let error = revocation_status(
        State(fixture.state.clone()),
        Path("invalid/id".into()),
        HeaderMap::new(),
    )
    .await
    .err()
    .unwrap();
    fixture.cleanup().await;
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "invalid_decision_id");
}
