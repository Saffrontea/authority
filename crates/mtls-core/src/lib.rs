//! Durable decision revocation shared by the issuer and enforcing TLS service.
use authority_contracts_model::{
    AdapterGrantKindV1, MtlsIssuanceAuthorizationV1, SignedDecisionRevocationNoticeV2,
};
use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use authority_issuer_core::verify_revocation_notice_v2_for_adapter;
use authority_replay_ledger::ReplayLedger;
use openssl::{asn1::Asn1Time, nid::Nid, x509::X509Ref};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("authorization is not active")]
    NotActive,
    #[error("decision is revoked")]
    Revoked,
    #[error("authorization was consumed")]
    Replay,
    #[error("invalid revocation: {0}")]
    InvalidRevocation(String),
    #[error("storage failure: {0}")]
    Storage(String),
    #[error("operation failed: {0}")]
    Operation(String),
}

/// # Errors
/// Returns an error if the clock precedes the epoch or exceeds i64.
pub fn unix_timestamp() -> Result<i64, String> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs(),
    )
    .map_err(|e| e.to_string())
}

/// Preserve fractional wall-clock time when deriving a monotonic session deadline.
/// # Errors
/// Rejects negative, unrepresentable or already elapsed expiration instants.
pub fn certificate_lifetime(
    expires_at: i64,
    now: SystemTime,
) -> Result<std::time::Duration, String> {
    let seconds = u64::try_from(expires_at).map_err(|e| e.to_string())?;
    let deadline = UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(seconds))
        .ok_or("expiration overflow")?;
    let remaining = deadline.duration_since(now).map_err(|e| e.to_string())?;
    if remaining.is_zero() {
        return Err("certificate expired".into());
    }
    Ok(remaining)
}

#[must_use]
pub fn decision_key(domain: &str, target: &str, decision: &str) -> String {
    // Length framing prevents ambiguous concatenations of otherwise valid IDs.
    let material = format!(
        "authority-mtls-revocation-v1:{}:{domain}{}:{target}{}:{decision}",
        domain.len(),
        target.len(),
        decision.len()
    );
    let digest = openssl::sha::sha256(material.as_bytes());
    format!("mtls_revoked_{}", openssl::base64::encode_block(&digest))
}

#[derive(Clone)]
pub struct AccessStore(Arc<Mutex<Store>>);
struct Store {
    ledger: ReplayLedger,
    next_session: u64,
    sessions: HashMap<u64, Session>,
}
struct Session {
    key: String,
    cancel: watch::Sender<bool>,
    closed: watch::Receiver<bool>,
}

pub struct SessionGuard {
    store: AccessStore,
    id: u64,
    pub cancelled: watch::Receiver<bool>,
    closed: watch::Sender<bool>,
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Ok(mut store) = self.store.0.lock() {
            store.sessions.remove(&self.id);
        }
        self.closed.send_replace(true);
    }
}

impl AccessStore {
    #[must_use]
    pub fn new(ledger: ReplayLedger) -> Self {
        Self(Arc::new(Mutex::new(Store {
            ledger,
            next_session: 0,
            sessions: HashMap::new(),
        })))
    }

    /// The caller's issuance operation completes under the same lock as revocation.
    /// # Errors
    /// Rejects inactive, revoked or consumed authority and reports durable-write or issuance failures.
    pub fn issue<T>(
        &self,
        authorization: &MtlsIssuanceAuthorizationV1,
        clock: impl FnOnce() -> Result<i64, String>,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, AccessError> {
        let mut store = self
            .0
            .lock()
            .map_err(|e| AccessError::Storage(e.to_string()))?;
        let now = clock().map_err(AccessError::Operation)?;
        if now < authorization.not_before || now >= authorization.expires_at {
            return Err(AccessError::NotActive);
        }
        let key = decision_key(
            &authorization.domain_id,
            &authorization.target_node_id,
            &authorization.decision_id,
        );
        if store.ledger.contains(&key, now) {
            return Err(AccessError::Revoked);
        }
        if !store
            .ledger
            .consume(&authorization.nonce, authorization.expires_at, now)
            .map_err(AccessError::Storage)?
        {
            return Err(AccessError::Replay);
        }
        operation().map_err(AccessError::Operation)
    }

    /// # Errors
    /// Reports invalid input, poisoned state or durable-write failure.
    pub fn consume_nonce(&self, nonce: &str, expires_at: i64, now: i64) -> Result<bool, String> {
        self.0
            .lock()
            .map_err(|e| e.to_string())?
            .ledger
            .consume(nonce, expires_at, now)
    }

    /// Verify before touching durable or session state. Issuers serve all signed
    /// targets; services supply their configured target and domain separately.
    /// # Errors
    /// Rejects unauthenticated, expired, wrong-target/domain/adapter notices and storage failures.
    pub fn revoke(
        &self,
        envelope: &SignedDecisionRevocationNoticeV2,
        verifier: &OpenSslEd25519Verifier,
        expected_target: &str,
        expected_domain: Option<&str>,
    ) -> Result<Vec<watch::Receiver<bool>>, AccessError> {
        let mut store = self
            .0
            .lock()
            .map_err(|e| AccessError::Storage(e.to_string()))?;
        let now = unix_timestamp().map_err(AccessError::Operation)?;
        verify_revocation_notice_v2_for_adapter(
            envelope,
            verifier,
            expected_target,
            AdapterGrantKindV1::MtlsClientCertificate,
            now,
        )
        .map_err(|e| AccessError::InvalidRevocation(e.to_string()))?;
        let notice = &envelope.notice;
        if expected_domain.is_some_and(|domain| domain != notice.domain_id) {
            return Err(AccessError::InvalidRevocation("domain mismatch".into()));
        }
        let key = decision_key(
            &notice.domain_id,
            &notice.target_node_id,
            &notice.decision_id,
        );
        store
            .ledger
            .consume(&key, notice.expires_at, now)
            .map_err(AccessError::Storage)?;
        let mut closed = Vec::new();
        for session in store.sessions.values().filter(|s| s.key == key) {
            closed.push(session.closed.clone());
            session.cancel.send_replace(true);
        }
        Ok(closed)
    }

    /// # Errors
    /// Rejects expired or revoked identities, poisoned state and exhausted session IDs.
    pub fn register(&self, identity: &ClientIdentity) -> Result<SessionGuard, AccessError> {
        let mut store = self
            .0
            .lock()
            .map_err(|e| AccessError::Storage(e.to_string()))?;
        let now = unix_timestamp().map_err(AccessError::Operation)?;
        if now < identity.not_before || now >= identity.expires_at {
            return Err(AccessError::NotActive);
        }
        let key = decision_key(
            &identity.domain_id,
            &identity.target_node_id,
            &identity.decision_id,
        );
        if store.ledger.contains(&key, now) {
            return Err(AccessError::Revoked);
        }
        let id = store.next_session;
        store.next_session = id
            .checked_add(1)
            .ok_or_else(|| AccessError::Operation("session ID exhausted".into()))?;
        let (cancel, cancelled) = watch::channel(false);
        let (closed, receiver) = watch::channel(false);
        store.sessions.insert(
            id,
            Session {
                key,
                cancel,
                closed: receiver,
            },
        );
        Ok(SessionGuard {
            store: self.clone(),
            id,
            cancelled,
            closed,
        })
    }
}

/// ACK only after the enforcing tasks have dropped their TLS sockets.
/// # Errors
/// Reports a cancelled completion channel without a confirmed socket close.
pub async fn wait_closed(receivers: Vec<watch::Receiver<bool>>) -> Result<(), String> {
    for mut receiver in receivers {
        while !*receiver.borrow_and_update() {
            receiver.changed().await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct ClientIdentity {
    pub domain_id: String,
    pub target_node_id: String,
    pub decision_id: String,
    pub not_before: i64,
    pub expires_at: i64,
}

fn epoch_seconds(time: &openssl::asn1::Asn1TimeRef) -> Result<i64, String> {
    let delta = Asn1Time::from_unix(0)
        .map_err(|e| e.to_string())?
        .diff(time)
        .map_err(|e| e.to_string())?;
    Ok(i64::from(delta.days) * 86400 + i64::from(delta.secs))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Chain/client-purpose verification is performed by the TLS acceptor before
/// this application binding check. Unbound legacy certificates fail closed.
/// # Errors
/// Rejects absent or mismatched certificate bindings and invalid certificate times.
pub fn client_identity(
    cert: &X509Ref,
    domain: &str,
    target: &str,
    audience: &str,
) -> Result<ClientIdentity, String> {
    let names = cert.subject_alt_names().ok_or("missing SANs")?;
    let target_uri = format!("urn:authority:target:{target}");
    let prefix = format!("spiffe://authority.local/domain/{domain}/user/");
    if names.len() != 3
        || !names.iter().any(|n| n.dnsname() == Some(audience))
        || !names.iter().any(|n| n.uri() == Some(&target_uri))
    {
        return Err("certificate target or service mismatch".into());
    }
    let identity = names
        .iter()
        .filter_map(|n| n.uri())
        .find_map(|uri| uri.strip_prefix(&prefix))
        .ok_or("certificate domain mismatch")?;
    let (user, device) = identity
        .split_once("/device/")
        .ok_or("invalid identity URI")?;
    if !identifier(user) || !identifier(device) {
        return Err("invalid identity binding".into());
    }
    let subject = cert.subject_name();
    let cn: Vec<_> = subject.entries_by_nid(Nid::COMMONNAME).collect();
    if cn.len() != 1 {
        return Err("invalid decision binding".into());
    }
    let decision = cn[0].data().to_string().map_err(|e| e.to_string())?;
    if !identifier(&decision) {
        return Err("invalid decision ID".into());
    }
    Ok(ClientIdentity {
        domain_id: domain.into(),
        target_node_id: target.into(),
        decision_id: decision,
        not_before: epoch_seconds(cert.not_before())?,
        expires_at: epoch_seconds(cert.not_after())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use authority_contracts_model::DecisionRevocationNoticeV2;
    use authority_credential_crypto_openssl::OpenSslEd25519Signer;
    use authority_issuer_core::sign_revocation_notice_v2;
    use std::{sync::mpsc, thread, time::Duration};

    fn authorization() -> MtlsIssuanceAuthorizationV1 {
        let mut value: MtlsIssuanceAuthorizationV1 = serde_json::from_str(include_str!(
            "../../../contracts/test-vectors/mtls-issuance-authorization-v1/valid/basic.json"
        ))
        .unwrap();
        let now = unix_timestamp().unwrap();
        value.not_before = now - 1;
        value.issued_at = now - 1;
        value.expires_at = now + 120;
        value
    }
    fn signer() -> (OpenSslEd25519Signer, OpenSslEd25519Verifier) {
        let signer = OpenSslEd25519Signer::generate("mtls-revocation-test").unwrap();
        let verifier = OpenSslEd25519Verifier::from_pem(
            "mtls-revocation-test",
            &signer.public_key_to_pem().unwrap(),
        )
        .unwrap();
        (signer, verifier)
    }
    fn notice(
        a: &MtlsIssuanceAuthorizationV1,
        signer: &OpenSslEd25519Signer,
    ) -> SignedDecisionRevocationNoticeV2 {
        sign_revocation_notice_v2(
            DecisionRevocationNoticeV2 {
                version: "2".into(),
                issuer: a.issuer.clone(),
                domain_id: a.domain_id.clone(),
                target_node_id: a.target_node_id.clone(),
                decision_id: a.decision_id.clone(),
                reason: "user_requested".into(),
                sequence: 1,
                revoked_at: unix_timestamp().unwrap(),
                expires_at: a.expires_at,
                adapter_kinds: vec![AdapterGrantKindV1::MtlsClientCertificate],
            },
            signer,
        )
        .unwrap()
    }
    fn identity(a: &MtlsIssuanceAuthorizationV1) -> ClientIdentity {
        ClientIdentity {
            domain_id: a.domain_id.clone(),
            target_node_id: a.target_node_id.clone(),
            decision_id: a.decision_id.clone(),
            not_before: a.not_before,
            expires_at: a.expires_at,
        }
    }

    #[test]
    fn durable_revocation_blocks_unissued_authority_and_is_scope_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ledger");
        let a = authorization();
        let (signer, verifier) = signer();
        let notice = notice(&a, &signer);
        let store = AccessStore::new(ReplayLedger::open(&path, unix_timestamp().unwrap()).unwrap());
        for _ in 0..2 {
            assert!(
                store
                    .revoke(&notice, &verifier, &a.target_node_id, Some(&a.domain_id))
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(matches!(
            store.issue::<()>(&a, unix_timestamp, || panic!(
                "revoked operation must not run"
            )),
            Err(AccessError::Revoked)
        ));
        for variant in 0..3 {
            let mut other = a.clone();
            other.nonce = format!("independent_{variant}");
            match variant {
                0 => other.domain_id.push('x'),
                1 => other.target_node_id.push('x'),
                _ => other.decision_id.push('x'),
            }
            assert!(store.issue(&other, unix_timestamp, || Ok(())).is_ok());
        }
        drop(store);
        let reopened =
            AccessStore::new(ReplayLedger::open(&path, unix_timestamp().unwrap()).unwrap());
        assert!(matches!(
            reopened.register(&identity(&a)),
            Err(AccessError::Revoked)
        ));
        assert!(matches!(
            reopened.issue(&a, unix_timestamp, || Ok(())),
            Err(AccessError::Revoked)
        ));
        assert_ne!(decision_key("ab", "c", "d"), decision_key("a", "bc", "d"));
    }

    #[tokio::test]
    async fn acknowledgement_waits_for_sessions_and_does_not_cancel_other_decisions() {
        let directory = tempfile::tempdir().unwrap();
        let a = authorization();
        let (signer, verifier) = signer();
        let store = AccessStore::new(
            ReplayLedger::open(directory.path().join("ledger"), unix_timestamp().unwrap()).unwrap(),
        );
        let session = store.register(&identity(&a)).unwrap();
        let mut independent = identity(&a);
        independent.decision_id.push('x');
        let other = store.register(&independent).unwrap();
        let waiters = store
            .revoke(&notice(&a, &signer), &verifier, &a.target_node_id, None)
            .unwrap();
        assert!(*session.cancelled.borrow());
        assert!(!*other.cancelled.borrow());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait_closed(waiters.clone()))
                .await
                .is_err()
        );
        assert!(matches!(
            store.register(&identity(&a)),
            Err(AccessError::Revoked)
        ));
        drop(session);
        wait_closed(waiters).await.unwrap();
        drop(other);
    }

    #[test]
    fn issuance_and_revocation_share_one_serialization_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let a = authorization();
        let (signer, verifier) = signer();
        let store = AccessStore::new(
            ReplayLedger::open(directory.path().join("ledger"), unix_timestamp().unwrap()).unwrap(),
        );
        let (entered, started) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let issuing = store.clone();
        let issued = a.clone();
        let issuance = thread::spawn(move || {
            issuing.issue(&issued, unix_timestamp, || {
                entered.send(()).unwrap();
                resume.recv().unwrap();
                Ok(())
            })
        });
        started.recv().unwrap();
        let revoking = store.clone();
        let target = a.target_node_id.clone();
        let envelope = notice(&a, &signer);
        let (ack, received) = mpsc::channel();
        let revocation = thread::spawn(move || {
            revoking
                .revoke(&envelope, &verifier, &target, None)
                .unwrap();
            ack.send(()).unwrap();
        });
        assert!(received.recv_timeout(Duration::from_millis(20)).is_err());
        release.send(()).unwrap();
        issuance.join().unwrap().unwrap();
        received.recv().unwrap();
        revocation.join().unwrap();
        let mut fresh = a;
        fresh.nonce.push('x');
        assert!(matches!(
            store.issue(&fresh, unix_timestamp, || Ok(())),
            Err(AccessError::Revoked)
        ));
    }

    #[test]
    fn invalid_revocation_cannot_mutate_durable_or_live_state() {
        let directory = tempfile::tempdir().unwrap();
        let a = authorization();
        let (signer, verifier) = signer();
        let store = AccessStore::new(
            ReplayLedger::open(directory.path().join("ledger"), unix_timestamp().unwrap()).unwrap(),
        );
        let session = store.register(&identity(&a)).unwrap();
        let mut corrupted = notice(&a, &signer);
        corrupted.signature.push('A');
        assert!(
            store
                .revoke(&corrupted, &verifier, &a.target_node_id, None)
                .is_err()
        );
        let envelope = notice(&a, &signer);
        assert!(
            store
                .revoke(&envelope, &verifier, "wrong-target", None)
                .is_err()
        );
        assert!(
            store
                .revoke(
                    &envelope,
                    &verifier,
                    &a.target_node_id,
                    Some("wrong-domain")
                )
                .is_err()
        );
        assert!(!*session.cancelled.borrow());
        store.issue(&a, unix_timestamp, || Ok(())).unwrap();
    }
    proptest::proptest! {
        #[test]
        fn generated_consumer_traces_preserve_revocation_and_replay(
            actions in proptest::collection::vec(0_u8..7, 1..32),
        ) {
            use proptest::prelude::*;
            use std::sync::LazyLock;
            static KEYS: LazyLock<(OpenSslEd25519Signer, OpenSslEd25519Verifier)> = LazyLock::new(signer);
            let directory = tempfile::tempdir().unwrap(); let path = directory.path().join("ledger");
            let a = authorization(); let envelope = notice(&a, &KEYS.0);
            let mut store = AccessStore::new(ReplayLedger::open(&path, unix_timestamp().unwrap()).unwrap());
            let mut revoked = false; let mut issued = false; let mut sessions = Vec::new();
            for action in actions {
                match action {
                    0 => {
                        let result = store.issue(&a, unix_timestamp, || Ok(()));
                        if revoked { prop_assert!(matches!(result, Err(AccessError::Revoked))); }
                        else if issued { prop_assert!(matches!(result, Err(AccessError::Replay))); }
                        else { prop_assert!(result.is_ok()); issued = true; }
                    }
                    1 => {
                        let result = store.register(&identity(&a));
                        if revoked { prop_assert!(matches!(result, Err(AccessError::Revoked))); }
                        else { prop_assert!(result.is_ok()); sessions.push(result.unwrap()); }
                    }
                    2 => { store.revoke(&envelope, &KEYS.1, &a.target_node_id, Some(&a.domain_id)).unwrap(); revoked = true; }
                    3 => { sessions.clear(); }
                    4 => {
                        sessions.clear(); drop(store);
                        store = AccessStore::new(ReplayLedger::open(&path, unix_timestamp().unwrap()).unwrap());
                    }
                    5 => {
                        let mut bad = envelope.clone(); bad.signature.push('x');
                        prop_assert!(store.revoke(&bad, &KEYS.1, &a.target_node_id, None).is_err());
                    }
                    _ => {
                        let mut independent = identity(&a); independent.decision_id.push('x');
                        prop_assert!(store.register(&independent).is_ok());
                    }
                }
                for session in &sessions { prop_assert_eq!(*session.cancelled.borrow(), revoked); }
            }
        }
    }
    proptest::proptest! {
        #[test]
        fn session_expiry_does_not_round_away_fractional_time(fraction in 0_u32..1_000_000_000, seconds in 1_u64..3600) {
            let now = UNIX_EPOCH + Duration::new(100, fraction);
            let remaining = certificate_lifetime(i64::try_from(100 + seconds).unwrap(), now).unwrap();
            proptest::prop_assert_eq!(now + remaining, UNIX_EPOCH + Duration::from_secs(100 + seconds));
            proptest::prop_assert!(certificate_lifetime(100, now).is_err());
        }
    }
}
