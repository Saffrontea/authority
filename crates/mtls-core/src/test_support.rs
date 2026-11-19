//! Legacy single-process fixtures for crypto and generated consumer tests.
//! Production authority is implemented exclusively by `database::AuthorityDb`.
use super::{AccessError, ClientIdentity, decision_key, unix_timestamp};
use authority_contracts_model::{
    AdapterGrantKindV1, MtlsIssuanceAuthorizationV1, SignedDecisionRevocationNoticeV2,
};
use authority_credential_crypto_openssl::OpenSslEd25519Verifier;
use authority_issuer_core::verify_revocation_notice_v2_for_adapter;
use authority_replay_ledger::ReplayLedger;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

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
