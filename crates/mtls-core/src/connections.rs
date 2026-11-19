//! Process-local sockets and derived cancellation fences, never authority storage.
use crate::{ClientIdentity, decision_key, unix_timestamp};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

#[derive(Clone, Default)]
pub struct Connections(Arc<Mutex<Inner>>);
#[derive(Default)]
struct Inner {
    next: u64,
    revoked: HashMap<String, i64>,
    sessions: HashMap<u64, Session>,
}
struct Session {
    key: String,
    cancel: watch::Sender<bool>,
    closed: watch::Receiver<bool>,
}
pub struct Guard {
    owner: Connections,
    id: u64,
    pub cancelled: watch::Receiver<bool>,
    closed: watch::Sender<bool>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.owner.0.lock() {
            inner.sessions.remove(&self.id);
        }
        self.closed.send_replace(true);
    }
}
impl Connections {
    /// # Errors
    /// Rejects expired/cancelled identities and poisoned or exhausted local state.
    pub fn register(&self, identity: &ClientIdentity) -> Result<Guard, String> {
        let mut inner = self.0.lock().map_err(|e| e.to_string())?;
        let now = unix_timestamp()?;
        if now < identity.not_before || now >= identity.expires_at {
            return Err("certificate expired".into());
        }
        inner.revoked.retain(|_, expiry| *expiry > now);
        let key = decision_key(
            &identity.domain_id,
            &identity.target_node_id,
            &identity.decision_id,
        );
        if inner.revoked.contains_key(&key) {
            return Err("decision revoked".into());
        }
        let id = inner.next;
        inner.next = id.checked_add(1).ok_or("session ID exhausted")?;
        let (cancel, cancelled) = watch::channel(false);
        let (closed, receiver) = watch::channel(false);
        inner.sessions.insert(
            id,
            Session {
                key,
                cancel,
                closed: receiver,
            },
        );
        Ok(Guard {
            owner: self.clone(),
            id,
            cancelled,
            closed,
        })
    }
    /// # Errors
    /// Installs the local registration fence before cancelling/draining sockets.
    pub fn revoke(
        &self,
        domain: &str,
        target: &str,
        decision: &str,
        expires_at: i64,
    ) -> Result<Vec<watch::Receiver<bool>>, String> {
        let mut inner = self.0.lock().map_err(|e| e.to_string())?;
        let key = decision_key(domain, target, decision);
        let now = unix_timestamp()?;
        inner.revoked.retain(|_, expiry| *expiry > now);
        if expires_at > now {
            inner
                .revoked
                .entry(key.clone())
                .and_modify(|expiry| *expiry = (*expiry).max(expires_at))
                .or_insert(expires_at);
        }
        let mut receivers = Vec::new();
        for session in inner.sessions.values().filter(|s| s.key == key) {
            receivers.push(session.closed.clone());
            session.cancel.send_replace(true);
        }
        Ok(receivers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_fences_registration_and_acknowledges_after_drop() {
        let connections = Connections::default();
        let now = unix_timestamp().unwrap();
        let mut identity = ClientIdentity {
            domain_id: "domain".into(),
            target_node_id: "target".into(),
            decision_id: "decision".into(),
            not_before: now - 1,
            expires_at: now + 60,
        };
        let mut session = connections.register(&identity).unwrap();
        let receivers = connections
            .revoke("domain", "target", "decision", now + 60)
            .unwrap();
        session.cancelled.changed().await.unwrap();
        assert!(*session.cancelled.borrow());
        assert!(connections.register(&identity).is_err());
        let mut waiting = tokio::spawn(crate::wait_closed(receivers));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        identity.decision_id = "independent".into();
        let independent = connections.register(&identity).unwrap();
        assert!(!*independent.cancelled.borrow());
        drop(session);
        waiting.await.unwrap().unwrap();
    }
}
