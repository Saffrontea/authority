//! Single-flight cache with hard expiry and bounded retries; no stale fallback.
use openssl::{
    asn1::Asn1Time,
    x509::{X509Crl, X509Ref},
};
use std::{
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Mutex, time::Instant};

pub struct RefreshCache<T> {
    state: Mutex<CacheState<T>>,
}
struct CacheState<T> {
    entry: Option<(T, Instant)>,
    retry_after: Option<Instant>,
}
impl<T> Default for RefreshCache<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(CacheState {
                entry: None,
                retry_after: None,
            }),
        }
    }
}
impl<T: Clone> RefreshCache<T> {
    pub async fn get_or_refresh<F: Future<Output = Result<(T, Instant), String>>>(
        &self,
        refresh: impl FnOnce() -> F,
    ) -> Result<T, String> {
        // Holding this lock across refresh coalesces concurrent unauthenticated
        // handshakes into one fetch. Every caller rechecks the hard deadline.
        let mut state = self.state.lock().await;
        let now = Instant::now();
        if let Some((value, expiry)) = &state.entry
            && *expiry > now
        {
            return Ok(value.clone());
        }
        if state.retry_after.is_some_and(|deadline| deadline > now) {
            return Err("CRL refresh temporarily unavailable".into());
        }
        match refresh().await {
            Ok((value, expiry)) if expiry > Instant::now() => {
                state.entry = Some((value.clone(), expiry));
                state.retry_after = None;
                Ok(value)
            }
            result => {
                state.retry_after = Some(Instant::now() + Duration::from_secs(1));
                Err(result
                    .err()
                    .unwrap_or_else(|| "CRL expired during refresh".into()))
            }
        }
    }
}

pub fn validated_deadline(bytes: &[u8], ca: &X509Ref) -> Result<Instant, String> {
    let crl = X509Crl::from_der(bytes).map_err(|error| error.to_string())?;
    let key = ca.public_key().map_err(|error| error.to_string())?;
    if !crl.verify(&key).map_err(|error| error.to_string())?
        || crl
            .issuer_name()
            .to_der()
            .map_err(|error| error.to_string())?
            != ca
                .subject_name()
                .to_der()
                .map_err(|error| error.to_string())?
    {
        return Err("CRL issuer or signature mismatch".into());
    }
    let clock = Instant::now();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    let now =
        Asn1Time::from_unix(i64::try_from(wall.as_secs()).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let next = crl.next_update().ok_or("CRL lacks nextUpdate")?;
    if crl
        .last_update()
        .compare(&now)
        .map_err(|error| error.to_string())?
        .is_gt()
        || next
            .compare(&now)
            .map_err(|error| error.to_string())?
            .is_le()
    {
        return Err("CRL is not currently valid".into());
    }
    let diff = now.diff(next).map_err(|error| error.to_string())?;
    let seconds = i64::from(diff.days) * 86400 + i64::from(diff.secs);
    let remaining = Duration::from_secs(u64::try_from(seconds).map_err(|error| error.to_string())?)
        .checked_sub(Duration::from_nanos(u64::from(wall.subsec_nanos())))
        .ok_or("CRL expired")?;
    let limit = Duration::from_secs(
        u64::try_from(authority_mtls_core::pki::STATUS_VALIDITY_SECONDS)
            .map_err(|error| error.to_string())?,
    );
    Ok(clock + remaining.min(limit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn concurrent_handshakes_share_one_refresh() {
        let cache = Arc::new(RefreshCache::default());
        let fetches = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..64 {
            let cache = cache.clone();
            let fetches = fetches.clone();
            tasks.spawn(async move {
                cache
                    .get_or_refresh(|| async {
                        fetches.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok((7, Instant::now() + Duration::from_secs(30)))
                    })
                    .await
                    .unwrap()
            });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(result.unwrap(), 7);
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expiry_and_refresh_failure_never_serve_stale_state() {
        let cache = RefreshCache::default();
        assert_eq!(
            cache
                .get_or_refresh(|| async { Ok((7, Instant::now() + Duration::from_millis(50))) })
                .await
                .unwrap(),
            7
        );
        tokio::time::sleep(Duration::from_millis(75)).await;
        assert!(
            cache
                .get_or_refresh(|| async { Err("issuer down".into()) })
                .await
                .is_err()
        );
        // Negative caching also prevents queued handshakes from amplifying a failure.
        assert!(
            cache
                .get_or_refresh(|| async { panic!("must back off") })
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use openssl::{
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        x509::{X509, X509CrlBuilder, X509NameBuilder},
    };
    fn ca() -> (X509, PKey<openssl::pkey::Private>) {
        let key = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "cache-test").unwrap();
        let name = name.build();
        let mut ca = X509::builder().unwrap();
        ca.set_version(2).unwrap();
        ca.set_subject_name(&name).unwrap();
        ca.set_issuer_name(&name).unwrap();
        ca.set_pubkey(&key).unwrap();
        ca.set_not_before(&Asn1Time::from_unix(0).unwrap()).unwrap();
        ca.set_not_after(&Asn1Time::from_unix(2_000_000_000).unwrap())
            .unwrap();
        ca.sign(&key, MessageDigest::sha256()).unwrap();
        (ca.build(), key)
    }
    fn crl(ca: &X509, key: &PKey<openssl::pkey::Private>, start: i64, end: i64) -> Vec<u8> {
        let mut crl = X509CrlBuilder::new().unwrap();
        crl.set_issuer_name(ca.subject_name()).unwrap();
        crl.set_last_update(&Asn1Time::from_unix(start).unwrap())
            .unwrap();
        crl.set_next_update(&Asn1Time::from_unix(end).unwrap())
            .unwrap();
        let dummy = X509::builder().unwrap();
        crl.append_extension(
            openssl::x509::extension::AuthorityKeyIdentifier::new()
                .issuer(true)
                .build(&dummy.x509v3_context(Some(ca), None))
                .unwrap(),
        )
        .unwrap();
        crl.append_extension(
            openssl::x509::extension::CrlNumber::new(openssl::bn::BigNum::from_u32(1).unwrap())
                .unwrap()
                .build()
                .unwrap(),
        )
        .unwrap();
        crl.sign(key, MessageDigest::sha256()).unwrap();
        crl.build().unwrap().to_der().unwrap()
    }
    #[test]
    fn cache_requires_signed_current_crl_and_caps_its_lifetime() {
        let (ca, key) = ca();
        let (wrong, _) = self::ca();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let valid = crl(&ca, &key, now - 1, now + 300);
        let before = Instant::now();
        let deadline = validated_deadline(&valid, &ca).unwrap();
        assert!(deadline > before && deadline <= Instant::now() + Duration::from_secs(30));
        assert!(validated_deadline(&valid, &wrong).is_err());
        assert!(validated_deadline(&crl(&ca, &key, now - 60, now - 1), &ca).is_err());
        assert!(validated_deadline(&crl(&ca, &key, now + 60, now + 90), &ca).is_err());
        assert!(validated_deadline(b"malformed", &ca).is_err());
    }
}
