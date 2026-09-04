//! Automatic renewal of delegations addressed to a local iroh endpoint.

use std::{
    collections::BTreeMap,
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use iroh::{Endpoint, EndpointId};
use rcan::Delegation;
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{Store, fetch::fetch};

const RENEW_BEFORE_SECS: u64 = 10 * 60;
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(30);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Signals that stored delegation evidence changed.
#[derive(Clone)]
pub struct RenewalTrigger(Arc<Notify>);

impl RenewalTrigger {
    /// Recalculates renewal deadlines.
    pub fn evidence_changed(&self) {
        self.0.notify_one();
    }
}

/// Wakes and shuts down a delegation-renewal task.
pub struct RenewalHandle {
    changed: Arc<Notify>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl RenewalHandle {
    /// Returns a clonable Store-change signal.
    pub fn trigger(&self) -> RenewalTrigger {
        RenewalTrigger(self.changed.clone())
    }

    /// Stops the renewal task.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

/// Starts automatic renewal for delegations in `snapshot` addressed to `endpoint`.
pub fn spawn<E>(
    endpoint: Endpoint,
    snapshot: impl Fn() -> Store + Send + Sync + 'static,
    merge: impl Fn(Vec<Delegation>) -> std::result::Result<(), E> + Send + Sync + 'static,
) -> RenewalHandle
where
    E: Send + 'static,
{
    let merge = Arc::new(merge);
    spawn_with(endpoint.id(), snapshot, move |issuer| {
        let endpoint = endpoint.clone();
        let merge = merge.clone();
        async move {
            match fetch(&endpoint, issuer).await {
                Ok(delegations) => merge(delegations).is_ok(),
                Err(_) => false,
            }
        }
    })
}

fn spawn_with<S, F, Fut>(audience: EndpointId, snapshot: S, fetch_from: F) -> RenewalHandle
where
    S: Fn() -> Store + Send + Sync + 'static,
    F: Fn(EndpointId) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    let changed = Arc::new(Notify::new());
    let cancel = CancellationToken::new();
    let task_changed = changed.clone();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        let mut retries = BTreeMap::<EndpointId, Retry>::new();
        loop {
            let now = SystemTime::now();
            let targets = snapshot().renewal_targets(audience);
            retries.retain(|issuer, retry| {
                targets
                    .iter()
                    .any(|(target, expires_at)| target == issuer && expires_at == &retry.expires_at)
            });
            let due_at = targets
                .iter()
                .map(|(issuer, expires_at)| {
                    retries
                        .get(issuer)
                        .map(|retry| retry.at)
                        .unwrap_or_else(|| {
                            UNIX_EPOCH
                                + Duration::from_secs(expires_at.saturating_sub(RENEW_BEFORE_SECS))
                        })
                })
                .min();
            let sleep_for = due_at
                .and_then(|due_at| due_at.duration_since(now).ok())
                .unwrap_or(Duration::ZERO);

            tokio::select! {
                _ = task_cancel.cancelled() => break,
                _ = task_changed.notified() => continue,
                _ = tokio::time::sleep(sleep_for), if due_at.is_some() => {}
            }

            let now = SystemTime::now();
            for (issuer, expires_at) in targets {
                let scheduled = retries
                    .get(&issuer)
                    .map(|retry| retry.at)
                    .unwrap_or_else(|| {
                        UNIX_EPOCH
                            + Duration::from_secs(expires_at.saturating_sub(RENEW_BEFORE_SECS))
                    });
                if scheduled > now {
                    continue;
                }
                let fetched = tokio::select! {
                    _ = task_cancel.cancelled() => return,
                    result = tokio::time::timeout(FETCH_TIMEOUT, fetch_from(issuer)) => {
                        result.is_ok_and(|result| result)
                    },
                };
                let current_expiry = snapshot().renewal_targets(audience).into_iter().find_map(
                    |(target, current_expiry)| (target == issuer).then_some(current_expiry),
                );
                if fetched && current_expiry.is_none_or(|current| current != expires_at) {
                    retries.remove(&issuer);
                } else {
                    let delay = if fetched {
                        INITIAL_RETRY_DELAY
                    } else {
                        retries.get(&issuer).map_or(INITIAL_RETRY_DELAY, |retry| {
                            (retry.delay * 2).min(MAX_RETRY_DELAY)
                        })
                    };
                    retries.insert(
                        issuer,
                        Retry {
                            at: now + delay,
                            delay,
                            expires_at,
                        },
                    );
                }
            }
        }
    });
    RenewalHandle {
        changed,
        cancel,
        task,
    }
}

struct Retry {
    at: SystemTime,
    delay: Duration,
    expires_at: u64,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, RwLock},
        time::Duration,
    };

    use iroh::SecretKey;
    use rcan::{Delegation, Expires};
    use tokio::sync::mpsc;

    use super::spawn_with;
    use crate::Store;

    #[tokio::test]
    async fn renews_only_local_audience_from_its_immediate_issuer() {
        let local = SecretKey::from_bytes(&[1; 32]).public();
        let local_issuer = SecretKey::from_bytes(&[2; 32]);
        let foreign = SecretKey::from_bytes(&[3; 32]).public();
        let foreign_issuer = SecretKey::from_bytes(&[4; 32]);
        let local_grant = Delegation::issuing_builder(
            local_issuer.as_signing_key(),
            local.as_verifying_key(),
            &"local".to_owned(),
        )
        .sign(Expires::At(1));
        let foreign_grant = Delegation::issuing_builder(
            foreign_issuer.as_signing_key(),
            foreign.as_verifying_key(),
            &"foreign".to_owned(),
        )
        .sign(Expires::At(1));
        let store = Arc::new(RwLock::new(Store::default()));
        store
            .write()
            .unwrap()
            .insert(local_grant.into_opaque())
            .unwrap();
        store
            .write()
            .unwrap()
            .insert(foreign_grant.into_opaque())
            .unwrap();
        let snapshot = store.clone();
        let (send, mut receive) = mpsc::unbounded_channel();
        let renewal = spawn_with(
            local,
            move || snapshot.read().unwrap().clone(),
            move |issuer| {
                send.send(issuer).unwrap();
                async { true }
            },
        );

        let issuer = tokio::time::timeout(Duration::from_secs(1), receive.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(issuer, local_issuer.public());
        assert!(receive.try_recv().is_err());
        renewal.shutdown().await;
    }
}
