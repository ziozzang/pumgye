//! Sole-writer Kubernetes source reconciliation with process-local, non-persisted leases.
use crate::{Authority, Document, View, kubernetes_api::Collector, kubernetes_mapping::Mapping};
use anyhow::{Result, ensure};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

#[cfg(any(test, not(feature = "observed-authentication")))]
fn install(a: &Authority, policy: pumgye_core::Policy, expires: Instant) -> Result<()> {
    #[cfg(feature = "observed-authentication")]
    let observed = {
        let start = a
            .source_clock
            .begin_exchange()
            .map_err(|_| anyhow::anyhow!("source clock unavailable"))?;
        let remaining = expires.saturating_duration_since(Instant::now());
        let sample = a
            .source_clock
            .finish_exchange(start)
            .map_err(|_| anyhow::anyhow!("source clock unavailable"))?;
        let bound = sample
            .before_ticks()
            .checked_add(u64::try_from(remaining.as_millis())?)
            .ok_or_else(|| anyhow::anyhow!("source deadline overflow"))?;
        sample
            .bind_bounds(bound, bound)
            .map_err(|_| anyhow::anyhow!("source deadline expired"))?
            .0
    };
    install_inner(
        a,
        policy,
        expires,
        #[cfg(feature = "observed-authentication")]
        observed,
    )
}
fn install_inner(
    a: &Authority,
    policy: pumgye_core::Policy,
    expires: Instant,
    #[cfg(feature = "observed-authentication")] observed: hangang_runtime::time::LocalDeadline,
) -> Result<()> {
    a.source_ready.store(false, Ordering::Release);
    ensure!(
        a.kubernetes_owned && a.healthy.load(Ordering::Acquire),
        "source owner unavailable"
    );
    let compiled = policy.compile()?;
    let mut store = a.store.lock().map_err(|_| {
        a.healthy.store(false, Ordering::Release);
        anyhow::anyhow!("source persistence unavailable")
    })?;
    ensure!(Instant::now() < expires, "source lease expired");
    let previous = a.view.load_full();
    let changed = serde_json::to_vec(&previous.document.policy)? != serde_json::to_vec(&policy)?;
    let revision = if changed {
        previous
            .document
            .revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or_else(|| anyhow::anyhow!("source revision exhausted"))?
    } else {
        previous.document.revision
    };
    let document = Document { revision, policy };
    if changed
        && store
            .publish(previous.document.revision, &document, "kubernetes-source")
            .is_err()
    {
        a.healthy.store(false, Ordering::Release);
        anyhow::bail!("source persistence unavailable");
    }
    // Even a slow durable commit cannot turn an expired observation into a live grant.
    a.view.store(Arc::new(View {
        document,
        compiled,
        source_expires: Some(expires),
        #[cfg(feature = "observed-authentication")]
        source_observed_deadline: Some(observed),
    }));
    a.source_ready
        .store(Instant::now() < expires, Ordering::Release);
    Ok(())
}

pub async fn run(
    a: Arc<Authority>,
    mut collector: Collector,
    mapping: Mapping,
    ca: PathBuf,
    token: PathBuf,
) {
    #[cfg(not(feature = "observed-authentication"))]
    let epoch = Instant::now();
    loop {
        // Withdraw before collection; errors never retain a prior permissive view.
        a.source_ready.store(false, Ordering::Release);
        a.source_phase.store(1, Ordering::Release);
        #[cfg(not(feature = "observed-authentication"))]
        let now = u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        #[cfg(feature = "observed-authentication")]
        let now = source_ticks(&a).unwrap_or(u64::MAX);
        let phase = if collector.refresh(&ca, &token, now).await.is_err() {
            // Do not expose transport errors, URLs, credential paths or provider bodies.
            3
        } else {
            #[cfg(not(feature = "observed-authentication"))]
            let now = u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
            #[cfg(feature = "observed-authentication")]
            let now = source_ticks(&a).unwrap_or(u64::MAX);
            let candidate = collector.fresh(now).and_then(|observation| {
                let policy = mapping.candidate(&observation.inventory).ok()?.policy;
                #[cfg(not(feature = "observed-authentication"))]
                let expires =
                    epoch.checked_add(Duration::from_millis(observation.valid_until_ms))?;
                #[cfg(feature = "observed-authentication")]
                let expires = Instant::now().checked_add(Duration::from_millis(
                    observation.valid_until_ms.checked_sub(now)?,
                ))?;
                #[cfg(feature = "observed-authentication")]
                let deadline = {
                    let bound = observation.valid_until_ms;
                    let result = a
                        .source_clock
                        .begin_exchange()
                        .and_then(|start| a.source_clock.finish_exchange(start))
                        .and_then(|sample| sample.bind_bounds(bound, bound));
                    match result {
                        Ok((deadline, _)) => deadline,
                        Err(error) => {
                            if matches!(
                                error,
                                hangang_runtime::time::TimeError::ClockRead
                                    | hangang_runtime::time::TimeError::UnsupportedClock
                                    | hangang_runtime::time::TimeError::Overflow
                            ) {
                                a.source_clock.retire();
                                a.source_ready.store(false, Ordering::Release);
                            }
                            return None;
                        }
                    }
                };
                #[cfg(not(feature = "observed-authentication"))]
                let deadline = expires;
                Some((policy, expires, deadline))
            });
            if let Some((policy, expires, deadline)) = candidate {
                let active = a.clone();
                // Durable writes and compilation stay off the decision executor.
                match tokio::task::spawn_blocking(move || {
                    #[cfg(feature = "observed-authentication")]
                    {
                        install_inner(&active, policy, expires, deadline)
                    }
                    #[cfg(not(feature = "observed-authentication"))]
                    {
                        let _ = deadline;
                        install(&active, policy, expires)
                    }
                })
                .await
                {
                    Ok(Ok(())) => 2,
                    _ => 4,
                }
            } else {
                4
            }
        };
        a.source_phase.store(phase, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(feature = "observed-authentication")]
fn source_ticks(a: &Authority) -> Result<u64> {
    let result = a
        .source_clock
        .begin_exchange()
        .and_then(|s| a.source_clock.finish_exchange(s))
        .map(|s| s.after_ticks());
    result.map_err(|_| {
        a.source_clock.retire();
        a.source_ready.store(false, Ordering::Release);
        anyhow::anyhow!("source clock unavailable")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{authority, headers};
    use axum::response::IntoResponse;
    #[tokio::test]
    async fn management_distinguishes_source_failure_and_expired_grants() {
        let root = tempfile::tempdir().unwrap();
        let mut a = authority(root.path());
        Arc::get_mut(&mut a).unwrap().kubernetes_owned = true;
        let current = crate::status(crate::State(a.clone())).await.0;
        let ready = crate::readiness(crate::State(a.clone()))
            .await
            .into_response();
        assert_eq!(ready.status(), crate::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(ready.headers()["cache-control"], "no-store");
        assert!(
            axum::body::to_bytes(ready.into_body(), 16)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(current["source_state"], "starting");
        assert_eq!(current["healthy"], false);
        for (phase, name) in [
            (1, "collecting"),
            (3, "collection_failed"),
            (4, "candidate_rejected"),
        ] {
            a.source_phase.store(phase, Ordering::Release);
            let current = crate::status(crate::State(a.clone())).await.0;
            assert_eq!(current["source_state"], name);
            assert_eq!(current["healthy"], false);
            assert_eq!(current["source_writable"], false);
        }
        let policy = a.view.load().document.policy.clone();
        install(&a, policy, Instant::now() + Duration::from_secs(1)).unwrap();
        a.source_phase.store(2, Ordering::Release);
        let current = crate::status(crate::State(a.clone())).await.0;
        assert_eq!(
            crate::readiness(crate::State(a.clone()))
                .await
                .into_response()
                .status(),
            crate::StatusCode::OK
        );
        assert_eq!(current["source_state"], "fresh");
        assert_eq!(current["healthy"], true);
        assert!(current["source_lease_remaining_ms"].as_u64().unwrap() <= 1000);
        let document = a.view.load().document.clone();
        a.view.store(Arc::new(View {
            compiled: document.policy.compile().unwrap(),
            document,
            source_expires: Some(Instant::now()),
            #[cfg(feature = "observed-authentication")]
            source_observed_deadline: None,
        }));
        let current = crate::status(crate::State(a.clone())).await.0;
        assert_eq!(
            crate::readiness(crate::State(a.clone()))
                .await
                .into_response()
                .status(),
            crate::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(current["source_state"], "expired");
        assert_eq!(current["healthy"], false);
        assert_eq!(current["source_lease_remaining_ms"], 0);
        a.healthy.store(false, Ordering::Release);
        assert_eq!(
            crate::status(crate::State(a)).await.0["source_state"],
            "persistence_failed"
        );
    }
    #[tokio::test]
    async fn source_lease_writer_exclusion_persistence_and_restart() {
        let root = tempfile::tempdir().unwrap();
        let mut a = authority(root.path());
        Arc::get_mut(&mut a).unwrap().kubernetes_owned = true;
        a.store.lock().unwrap().claim_source(true).unwrap();
        assert!(!a.available());
        let policy = a.view.load().document.policy.clone();
        install(&a, policy.clone(), Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(a.available());
        assert!(matches!(
            crate::publish(
                crate::State(a.clone()),
                headers(),
                axum::Extension(crate::PeerIdentity("fixture".into())),
                crate::Json(a.view.load().document.clone())
            )
            .await,
            Err(crate::StatusCode::CONFLICT)
        ));
        // Lease renewal alone creates no revision or durable audit churn.
        assert_eq!(a.view.load().document.revision, 1);
        install(&a, policy.clone(), Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(a.store.lock().unwrap().audit_after(0).unwrap().len(), 1);
        let expired = a.view.load().document.clone();
        a.view.store(Arc::new(View {
            compiled: expired.policy.compile().unwrap(),
            document: expired,
            source_expires: Some(Instant::now()),
            #[cfg(feature = "observed-authentication")]
            source_observed_deadline: None,
        }));
        assert!(!a.available());
        install(&a, policy.clone(), Instant::now() + Duration::from_secs(1)).unwrap();
        // A changed policy whose durable write fails permanently fences the old view.
        a.store.lock().unwrap().reject_writes();
        let mut changed = policy.clone();
        changed.information_classes.push("restricted".into());
        assert!(install(&a, changed, Instant::now() + Duration::from_secs(1)).is_err());
        assert!(!a.healthy.load(Ordering::Acquire));
        assert!(!a.available());
        a.source_ready.store(false, Ordering::Release);
        assert!(!a.available());
        assert!(install(&a, policy, Instant::now()).is_err());
        drop(a);
        let (mut store, _) =
            crate::store::Store::open(&root.path().join("authority.sqlite3"), None).unwrap();
        assert!(store.claim_source(false).is_err());
        store.claim_source(true).unwrap();
    }
}
