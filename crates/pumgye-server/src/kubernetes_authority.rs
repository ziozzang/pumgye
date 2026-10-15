//! Sole-writer Kubernetes source reconciliation with process-local, non-persisted leases.
use crate::{Authority, Document, View, kubernetes_api::Collector, kubernetes_mapping::Mapping};
use anyhow::{Result, ensure};
#[cfg(all(test, target_os = "linux"))]
use std::time::Instant;
use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

#[cfg(all(test, target_os = "linux"))]
fn install(a: &Authority, policy: pumgye_core::Policy, expires: Instant) -> Result<()> {
    let clock = a
        .source_clock
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("source clock absent"))?;
    let sample = clock
        .finish_exchange(
            clock
                .begin_exchange()
                .map_err(|_| anyhow::anyhow!("source clock unavailable"))?,
        )
        .map_err(|_| anyhow::anyhow!("source clock unavailable"))?;
    let bound = sample
        .before_ticks()
        .checked_add(u64::try_from(
            expires
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )?)
        .ok_or_else(|| anyhow::anyhow!("source expiry overflow"))?;
    let (deadline, _) = sample
        .bind_bounds(bound, bound)
        .map_err(|_| anyhow::anyhow!("source expired"))?;
    install_inner(a, policy, crate::source_lifetime::Lifetime::new(deadline))
}
fn install_inner(
    a: &Authority,
    policy: pumgye_core::Policy,
    lifetime: Arc<crate::source_lifetime::Lifetime>,
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
    ensure!(
        lifetime
            .remaining(
                a.source_clock
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("source clock absent"))?
            )
            .is_some(),
        "source lease expired"
    );
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
        source_lifetime: Some(lifetime.clone()),
    }));
    a.source_ready.store(
        lifetime
            .remaining(
                a.source_clock
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("source clock absent"))?,
            )
            .is_some(),
        Ordering::Release,
    );
    Ok(())
}

pub async fn run(
    a: Arc<Authority>,
    mut collector: Collector,
    mapping: Mapping,
    ca: PathBuf,
    token: PathBuf,
) {
    loop {
        // Withdraw before collection; errors never retain a prior permissive view.
        a.source_ready.store(false, Ordering::Release);
        a.source_phase.store(1, Ordering::Release);
        let collection = match source_ticks(&a) {
            Ok(now) => collector.refresh(&ca, &token, now).await,
            Err(error) => Err(error),
        };
        let phase = if collection.is_err() {
            // Do not expose transport errors, URLs, credential paths or provider bodies.
            3
        } else {
            let candidate = source_ticks(&a)
                .ok()
                .and_then(|now| collector.fresh(now))
                .and_then(|observation| {
                    let policy = mapping.candidate(&observation.inventory).ok()?.policy;
                    let clock = a.source_clock.as_ref()?;
                    let lifetime = observation.lifetime(clock)?;
                    Some((policy, lifetime))
                });
            if let Some((policy, lifetime)) = candidate {
                let active = a.clone();
                match tokio::task::spawn_blocking(move || install_inner(&active, policy, lifetime))
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

fn invalidate_source(a: &Authority) {
    a.source_ready.store(false, Ordering::Release);
    if let Some(lifetime) = &a.view.load().source_lifetime {
        lifetime.retire();
    }
}
fn source_ticks(a: &Authority) -> Result<u64> {
    let previous = a.source_ticks_floor.load(Ordering::Acquire);
    let result = a
        .source_clock
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("source clock absent"))?
        .sample_ticks();
    match result {
        Ok(now) if now >= previous => {
            a.source_ticks_floor.fetch_max(now, Ordering::AcqRel);
            Ok(now)
        }
        _ => {
            invalidate_source(a);
            Err(anyhow::anyhow!("source clock unavailable or reversed"))
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::tests::{authority, headers};
    use axum::response::IntoResponse;
    #[tokio::test]
    async fn original_publication_budget_fences_generic_resource_readiness_and_repeat_install() {
        use std::sync::atomic::AtomicU64;
        let root = tempfile::tempdir().unwrap();
        let mut a = authority(root.path());
        Arc::get_mut(&mut a).unwrap().kubernetes_owned = true;
        let document: Document =
            serde_json::from_str(include_str!("../../../examples/resource-catalog.json")).unwrap();
        let remaining = Arc::new(AtomicU64::new(900));
        let read = remaining.clone();
        let lifetime = crate::source_lifetime::Lifetime::controlled(
            a.source_clock.as_ref().unwrap(),
            Arc::new(move || Some(Duration::from_millis(read.load(Ordering::Acquire)))),
        );
        install_inner(&a, document.policy.clone(), lifetime.clone()).unwrap();
        let revision = a.view.load().document.revision;
        a.source_phase.store(2, Ordering::Release);
        let query = pumgye_protocol::Query {
            request_id: 1,
            minimum_revision: 1,
            ip: "192.0.2.9".parse().unwrap(),
            aal: 2,
            guard: crate::GuardEvidence::EnforcedAllow,
            service_id: "orders",
            subject: "fixture",
            permission: "read",
            information_class: "internal",
        };
        let resource = crate::ResourceEvaluation {
            service_id: "orders",
            resource: "db:orders",
            action: "select",
            subject: "fixture",
            ip: query.ip,
            aal: 2,
            guard: query.guard,
            minimum_revision: 1,
        };
        assert_eq!(
            a.evaluate(&query).decision,
            Some(pumgye_core::Decision::Allow)
        );
        assert!(a.resource_authorize_then(&resource, |_, _| ()).is_ok());
        let captured = a.view.load_full();
        remaining.store(700, Ordering::Release);
        assert_eq!(
            a.source_remaining(&captured).unwrap(),
            Duration::from_millis(700)
        );
        // Reinstalling the same immutable source observation preserves its
        // remaining budget; no policy/version equality can re-anchor it.
        install_inner(&a, document.policy.clone(), lifetime.clone()).unwrap();
        assert_eq!(
            a.source_remaining(&a.view.load()).unwrap(),
            Duration::from_millis(700)
        );
        assert_eq!(a.view.load().document.revision, revision);
        let private = a.resource_authorize_then(&resource, |_, _| {
            remaining.store(0, Ordering::Release);
            "private signed candidate"
        });
        assert!(private.is_err());
        assert!(a.evaluate(&query).decision.is_none());
        assert!(!a.available());
        assert_eq!(
            crate::readiness(crate::State(a.clone()))
                .await
                .into_response()
                .status(),
            crate::StatusCode::SERVICE_UNAVAILABLE
        );
        let status = crate::status(crate::State(a.clone())).await.0;
        assert_eq!(status["source_state"], "expired");
        assert_eq!(status["source_lease_remaining_ms"], 0);
        remaining.store(900, Ordering::Release); // wall/repeat-poll recovery cannot revive old evidence
        assert!(install_inner(&a, document.policy.clone(), lifetime.clone()).is_err());
        assert!(!a.available());
        // Only a distinct legitimate complete collection may publish a fresh
        // lifetime, even when the native policy's content revision is unchanged.
        let read = remaining.clone();
        let fresh = crate::source_lifetime::Lifetime::controlled(
            a.source_clock.as_ref().unwrap(),
            Arc::new(move || Some(Duration::from_millis(read.load(Ordering::Acquire)))),
        );
        install_inner(&a, document.policy, fresh).unwrap();
        assert_eq!(a.view.load().document.revision, revision);
        assert!(a.available());
        assert_eq!(
            a.evaluate(&query).decision,
            Some(pumgye_core::Decision::Allow)
        );
        assert!(
            lifetime
                .remaining(a.source_clock.as_ref().unwrap())
                .is_none()
        );
    }
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
            source_lifetime: None,
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
            source_lifetime: None,
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
