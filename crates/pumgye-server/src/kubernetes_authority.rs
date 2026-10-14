//! Sole-writer Kubernetes source reconciliation with process-local, non-persisted leases.
use crate::{Authority, Document, View, kubernetes_api::Collector, kubernetes_mapping::Mapping};
use anyhow::{Result, ensure};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

fn install(a: &Authority, policy: pumgye_core::Policy, expires: Instant) -> Result<()> {
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
    let epoch = Instant::now();
    loop {
        // Withdraw before collection; errors never retain a prior permissive view.
        a.source_ready.store(false, Ordering::Release);
        let now = u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        if collector.refresh(&ca, &token, now).await.is_ok() {
            let now = u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
            if let Some(observation) = collector.fresh(now)
                && let Ok(candidate) = mapping.candidate(&observation.inventory)
                && let Some(expires) =
                    epoch.checked_add(Duration::from_millis(observation.valid_until_ms))
            {
                let active = a.clone();
                // Durable writes and compilation stay off the decision executor.
                let _ = tokio::task::spawn_blocking(move || {
                    install(&active, candidate.policy, expires)
                })
                .await;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{authority, headers};
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
