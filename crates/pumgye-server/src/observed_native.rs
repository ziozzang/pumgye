//! Adapter to the binary authority's exact database/Kubernetes publication.
use super::*;
use pumgye_server::observed_permit::{NativePolicySnapshot, NativePolicySource};
use std::sync::Weak;
use tonic::Status;
pub(crate) struct Source(pub(crate) Weak<Authority>);
struct Snapshot {
    owner: Arc<Authority>,
    view: Arc<View>,
}
impl NativePolicySource for Source {
    fn capture(&self) -> Result<Arc<dyn NativePolicySnapshot>, Status> {
        let owner = self
            .0
            .upgrade()
            .ok_or_else(|| Status::unavailable("policy owner retired"))?;
        let view = owner.view.load_full();
        Ok(Arc::new(Snapshot { owner, view }))
    }
}
impl NativePolicySnapshot for Snapshot {
    fn compiled(&self) -> &CompiledPolicy {
        &self.view.compiled
    }
    fn revision(&self) -> u64 {
        self.view.document.revision
    }
    fn current(&self) -> bool {
        self.owner.healthy.load(Ordering::Acquire)
            && Arc::ptr_eq(&self.view, &self.owner.view.load_full())
            && self.owner.source_remaining(&self.view).is_some()
    }
    fn remaining(&self) -> Result<std::time::Duration, Status> {
        if !self.current() {
            return Err(Status::unavailable("policy publication unavailable"));
        }
        if !self.owner.kubernetes_owned {
            return Ok(std::time::Duration::from_millis(1000));
        }
        self.owner
            .source_remaining(&self.view)
            .ok_or_else(|| Status::unavailable("policy source evidence expired or retired"))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn exact_database_view_and_boottime_kubernetes_readiness_are_mandatory() {
        let root = tempfile::tempdir().unwrap();
        let mut owner = crate::tests::authority(root.path());
        let source = Source(Arc::downgrade(&owner));
        let snapshot = source.capture().unwrap();
        assert!(snapshot.current());
        assert!(std::ptr::eq(
            snapshot.compiled(),
            &owner.view.load_full().compiled
        ));
        let document = owner.view.load_full().document.clone();
        owner.view.store(Arc::new(View {
            compiled: document.policy.compile().unwrap(),
            document,
            source_lifetime: None,
        }));
        assert!(!snapshot.current());
        drop(snapshot);
        owner.healthy.store(false, Ordering::Release);
        assert!(!source.capture().unwrap().current());
        owner.healthy.store(true, Ordering::Release);
        drop(source);
        Arc::get_mut(&mut owner).unwrap().kubernetes_owned = true;
        let source = Source(Arc::downgrade(&owner));
        owner.source_ready.store(true, Ordering::Release);
        assert!(!source.capture().unwrap().current());
        let clock = owner.source_clock.as_ref().unwrap();
        let sample = clock
            .finish_exchange(clock.begin_exchange().unwrap())
            .unwrap();
        let bound = sample.before_ticks() + 30;
        let deadline = sample.bind_bounds(bound, bound).unwrap().0;
        let document = owner.view.load_full().document.clone();
        owner.view.store(Arc::new(View {
            compiled: document.policy.compile().unwrap(),
            document,
            source_lifetime: Some(crate::source_lifetime::Lifetime::new(deadline)),
        }));
        let snapshot = source.capture().unwrap();
        assert!(snapshot.current());
        assert!(snapshot.remaining().unwrap().as_millis() <= 30);
        tokio::time::sleep(std::time::Duration::from_millis(35)).await;
        assert!(!snapshot.current());
        assert!(snapshot.remaining().is_err());
    }
}
