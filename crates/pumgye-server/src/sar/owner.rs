use super::*;
use hangang_runtime::time::ElapsedStamp;
use std::sync::atomic::AtomicU64;
// Native original Duration only; no public timestamp/remaining constructor.
pub(super) struct Budget {
    stamp: ElapsedStamp,
    limit: Duration,
    failed: AtomicBool,
    floor: AtomicU64,
    #[cfg(test)]
    pub(super) controlled: Option<Arc<dyn Fn() -> Option<Duration> + Send + Sync>>,
}
impl Budget {
    pub(super) fn new(limit: Duration) -> std::io::Result<Arc<Self>> {
        Ok(Self::from_stamp(
            ElapsedStamp::now().map_err(|_| io_error())?,
            limit,
        ))
    }
    pub(super) fn from_stamp(stamp: ElapsedStamp, limit: Duration) -> Arc<Self> {
        Arc::new(Self {
            stamp,
            limit,
            failed: AtomicBool::new(false),
            floor: AtomicU64::new(0),
            #[cfg(test)]
            controlled: None,
        })
    }
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn controlled(
        limit: Duration,
        read: Arc<dyn Fn() -> Option<Duration> + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self {
            stamp: ElapsedStamp::now().unwrap(),
            limit,
            failed: AtomicBool::new(false),
            floor: AtomicU64::new(0),
            controlled: Some(read),
        })
    }
    pub(super) fn current(&self) -> bool {
        if self.failed.load(Ordering::Acquire) {
            return false;
        }
        let before = self.floor.load(Ordering::Acquire);
        #[cfg(test)]
        let elapsed = match &self.controlled {
            Some(read) => read(),
            None => self.stamp.elapsed().ok(),
        };
        #[cfg(not(test))]
        let elapsed = self.stamp.elapsed().ok();
        let Some(ns) = elapsed
            .filter(|v| *v < self.limit)
            .and_then(|v| u64::try_from(v.as_nanos()).ok())
            .filter(|n| *n >= before)
        else {
            self.failed.store(true, Ordering::Release);
            return false;
        };
        if ns > before {
            self.floor.fetch_max(ns, Ordering::AcqRel);
        }
        !self.failed.load(Ordering::Acquire)
    }
}
pub(super) struct Capture {
    failed: AtomicBool,
    authority: Weak<Authority>,
    view: Arc<crate::View>,
    budget: Arc<Budget>,
}
impl Capture {
    pub(super) fn current(&self) -> bool {
        if self.failed.load(Ordering::Acquire) {
            return false;
        }
        let Some(a) = self.authority.upgrade() else {
            self.failed.store(true, Ordering::Release);
            return false;
        };
        let time_current = self.budget.current() && a.source_remaining(&self.view).is_some();
        let live = time_current
            && a.healthy.load(Ordering::Acquire)
            && Arc::ptr_eq(&self.view, &a.view.load());
        if !live {
            self.failed.store(true, Ordering::Release);
        }
        live && !self.failed.load(Ordering::Acquire)
    }
}
pub(super) fn authorize(
    a: &Arc<Authority>,
    cluster: &str,
    principal: &pumgye_core::kubernetes_authorization::Principal,
    attributes: &pumgye_core::kubernetes_authorization::Attributes,
    budget: Arc<Budget>,
) -> Option<Capture> {
    authorize_then(a, cluster, principal, attributes, budget, || {})
}
fn authorize_then(
    a: &Arc<Authority>,
    cluster: &str,
    principal: &pumgye_core::kubernetes_authorization::Principal,
    attributes: &pumgye_core::kubernetes_authorization::Attributes,
    budget: Arc<Budget>,
    finalize: impl FnOnce(),
) -> Option<Capture> {
    use pumgye_core::{
        Decision as D, ResourceDecision as R, kubernetes_authorization::MappingDecision as M,
    };
    let view = a.view.load_full();
    if !budget.current()
        || !a.healthy.load(Ordering::Acquire)
        || a.source_remaining(&view).is_none()
    {
        return None;
    }
    let decision = view
        .compiled
        .evaluate_kubernetes_request(cluster, principal, attributes);
    a.queries.fetch_add(1, Ordering::Relaxed);
    if decision != M::Decided(R::Decided(D::Allow)) {
        return None;
    }
    let owner = Capture {
        failed: AtomicBool::new(false),
        authority: Arc::downgrade(a),
        view,
        budget,
    };
    finalize();
    owner.current().then_some(owner)
}
#[cfg(all(test, target_os = "linux"))]
pub(super) fn after(
    a: &Arc<Authority>,
    cluster: &str,
    p: &pumgye_core::kubernetes_authorization::Principal,
    v: &pumgye_core::kubernetes_authorization::Attributes,
    b: Arc<Budget>,
    f: impl FnOnce(),
) -> Option<Capture> {
    authorize_then(a, cluster, p, v, b, f)
}
