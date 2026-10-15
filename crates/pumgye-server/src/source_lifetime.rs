//! Original native publication age, shared by every decision/readiness path.
//! A new authenticated collection may publish a new lifetime; sampling this
//! immutable lifetime never renews it, including after a read failure or reversal.
use hangang_runtime::time::{LocalDeadline, ReceiverClock};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

pub(crate) struct Lifetime {
    deadline: LocalDeadline,
    remaining_floor_ns: AtomicU64,
    failed: AtomicBool,
    #[cfg(all(test, target_os = "linux"))]
    controlled: Option<Arc<dyn Fn() -> Option<Duration> + Send + Sync>>,
}
impl Lifetime {
    pub(crate) fn new(deadline: LocalDeadline) -> Arc<Self> {
        Arc::new(Self {
            deadline,
            remaining_floor_ns: AtomicU64::new(u64::MAX),
            failed: AtomicBool::new(false),
            #[cfg(all(test, target_os = "linux"))]
            controlled: None,
        })
    }
    pub(crate) fn retire(&self) {
        self.failed.store(true, Ordering::Release);
    }
    pub(crate) fn remaining(&self, clock: &ReceiverClock) -> Option<Duration> {
        if self.failed.load(Ordering::Acquire) {
            return None;
        }
        // Read the prior floor BEFORE sampling. A concurrent newer sample must
        // not turn an older, delayed thread into a false clock-reversal report.
        let previous = self.remaining_floor_ns.load(Ordering::Acquire);
        #[cfg(all(test, target_os = "linux"))]
        let remaining = match &self.controlled {
            Some(read) => read(),
            None => self.deadline.remaining(clock).ok(),
        };
        #[cfg(not(all(test, target_os = "linux")))]
        let remaining = self.deadline.remaining(clock).ok();
        let Some(remaining) = remaining.filter(|r| !r.is_zero() && *r <= Duration::from_secs(1))
        else {
            self.retire();
            return None;
        };
        let Ok(nanos) = u64::try_from(remaining.as_nanos()) else {
            self.retire();
            return None;
        };
        if nanos > previous {
            self.retire();
            return None;
        }
        self.remaining_floor_ns.fetch_min(nanos, Ordering::AcqRel);
        if self.failed.load(Ordering::Acquire) {
            return None;
        }
        Some(remaining)
    }
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn controlled(
        clock: &ReceiverClock,
        read: Arc<dyn Fn() -> Option<Duration> + Send + Sync>,
    ) -> Arc<Self> {
        let sample = clock
            .finish_exchange(clock.begin_exchange().unwrap())
            .unwrap();
        let bound = sample.before_ticks() + 1000;
        let (deadline, _) = sample.bind_bounds(bound, bound).unwrap();
        Arc::new(Self {
            deadline,
            remaining_floor_ns: AtomicU64::new(u64::MAX),
            failed: AtomicBool::new(false),
            controlled: Some(read),
        })
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn older_read_completing_after_newer_read_does_not_retire_source() {
        use std::sync::{Barrier, atomic::AtomicUsize};
        let clock = Arc::new(ReceiverClock::new([2; 16]).unwrap());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let lifetime = Lifetime::controlled(&clock, {
            let entered = entered.clone();
            let release = release.clone();
            Arc::new(move || {
                let millis = match calls.fetch_add(1, Ordering::AcqRel) {
                    0 => {
                        // This older clock read completes after the newer one.
                        entered.wait();
                        release.wait();
                        800
                    }
                    1 => 700,
                    _ => 650,
                };
                Some(Duration::from_millis(millis))
            })
        });
        let older = {
            let lifetime = lifetime.clone();
            let clock = clock.clone();
            std::thread::spawn(move || lifetime.remaining(&clock))
        };
        entered.wait();
        assert_eq!(lifetime.remaining(&clock), Some(Duration::from_millis(700)));
        release.wait();
        assert_eq!(older.join().unwrap(), Some(Duration::from_millis(800)));
        assert_eq!(lifetime.remaining(&clock), Some(Duration::from_millis(650)));
    }
    #[test]
    fn repeated_snapshot_reads_do_not_renew_and_refusal_cannot_revive() {
        let clock = ReceiverClock::new([1; 16]).unwrap();
        let remaining = Arc::new(AtomicU64::new(900));
        let read = remaining.clone();
        let lifetime = Lifetime::controlled(
            &clock,
            Arc::new(move || match read.load(Ordering::Acquire) {
                u64::MAX => None,
                v => Some(Duration::from_millis(v)),
            }),
        );
        assert_eq!(
            lifetime.remaining(&clock).unwrap(),
            Duration::from_millis(900)
        );
        remaining.store(700, Ordering::Release);
        assert_eq!(
            lifetime.remaining(&clock).unwrap(),
            Duration::from_millis(700)
        );
        remaining.store(800, Ordering::Release); // clock reversal / stale re-anchor
        assert!(lifetime.remaining(&clock).is_none());
        remaining.store(100, Ordering::Release);
        assert!(lifetime.remaining(&clock).is_none());
        for refusal in [0, u64::MAX] {
            let read = remaining.clone();
            remaining.store(500, Ordering::Release);
            let fresh = Lifetime::controlled(
                &clock,
                Arc::new(move || match read.load(Ordering::Acquire) {
                    u64::MAX => None,
                    v => Some(Duration::from_millis(v)),
                }),
            );
            assert!(fresh.remaining(&clock).is_some());
            remaining.store(refusal, Ordering::Release);
            assert!(fresh.remaining(&clock).is_none());
            remaining.store(400, Ordering::Release);
            assert!(fresh.remaining(&clock).is_none());
        }
    }
}
