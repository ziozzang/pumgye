//! Metrics recording on decision hot paths must not allocate.
use pumgye_core::{Decision, ResourceDecision};
use pumgye_server::metrics::{Context, METRICS, PermitKind, Transport};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::Instant,
};

struct Counting;
thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn recording_is_allocation_free() {
    let started = Instant::now();
    let before = ALLOCATIONS.with(Cell::get);
    for context in [
        Context::Permission,
        Context::Resource,
        Context::WorkloadResource,
        Context::HumanResource,
    ] {
        METRICS.decision(context, Some(Decision::Allow));
        METRICS.decision(context, Some(Decision::GuardDenied));
        METRICS.decision(context, None);
        METRICS.resource_decision(context, Some(ResourceDecision::UnknownAction));
        METRICS.resource_decision(context, Some(ResourceDecision::Decided(Decision::Guest)));
        METRICS.resource_decision(context, None);
    }
    for transport in [
        Transport::Http,
        Transport::Ppg1,
        Transport::Grpc,
        Transport::Sar,
    ] {
        METRICS.observe(transport, started);
    }
    METRICS.observed_permit(PermitKind::Human, None);
    METRICS.observed_permit(PermitKind::Service, Some(tonic::Code::PermissionDenied));
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);
}
