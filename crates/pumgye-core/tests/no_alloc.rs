//! The production evaluation instantiation (NoTrace) must not allocate on any path.
use pumgye_core::{GuardEvidence as G, KubernetesApiSubject, NoTrace, Policy};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
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

fn allocations(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    f();
    ALLOCATIONS.with(Cell::get) - before
}

const HUMAN: &str = "human1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const WORKLOAD: &str = "s_0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn production_paths_are_allocation_free_for_every_outcome() {
    assert_eq!(std::mem::size_of::<NoTrace>(), 0);
    let policy: Policy = serde_json::from_value(serde_json::json!({
     "version":1,"information_classes":["public","internal"],
     "services":{
      "orders":{"permissions":["read","write"],"require_guard":true,
       "roles":{"reader":{"permissions":["read"],"information_classes":["public"]},
                "writer":{"permissions":["write"],"information_classes":["internal"],"inherits":["reader"],"minimum_aal":2}},
       "users":{"u_reader":["reader"],"u_writer":["writer"],"u_guest":["guest"]},
       "workload_users":{WORKLOAD:["reader"]},"human_users":{HUMAN:["writer"]},
       "networks":[{"cidr":"192.0.2.0/24","roles":["writer"]},{"cidr":"192.0.2.7/32","roles":["guest"]}]},
      "kube":{"authorization_context":"kubernetes_api","require_guard":false,"permissions":["get"],
       "roles":{"viewer":{"permissions":["get"],"information_classes":["internal"]}},
       "users":{"k8sapi:team:alice":["viewer"]},"networks":[]}},
     "resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read","update":"write"},"minimum_aal":1},
                  "kube:pods":{"service":"kube","information_class":"internal","actions":{"get":"get"}}}}))
    .unwrap();
    let p = policy.compile().unwrap();
    let ips =
        ["192.0.2.1", "192.0.2.7", "203.0.113.1", "2001:db8::1"].map(|ip| ip.parse().unwrap());
    let guards = [G::EnforcedAllow, G::Deny, G::Observe, G::Unavailable];
    let kube = KubernetesApiSubject::parse("k8sapi:team:alice").unwrap();
    let mut outcomes = [0usize; 9];
    let count = allocations(|| {
        for ip in ips {
            for guard in guards {
                for aal in 0..=4u8 {
                    for subject in ["u_reader", "u_writer", "u_guest", "u_none"] {
                        for service in ["orders", "kube", "none"] {
                            for (permission, class) in [
                                ("read", "public"),
                                ("write", "internal"),
                                ("x", "public"),
                                ("read", "x"),
                            ] {
                                let d =
                                    p.evaluate(service, subject, ip, permission, class, aal, guard);
                                outcomes[d as usize] += 1;
                            }
                        }
                        for (resource, action) in [
                            ("db:orders", "select"),
                            ("db:orders", "update"),
                            ("db:orders", "drop"),
                            ("none", "select"),
                        ] {
                            std::hint::black_box(p.evaluate_scoped_resource(
                                "orders", resource, action, subject, ip, aal, guard,
                            ));
                            std::hint::black_box(
                                p.evaluate_resource(resource, action, subject, ip, aal, guard),
                            );
                            std::hint::black_box(p.evaluate_scoped_workload_resource(
                                "orders", resource, action, WORKLOAD, ip, guard,
                            ));
                            std::hint::black_box(p.evaluate_scoped_human_resource(
                                "orders", resource, action, HUMAN, ip, aal, guard,
                            ));
                            std::hint::black_box(p.evaluate_kubernetes_api_resource(
                                "kube",
                                "kube:pods",
                                action,
                                kube,
                            ));
                        }
                    }
                }
            }
        }
    });
    assert_eq!(count, 0, "production evaluation allocated {count} times");
    // Every Decision variant was produced inside the measured region.
    assert!(outcomes.iter().all(|n| *n > 0), "{outcomes:?}");
}

#[test]
fn version_2_evaluation_is_allocation_free_for_every_outcome() {
    use pumgye_core::v2::{
        DecisionV2, MembershipIndex, PolicyV2, PrincipalKind as K, RequestV2, TargetV2,
    };
    let policy: PolicyV2 =
        serde_json::from_str(include_str!("../../../examples/v2/policy.json")).unwrap();
    let compiled = policy.compile().unwrap();
    let h1 = "human1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let h2 = "human1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let h4 = "human1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let s1 = "s_111111111111111111111111111111111111111111111111";
    let eng: std::collections::BTreeSet<String> =
        ["grp1:00000000000000000000000000".to_owned()].into();
    let both: std::collections::BTreeSet<String> = [
        "grp1:00000000000000000000000000".to_owned(),
        "grp1:11111111111111111111111111".to_owned(),
    ]
    .into();
    let ops: std::collections::BTreeSet<String> =
        ["grp1:11111111111111111111111111".to_owned()].into();
    let membership = MembershipIndex::build(&compiled, [(h1, &eng), (h2, &both), (h4, &ops)]);
    let ips = [
        "192.0.2.10",
        "192.0.2.7",
        "10.1.1.1",
        "203.0.113.1",
        "2001:db8::1",
    ]
    .map(|ip| ip.parse().unwrap());
    let subjects = [
        (K::Human, h1),
        (K::Human, h2),
        (K::Human, h4),
        (K::Service, s1),
        (K::Workload, s1),
    ];
    let targets = [
        TargetV2::Permission {
            permission: "write",
            level: "internal",
        },
        TargetV2::Permission {
            permission: "admin",
            level: "restricted",
        },
        TargetV2::Permission {
            permission: "view",
            level: "public",
        },
        TargetV2::Permission {
            permission: "read",
            level: "secret",
        },
        TargetV2::Permission {
            permission: "nope",
            level: "public",
        },
        TargetV2::Resource {
            resource: "db:payroll",
            action: "select",
        },
        TargetV2::Resource {
            resource: "db:orders",
            action: "drop",
        },
        TargetV2::Resource {
            resource: "db:x",
            action: "select",
        },
    ];
    let now = 1_792_108_800; // 2026-10-16
    let mut seen = [0usize; 12];
    let count = allocations(|| {
        for service in ["orders", "reports", "billing"] {
            for (kind, subject) in subjects {
                for ip in ips {
                    for guard in [G::EnforcedAllow, G::Deny, G::Observe] {
                        for aal in 0..=4u8 {
                            for target in targets {
                                for at in [now, 1_768_435_200 /* 2026-01-15 */] {
                                    let r = RequestV2 {
                                        service,
                                        kind,
                                        subject,
                                        target,
                                        ip,
                                        aal,
                                        guard,
                                        now: at,
                                    };
                                    let d = compiled.evaluate(&membership, &r);
                                    seen[DecisionV2::ALL.iter().position(|x| *x == d).unwrap()] +=
                                        1;
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    assert_eq!(count, 0, "version 2 evaluation allocated {count} times");
    assert!(seen.iter().all(|n| *n > 0), "{seen:?}");
}
