use pumgye_core::{Decision as D, GuardEvidence as G, Policy, ResourceDecision as R};
const SUBJECT: &str = "s_529be5b595ab327853eabe2d1adf52256e262af036510607";
fn policy() -> Policy {
    serde_json::from_value(serde_json::json!({
        "version":1,"information_classes":["public","secret"],
        "services":{"logs":{"permissions":["read","write"],"users":{},
            "workload_users":{SUBJECT:["reader"]},
            "roles":{"reader":{"permissions":["read"],"information_classes":["public"]},
                "writer":{"permissions":["write"],"information_classes":["secret"]}},
            "networks":[{"cidr":"192.0.2.0/24","roles":["reader","writer"]},
                {"cidr":"192.0.2.7/32","roles":["guest"]}],"require_guard":true}},
        "resources":{"logs:public":{"service":"logs","information_class":"public","actions":{"get":"read","put":"write"}},
            "logs:secret":{"service":"logs","information_class":"secret","actions":{"get":"read"}}}
    })).unwrap()
}
fn workload(p: &Policy, subject: &str, resource: &str, action: &str, ip: &str, guard: G) -> R {
    p.compile().unwrap().evaluate_scoped_workload_resource(
        "logs",
        resource,
        action,
        subject,
        ip.parse().unwrap(),
        guard,
    )
}
#[test]
fn equal_subject_bytes_never_cross_principal_maps_in_either_direction() {
    let mut p = policy();
    assert_eq!(
        workload(
            &p,
            SUBJECT,
            "logs:public",
            "get",
            "192.0.2.9",
            G::EnforcedAllow
        ),
        R::Decided(D::Allow)
    );
    let legacy = |p: &Policy| {
        p.compile().unwrap().evaluate_scoped_resource(
            "logs",
            "logs:public",
            "get",
            SUBJECT,
            "192.0.2.9".parse().unwrap(),
            0,
            G::EnforcedAllow,
        )
    };
    assert_eq!(legacy(&p), R::Decided(D::Guest));
    let service = p.services.get_mut("logs").unwrap();
    service.users.insert(SUBJECT.into(), vec!["writer".into()]);
    assert_eq!(legacy(&p), R::Decided(D::PermissionDenied));
    assert_eq!(
        workload(
            &p,
            SUBJECT,
            "logs:public",
            "get",
            "192.0.2.9",
            G::EnforcedAllow
        ),
        R::Decided(D::Allow)
    );
    let service = p.services.get_mut("logs").unwrap();
    service.workload_users.clear();
    service.users.insert(SUBJECT.into(), vec!["reader".into()]);
    assert_eq!(legacy(&p), R::Decided(D::Allow));
    assert_eq!(
        workload(
            &p,
            SUBJECT,
            "logs:public",
            "get",
            "192.0.2.9",
            G::EnforcedAllow
        ),
        R::Decided(D::Guest)
    );
}
#[test]
fn workload_uses_same_resource_network_class_guard_and_assurance_conjunction() {
    let p = policy();
    for (resource, action, ip, guard, expected) in [
        (
            "missing",
            "get",
            "192.0.2.9",
            G::EnforcedAllow,
            R::UnknownResource,
        ),
        (
            "logs:public",
            "missing",
            "192.0.2.9",
            G::EnforcedAllow,
            R::UnknownAction,
        ),
        (
            "logs:public",
            "put",
            "192.0.2.9",
            G::EnforcedAllow,
            R::Decided(D::PermissionDenied),
        ),
        (
            "logs:secret",
            "get",
            "192.0.2.9",
            G::EnforcedAllow,
            R::Decided(D::ClassDenied),
        ),
        (
            "logs:public",
            "get",
            "198.51.100.9",
            G::EnforcedAllow,
            R::Decided(D::NetworkGuest),
        ),
        (
            "logs:public",
            "get",
            "192.0.2.7",
            G::EnforcedAllow,
            R::Decided(D::PermissionDenied),
        ),
        (
            "logs:public",
            "get",
            "192.0.2.9",
            G::Deny,
            R::Decided(D::GuardDenied),
        ),
        (
            "logs:public",
            "get",
            "192.0.2.9",
            G::Observe,
            R::Decided(D::GuardUnavailable),
        ),
        (
            "logs:public",
            "get",
            "192.0.2.9",
            G::Unavailable,
            R::Decided(D::GuardUnavailable),
        ),
    ] {
        assert_eq!(workload(&p, SUBJECT, resource, action, ip, guard), expected);
    }
    assert_eq!(
        p.compile().unwrap().evaluate_scoped_workload_resource(
            "other",
            "logs:public",
            "get",
            SUBJECT,
            "192.0.2.9".parse().unwrap(),
            G::EnforcedAllow
        ),
        R::Decided(D::UnknownService)
    );
    for owner in ["resource", "role", "network"] {
        let mut changed = p.clone();
        match owner {
            "resource" => {
                changed
                    .resources
                    .get_mut("logs:public")
                    .unwrap()
                    .minimum_aal = 1
            }
            "role" => {
                changed
                    .services
                    .get_mut("logs")
                    .unwrap()
                    .roles
                    .get_mut("reader")
                    .unwrap()
                    .minimum_aal = 1
            }
            _ => {
                let s = changed.services.get_mut("logs").unwrap();
                s.roles.get_mut("writer").unwrap().minimum_aal = 1;
            }
        }
        assert_eq!(
            workload(
                &changed,
                SUBJECT,
                "logs:public",
                "get",
                "192.0.2.9",
                G::EnforcedAllow
            ),
            R::Decided(D::AssuranceDenied)
        );
    }
}
#[test]
fn workload_assignments_share_role_compilation_and_canonical_capacity_validation() {
    let mut p = policy();
    let service = p.services.get_mut("logs").unwrap();
    service
        .roles
        .get_mut("writer")
        .unwrap()
        .inherits
        .push("reader".into());
    service
        .workload_users
        .insert(SUBJECT.into(), vec!["writer".into()]);
    assert_eq!(
        workload(
            &p,
            SUBJECT,
            "logs:public",
            "get",
            "192.0.2.9",
            G::EnforcedAllow
        ),
        R::Decided(D::Allow)
    );
    for invalid in [
        "worker",
        "s_123",
        "s_529BE5B595AB327853EABE2D1ADF52256E262AF036510607",
    ] {
        let mut invalid_policy = p.clone();
        invalid_policy
            .services
            .get_mut("logs")
            .unwrap()
            .workload_users
            .insert(invalid.into(), vec!["reader".into()]);
        assert!(invalid_policy.compile().is_err());
    }
    for ids in [
        vec!["missing".into()],
        vec!["reader".into(), "reader".into()],
        vec![],
    ] {
        let mut invalid = p.clone();
        invalid
            .services
            .get_mut("logs")
            .unwrap()
            .workload_users
            .insert(SUBJECT.into(), ids);
        assert!(invalid.compile().is_err());
    }
    // Both maps count toward one bound, rather than allowing twice the native limit.
    let service = p.services.get_mut("logs").unwrap();
    service.users = (0..65536)
        .map(|i| (format!("legacy-{i}"), vec!["reader".into()]))
        .collect();
    assert!(p.compile().is_err());
}
#[test]
fn absent_or_empty_optional_map_preserves_legacy_serialized_policy() {
    let mut legacy = serde_json::to_value(policy()).unwrap();
    legacy["services"]["logs"]
        .as_object_mut()
        .unwrap()
        .remove("workload_users");
    let parsed: Policy = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), legacy);
    legacy["services"]["logs"]["workload_users"] = serde_json::json!({});
    let parsed: Policy = serde_json::from_value(legacy.clone()).unwrap();
    legacy["services"]["logs"]
        .as_object_mut()
        .unwrap()
        .remove("workload_users");
    assert_eq!(serde_json::to_value(parsed).unwrap(), legacy);
}
