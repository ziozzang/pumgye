use pumgye_core::{Decision as D, GuardEvidence as G, HumanSubject, Policy, ResourceDecision as R};
const H: &str = "human1:1111111111111111111111111111111111111111111111111111111111111111";
const MFA: &str = "human1:2222222222222222222222222222222222222222222222222222222222222222";
const W: &str = "s_529be5b595ab327853eabe2d1adf52256e262af036510607";
fn policy() -> Policy {
    serde_json::from_value(serde_json::json!({"version":1,"information_classes":["public","secret"],"services":{"orders":{"permissions":["read","write"],"users":{},"human_users":{H:["reader"],MFA:["mfa"]},"workload_users":{W:["writer"]},"roles":{"reader":{"permissions":["read"],"information_classes":["public"]},"mfa":{"inherits":["reader"],"permissions":[],"information_classes":[],"minimum_aal":2},"writer":{"permissions":["write"],"information_classes":["public","secret"]}},"networks":[{"cidr":"192.0.2.0/24","roles":["reader","writer"]}],"require_guard":true}},"resources":{"orders:public":{"service":"orders","information_class":"public","actions":{"get":"read","put":"write"}},"orders:secret":{"service":"orders","information_class":"secret","actions":{"get":"read"}}}})).unwrap()
}
fn eval(p: &Policy, h: &str, aal: u8) -> R {
    p.compile().unwrap().evaluate_scoped_human_resource(
        "orders",
        "orders:public",
        "get",
        h,
        "192.0.2.9".parse().unwrap(),
        aal,
        G::EnforcedAllow,
    )
}
#[test]
fn namespace_metadata_is_strict_and_independent() {
    assert_eq!(HumanSubject::parse(H).unwrap().as_str(), H);
    for bad in [
        "human1:",
        W,
        "human1:ABC",
        "human1:111111111111111111111111111111111111111111111111111111111111111A",
    ] {
        assert!(HumanSubject::parse(bad).is_err());
        assert_eq!(eval(&policy(), bad, 1), R::Decided(D::Guest));
    }
    let mut p = policy();
    p.services
        .get_mut("orders")
        .unwrap()
        .human_users
        .insert(W.into(), vec!["reader".into()]);
    assert!(p.compile().is_err());
}
#[test]
fn assurance_is_per_user_and_not_a_global_floor() {
    let mut p = policy();
    assert_eq!(eval(&p, H, 1), R::Decided(D::Allow));
    assert_eq!(eval(&p, MFA, 1), R::Decided(D::AssuranceDenied));
    assert_eq!(eval(&p, MFA, 2), R::Decided(D::Allow));
    for aal in [0, 3, 255] {
        assert_eq!(eval(&p, H, aal), R::Decided(D::AssuranceDenied));
    }
    p.resources.get_mut("orders:public").unwrap().minimum_aal = 2;
    assert_eq!(eval(&p, H, 1), R::Decided(D::AssuranceDenied));
    assert_eq!(eval(&p, H, 2), R::Decided(D::Allow));
    p.resources.get_mut("orders:public").unwrap().minimum_aal = 3;
    assert_eq!(eval(&p, H, 2), R::Decided(D::AssuranceDenied));
}
#[test]
fn map_isolation_and_new_publication_withdrawal() {
    let mut p = policy();
    p.services
        .get_mut("orders")
        .unwrap()
        .users
        .insert(H.into(), vec!["writer".into()]);
    let old = p.compile().unwrap();
    p.services.get_mut("orders").unwrap().human_users.remove(H);
    assert_eq!(eval(&p, H, 2), R::Decided(D::Guest));
    assert_eq!(
        old.evaluate_scoped_human_resource(
            "orders",
            "orders:public",
            "get",
            H,
            "192.0.2.9".parse().unwrap(),
            1,
            G::EnforcedAllow
        ),
        R::Decided(D::Allow)
    ); // Pure old snapshots do not self-retire.
    assert_eq!(
        old.evaluate_scoped_resource(
            "orders",
            "orders:public",
            "get",
            H,
            "192.0.2.9".parse().unwrap(),
            2,
            G::EnforcedAllow
        ),
        R::Decided(D::PermissionDenied)
    );
    assert_eq!(
        old.evaluate_scoped_workload_resource(
            "orders",
            "orders:public",
            "get",
            H,
            "192.0.2.9".parse().unwrap(),
            G::EnforcedAllow
        ),
        R::Decided(D::Guest)
    );
}
#[test]
fn catalog_network_guard_and_scope_remain_native() {
    let p = policy();
    let c = p.compile().unwrap();
    let call = |service, resource, action, ip, guard| {
        c.evaluate_scoped_human_resource(service, resource, action, H, ip, 1, guard)
    };
    let ip = "192.0.2.9".parse().unwrap();
    assert_eq!(
        call("wrong", "orders:public", "get", ip, G::EnforcedAllow),
        R::Decided(D::UnknownService)
    );
    assert_eq!(
        call("orders", "missing", "get", ip, G::EnforcedAllow),
        R::UnknownResource
    );
    assert_eq!(
        call("orders", "orders:public", "bad", ip, G::EnforcedAllow),
        R::UnknownAction
    );
    assert_eq!(
        call("orders", "orders:secret", "get", ip, G::EnforcedAllow),
        R::Decided(D::ClassDenied)
    );
    assert_eq!(
        call(
            "orders",
            "orders:public",
            "get",
            "198.51.100.1".parse().unwrap(),
            G::EnforcedAllow
        ),
        R::Decided(D::NetworkGuest)
    );
    assert_ne!(
        call("orders", "orders:public", "get", ip, G::Deny),
        R::Decided(D::Allow)
    );
}
#[test]
fn default_serialization_and_api_context_prohibition() {
    let mut p = policy();
    p.services.get_mut("orders").unwrap().human_users.clear();
    let absent = serde_json::to_value(&p).unwrap();
    assert!(absent["services"]["orders"].get("human_users").is_none());
    let mut explicit = absent.clone();
    explicit["services"]["orders"]["human_users"] = serde_json::json!({});
    assert_eq!(
        serde_json::to_value(serde_json::from_value::<Policy>(explicit).unwrap()).unwrap(),
        absent
    );
    let s = p.services.get_mut("orders").unwrap();
    s.authorization_context = pumgye_core::AuthorizationContext::KubernetesApi;
    s.require_guard = false;
    s.networks.clear();
    s.users.clear();
    s.workload_users.clear();
    assert!(p.compile().is_ok());
    assert_eq!(eval(&p, H, 1), R::Decided(D::UnknownService));
    p.services
        .get_mut("orders")
        .unwrap()
        .human_users
        .insert(H.into(), vec!["reader".into()]);
    assert!(p.compile().is_err());
}
#[test]
fn all_maps_share_assignment_capacity_and_network_assurance() {
    let mut p = policy();
    let service = p.services.get_mut("orders").unwrap();
    service.users = (0..65533)
        .map(|i| (format!("legacy{i}"), vec!["reader".into()]))
        .collect();
    assert!(p.compile().is_ok());
    p.services
        .get_mut("orders")
        .unwrap()
        .users
        .insert("overflow".into(), vec!["reader".into()]);
    assert!(p.compile().is_err());
    let mut p = policy();
    p.services
        .get_mut("orders")
        .unwrap()
        .roles
        .get_mut("writer")
        .unwrap()
        .minimum_aal = 2;
    assert_eq!(eval(&p, H, 1), R::Decided(D::AssuranceDenied));
    assert_eq!(eval(&p, H, 2), R::Decided(D::Allow));
}

/// AAL3 is accepted only from Hopae-sealed evidence (Hopae ADR-0018 decision 11).
#[test]
fn aal3_requires_sealed_evidence() {
    use pumgye_core::{Decision as D, GuardEvidence as G, ResourceDecision as R, SealedAssurance};
    let subject = "human1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let p: pumgye_core::Policy = serde_json::from_value(serde_json::json!({
     "version":1,"information_classes":["restricted"],
     "services":{"vault":{"permissions":["read"],"require_guard":true,
       "roles":{"keeper":{"permissions":["read"],"information_classes":["restricted"],"minimum_aal":3}},
       "users":{},"human_users":{subject:["keeper"]},"networks":[{"cidr":"192.0.2.0/24","roles":["keeper"]}]}},
     "resources":{"vault:secret":{"service":"vault","information_class":"restricted","actions":{"get":"read"},"minimum_aal":3}}}))
    .unwrap();
    let c = p.compile().unwrap();
    let ip = "192.0.2.1".parse().unwrap();
    let asserted = |aal| {
        c.evaluate_scoped_human_resource(
            "vault",
            "vault:secret",
            "get",
            subject,
            ip,
            aal,
            G::EnforcedAllow,
        )
    };
    let sealed = |aal| {
        c.evaluate_scoped_human_sealed_resource(
            "vault",
            "vault:secret",
            "get",
            subject,
            ip,
            SealedAssurance::from_verified_receipt(aal).unwrap(),
            G::EnforcedAllow,
        )
    };
    assert_eq!(
        asserted(3),
        R::Decided(D::AssuranceDenied),
        "an adapter cannot assert AAL3"
    );
    assert_eq!(asserted(2), R::Decided(D::AssuranceDenied));
    assert_eq!(
        sealed(2),
        R::Decided(D::AssuranceDenied),
        "AAL2 does not meet a level-3 requirement"
    );
    assert_eq!(sealed(3), R::Decided(D::Allow));
    assert!(
        SealedAssurance::from_verified_receipt(0).is_none()
            && SealedAssurance::from_verified_receipt(4).is_none()
    );
    // Explain: an adapter-asserted 3 is refused at the principal stage, sealed 3 allows.
    let explain = |evidence: &str| {
        let case: pumgye_core::explain::Case = serde_json::from_value(serde_json::json!({"subject":{"id":subject,"kind":"human"},"service":"vault",
            "resource":"vault:secret","action":"get","ip":"192.0.2.1","aal":3,"guard":"enforced_allow","assurance_evidence":evidence})).unwrap();
        pumgye_core::explain::explain(
            pumgye_core::explain::Snapshot {
                policy: &p,
                compiled: &c,
                revision: 1,
                serving: true,
            },
            &case,
            true,
        )
        .unwrap()
    };
    assert_eq!(
        explain("asserted").outcome.detail_code,
        "pumgye.detail.principal_assurance_invalid"
    );
    let e = explain("sealed");
    assert!(e.outcome.allow);
    let v = serde_json::to_value(&e).unwrap();
    let last = v["trace"]
        .as_array()
        .unwrap()
        .iter()
        .rfind(|s| s["stage"] == "assurance")
        .unwrap()
        .clone();
    assert_eq!(last["detail"]["presented"], 3);
    assert_eq!(last["detail"]["required"], 3);
}
