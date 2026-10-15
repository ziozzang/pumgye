use pumgye_core::{
    AuthorizationContext as C, Decision as D, GuardEvidence as G, KubernetesApiSubject, Policy,
    ResourceDecision as R,
};
const SUBJECT: &str = "k8sapi:cluster-a:reader";
fn policy() -> Policy {
    serde_json::from_value(serde_json::json!({
        "version":1,"information_classes":["public","secret"],
        "services":{"k8s-config":{"authorization_context":"kubernetes_api",
            "permissions":["read","write"],"require_guard":false,"networks":[],
            "roles":{"reader":{"permissions":["read"],"information_classes":["public"]},
                "writer":{"permissions":["write"],"information_classes":["secret"]}},
            "users":{SUBJECT:["reader"]}}},
        "resources":{"k8s:blue:settings":{"service":"k8s-config","information_class":"public",
            "actions":{"get":"read","update":"write"}}}
    }))
    .unwrap()
}
fn api(p: &Policy, service: &str, resource: &str, action: &str, subject: &str) -> R {
    p.compile().unwrap().evaluate_kubernetes_api_resource(
        service,
        resource,
        action,
        KubernetesApiSubject::parse(subject).unwrap(),
    )
}
fn read(p: &Policy) -> R {
    api(p, "k8s-config", "k8s:blue:settings", "get", SUBJECT)
}
#[test]
fn explicit_api_context_allows_without_inventing_ip_or_sum_and_ordinary_paths_cannot_enter() {
    let p = policy();
    assert_eq!(read(&p), R::Decided(D::Allow));
    let compiled = p.compile().unwrap();
    for ip in ["127.0.0.1", "192.0.2.9", "::1"] {
        for guard in [G::EnforcedAllow, G::Deny, G::Observe, G::Unavailable] {
            for aal in 0..=3 {
                let ip = ip.parse().unwrap();
                assert_eq!(
                    compiled.evaluate("k8s-config", SUBJECT, ip, "read", "public", aal, guard),
                    D::PermissionDenied
                );
                assert_eq!(
                    compiled.evaluate_resource("k8s:blue:settings", "get", SUBJECT, ip, aal, guard),
                    R::Decided(D::PermissionDenied)
                );
                assert_eq!(
                    compiled.evaluate_scoped_resource(
                        "k8s-config",
                        "k8s:blue:settings",
                        "get",
                        SUBJECT,
                        ip,
                        aal,
                        guard
                    ),
                    R::Decided(D::PermissionDenied)
                );
                assert_eq!(
                    compiled.evaluate_scoped_workload_resource(
                        "k8s-config",
                        "k8s:blue:settings",
                        "get",
                        SUBJECT,
                        ip,
                        guard
                    ),
                    R::Decided(D::PermissionDenied)
                );
            }
        }
    }
}
#[test]
fn ordinary_network_service_is_never_reinterpreted_as_network_free() {
    let mut p = policy();
    let service = p.services.get_mut("k8s-config").unwrap();
    service.authorization_context = C::NetworkAndGuard;
    service.require_guard = true;
    service.networks = serde_json::from_value(serde_json::json!([
        {"cidr":"192.0.2.0/24","roles":["reader"]}
    ]))
    .unwrap();
    assert_eq!(read(&p), R::Decided(D::PermissionDenied));
    let compiled = p.compile().unwrap();
    let ordinary = |ip: &str, guard| {
        compiled.evaluate_scoped_resource(
            "k8s-config",
            "k8s:blue:settings",
            "get",
            SUBJECT,
            ip.parse().unwrap(),
            0,
            guard,
        )
    };
    assert_eq!(
        ordinary("192.0.2.9", G::EnforcedAllow),
        R::Decided(D::Allow)
    );
    assert_eq!(
        ordinary("192.0.2.9", G::Unavailable),
        R::Decided(D::GuardUnavailable)
    );
    assert_eq!(
        ordinary("198.51.100.9", G::EnforcedAllow),
        R::Decided(D::NetworkGuest)
    );
}
#[test]
fn api_context_rejects_ambiguous_network_guard_and_principal_configuration() {
    let mutations: Vec<serde_json::Value> = vec![
        serde_json::json!({"require_guard":true}),
        serde_json::json!({"networks":[{"cidr":"0.0.0.0/0","roles":["reader"]}]}),
        serde_json::json!({"workload_users":{"s_529be5b595ab327853eabe2d1adf52256e262af036510607":["reader"]}}),
        serde_json::json!({"users":{"human-reader":["reader"]}}),
        serde_json::json!({"users":{"k8sapi:":["reader"]}}),
    ];
    for fields in mutations {
        let mut value = serde_json::to_value(policy()).unwrap();
        for (name, value2) in fields.as_object().unwrap() {
            value["services"]["k8s-config"][name] = value2.clone();
        }
        assert!(
            serde_json::from_value::<Policy>(value)
                .unwrap()
                .compile()
                .is_err()
        );
    }
    let mut value = serde_json::to_value(policy()).unwrap();
    value["services"]["k8s-config"]
        .as_object_mut()
        .unwrap()
        .remove("require_guard");
    assert!(
        serde_json::from_value::<Policy>(value)
            .unwrap()
            .compile()
            .is_err(),
        "default guard requirement must remain true"
    );
    let mut value = serde_json::to_value(policy()).unwrap();
    value["services"]["k8s-config"]["authorization_context"] = "unknown".into();
    assert!(serde_json::from_value::<Policy>(value).is_err());
}
#[test]
fn api_uses_existing_catalog_roles_classes_and_fixed_zero_assurance() {
    let p = policy();
    assert_eq!(
        api(&p, "k8s-config", "k8s:blue:settings", "update", SUBJECT),
        R::Decided(D::PermissionDenied)
    );
    let mut secret = p.clone();
    secret
        .resources
        .get_mut("k8s:blue:settings")
        .unwrap()
        .information_class = "secret".into();
    assert_eq!(read(&secret), R::Decided(D::ClassDenied));
    let mut resource_mfa = p.clone();
    resource_mfa
        .resources
        .get_mut("k8s:blue:settings")
        .unwrap()
        .minimum_aal = 1;
    assert_eq!(read(&resource_mfa), R::Decided(D::AssuranceDenied));
    let mut inherited_mfa = p.clone();
    let roles = &mut inherited_mfa.services.get_mut("k8s-config").unwrap().roles;
    let mut elevated = roles["reader"].clone();
    elevated.minimum_aal = 2;
    roles.insert("elevated".into(), elevated);
    roles.get_mut("reader").unwrap().inherits = vec!["elevated".into()];
    assert_eq!(read(&inherited_mfa), R::Decided(D::AssuranceDenied));
}
#[test]
fn scope_subject_and_action_cannot_select_a_different_grant() {
    let p = policy();
    assert_eq!(
        api(&p, "other", "k8s:blue:settings", "get", SUBJECT),
        R::Decided(D::UnknownService)
    );
    assert_eq!(
        api(&p, "k8s-config", "absent", "get", SUBJECT),
        R::UnknownResource
    );
    assert_eq!(
        api(&p, "k8s-config", "k8s:blue:settings", "delete", SUBJECT),
        R::UnknownAction
    );
    assert_eq!(
        api(
            &p,
            "k8s-config",
            "k8s:blue:settings",
            "get",
            "k8sapi:cluster-b:reader"
        ),
        R::Decided(D::Guest)
    );
    assert_eq!(
        api(
            &p,
            "k8s-config",
            "k8s:blue:settings",
            "get",
            "k8sapi:cluster-a:unknown"
        ),
        R::Decided(D::Guest)
    );
    for invalid in [
        "k8sapi:",
        "reader",
        "s_529be5b595ab327853eabe2d1adf52256e262af036510607",
        "k8sapi:bad/label",
        "k8sapi:é",
    ] {
        assert!(KubernetesApiSubject::parse(invalid).is_err());
    }
}
#[test]
fn recompilation_observes_grant_withdrawal_without_an_independent_api_grant_store() {
    let mut p = policy();
    let original = p.compile().unwrap();
    p.services.get_mut("k8s-config").unwrap().users.clear();
    assert_eq!(read(&p), R::Decided(D::Guest));
    // A compiled snapshot is immutable, not self-retiring: the server must fence
    // its exact publication/source before emitting an authorization response.
    assert_eq!(
        original.evaluate_kubernetes_api_resource(
            "k8s-config",
            "k8s:blue:settings",
            "get",
            KubernetesApiSubject::parse(SUBJECT).unwrap()
        ),
        R::Decided(D::Allow)
    );
    let roles = &mut p.services.get_mut("k8s-config").unwrap().roles;
    roles.get_mut("reader").unwrap().permissions.clear();
    p.services
        .get_mut("k8s-config")
        .unwrap()
        .users
        .insert(SUBJECT.into(), vec!["reader".into()]);
    assert_eq!(read(&p), R::Decided(D::Guest));
}
#[test]
fn absent_or_explicit_default_context_preserves_original_serialized_service_bytes() {
    let bytes = r#"{"permissions":["read"],"roles":{"reader":{"permissions":["read"],"information_classes":["public"],"inherits":[],"minimum_aal":0}},"users":{"u_reader":["reader"]},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}],"require_guard":true}"#;
    let service: pumgye_core::Service = serde_json::from_str(bytes).unwrap();
    assert_eq!(service.authorization_context, C::NetworkAndGuard);
    assert_eq!(serde_json::to_string(&service).unwrap(), bytes);
    let mut explicit = serde_json::from_str::<serde_json::Value>(bytes).unwrap();
    explicit["authorization_context"] = "network_and_guard".into();
    assert_eq!(
        serde_json::to_string(&serde_json::from_value::<pumgye_core::Service>(explicit).unwrap())
            .unwrap(),
        bytes
    );
}
