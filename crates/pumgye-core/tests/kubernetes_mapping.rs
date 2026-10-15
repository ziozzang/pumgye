use pumgye_core::kubernetes_authorization::{Attributes, MappingDecision as M, Principal};
use pumgye_core::{Decision as D, Policy, ResourceDecision as R};
use serde_json::{Value, json};
fn document() -> Value {
    json!({"version":1,"information_classes":["public","secret"],
 "services":{"api":{"authorization_context":"kubernetes_api","permissions":["read"],"require_guard":false,"networks":[],"roles":{"reader":{"permissions":["read"],"information_classes":["public"]}},"users":{"k8sapi:cluster-a:reader":["reader"]}}},
 "resources":{"settings":{"service":"api","information_class":"public","actions":{"read":"read"}}},
 "kubernetes_authorization":{"version":1,"principals":[{"cluster":"cluster-a","user":"fixture-reader","uid":{"mode":"exact","value":"owned-uid"},"required_groups":["readers"],"required_extra":{"owned.example/session":["a","b"]},"subject":"k8sapi:cluster-a:reader"}],
 "routes":[{"cluster":"cluster-a","attributes":{"kind":"resource","group":"","version":"v1","resource":"configmaps","subresource":"","namespace":"blue","name":"settings","verb":"get"},"service":"api","resource":"settings","action":"read"}]}})
}
fn principal() -> Principal {
    serde_json::from_value(json!({"user":"fixture-reader","uid":"owned-uid","groups":["readers","system:authenticated"],"extra":{"owned.example/session":["b","a"],"ignored.example/key":["inert"]}})).unwrap()
}
fn attrs() -> Attributes {
    serde_json::from_value(
        document()["kubernetes_authorization"]["routes"][0]["attributes"].clone(),
    )
    .unwrap()
}
fn policy(v: Value) -> Policy {
    serde_json::from_value(v).unwrap()
}
fn evaluate(v: Value, p: &Principal, a: &Attributes) -> M {
    policy(v)
        .compile()
        .unwrap()
        .evaluate_kubernetes_request("cluster-a", p, a)
}
#[test]
fn exact_cluster_principal_and_attributes_use_same_native_grants() {
    let p = policy(document()).compile().unwrap();
    assert_eq!(
        p.evaluate_kubernetes_request("cluster-a", &principal(), &attrs()),
        M::Decided(R::Decided(D::Allow))
    );
    assert_eq!(
        p.evaluate_kubernetes_request("cluster-b", &principal(), &attrs()),
        M::UnknownPrincipal
    );
    for field in ["group", "version", "resource", "namespace", "name", "verb"] {
        let mut a = document()["kubernetes_authorization"]["routes"][0]["attributes"].clone();
        a[field] = if field == "verb" {
            json!("delete")
        } else {
            json!("other")
        };
        assert_eq!(
            p.evaluate_kubernetes_request(
                "cluster-a",
                &principal(),
                &serde_json::from_value(a).unwrap()
            ),
            M::UnknownRoute,
            "{field}"
        );
    }
}
#[test]
fn uid_groups_and_exact_extra_sets_are_conjunctive_and_never_promote() {
    let original = principal();
    let mut changes = vec![];
    let mut p = original.clone();
    p.uid = None;
    changes.push(p);
    let mut p = original.clone();
    p.uid = Some("replacement".into());
    changes.push(p);
    let mut p = original.clone();
    p.groups.clear();
    changes.push(p);
    let mut p = original.clone();
    p.extra.clear();
    changes.push(p);
    let mut p = original.clone();
    p.extra
        .get_mut("owned.example/session")
        .unwrap()
        .push("more".into());
    changes.push(p);
    let mut p = original.clone();
    p.user = "unknown".into();
    changes.push(p);
    for p in changes {
        assert_eq!(evaluate(document(), &p, &attrs()), M::UnknownPrincipal);
    }
    let mut absent = document();
    absent["kubernetes_authorization"]["principals"][0]["uid"] = json!({"mode":"absent"});
    assert_eq!(
        evaluate(absent.clone(), &original, &attrs()),
        M::UnknownPrincipal
    );
    let mut p = original;
    p.uid = None;
    assert_eq!(
        evaluate(absent, &p, &attrs()),
        M::Decided(R::Decided(D::Allow))
    );
}
#[test]
fn ambiguous_matching_bindings_deny_even_same_subject_or_different_rights() {
    let mut v = document();
    let mut second = v["kubernetes_authorization"]["principals"][0].clone();
    second["required_groups"] = json!([]);
    v["kubernetes_authorization"]["principals"]
        .as_array_mut()
        .unwrap()
        .push(second);
    assert_eq!(evaluate(v, &principal(), &attrs()), M::AmbiguousPrincipal);
}
#[test]
fn native_grant_class_assurance_and_mapping_withdrawal_remain_authoritative() {
    let allow = M::Decided(R::Decided(D::Allow));
    let original = policy(document()).compile().unwrap();
    for (field, value, expected) in [
        ("users", json!({}), D::Guest),
        (
            "roles",
            json!({"reader":{"permissions":[],"information_classes":["public"]}}),
            D::Guest,
        ),
    ] {
        let mut v = document();
        v["services"]["api"][field] = value;
        assert_eq!(
            evaluate(v, &principal(), &attrs()),
            M::Decided(R::Decided(expected))
        );
    }
    let mut v = document();
    v["resources"]["settings"]["information_class"] = json!("secret");
    assert_eq!(
        evaluate(v, &principal(), &attrs()),
        M::Decided(R::Decided(D::ClassDenied))
    );
    for target in ["resource", "role"] {
        let mut v = document();
        if target == "resource" {
            v["resources"]["settings"]["minimum_aal"] = json!(1);
        } else {
            v["services"]["api"]["roles"]["reader"]["minimum_aal"] = json!(1);
        }
        assert_eq!(
            evaluate(v, &principal(), &attrs()),
            M::Decided(R::Decided(D::AssuranceDenied))
        );
    }
    let mut v = document();
    v["kubernetes_authorization"]["routes"] = json!([]);
    assert_eq!(evaluate(v, &principal(), &attrs()), M::UnknownRoute);
    assert_eq!(
        original.evaluate_kubernetes_request("cluster-a", &principal(), &attrs()),
        allow
    ); // immutable snapshot: owner must retire it
}
#[test]
fn unsupported_resource_scope_and_paths_are_never_mapped() {
    for (field, values) in [
        (
            "verb",
            vec!["create", "list", "watch", "bind", "escalate", "*", "GET"],
        ),
        ("namespace", vec!["", "*"]),
        ("name", vec!["", "*", "a/b"]),
        ("subresource", vec!["exec", "proxy"]),
    ] {
        for value in values {
            let mut v = document();
            v["kubernetes_authorization"]["routes"][0]["attributes"][field] = json!(value);
            assert!(policy(v.clone()).compile().is_err());
            let a = serde_json::from_value(
                v["kubernetes_authorization"]["routes"][0]["attributes"].clone(),
            )
            .unwrap();
            assert_eq!(evaluate(document(), &principal(), &a), M::InvalidRequest);
        }
    }
    for path in [
        "/a/../healthz",
        "/%68ealthz",
        "//healthz",
        "/healthz?admin=1",
        "healthz",
    ] {
        let mut v = document();
        v["kubernetes_authorization"]["routes"][0]["attributes"] =
            json!({"kind":"non_resource","path":path,"verb":"get"});
        assert!(policy(v).compile().is_err());
    }
    let mut v = document();
    v["kubernetes_authorization"]["routes"][0]["attributes"] =
        json!({"kind":"non_resource","path":"/healthz","verb":"get"});
    let a =
        serde_json::from_value(v["kubernetes_authorization"]["routes"][0]["attributes"].clone())
            .unwrap();
    assert_eq!(
        evaluate(v, &principal(), &a),
        M::Decided(R::Decided(D::Allow))
    );
}
#[test]
fn metadata_compilation_rejects_invalid_scope_context_namespace_and_duplicates() {
    for (key, value) in [
        ("service", json!("other")),
        ("resource", json!("absent")),
        ("action", json!("unknown")),
        ("cluster", json!("cluster-a:evil")),
    ] {
        let mut v = document();
        v["kubernetes_authorization"]["routes"][0][key] = value;
        assert!(policy(v).compile().is_err());
    }
    let mut v = document();
    v["services"]["api"]["authorization_context"] = json!("network_and_guard");
    assert!(policy(v).compile().is_err());
    for subject in [
        "k8sapi:cluster-ab:reader",
        "k8sapi:cluster-b:reader",
        "k8sapi:cluster-a:",
        "human",
    ] {
        let mut v = document();
        v["kubernetes_authorization"]["principals"][0]["subject"] = json!(subject);
        assert!(policy(v).compile().is_err());
    }
    for kind in ["routes", "principals"] {
        let mut v = document();
        let dup = v["kubernetes_authorization"][kind][0].clone();
        v["kubernetes_authorization"][kind]
            .as_array_mut()
            .unwrap()
            .push(dup);
        assert!(policy(v).compile().is_err());
    }
}
#[test]
fn bounded_inputs_duplicate_values_anonymous_and_unknown_fields_refuse() {
    let mut variants = vec![];
    let mut p = principal();
    p.groups.push("readers".into());
    variants.push(p);
    let mut p = principal();
    p.groups = vec!["x".into(); 65];
    variants.push(p);
    let mut p = principal();
    p.user = "x".repeat(257);
    variants.push(p);
    let mut p = principal();
    p.user = "system:anonymous".into();
    variants.push(p);
    let mut p = principal();
    p.groups.push("system:unauthenticated".into());
    variants.push(p);
    let mut p = principal();
    p.extra
        .get_mut("owned.example/session")
        .unwrap()
        .push("a".into());
    variants.push(p);
    for p in variants {
        assert_eq!(evaluate(document(), &p, &attrs()), M::InvalidRequest);
    }
    let mut a = document()["kubernetes_authorization"]["routes"][0]["attributes"].clone();
    a["labelSelector"] = json!({});
    assert!(serde_json::from_value::<Attributes>(a).is_err());
    let duplicate = r#"{"user":"u","uid":null,"groups":[],"extra":{"x":["a"],"x":["b"]}}"#;
    assert!(serde_json::from_str::<Principal>(duplicate).is_err());
    let duplicate = r#"{"user":"u","user":"v","uid":null,"groups":[],"extra":{}}"#;
    assert!(serde_json::from_str::<Principal>(duplicate).is_err());
}
#[test]
fn absent_metadata_serialization_preserves_original_policy_bytes() {
    let mut v = document();
    v.as_object_mut()
        .unwrap()
        .remove("kubernetes_authorization");
    let bytes = serde_json::to_string(&policy(v)).unwrap();
    assert!(!bytes.contains("kubernetes_authorization"));
    let roundtrip: Policy = serde_json::from_str(&bytes).unwrap();
    assert_eq!(serde_json::to_string(&roundtrip).unwrap(), bytes);
    assert_eq!(
        roundtrip.compile().unwrap().evaluate_kubernetes_request(
            "cluster-a",
            &principal(),
            &attrs()
        ),
        M::UnknownPrincipal
    );
}
#[test]
fn compiled_metadata_capacities_and_canonical_constraint_duplicates_are_bounded() {
    for field in ["principals", "routes"] {
        let mut v = document();
        let item = v["kubernetes_authorization"][field][0].clone();
        v["kubernetes_authorization"][field] = Value::Array(vec![item; 4097]);
        assert!(policy(v).compile().is_err());
    }
    let mut v = document();
    v["kubernetes_authorization"]["principals"][0]["required_groups"] = json!(["readers", "other"]);
    let mut duplicate = v["kubernetes_authorization"]["principals"][0].clone();
    duplicate["required_groups"] = json!(["other", "readers"]);
    duplicate["required_extra"]["owned.example/session"] = json!(["b", "a"]);
    v["kubernetes_authorization"]["principals"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(policy(v).compile().is_err());
    let mut v = document();
    let item = v["kubernetes_authorization"]["principals"][0].clone();
    let candidates = v["kubernetes_authorization"]["principals"]
        .as_array_mut()
        .unwrap();
    candidates.clear();
    for n in 0..65 {
        let mut next = item.clone();
        next["uid"] = json!({"mode":"exact","value":format!("uid-{n}")});
        candidates.push(next);
    }
    assert!(policy(v).compile().is_err());
    for (field, value) in [
        ("user", json!("x".repeat(257))),
        ("required_groups", json!(["readers", "readers"])),
        ("required_extra", json!({"a":["x","x"]})),
        ("uid", json!({"mode":"exact","value":""})),
    ] {
        let mut v = document();
        v["kubernetes_authorization"]["principals"][0][field] = value;
        assert!(policy(v).compile().is_err());
    }
    let wire = r#"{"cluster":"cluster-a","user":"u","uid":{"mode":"absent"},"required_groups":[],"required_extra":{"x":["a"],"x":["b"]},"subject":"k8sapi:cluster-a:u"}"#;
    assert!(
        serde_json::from_str::<pumgye_core::kubernetes_authorization::PrincipalBinding>(wire)
            .is_err()
    );
}
#[test]
fn nonresource_mapping_is_exact_and_never_infers_public_health_access() {
    let mut v = document();
    v["kubernetes_authorization"]["routes"][0]["attributes"] =
        json!({"kind":"non_resource","path":"/healthz","verb":"get"});
    let compiled = policy(v).compile().unwrap();
    for (path, verb, expected) in [
        ("/healthz", "get", M::Decided(R::Decided(D::Allow))),
        ("/healthz/", "get", M::UnknownRoute),
        ("/healthz/live", "get", M::UnknownRoute),
        ("/healthz", "post", M::UnknownRoute),
        ("/Healthz", "get", M::UnknownRoute),
    ] {
        assert_eq!(
            compiled.evaluate_kubernetes_request(
                "cluster-a",
                &principal(),
                &Attributes::NonResource {
                    path: path.into(),
                    verb: verb.into()
                }
            ),
            expected
        );
    }
    let mut p = principal();
    p.user = "unmapped".into();
    assert_eq!(
        compiled.evaluate_kubernetes_request(
            "cluster-a",
            &p,
            &Attributes::NonResource {
                path: "/healthz".into(),
                verb: "get".into()
            }
        ),
        M::UnknownPrincipal
    );
}
