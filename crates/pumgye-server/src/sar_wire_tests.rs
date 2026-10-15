use super::*;
use serde_json::json;
fn fixture() -> Value {
    serde_json::from_slice(include_bytes!(
        "../tests/fixtures/sar-v1-generated-shape.json"
    ))
    .unwrap()
}
fn decode_value(value: Value) -> Result<Decoded, BadRequest> {
    decode(&serde_json::to_vec(&value).unwrap())
}
fn supported(value: Value) -> (Principal, Attributes) {
    match decode_value(value).unwrap() {
        Decoded::Supported {
            principal,
            attributes,
        } => (principal, attributes),
        Decoded::Deny => panic!("expected supported fixture"),
    }
}
#[test]
fn public_v1_generated_shape_and_zero_envelope_defaults_convert_exactly() {
    let (p, a) = supported(fixture());
    assert_eq!(p.user, "owned-reader");
    assert_eq!(p.uid.as_deref(), Some("owned-user-uid"));
    assert_eq!(p.groups.len(), 2);
    assert_eq!(
        p.extra["qualification.example/session"],
        vec!["owned-session"]
    );
    assert_eq!(
        a,
        Attributes::Resource {
            group: "".into(),
            version: "v1".into(),
            resource: "configmaps".into(),
            subresource: "".into(),
            namespace: "owned-blue".into(),
            name: "owned-settings".into(),
            verb: "get".into()
        }
    );
    for metadata in [
        None,
        Some(json!({})),
        Some(json!({"creationTimestamp":null})),
    ] {
        for status in [None, Some(json!({})), Some(json!({"allowed":false}))] {
            let mut v = fixture();
            v.as_object_mut().unwrap().remove("metadata");
            v.as_object_mut().unwrap().remove("status");
            if let Some(m) = metadata.clone() {
                v["metadata"] = m;
            }
            if let Some(s) = status {
                v["status"] = s;
            }
            supported(v);
        }
    }
    let mut v = fixture();
    for key in ["uid", "groups", "extra"] {
        v["spec"].as_object_mut().unwrap().remove(key);
    }
    let (p, _) = supported(v);
    assert!(p.uid.is_none() && p.groups.is_empty() && p.extra.is_empty());
}
#[test]
fn duplicate_keys_everywhere_including_escaped_spellings_are_bad_requests() {
    let original = String::from_utf8(serde_json::to_vec(&fixture()).unwrap()).unwrap();
    for (needle, replacement) in [
        (
            "\"kind\":\"SubjectAccessReview\"",
            "\"kind\":\"SubjectAccessReview\",\"kind\":\"SubjectAccessReview\"",
        ),
        (
            "\"user\":\"owned-reader\"",
            "\"user\":\"owned-reader\",\"u\\u0073er\":\"owned-reader\"",
        ),
        ("\"verb\":\"get\"", "\"verb\":\"get\",\"verb\":\"get\""),
        (
            "\"qualification.example/session\":[\"owned-session\"]",
            "\"qualification.example/session\":[\"owned-session\"],\"qualification.example/session\":[\"other\"]",
        ),
        ("\"allowed\":false", "\"allowed\":false,\"allowed\":true"),
        (
            "\"creationTimestamp\":null",
            "\"creationTimestamp\":null,\"creationTimestamp\":null",
        ),
    ] {
        assert!(original.contains(needle));
        assert_eq!(
            decode(original.replace(needle, replacement).as_bytes()),
            Err(BadRequest)
        );
    }
    let mut v = fixture();
    v["spec"]["unsupported"] = json!({"deep":{"nested":1}});
    let s = serde_json::to_string(&v)
        .unwrap()
        .replace("\"nested\":1", "\"nested\":1,\"nested\":2");
    assert_eq!(decode(s.as_bytes()), Err(BadRequest));
}
#[test]
fn strict_size_depth_trailing_and_bad_envelope_are_400_class_only() {
    let mut exact = include_bytes!("../tests/fixtures/sar-v1-generated-shape.json").to_vec();
    exact.resize(MAX_BODY, b' ');
    assert!(matches!(decode(&exact), Ok(Decoded::Supported { .. })));
    exact.push(b' ');
    assert_eq!(decode(&exact), Err(BadRequest));
    for raw in [
        b"".as_slice(),
        b"[]",
        b"null",
        b"{}",
        b"{}{}",
        b"{",
        b"\xff",
    ] {
        assert_eq!(decode(raw), Err(BadRequest));
    }
    for (field, value) in [
        ("apiVersion", json!("authorization.k8s.io/v1beta1")),
        ("kind", json!("SelfSubjectAccessReview")),
        ("spec", json!(null)),
        ("spec", json!([])),
    ] {
        let mut v = fixture();
        v[field] = value;
        assert_eq!(decode_value(v), Err(BadRequest));
    }
    for field in ["kind", "apiVersion", "spec"] {
        let mut v = fixture();
        v.as_object_mut().unwrap().remove(field);
        assert_eq!(decode_value(v), Err(BadRequest));
    }
    let mut raw = serde_json::to_string(&fixture()).unwrap();
    raw.pop();
    raw.push_str(",\"unknown\":");
    raw.push_str(&"[".repeat(MAX_DEPTH + 1));
    raw.push('0');
    raw.push_str(&"]".repeat(MAX_DEPTH + 1));
    raw.push('}');
    assert_eq!(decode(raw.as_bytes()), Err(BadRequest));
    // Root is depth1. Unknown value with15 arrays reaches exactly16 containers.
    let mut v = fixture();
    let mut nested = json!(0);
    for _ in 0..MAX_DEPTH - 1 {
        nested = json!([nested]);
    }
    v["unknown"] = nested;
    assert_eq!(decode_value(v), Ok(Decoded::Deny));
}
#[test]
fn unknown_security_and_inert_input_status_never_authorize_or_echo() {
    for (level, key, value) in [
        ("root", "cluster", json!("other")),
        ("spec", "aal", json!(3)),
        ("spec", "service", json!("admin")),
        ("spec", "group", json!(["admins"])),
        ("resource", "labelSelector", json!({})),
        ("resource", "fieldSelector", json!({"rawSelector":"a=b"})),
        ("metadata", "name", json!("owned")),
        ("status", "allowed", json!(true)),
        ("status", "denied", json!(false)),
    ] {
        let mut v = fixture();
        let target = match level {
            "root" => &mut v,
            "spec" => &mut v["spec"],
            "resource" => &mut v["spec"]["resourceAttributes"],
            other => &mut v[other],
        };
        target[key] = value;
        assert_eq!(decode_value(v), Ok(Decoded::Deny));
    }
    for field in ["metadata", "status"] {
        for value in [json!(null), json!("ignored"), json!([])] {
            let mut v = fixture();
            v[field] = value;
            assert_eq!(decode_value(v), Ok(Decoded::Deny));
        }
    }
}
#[test]
fn exact_one_attributes_branch_and_native_scope_restrictions_fail_closed() {
    let mut v = fixture();
    v["spec"]["nonResourceAttributes"] = json!({"path":"/healthz","verb":"get"});
    assert_eq!(decode_value(v), Ok(Decoded::Deny));
    let mut v = fixture();
    v["spec"]
        .as_object_mut()
        .unwrap()
        .remove("resourceAttributes");
    assert_eq!(decode_value(v), Ok(Decoded::Deny));
    for val in [json!(null), json!([]), json!("get")] {
        let mut v = fixture();
        v["spec"]["resourceAttributes"] = val;
        assert_eq!(decode_value(v), Ok(Decoded::Deny));
    }
    for (field, values) in [
        (
            "verb",
            vec!["create", "list", "watch", "bind", "escalate", "GET", "*"],
        ),
        ("subresource", vec!["exec", "proxy", "connect"]),
        ("namespace", vec!["", "*"]),
        ("name", vec!["", "*", "a/b"]),
        ("version", vec![""]),
    ] {
        for value in values {
            let mut v = fixture();
            v["spec"]["resourceAttributes"][field] = json!(value);
            assert_eq!(decode_value(v), Ok(Decoded::Deny));
        }
    }
    for field in ["namespace", "name", "version", "resource", "verb"] {
        let mut v = fixture();
        v["spec"]["resourceAttributes"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert_eq!(decode_value(v), Ok(Decoded::Deny));
    }
}
#[test]
fn bounded_uid_groups_extras_anonymous_and_duplicate_values_refuse() {
    for (key, values) in [
        (
            "uid",
            vec![json!(""), json!(null), json!(5), json!("x".repeat(257))],
        ),
        (
            "user",
            vec![
                json!(""),
                json!("system:anonymous"),
                json!("a\nb"),
                json!("x".repeat(257)),
            ],
        ),
        (
            "groups",
            vec![
                json!(["a", "a"]),
                json!(["system:unauthenticated"]),
                json!(vec!["x"; 65]),
                json!(null),
            ],
        ),
        (
            "extra",
            vec![
                json!({"x":[]}),
                json!({"x":["a","a"]}),
                json!({"x":vec!["a";9]}),
                json!({"x":"a"}),
                json!({"x":["x".repeat(257)]}),
                json!(null),
            ],
        ),
    ] {
        for value in values {
            let mut v = fixture();
            v["spec"][key] = value;
            assert_eq!(decode_value(v), Ok(Decoded::Deny));
        }
    }
    let mut v = fixture();
    v["spec"]["extra"] = json!(
        (0..33)
            .map(|n| (format!("k{n}"), vec!["a"]))
            .collect::<BTreeMap<_, _>>()
    );
    assert_eq!(decode_value(v), Ok(Decoded::Deny));
}
#[test]
fn nonresource_paths_are_exact_no_decode_or_normalization_and_no_native_fields() {
    for path in ["/healthz", "/readyz", "/api/v1"] {
        let mut v = fixture();
        v["spec"]
            .as_object_mut()
            .unwrap()
            .remove("resourceAttributes");
        v["spec"]["nonResourceAttributes"] = json!({"path":path,"verb":"get"});
        let (_, a) = supported(v);
        assert_eq!(
            a,
            Attributes::NonResource {
                path: path.into(),
                verb: "get".into()
            }
        );
    }
    for path in [
        "healthz",
        "/%68ealthz",
        "//healthz",
        "/a/../healthz",
        "/healthz?admin=1",
        "/é",
        "/x#y",
    ] {
        let mut v = fixture();
        v["spec"]
            .as_object_mut()
            .unwrap()
            .remove("resourceAttributes");
        v["spec"]["nonResourceAttributes"] = json!({"path":path,"verb":"get"});
        assert_eq!(decode_value(v), Ok(Decoded::Deny));
    }
    let mut v = fixture();
    v["spec"]
        .as_object_mut()
        .unwrap()
        .remove("resourceAttributes");
    v["spec"]["nonResourceAttributes"] = json!({"path":"/healthz","verb":"get","service":"admin"});
    assert_eq!(decode_value(v), Ok(Decoded::Deny));
}
#[test]
fn fixed_response_buffers_are_mutually_consistent_schema_and_contain_no_echo() {
    for (bytes, allowed) in [(ALLOW, true), (DENY, false)] {
        assert!(bytes.len() < 2048);
        let v: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(v["apiVersion"], "authorization.k8s.io/v1");
        assert_eq!(v["kind"], "SubjectAccessReview");
        assert_eq!(v["status"]["allowed"], allowed);
        assert_eq!(v["status"]["denied"], !allowed);
        assert_eq!(v.as_object().unwrap().len(), 3);
        assert!(v.get("spec").is_none());
        assert!(!String::from_utf8_lossy(bytes).contains("owned-"));
    }
}
#[test]
fn supported_conversion_reaches_same_native_mapping_and_grant_withdrawal() {
    use pumgye_core::kubernetes_authorization::MappingDecision as M;
    use pumgye_core::{Decision as D, Policy, ResourceDecision as R};
    let (p, a) = supported(fixture());
    let mut doc = json!({"version":1,"information_classes":["public"],"services":{"api":{"authorization_context":"kubernetes_api","permissions":["read"],"roles":{"reader":{"permissions":["read"],"information_classes":["public"]}},"users":{"k8sapi:owned-cluster:reader":["reader"]},"networks":[],"require_guard":false}},"resources":{"settings":{"service":"api","information_class":"public","actions":{"read":"read"}}},"kubernetes_authorization":{"version":1,"principals":[{"cluster":"owned-cluster","user":"owned-reader","uid":{"mode":"exact","value":"owned-user-uid"},"required_groups":["owned-readers"],"required_extra":{},"subject":"k8sapi:owned-cluster:reader"}],"routes":[{"cluster":"owned-cluster","attributes":a,"service":"api","resource":"settings","action":"read"}]}});
    let compile = |v: Value| {
        serde_json::from_value::<Policy>(v)
            .unwrap()
            .compile()
            .unwrap()
    };
    assert_eq!(
        compile(doc.clone()).evaluate_kubernetes_request("owned-cluster", &p, &a),
        M::Decided(R::Decided(D::Allow))
    );
    doc["services"]["api"]["users"] = json!({});
    assert_eq!(
        compile(doc).evaluate_kubernetes_request("owned-cluster", &p, &a),
        M::Decided(R::Decided(D::Guest))
    );
}
