//! Explain must report exactly the enforcement decision, with a complete ordered trace.
use pumgye_core::{
    Decision, GuardEvidence, KubernetesApiSubject, Policy, ResourceDecision,
    diff::{Change, ChangeKind, Side, diff},
    explain::{
        Case, CaseError, DETAIL_CODES, Explanation, REASON_CODES, Snapshot, Stage, StageResult,
        explain, message_keys,
    },
};
use serde_json::{Value, json};

const WORKLOAD: &str = "s_0123456789abcdef0123456789abcdef0123456789abcdef";
const HUMAN: &str = "human1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn document() -> Value {
    json!({
    "version":1,"information_classes":["public","internal","restricted"],
    "services":{
     "orders":{"permissions":["read","write","admin"],"require_guard":true,
      "roles":{"reader":{"permissions":["read"],"information_classes":["public"]},
               "writer":{"permissions":["write"],"information_classes":["internal"],"inherits":["reader"],"minimum_aal":2},
               "auditor":{"permissions":["read"],"information_classes":["public","internal","restricted"]}},
      "users":{"u_reader":["reader"],"u_writer":["writer"],"u_guest":["guest"],"u_auditor":["auditor"]},
      "workload_users":{WORKLOAD:["reader"]},
      "human_users":{HUMAN:["writer"]},
      "networks":[{"cidr":"192.0.2.0/24","roles":["writer"]},{"cidr":"192.0.2.7/32","roles":["guest"]},
                  {"cidr":"198.51.100.0/24","roles":["reader"]},{"cidr":"10.0.0.0/8","roles":["writer","auditor"]}]},
     "open":{"permissions":["read"],"require_guard":false,
      "roles":{"reader":{"permissions":["read"],"information_classes":["public"]}},
      "users":{"u_reader":["reader"]},"networks":[{"cidr":"0.0.0.0/0","roles":["reader"]}]},
     "kube":{"authorization_context":"kubernetes_api","require_guard":false,"permissions":["get"],
      "roles":{"viewer":{"permissions":["get"],"information_classes":["internal"]}},
      "users":{"k8sapi:team:alice":["viewer"]},"networks":[]}
    },
    "resources":{
     "db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read","update":"write"},"minimum_aal":1},
     "db:public":{"service":"orders","information_class":"public","actions":{"select":"read"}},
     "kube:pods":{"service":"kube","information_class":"internal","actions":{"get":"get"}}
    }})
}
fn policy() -> Policy {
    serde_json::from_value(document()).unwrap()
}
fn case(value: Value) -> Case {
    serde_json::from_value(value).unwrap()
}
fn run(p: &Policy, c: Value) -> Explanation {
    let compiled = p.compile().unwrap();
    explain(
        Snapshot {
            policy: p,
            compiled: &compiled,
            revision: 7,
            serving: true,
        },
        &case(c),
        true,
    )
    .unwrap()
}
fn perm(subject: &str, ip: &str, permission: &str, class: &str, aal: u8, guard: &str) -> Value {
    json!({"subject":{"id":subject,"kind":"user"},"service":"orders","permission":permission,
           "information_class":class,"ip":ip,"aal":aal,"guard":guard})
}
fn stages(e: &Explanation) -> Vec<(Stage, StageResult, &'static str)> {
    e.trace
        .as_ref()
        .unwrap()
        .iter()
        .map(|s| (s.stage, s.result, s.code))
        .collect()
}
fn deciding(e: &Explanation) -> (Option<&'static str>, Stage, &'static str) {
    (
        e.outcome.decision,
        e.outcome.deciding_stage,
        e.outcome.detail_code,
    )
}
/// The trace is well formed: fence first, passes, exactly one deciding entry
/// (deny unless allowed), then only `not_evaluated`, all codes registered.
fn well_formed(e: &Explanation) {
    let trace = e.trace.as_ref().unwrap();
    assert_eq!(trace[0].stage, Stage::Fence);
    let decided = trace
        .iter()
        .rposition(|s| s.result != StageResult::NotEvaluated)
        .unwrap();
    for (i, s) in trace.iter().enumerate() {
        assert!(DETAIL_CODES.contains(&s.code), "{}", s.code);
        if i < decided {
            assert_eq!(s.result, StageResult::Pass, "{:?}", s.stage);
        } else if i > decided {
            assert_eq!(s.result, StageResult::NotEvaluated);
        }
    }
    let d = &trace[decided];
    assert_eq!(d.stage, e.outcome.deciding_stage);
    assert_eq!(d.code, e.outcome.detail_code);
    assert_eq!(
        d.result,
        if e.outcome.allow {
            StageResult::Pass
        } else {
            StageResult::Deny
        }
    );
    assert!(REASON_CODES.contains(&e.outcome.reason_code));
    assert!(!e.trace_truncated);
}

#[test]
fn allow_reports_every_stage_and_role_provenance() {
    let p = policy();
    let e = run(
        &p,
        perm(
            "u_writer",
            "192.0.2.1",
            "write",
            "internal",
            2,
            "enforced_allow",
        ),
    );
    well_formed(&e);
    assert!(e.outcome.allow);
    assert_eq!(e.outcome.reason_code, "pumgye.allow");
    assert_eq!(e.outcome.message_key, "pumgye.reason.allow");
    assert_eq!(e.outcome.hint_key, "pumgye.hint.allow");
    use Stage::*;
    assert_eq!(
        stages(&e).iter().map(|s| s.0).collect::<Vec<_>>(),
        [
            Fence,
            Service,
            Context,
            Guard,
            Subject,
            Network,
            RoleExpansion,
            Permission,
            InformationClass,
            Assurance
        ]
    );
    let v = serde_json::to_value(&e).unwrap();
    let trace = v["trace"].as_array().unwrap();
    assert_eq!(trace[4]["detail"]["map"], "users");
    assert_eq!(trace[4]["detail"]["roles"], json!(["writer"]));
    assert_eq!(trace[5]["detail"]["matched"]["cidr"], "192.0.2.0/24");
    assert_eq!(trace[5]["detail"]["matched"]["index"], 0);
    let roles = &trace[6]["detail"];
    assert_eq!(roles["subject_roles"][0]["role"], "writer");
    assert_eq!(roles["subject_roles"][1]["role"], "reader");
    assert_eq!(roles["subject_roles"][1]["inherited_from"], "writer");
    assert_eq!(
        roles["effective"],
        json!({"permissions":["read","write"],"information_classes":["public","internal"],"minimum_aal":2})
    );
    assert_eq!(
        trace[7]["detail"]["granted_by_subject_roles"],
        json!(["writer"])
    );
    assert_eq!(trace[9]["detail"]["required"], 2);
    assert!(e.obligations.is_none());
}

#[test]
fn every_decision_variant_has_a_deciding_stage_and_detail() {
    let p = policy();
    let cases: Vec<(Value, Option<&str>, Stage, &str)> = vec![
        (
            json!({"subject":{"id":"u_reader","kind":"user"},"service":"nope","permission":"read","information_class":"public","ip":"192.0.2.1","guard":"enforced_allow"}),
            Some("UnknownService"),
            Stage::Service,
            "pumgye.detail.service_not_found",
        ),
        (
            perm(
                "u_nobody",
                "192.0.2.1",
                "read",
                "public",
                1,
                "enforced_allow",
            ),
            Some("Guest"),
            Stage::Subject,
            "pumgye.detail.subject_not_assigned",
        ),
        (
            perm(
                "u_guest",
                "192.0.2.1",
                "read",
                "public",
                1,
                "enforced_allow",
            ),
            Some("Guest"),
            Stage::Subject,
            "pumgye.detail.subject_guest_only",
        ),
        (
            perm(
                "u_reader",
                "203.0.113.1",
                "read",
                "public",
                1,
                "enforced_allow",
            ),
            Some("NetworkGuest"),
            Stage::Network,
            "pumgye.detail.network_no_match",
        ),
        (
            perm(
                "u_reader",
                "192.0.2.1",
                "write",
                "public",
                1,
                "enforced_allow",
            ),
            Some("PermissionDenied"),
            Stage::Permission,
            "pumgye.detail.permission_missing_subject",
        ),
        (
            perm(
                "u_writer",
                "198.51.100.1",
                "write",
                "public",
                2,
                "enforced_allow",
            ),
            Some("PermissionDenied"),
            Stage::Permission,
            "pumgye.detail.permission_removed_by_network",
        ),
        (
            perm(
                "u_reader",
                "192.0.2.1",
                "delete",
                "public",
                1,
                "enforced_allow",
            ),
            Some("PermissionDenied"),
            Stage::Permission,
            "pumgye.detail.permission_unknown",
        ),
        (
            perm(
                "u_reader",
                "192.0.2.1",
                "read",
                "internal",
                1,
                "enforced_allow",
            ),
            Some("ClassDenied"),
            Stage::InformationClass,
            "pumgye.detail.class_missing_subject",
        ),
        (
            perm(
                "u_auditor",
                "198.51.100.1",
                "read",
                "restricted",
                1,
                "enforced_allow",
            ),
            Some("ClassDenied"),
            Stage::InformationClass,
            "pumgye.detail.class_removed_by_network",
        ),
        (
            perm(
                "u_reader",
                "192.0.2.1",
                "read",
                "secret",
                1,
                "enforced_allow",
            ),
            Some("ClassDenied"),
            Stage::InformationClass,
            "pumgye.detail.class_unknown",
        ),
        (
            perm(
                "u_writer",
                "192.0.2.1",
                "write",
                "internal",
                1,
                "enforced_allow",
            ),
            Some("AssuranceDenied"),
            Stage::Assurance,
            "pumgye.detail.assurance_below_required",
        ),
        (
            perm("u_writer", "192.0.2.1", "write", "internal", 2, "deny"),
            Some("GuardDenied"),
            Stage::Guard,
            "pumgye.detail.guard_denied",
        ),
        (
            perm("u_writer", "192.0.2.1", "write", "internal", 2, "observe"),
            Some("GuardUnavailable"),
            Stage::Guard,
            "pumgye.detail.guard_not_enforced",
        ),
        (
            perm(
                "u_writer",
                "192.0.2.1",
                "write",
                "internal",
                2,
                "unavailable",
            ),
            Some("GuardUnavailable"),
            Stage::Guard,
            "pumgye.detail.guard_not_enforced",
        ),
        (
            json!({"subject":{"id":"u_reader","kind":"user"},"service":"kube","permission":"get","information_class":"internal","ip":"192.0.2.1","guard":"enforced_allow"}),
            Some("PermissionDenied"),
            Stage::Context,
            "pumgye.detail.context_mismatch",
        ),
        (
            json!({"subject":{"id":"u_reader","kind":"user"},"service":"orders","resource":"db:none","action":"select","ip":"192.0.2.1","guard":"enforced_allow"}),
            Some("UnknownResource"),
            Stage::Resource,
            "pumgye.detail.resource_not_found",
        ),
        (
            json!({"subject":{"id":"u_reader","kind":"user"},"service":"open","resource":"db:orders","action":"select","ip":"192.0.2.1","guard":"enforced_allow"}),
            Some("UnknownService"),
            Stage::ServiceScope,
            "pumgye.detail.scope_mismatch",
        ),
        (
            json!({"subject":{"id":"u_reader","kind":"user"},"service":"orders","resource":"db:orders","action":"drop","ip":"192.0.2.1","guard":"deny"}),
            Some("UnknownAction"),
            Stage::Action,
            "pumgye.detail.action_unknown",
        ),
        (
            json!({"subject":{"id":"x","kind":"human"},"service":"orders","resource":"db:orders","action":"select","ip":"192.0.2.1","aal":2,"guard":"enforced_allow"}),
            Some("Guest"),
            Stage::PrincipalFormat,
            "pumgye.detail.principal_invalid",
        ),
        (
            json!({"subject":{"id":HUMAN,"kind":"human"},"service":"orders","resource":"db:orders","action":"select","ip":"192.0.2.1","aal":3,"guard":"enforced_allow"}),
            Some("AssuranceDenied"),
            Stage::PrincipalAssurance,
            "pumgye.detail.principal_assurance_invalid",
        ),
        (
            json!({"subject":{"id":"u_reader","kind":"user"},"service":"kube","resource":"kube:pods","action":"get","ip":"192.0.2.1","guard":"enforced_allow"}),
            Some("PermissionDenied"),
            Stage::Context,
            "pumgye.detail.context_mismatch",
        ),
        (
            json!({"subject":{"id":"k8sapi:team:bob","kind":"kubernetes_api"},"service":"kube","resource":"kube:pods","action":"get"}),
            Some("Guest"),
            Stage::Subject,
            "pumgye.detail.subject_not_assigned",
        ),
    ];
    for (input, decision, stage, code) in cases {
        let e = run(&p, input.clone());
        well_formed(&e);
        assert_eq!(deciding(&e), (decision, stage, code), "{input}");
        assert!(!e.outcome.allow);
    }
}

#[test]
fn assurance_denial_returns_step_up_obligation() {
    let p = policy();
    let e = run(
        &p,
        perm(
            "u_writer",
            "192.0.2.1",
            "write",
            "internal",
            1,
            "enforced_allow",
        ),
    );
    assert_eq!(e.obligations.as_ref().unwrap().required_aal, 2);
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["obligations"], json!({"required_aal":2}));
    // A Human resource minimum is reported separately from role minimums.
    let e = run(
        &p,
        json!({"subject":{"id":HUMAN,"kind":"human"},"service":"orders","resource":"db:orders","action":"update","ip":"192.0.2.1","aal":1,"guard":"enforced_allow"}),
    );
    well_formed(&e);
    assert_eq!(e.outcome.decision, Some("AssuranceDenied"));
    let v = serde_json::to_value(&e).unwrap();
    let last = v["trace"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(
        last["detail"],
        json!({"presented":1,"required":2,"role_minimum":2,"resource_minimum":1})
    );
}

#[test]
fn exact_host_rule_overrides_prefix_and_reports_shadowed_rules() {
    let p = policy();
    let e = run(
        &p,
        perm(
            "u_writer",
            "192.0.2.7",
            "write",
            "internal",
            2,
            "enforced_allow",
        ),
    );
    well_formed(&e);
    assert_eq!(
        deciding(&e),
        (
            Some("PermissionDenied"),
            Stage::Permission,
            "pumgye.detail.permission_removed_by_network"
        )
    );
    let v = serde_json::to_value(&e).unwrap();
    let network = &v["trace"][5]["detail"];
    assert_eq!(
        network["matched"],
        json!({"index":1,"cidr":"192.0.2.7/32","exact_host":true,"roles":["guest"]})
    );
    assert_eq!(network["shadowed"][0]["cidr"], "192.0.2.0/24");
}

#[test]
fn guard_not_required_passes_observe_evidence() {
    let p = policy();
    let e = run(
        &p,
        json!({"subject":{"id":"u_reader","kind":"user"},"service":"open","permission":"read","information_class":"public","ip":"203.0.113.9","aal":0,"guard":"observe"}),
    );
    well_formed(&e);
    assert!(e.outcome.allow);
    assert!(stages(&e).contains(&(
        Stage::Guard,
        StageResult::Pass,
        "pumgye.detail.guard_not_required"
    )));
}

#[test]
fn typed_and_kubernetes_paths_allow_with_their_own_maps() {
    let p = policy();
    let workload = run(
        &p,
        json!({"subject":{"id":WORKLOAD,"kind":"workload"},"service":"orders","resource":"db:public","action":"select","ip":"198.51.100.4","guard":"enforced_allow"}),
    );
    well_formed(&workload);
    assert!(workload.outcome.allow);
    let v = serde_json::to_value(&workload).unwrap();
    assert_eq!(v["trace"][6]["detail"]["map"], "workload_users");
    // The same identifier in the generic map is not consulted.
    let legacy = run(
        &p,
        json!({"subject":{"id":WORKLOAD,"kind":"user"},"service":"orders","resource":"db:public","action":"select","ip":"198.51.100.4","guard":"enforced_allow"}),
    );
    assert_eq!(legacy.outcome.decision, Some("Guest"));

    let human = run(
        &p,
        json!({"subject":{"id":HUMAN,"kind":"human"},"service":"orders","resource":"db:orders","action":"update","ip":"192.0.2.1","aal":2,"guard":"enforced_allow"}),
    );
    well_formed(&human);
    assert!(human.outcome.allow);
    // Human path reports the context check once, before principal validation.
    let order: Vec<Stage> = stages(&human).iter().map(|s| s.0).collect();
    assert_eq!(order.iter().filter(|s| **s == Stage::Context).count(), 1);
    assert_eq!(
        &order[..6],
        [
            Stage::Fence,
            Stage::Resource,
            Stage::ServiceScope,
            Stage::Context,
            Stage::PrincipalFormat,
            Stage::PrincipalAssurance
        ]
    );

    let kube = run(
        &p,
        json!({"subject":{"id":"k8sapi:team:alice","kind":"kubernetes_api"},"service":"kube","resource":"kube:pods","action":"get"}),
    );
    well_formed(&kube);
    assert!(kube.outcome.allow);
    assert!(
        !stages(&kube)
            .iter()
            .any(|s| matches!(s.0, Stage::Guard | Stage::Network))
    );
}

#[test]
fn fence_refusals_are_unavailable_not_decisions() {
    let p = policy();
    let compiled = p.compile().unwrap();
    let mut input = perm(
        "u_writer",
        "192.0.2.1",
        "write",
        "internal",
        2,
        "enforced_allow",
    );
    input["minimum_revision"] = json!(8);
    let snapshot = Snapshot {
        policy: &p,
        compiled: &compiled,
        revision: 7,
        serving: true,
    };
    let e = explain(snapshot, &case(input.clone()), true).unwrap();
    well_formed(&e);
    assert_eq!(
        deciding(&e),
        (None, Stage::Fence, "pumgye.detail.revision_floor")
    );
    assert_eq!(e.outcome.reason_code, "pumgye.unavailable");
    assert!(
        stages(&e)[1..]
            .iter()
            .all(|s| s.1 == StageResult::NotEvaluated)
    );
    input["minimum_revision"] = json!(7);
    let e = explain(
        Snapshot {
            serving: false,
            ..snapshot
        },
        &case(input.clone()),
        false,
    )
    .unwrap();
    assert_eq!(e.outcome.detail_code, "pumgye.detail.snapshot_unavailable");
    assert!(e.trace.is_none());
    assert!(
        explain(snapshot, &case(input), false)
            .unwrap()
            .outcome
            .allow
    );
}

#[test]
fn invalid_cases_are_refused_before_evaluation() {
    let p = policy();
    let compiled = p.compile().unwrap();
    let snapshot = Snapshot {
        policy: &p,
        compiled: &compiled,
        revision: 1,
        serving: true,
    };
    let refuse = |value: Value| explain(snapshot, &case(value), true).unwrap_err();
    let base = perm(
        "u_reader",
        "192.0.2.1",
        "read",
        "public",
        1,
        "enforced_allow",
    );
    let mut both = base.clone();
    both["resource"] = json!("db:orders");
    both["action"] = json!("select");
    assert_eq!(refuse(both), CaseError::AmbiguousTarget);
    let mut neither = base.clone();
    neither.as_object_mut().unwrap().remove("permission");
    assert_eq!(refuse(neither), CaseError::AmbiguousTarget);
    let mut aal = base.clone();
    aal["aal"] = json!(4);
    assert_eq!(refuse(aal), CaseError::AssuranceOutOfRange);
    let mut long = base.clone();
    long["service"] = json!("x".repeat(129));
    assert_eq!(refuse(long), CaseError::InvalidName);
    let mut bad = base.clone();
    bad["subject"]["id"] = json!("a b");
    assert_eq!(refuse(bad), CaseError::InvalidName);
    let mut no_ip = base.clone();
    no_ip.as_object_mut().unwrap().remove("ip");
    assert_eq!(refuse(no_ip), CaseError::MissingNetworkEvidence);
    let mut label = base.clone();
    label["label"] = json!("x".repeat(65));
    assert_eq!(refuse(label), CaseError::InvalidLabel);
    let mut typed = base.clone();
    typed["subject"]["kind"] = json!("workload");
    assert_eq!(refuse(typed), CaseError::UnsupportedCombination);
    assert_eq!(
        refuse(
            json!({"subject":{"id":WORKLOAD,"kind":"workload"},"service":"orders","resource":"db:public","action":"select","ip":"198.51.100.4","aal":1,"guard":"enforced_allow"})
        ),
        CaseError::AssuranceOutOfRange
    );
    assert_eq!(
        refuse(
            json!({"subject":{"id":"k8sapi:team:alice","kind":"kubernetes_api"},"service":"kube","resource":"kube:pods","action":"get","ip":"192.0.2.1"})
        ),
        CaseError::UnexpectedNetworkEvidence
    );
    assert!(
        serde_json::from_value::<Case>(json!({"subject":{"id":"a","kind":"root"},"service":"s"}))
            .is_err()
    );
    let mut extra = base;
    extra["groups"] = json!(["admins"]);
    assert!(serde_json::from_value::<Case>(extra).is_err());
}

/// Parity corpus: the explain decision equals the production (NoTrace) decision
/// for every entrypoint over a cross product of inputs.
#[test]
fn explain_decision_equals_enforcement_over_corpus() {
    let p = policy();
    let compiled = p.compile().unwrap();
    let snapshot = Snapshot {
        policy: &p,
        compiled: &compiled,
        revision: 1,
        serving: true,
    };
    let guards = [
        ("enforced_allow", GuardEvidence::EnforcedAllow),
        ("deny", GuardEvidence::Deny),
        ("observe", GuardEvidence::Observe),
        ("unavailable", GuardEvidence::Unavailable),
    ];
    let ips = [
        "192.0.2.1",
        "192.0.2.7",
        "198.51.100.4",
        "10.1.2.3",
        "203.0.113.1",
        "2001:db8::1",
    ];
    let users = [
        "u_reader",
        "u_writer",
        "u_guest",
        "u_auditor",
        "u_nobody",
        WORKLOAD,
    ];
    let mut checked = 0;
    let mut seen = std::collections::BTreeSet::new();
    for service in ["orders", "open", "kube", "nope"] {
        for subject in users {
            for ip in ips {
                for (guard_name, guard) in guards {
                    for aal in 0..=3u8 {
                        for permission in ["read", "write", "admin", "get", "delete"] {
                            for class in ["public", "internal", "restricted", "secret"] {
                                let c = case(
                                    json!({"subject":{"id":subject,"kind":"user"},"service":service,"permission":permission,"information_class":class,"ip":ip,"aal":aal,"guard":guard_name}),
                                );
                                let e = explain(snapshot, &c, true).unwrap();
                                let expected = compiled.evaluate(
                                    service,
                                    subject,
                                    ip.parse().unwrap(),
                                    permission,
                                    class,
                                    aal,
                                    guard,
                                );
                                assert_eq!(
                                    e.outcome.decision,
                                    Some(pumgye_core::explain::decision_name(
                                        ResourceDecision::Decided(expected)
                                    ))
                                );
                                well_formed(&e);
                                seen.insert(e.outcome.reason_code);
                                checked += 1;
                            }
                        }
                        for resource in ["db:orders", "db:public", "kube:pods", "db:none"] {
                            for action in ["select", "update", "get", "drop"] {
                                for (kind, id) in
                                    [("user", subject), ("workload", WORKLOAD), ("human", HUMAN)]
                                {
                                    if kind == "workload" && aal != 0 {
                                        continue;
                                    }
                                    let c = case(
                                        json!({"subject":{"id":id,"kind":kind},"service":service,"resource":resource,"action":action,"ip":ip,"aal":aal,"guard":guard_name}),
                                    );
                                    let e = explain(snapshot, &c, true).unwrap();
                                    let ip = ip.parse().unwrap();
                                    let expected = match kind {
                                        "user" => compiled.evaluate_scoped_resource(
                                            service, resource, action, id, ip, aal, guard,
                                        ),
                                        "workload" => compiled.evaluate_scoped_workload_resource(
                                            service, resource, action, id, ip, guard,
                                        ),
                                        _ => compiled.evaluate_scoped_human_resource(
                                            service, resource, action, id, ip, aal, guard,
                                        ),
                                    };
                                    assert_eq!(
                                        e.outcome.decision,
                                        Some(pumgye_core::explain::decision_name(expected))
                                    );
                                    well_formed(&e);
                                    seen.insert(e.outcome.reason_code);
                                    checked += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for subject in ["k8sapi:team:alice", "k8sapi:team:bob"] {
        for service in ["kube", "orders"] {
            for resource in ["kube:pods", "db:orders", "db:none"] {
                for action in ["get", "select", "drop"] {
                    let c = case(
                        json!({"subject":{"id":subject,"kind":"kubernetes_api"},"service":service,"resource":resource,"action":action}),
                    );
                    let e = explain(snapshot, &c, true).unwrap();
                    let expected = compiled.evaluate_kubernetes_api_resource(
                        service,
                        resource,
                        action,
                        KubernetesApiSubject::parse(subject).unwrap(),
                    );
                    assert_eq!(
                        e.outcome.decision,
                        Some(pumgye_core::explain::decision_name(expected))
                    );
                    well_formed(&e);
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 50_000, "{checked}");
    // The corpus reaches every final reason except the fence refusal.
    for code in REASON_CODES.iter().filter(|c| **c != "pumgye.unavailable") {
        assert!(seen.contains(code), "corpus misses {code}");
    }
    let _ = Decision::Allow;
}

#[test]
fn message_catalogs_cover_exactly_the_registered_keys() {
    let keys = message_keys();
    assert_eq!(
        keys.len(),
        REASON_CODES.len() * 2 + DETAIL_CODES.len() + Stage::ALL.len()
    );
    for catalog in [
        include_str!("../messages/en.json"),
        include_str!("../messages/ko.json"),
    ] {
        let catalog: std::collections::BTreeMap<String, String> =
            serde_json::from_str(catalog).unwrap();
        assert_eq!(catalog.keys().cloned().collect::<Vec<_>>(), keys);
        assert!(catalog.values().all(|v| !v.trim().is_empty()));
    }
}

#[test]
fn what_if_candidate_changes_decision_and_diff_lists_rights() {
    let base = policy();
    let mut doc = document();
    // Candidate: grant writer to u_reader, drop u_guest, narrow a network rule,
    // add a resource, and require AAL3 for db:orders.
    doc["services"]["orders"]["users"]["u_reader"] = json!(["writer"]);
    doc["services"]["orders"]["users"]
        .as_object_mut()
        .unwrap()
        .remove("u_guest");
    doc["services"]["orders"]["networks"][2]["roles"] = json!(["guest"]);
    doc["resources"]["db:orders"]["minimum_aal"] = json!(3);
    doc["resources"]["db:new"] =
        json!({"service":"orders","information_class":"public","actions":{"select":"read"}});
    let candidate: Policy = serde_json::from_value(doc).unwrap();
    let input = perm(
        "u_reader",
        "192.0.2.1",
        "write",
        "internal",
        2,
        "enforced_allow",
    );
    assert_eq!(
        run(&base, input.clone()).outcome.decision,
        Some("PermissionDenied")
    );
    assert_eq!(run(&candidate, input).outcome.decision, Some("Allow"));

    let (bc, cc) = (base.compile().unwrap(), candidate.compile().unwrap());
    let page = diff(
        Side {
            policy: &base,
            compiled: &bc,
        },
        Side {
            policy: &candidate,
            compiled: &cc,
        },
        0,
        100,
    );
    assert_eq!(page.total, 5, "{:#?}", page.changes);
    assert!(page.next_cursor.is_none());
    match &page.changes[0] {
        Change::Assignment {
            subject,
            change,
            delta,
            ..
        } => {
            assert_eq!(subject, "u_guest");
            assert_eq!(*change, ChangeKind::Removed);
            assert!(delta.added_permissions.is_empty());
        }
        other => panic!("{other:?}"),
    }
    match &page.changes[1] {
        Change::Assignment { subject, delta, .. } => {
            assert_eq!(subject, "u_reader");
            assert_eq!(delta.added_permissions, ["write"]);
            assert_eq!(delta.added_information_classes, ["internal"]);
            assert_eq!(delta.minimum_aal, Some((0, 2)));
        }
        other => panic!("{other:?}"),
    }
    match &page.changes[2] {
        Change::Network { cidr, delta, .. } => {
            assert_eq!(cidr, "198.51.100.0/24");
            assert_eq!(delta.removed_permissions, ["read"]);
        }
        other => panic!("{other:?}"),
    }
    let v = serde_json::to_value(&page.changes[3]).unwrap();
    assert_eq!(v["entity"], "resource");
    assert_eq!(v["resource"], "db:new");
    assert_eq!(v["change"], "added");
    // Pagination is a deterministic window over the same ordering.
    let first = diff(
        Side {
            policy: &base,
            compiled: &bc,
        },
        Side {
            policy: &candidate,
            compiled: &cc,
        },
        0,
        2,
    );
    assert_eq!(first.next_cursor, Some(2));
    let rest = diff(
        Side {
            policy: &base,
            compiled: &bc,
        },
        Side {
            policy: &candidate,
            compiled: &cc,
        },
        2,
        10,
    );
    assert_eq!(first.changes, page.changes[..2]);
    assert_eq!(rest.changes, page.changes[2..]);
    // Identical documents (even with a reordered permission vocabulary) do not differ.
    let mut reordered = document();
    reordered["services"]["orders"]["permissions"] = json!(["read", "write", "admin"]);
    let same: Policy = serde_json::from_value(reordered).unwrap();
    let sc = same.compile().unwrap();
    assert_eq!(
        diff(
            Side {
                policy: &base,
                compiled: &bc
            },
            Side {
                policy: &same,
                compiled: &sc
            },
            0,
            10
        )
        .total,
        0
    );
}
