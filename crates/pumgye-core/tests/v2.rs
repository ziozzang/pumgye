//! Policy model version 2 (ADR 0021 P0): decisions, explain parity, fixtures,
//! properties, conversion and shadow parity with version 1.
use pumgye_core::{
    GuardEvidence as G, Policy,
    v2::{
        CompileOptions, CompiledV2, DecisionV2 as D, Lifecycle, MembershipIndex, PolicyV2,
        PrincipalKind as K, RequestV2, TargetV2, Timestamp,
        convert::{ConvertOptions, classify_by_prefix, convert},
        diff::{SideV2, diff},
        explain::{CaseV2, SnapshotV2, explain},
    },
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const H1: &str = "human1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const H2: &str = "human1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const H3: &str = "human1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const H4: &str = "human1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const S1: &str = "s_111111111111111111111111111111111111111111111111";
const W1: &str = "wk2:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const GE: &str = "grp1:00000000000000000000000000";
const GO: &str = "grp1:11111111111111111111111111";

fn now() -> u64 {
    Timestamp::parse("2026-10-16T00:00:00Z").unwrap().0
}
fn document() -> Value {
    serde_json::from_str(include_str!("../../../examples/v2/policy.json")).unwrap()
}
fn policy() -> PolicyV2 {
    serde_json::from_value(document()).unwrap()
}
fn membership(c: &CompiledV2) -> MembershipIndex {
    let eng: BTreeSet<String> = [GE.to_owned()].into();
    let both: BTreeSet<String> = [GE.to_owned(), GO.to_owned()].into();
    let ops: BTreeSet<String> = [GO.to_owned()].into();
    MembershipIndex::build(c, [(H1, &eng), (H2, &both), (H4, &ops)])
}
struct Fixture {
    policy: PolicyV2,
    compiled: CompiledV2,
    membership: MembershipIndex,
}
fn fixture() -> Fixture {
    let policy = policy();
    let compiled = policy
        .compile_with(&CompileOptions {
            max_issued_aal: 2,
            now: now(),
            ..Default::default()
        })
        .unwrap();
    let membership = membership(&compiled);
    Fixture {
        policy,
        compiled,
        membership,
    }
}
#[allow(clippy::too_many_arguments)]
fn req<'a>(
    service: &'a str,
    kind: K,
    subject: &'a str,
    target: TargetV2<'a>,
    ip: &str,
    aal: u8,
    guard: G,
    at: u64,
) -> RequestV2<'a> {
    RequestV2 {
        service,
        kind,
        subject,
        target,
        ip: ip.parse().unwrap(),
        aal,
        guard,
        now: at,
    }
}
fn perm<'a>(permission: &'a str, level: &'a str) -> TargetV2<'a> {
    TargetV2::Permission { permission, level }
}
fn res<'a>(resource: &'a str, action: &'a str) -> TargetV2<'a> {
    TargetV2::Resource { resource, action }
}
const E: G = G::EnforcedAllow;

#[test]
fn every_v2_outcome_is_reachable_with_adr_precedence() {
    let f = fixture();
    let t = now();
    let jan = Timestamp::parse("2026-01-15T00:00:00Z").unwrap().0;
    let later = Timestamp::parse("2031-01-01T00:00:00Z").unwrap().0;
    let cases: Vec<(RequestV2<'_>, D)> = vec![
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("write", "internal"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::Allow,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("write", "internal"),
                "192.0.2.10",
                1,
                E,
                t,
            ),
            D::AssuranceDenied,
        ),
        // anywhere ceiling (reader) removes write
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("write", "internal"),
                "203.0.113.1",
                2,
                E,
                t,
            ),
            D::PermissionDenied,
        ),
        // most-specific guest ceiling overrides the office ceiling
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("read", "public"),
                "192.0.2.7",
                2,
                E,
                t,
            ),
            D::PermissionDenied,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("read", "restricted"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::ClassDenied,
        ),
        // deny overrides the allow G_ENG grants on reports
        (
            req(
                "reports",
                K::Human,
                H2,
                perm("view", "public"),
                "203.0.113.1",
                1,
                E,
                t,
            ),
            D::ExplicitDenied,
        ),
        (
            req(
                "reports",
                K::Human,
                H1,
                perm("view", "internal"),
                "203.0.113.1",
                1,
                E,
                t,
            ),
            D::Allow,
        ),
        (
            req(
                "orders",
                K::Human,
                H2,
                perm("admin", "internal"),
                "10.1.1.1",
                2,
                E,
                t,
            ),
            D::Allow,
        ),
        (
            req(
                "orders",
                K::Human,
                H2,
                perm("admin", "internal"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::PermissionDenied,
        ),
        (
            req(
                "orders",
                K::Human,
                H2,
                perm("write", "internal"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::PermissionDenied,
        ),
        (
            req(
                "orders",
                K::Human,
                H2,
                perm("write", "internal"),
                "192.0.2.10",
                2,
                E,
                jan,
            ),
            D::Allow,
        ),
        (
            req(
                "orders",
                K::Human,
                H3,
                perm("read", "public"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::Guest,
        ),
        (
            req(
                "orders",
                K::Human,
                H4,
                perm("admin", "internal"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::NetworkGuest,
        ),
        (
            req(
                "orders",
                K::Service,
                S1,
                perm("read", "internal"),
                "203.0.113.1",
                0,
                E,
                t,
            ),
            D::Allow,
        ),
        // v1 parity: a ceiling's AAL is the maximum over its templates
        (
            req(
                "orders",
                K::Service,
                S1,
                perm("read", "internal"),
                "10.1.1.1",
                0,
                E,
                t,
            ),
            D::AssuranceDenied,
        ),
        // kind isolation
        (
            req(
                "orders",
                K::Human,
                S1,
                perm("read", "internal"),
                "203.0.113.1",
                0,
                E,
                t,
            ),
            D::Guest,
        ),
        (
            req(
                "orders",
                K::Workload,
                S1,
                perm("read", "internal"),
                "203.0.113.1",
                0,
                E,
                t,
            ),
            D::Guest,
        ),
        (
            req(
                "orders",
                K::Workload,
                W1,
                perm("read", "internal"),
                "203.0.113.1",
                0,
                E,
                t,
            ),
            D::Allow,
        ),
        (
            req(
                "orders",
                K::Workload,
                W1,
                perm("read", "internal"),
                "203.0.113.1",
                0,
                E,
                later,
            ),
            D::Guest,
        ),
        (
            req(
                "billing",
                K::Human,
                H1,
                perm("read", "public"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::UnknownService,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("read", "public"),
                "192.0.2.10",
                2,
                G::Observe,
                t,
            ),
            D::GuardUnavailable,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("read", "public"),
                "192.0.2.10",
                2,
                G::Deny,
                t,
            ),
            D::GuardDenied,
        ),
        (
            req(
                "reports",
                K::Human,
                H1,
                perm("view", "public"),
                "203.0.113.1",
                1,
                G::Observe,
                t,
            ),
            D::Allow,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("delete", "public"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::PermissionDenied,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("read", "secret"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::ClassDenied,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                res("db:payroll", "select"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::Allow,
        ),
        // G_ENG reader is not cleared for confidential/finance
        (
            req(
                "orders",
                K::Human,
                H2,
                res("db:payroll", "select"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::ClassDenied,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                res("db:orders", "select"),
                "192.0.2.10",
                1,
                E,
                t,
            ),
            D::AssuranceDenied,
        ),
        (
            req(
                "reports",
                K::Human,
                H1,
                res("db:orders", "select"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::UnknownService,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                res("db:none", "select"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::UnknownResource,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                res("db:orders", "drop"),
                "192.0.2.10",
                2,
                E,
                t,
            ),
            D::UnknownAction,
        ),
        // AAL3 break-glass is never downgraded to the AAL Hopae can issue
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("admin", "internal"),
                "10.1.1.1",
                2,
                E,
                t,
            ),
            D::AssuranceDenied,
        ),
        (
            req(
                "orders",
                K::Human,
                H1,
                perm("admin", "internal"),
                "10.1.1.1",
                3,
                E,
                t,
            ),
            D::Allow,
        ),
    ];
    let mut seen = BTreeSet::new();
    for (i, (r, want)) in cases.iter().enumerate() {
        assert_eq!(
            f.compiled.evaluate(&f.membership, r),
            *want,
            "case {i}: {r:?}"
        );
        seen.insert(*want);
    }
    for d in D::ALL {
        assert!(seen.contains(&d), "{d:?} unreachable");
    }
    assert!(
        f.compiled
            .warnings
            .iter()
            .any(|w| w.code == "pumgye.warning.unsatisfiable_assurance"
                && w.path == "templates.breakglass.minimum_aal")
    );
    assert_eq!(
        f.compiled.next_boundary,
        Some(Timestamp::parse("2027-01-01T00:00:00Z").unwrap().0)
    );
}

#[test]
fn groups_come_only_from_the_projection_index() {
    let f = fixture();
    let t = now();
    let r = req(
        "orders",
        K::Human,
        H3,
        perm("read", "public"),
        "192.0.2.10",
        2,
        E,
        t,
    );
    assert_eq!(f.compiled.evaluate(&f.membership, &r), D::Guest);
    let eng: BTreeSet<String> =
        [GE.to_owned(), "grp1:22222222222222222222222222".to_owned()].into();
    let granted = MembershipIndex::build(&f.compiled, [(H3, &eng)]);
    assert_eq!(f.compiled.evaluate(&granted, &r), D::Allow);
    // A non-Human principal never inherits group grants, even if listed.
    let svc = MembershipIndex::build(&f.compiled, [(S1, &eng)]);
    let r = req(
        "orders",
        K::Service,
        S1,
        perm("list", "public"),
        "203.0.113.1",
        0,
        E,
        t,
    );
    assert_eq!(f.compiled.evaluate(&svc, &r), D::Allow); // its own direct binding
    let r = req(
        "reports",
        K::Service,
        S1,
        perm("view", "public"),
        "203.0.113.1",
        0,
        E,
        t,
    );
    assert_eq!(f.compiled.evaluate(&svc, &r), D::Guest);
    assert_eq!(f.compiled.group_vocabulary(), [GE, GO]);
}

#[test]
fn lifecycle_orphans_and_disabled_subjects() {
    let p = policy();
    let mut lifecycle = Lifecycle::default();
    lifecycle.deleted.insert(S1.to_owned());
    lifecycle.disabled.insert(H1.to_owned());
    let c = p
        .compile_with(&CompileOptions {
            lifecycle: Some(&lifecycle),
            max_issued_aal: 2,
            now: now(),
        })
        .unwrap();
    assert_eq!(c.orphaned, ["bnd_svc_reader"]);
    assert_eq!(
        c.subject_disabled,
        ["bnd_alice_writer", "bnd_alice_breakglass"]
    );
    let m = membership(&c);
    let r = req(
        "orders",
        K::Service,
        S1,
        perm("read", "internal"),
        "203.0.113.1",
        0,
        E,
        now(),
    );
    assert_eq!(c.evaluate(&m, &r), D::Guest);
}

#[test]
fn valid_and_adversarial_fixtures() {
    assert!(policy().compile().is_ok());
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/v2/adversarial");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let fixture: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let parsed = serde_json::from_value::<PolicyV2>(fixture["policy"].clone());
        if fixture["expect"]["schema"] == true {
            assert!(parsed.is_err(), "{path:?} must be refused by the schema");
        } else {
            let v = parsed
                .unwrap()
                .compile_located(&CompileOptions::default())
                .err()
                .unwrap_or_else(|| panic!("{path:?} compiled"));
            assert_eq!(
                json!({"path": v.path, "code": v.code}),
                fixture["expect"],
                "{path:?}"
            );
            assert!(pumgye_core::explain::message_keys().contains(&v.code.to_owned()));
        }
        n += 1;
    }
    assert!(n >= 20, "{n}");
}

#[test]
fn explain_v2_matches_evaluation_and_reports_provenance() {
    let f = fixture();
    let snapshot = SnapshotV2 {
        policy: &f.policy,
        compiled: &f.compiled,
        membership: &f.membership,
        revision: 9,
        serving: true,
        membership_fresh: true,
        now: now(),
    };
    let subjects = [
        (K::Human, H1),
        (K::Human, H2),
        (K::Human, H3),
        (K::Human, H4),
        (K::Service, S1),
        (K::Workload, W1),
        (K::Workload, S1),
    ];
    let ips = [
        "192.0.2.10",
        "192.0.2.7",
        "10.1.1.1",
        "203.0.113.1",
        "2001:db8::1",
    ];
    let guards = [
        ("enforced_allow", E),
        ("deny", G::Deny),
        ("observe", G::Observe),
    ];
    let targets: Vec<(Value, TargetV2<'_>)> = vec![
        (
            json!({"permission":"write","information_class":"internal"}),
            perm("write", "internal"),
        ),
        (
            json!({"permission":"admin","information_class":"restricted"}),
            perm("admin", "restricted"),
        ),
        (
            json!({"permission":"view","information_class":"public"}),
            perm("view", "public"),
        ),
        (
            json!({"permission":"read","information_class":"finance"}),
            perm("read", "finance"),
        ),
        (
            json!({"permission":"nope","information_class":"public"}),
            perm("nope", "public"),
        ),
        (
            json!({"resource":"db:payroll","action":"select"}),
            res("db:payroll", "select"),
        ),
        (
            json!({"resource":"db:orders","action":"update"}),
            res("db:orders", "update"),
        ),
        (
            json!({"resource":"db:orders","action":"drop"}),
            res("db:orders", "drop"),
        ),
        (
            json!({"resource":"db:x","action":"select"}),
            res("db:x", "select"),
        ),
    ];
    let mut reasons = BTreeSet::new();
    let mut count = 0;
    for service in ["orders", "reports", "billing"] {
        for (kind, id) in subjects {
            for ip in ips {
                for (gname, guard) in guards {
                    for aal in 0..=3u8 {
                        if kind != K::Human && aal != 0 {
                            continue;
                        }
                        for (tjson, target) in &targets {
                            let mut case = json!({"subject":{"kind":kind,"id":id},"service":service,"ip":ip,"aal":aal,"guard":gname});
                            for (k, v) in tjson.as_object().unwrap() {
                                case[k] = v.clone();
                            }
                            let case: CaseV2 = serde_json::from_value(case).unwrap();
                            let e = explain(snapshot, &case, true).unwrap();
                            let want = f.compiled.evaluate(
                                &f.membership,
                                &req(service, kind, id, *target, ip, aal, guard, now()),
                            );
                            assert_eq!(e.decision, Some(want));
                            assert_eq!(e.value["outcome"]["decision"], want.name());
                            let trace = e.value["trace"].as_array().unwrap();
                            let decided = trace
                                .iter()
                                .rposition(|s| s["result"] != "not_evaluated")
                                .unwrap();
                            assert_eq!(
                                trace[decided]["stage"],
                                e.value["outcome"]["deciding_stage"]
                            );
                            for (i, s) in trace.iter().enumerate() {
                                let code = s["code"].as_str().unwrap();
                                assert!(
                                    pumgye_core::explain::DETAIL_CODES.contains(&code),
                                    "{code}"
                                );
                                if i < decided {
                                    assert_eq!(s["result"], "pass", "{}", e.value);
                                }
                            }
                            reasons.insert(
                                e.value["outcome"]["reason_code"]
                                    .as_str()
                                    .unwrap()
                                    .to_owned(),
                            );
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(count > 4000, "{count}");
    assert!(reasons.contains("pumgye.explicit_denied"), "{reasons:?}");
    // Provenance of a deny and of contributing allows.
    let case: CaseV2 = serde_json::from_value(json!({"subject":{"kind":"human","id":H2},"service":"reports","permission":"view","information_class":"public","ip":"203.0.113.1","aal":1,"guard":"enforced_allow"})).unwrap();
    let e = explain(snapshot, &case, true).unwrap();
    let deny = e.value["trace"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"] == "explicit_deny")
        .unwrap()
        .clone();
    assert_eq!(deny["detail"]["binding"]["id"], "bnd_incident_deny");
    assert_eq!(
        deny["detail"]["binding"]["metadata"]["reason"],
        "incident INC-77"
    );
    let case: CaseV2 = serde_json::from_value(json!({"subject":{"kind":"human","id":H1},"service":"orders","resource":"db:payroll","action":"select","ip":"192.0.2.10","aal":2,"guard":"enforced_allow"})).unwrap();
    let e = explain(snapshot, &case, true).unwrap();
    assert_eq!(
        e.value["contributing_bindings"],
        json!(["bnd_alice_writer"])
    );
    let principal = e.value["trace"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"] == "principal")
        .unwrap()
        .clone();
    assert_eq!(principal["detail"]["groups"], json!([GE]));
    // Hypothetical groups and simulated time.
    let case: CaseV2 = serde_json::from_value(json!({"subject":{"kind":"human","id":H3},"service":"orders","permission":"admin","information_class":"internal","ip":"10.9.9.9","aal":2,"guard":"enforced_allow","hypothetical_groups":[GO]})).unwrap();
    assert_eq!(
        explain(snapshot, &case, false).unwrap().decision,
        Some(D::Allow)
    );
    let case: CaseV2 = serde_json::from_value(json!({"subject":{"kind":"human","id":H2},"service":"orders","permission":"write","information_class":"internal","ip":"192.0.2.10","aal":2,"guard":"enforced_allow","at":"2026-01-20T00:00:00Z"})).unwrap();
    assert_eq!(
        explain(snapshot, &case, false).unwrap().decision,
        Some(D::Allow)
    );
    // Membership fence.
    let stale = SnapshotV2 {
        membership_fresh: false,
        ..snapshot
    };
    let case: CaseV2 = serde_json::from_value(json!({"subject":{"kind":"human","id":H1},"service":"orders","permission":"read","information_class":"public","ip":"192.0.2.10","aal":2,"guard":"enforced_allow"})).unwrap();
    let e = explain(stale, &case, true).unwrap();
    assert_eq!(e.decision, None);
    assert_eq!(
        e.value["outcome"]["detail_code"],
        "pumgye.detail.membership_unavailable"
    );
}

// ---------------------------------------------------------------------------
// Deterministic property tests
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[(self.next() % v.len() as u64) as usize]
    }
    fn chance(&mut self, n: u64) -> bool {
        self.next().is_multiple_of(n)
    }
}
const HUMANS: [&str; 4] = [H1, H2, H3, H4];
fn random_policy(rng: &mut Rng) -> Value {
    let mut doc = document();
    let templates = ["reader", "writer", "admin"];
    let zones = ["anywhere", "corp", "office", "vpn-admin"];
    let mut bindings = vec![];
    for i in 0..(3 + rng.next() % 6) {
        let subject = match rng.next() % 4 {
            0 => json!({"group": *rng.pick(&[GE, GO])}),
            1 => json!({"kind":"service","ref":S1}),
            _ => json!({"kind":"human","ref":*rng.pick(&HUMANS)}),
        };
        let mut b = json!({"id": format!("bnd_r{i}"), "effect":"allow", "subjects":[subject], "role": *rng.pick(&templates),
            "scope":{"services": if rng.chance(2) { json!("all") } else { json!([*rng.pick(&["orders","reports"])]) }}});
        if rng.chance(3) {
            b["conditions"]["zones"] = json!([*rng.pick(&zones)]);
        }
        if rng.chance(4) {
            b["conditions"]["expires_at"] =
                json!(*rng.pick(&["2026-06-01T00:00:00Z", "2027-06-01T00:00:00Z"]));
        }
        bindings.push(b);
    }
    doc["bindings"] = json!(bindings);
    doc
}
fn random_deny(rng: &mut Rng) -> Value {
    let subject = if rng.chance(2) {
        json!({"group": *rng.pick(&[GE, GO])})
    } else {
        json!({"kind":"human","ref":*rng.pick(&HUMANS)})
    };
    let mut d = json!({"id":"bnd_deny_prop","effect":"deny","subjects":[subject],
        "permissions": if rng.chance(2) { json!("all") } else { json!([*rng.pick(&["read","write","admin","view"])]) },
        "scope":{"services":"all"}});
    if rng.chance(3) {
        d["conditions"]["zones"] = json!([*rng.pick(&["corp", "office"])]);
    }
    d
}
fn allowed_set(doc: &Value, at: u64) -> BTreeSet<String> {
    let p: PolicyV2 = serde_json::from_value(doc.clone()).unwrap();
    let c = p.compile().unwrap();
    let m = membership(&c);
    let mut out = BTreeSet::new();
    for service in ["orders", "reports"] {
        for (kind, id) in [
            (K::Human, H1),
            (K::Human, H2),
            (K::Human, H3),
            (K::Human, H4),
            (K::Service, S1),
            (K::Workload, S1),
        ] {
            for ip in ["192.0.2.10", "192.0.2.7", "10.1.1.1", "203.0.113.1"] {
                for p in ["read", "list", "write", "admin", "view", "export"] {
                    for l in ["public", "internal", "confidential", "finance"] {
                        for aal in [0u8, 2, 3] {
                            let r = req(service, kind, id, perm(p, l), ip, aal, E, at);
                            if c.evaluate(&m, &r) == D::Allow {
                                out.insert(format!("{service}|{kind:?}|{id}|{ip}|{p}|{l}|{aal}"));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

#[test]
fn property_deny_is_monotonic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..40 {
        let base = random_policy(&mut rng);
        let mut denied = base.clone();
        denied["bindings"]
            .as_array_mut()
            .unwrap()
            .push(random_deny(&mut rng));
        let (a, b) = (allowed_set(&base, now()), allowed_set(&denied, now()));
        assert!(
            b.is_subset(&a),
            "a deny added rights: {:?}",
            b.difference(&a).collect::<Vec<_>>()
        );
    }
}

#[test]
fn property_ceilings_only_reduce() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..40 {
        let base = random_policy(&mut rng);
        let mut open = base.clone();
        // Widest possible ceiling everywhere: every template from every zone.
        open["templates"]["unbounded"] = json!({"permissions":["read","list","write","admin","view","export"],
            "clearance_ceiling":{"level":"restricted","compartments":["finance","hr"]}});
        for s in ["orders", "reports"] {
            open["services"][s]["network_ceiling"] = json!([{"zone":"anywhere","max":"unbounded"}]);
        }
        let (bounded, unbounded) = (allowed_set(&base, now()), allowed_set(&open, now()));
        assert!(bounded.is_subset(&unbounded));
    }
}

#[test]
fn property_no_rights_without_binding_and_kind_isolation() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..40 {
        let doc = random_policy(&mut rng);
        let bound: BTreeSet<String> = doc["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|b| b["subjects"].as_array().unwrap().clone())
            .map(|s| s.to_string())
            .collect();
        for entry in allowed_set(&doc, now()) {
            let parts: Vec<&str> = entry.split('|').collect();
            let (kind, id) = (parts[1], parts[2]);
            let direct =
                bound.contains(&json!({"kind": kind.to_lowercase(), "ref": id}).to_string());
            let via_group = kind == "Human"
                && [(H1, vec![GE]), (H2, vec![GE, GO]), (H4, vec![GO])]
                    .iter()
                    .any(|(h, gs)| {
                        *h == id
                            && gs
                                .iter()
                                .any(|g| bound.contains(&json!({"group": g}).to_string()))
                    });
            assert!(direct || via_group, "{entry} allowed without a binding");
            assert_ne!(kind, "Workload", "kind isolation: {entry}");
        }
    }
}

#[test]
fn property_expired_bindings_grant_nothing() {
    let mut rng = Rng(0x0bad_cafe_1234_5678);
    let far = Timestamp::parse("2028-01-01T00:00:00Z").unwrap().0;
    for _ in 0..30 {
        let doc = random_policy(&mut rng);
        let mut without = doc.clone();
        without["bindings"]
            .as_array_mut()
            .unwrap()
            .retain(|b| b["conditions"]["expires_at"].is_null());
        // After every expiry boundary, the policy is equivalent to one without expiring bindings.
        assert_eq!(allowed_set(&doc, far), allowed_set(&without, far));
        // Before expiry, expiring bindings may only add rights.
        assert!(allowed_set(&without, now()).is_subset(&allowed_set(&doc, now())));
    }
}

// ---------------------------------------------------------------------------
// Converter and v1/v2 shadow parity
// ---------------------------------------------------------------------------

fn v1_fixture() -> Policy {
    serde_json::from_value(json!({
     "version":1,"information_classes":["public","internal","restricted"],
     "services":{
      "orders":{"permissions":["read","write","admin"],"require_guard":true,
       "roles":{"reader":{"permissions":["read"],"information_classes":["public"]},
                "writer":{"permissions":["write"],"information_classes":["internal"],"inherits":["reader"],"minimum_aal":2},
                "auditor":{"permissions":["read"],"information_classes":["public","internal","restricted"]},
                "empty":{"permissions":[],"information_classes":[]}},
       "users":{"s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":["reader"],"s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":["writer"],"s_cccccccccccccccccccccccccccccccccccccccccccccccc":["guest"],"s_dddddddddddddddddddddddddddddddddddddddddddddddd":["auditor"],"s_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":["reader","auditor"],"unresolvable":["reader"]},
       "workload_users":{S1:["reader"]},
       "human_users":{H1:["writer"]},
       "networks":[{"cidr":"192.0.2.0/24","roles":["writer"]},{"cidr":"192.0.2.7/32","roles":["guest"]},
                   {"cidr":"198.51.100.0/24","roles":["reader"]},{"cidr":"10.0.0.0/8","roles":["writer","auditor"]}]},
      "kube":{"authorization_context":"kubernetes_api","require_guard":false,"permissions":["get"],
       "roles":{"viewer":{"permissions":["get"],"information_classes":["internal"]}},"users":{"k8sapi:team:alice":["viewer"]},"networks":[]}},
     "resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read","update":"write"},"minimum_aal":1}}}))
    .unwrap()
}
/// The owner lookup the converter is given (prefix form for the fixture).
fn classify(s: &str) -> Option<K> {
    classify_by_prefix(s)
}
fn kind_of(s: &str) -> K {
    if s.starts_with("human1:") {
        K::Human
    } else {
        K::Service
    }
}

#[test]
fn converter_is_deterministic_and_reports_what_it_did_not_migrate() {
    let v1 = v1_fixture();
    let mapping = BTreeMap::new();
    let options = ConvertOptions {
        classify: &classify,
        workload_mapping: &mapping,
    };
    let a = convert(&v1, &options).unwrap();
    let b = convert(&v1, &options).unwrap();
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
    let r = &a.report;
    assert_eq!(r.retained_v1, ["kube"]);
    assert_eq!(r.unmigrated.len(), 1);
    assert_eq!(r.unmigrated[0].subject, "unresolvable");
    // Every role closure here is downward closed: ordered levels, no compartments.
    assert!(
        !r.review
            .iter()
            .any(|i| i.code == "pumgye.migration.class_compartments")
    );
    assert_eq!(
        a.document.catalog.levels,
        ["public", "internal", "restricted"]
    );
    assert!(
        r.review
            .iter()
            .any(|i| i.code == "pumgye.migration.legacy_workload")
    );
    assert!(r.review.iter().any(|i| {
        i.code == "pumgye.migration.class_union"
            && i.path
                .ends_with("s_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    }));
    assert!(
        r.review
            .iter()
            .any(|i| i.code == "pumgye.migration.empty_role")
    );
    assert_eq!(r.zone_proposals.len(), 4);
    assert!(
        a.document
            .bindings
            .iter()
            .all(|b| b.metadata.source.as_deref() == Some("migrated:v1"))
    );
    for code in r
        .review
        .iter()
        .map(|i| i.code)
        .chain(r.unmigrated.iter().map(|u| u.reason))
    {
        assert!(
            pumgye_core::explain::message_keys().contains(&code.to_owned()),
            "{code}"
        );
    }
    // Downward-closed vocabularies convert to ordered levels.
    let simple: Policy =
        serde_json::from_str::<Value>(include_str!("../../../examples/policy.json"))
            .map(|v| serde_json::from_value(v["policy"].clone()).unwrap())
            .unwrap();
    let c = convert(
        &simple,
        &ConvertOptions {
            classify: &classify_by_prefix,
            workload_mapping: &mapping,
        },
    )
    .unwrap();
    assert_eq!(c.report.unmigrated[0].subject, "fixture");
    assert_eq!(c.document.catalog.levels, ["public"]);
    assert!(c.document.catalog.compartments.is_empty());
}

/// Shadow parity over the version 1 corpus: allow/deny agree everywhere except
/// for subjects the converter reported as not migrated or cross-role class
/// unions it reported for review (ADR 0021 "zero unexplained mismatches").
#[test]
fn v1_v2_shadow_parity_on_the_corpus() {
    let v1 = v1_fixture();
    let c1 = v1.compile().unwrap();
    let mapping = BTreeMap::new();
    let conv = convert(
        &v1,
        &ConvertOptions {
            classify: &classify,
            workload_mapping: &mapping,
        },
    )
    .unwrap();
    let c2 = conv.document.compile().unwrap();
    let m = MembershipIndex::default();
    let explained: BTreeSet<String> = conv
        .report
        .unmigrated
        .iter()
        .map(|u| u.subject.clone())
        .chain(
            conv.report
                .review
                .iter()
                .filter(|i| i.code == "pumgye.migration.class_union")
                .map(|i| i.path.rsplit('.').next().unwrap().to_owned()),
        )
        .collect();
    let (mut total, mut outcome_mismatch, mut explained_mismatch, mut reason_drift) = (0, 0, 0, 0);
    let guards = [E, G::Deny, G::Observe, G::Unavailable];
    for subject in [
        "s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "s_cccccccccccccccccccccccccccccccccccccccccccccccc",
        "s_dddddddddddddddddddddddddddddddddddddddddddddddd",
        "s_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "unresolvable",
        "s_ffffffffffffffffffffffffffffffffffffffffffffffff",
        H1,
    ] {
        for ip in [
            "192.0.2.1",
            "192.0.2.7",
            "198.51.100.4",
            "10.1.2.3",
            "203.0.113.1",
            "2001:db8::1",
        ] {
            for guard in guards {
                for aal in 0..=3u8 {
                    for p in ["read", "write", "admin", "delete"] {
                        for class in ["public", "internal", "restricted", "secret"] {
                            let ipa = ip.parse().unwrap();
                            let d1 = if subject == H1 {
                                c1.evaluate_scoped_human_resource(
                                    "orders",
                                    "db:orders",
                                    if p == "write" { "update" } else { "select" },
                                    subject,
                                    ipa,
                                    aal,
                                    guard,
                                )
                            } else {
                                pumgye_core::ResourceDecision::Decided(
                                    c1.evaluate("orders", subject, ipa, p, class, aal, guard),
                                )
                            };
                            let target = if subject == H1 {
                                res("db:orders", if p == "write" { "update" } else { "select" })
                            } else {
                                perm(p, class)
                            };
                            if subject == H1 && !matches!(aal, 1 | 2) {
                                continue; // the v1 Human entrypoint refuses before evaluation
                            }
                            let d2 = c2.evaluate(
                                &m,
                                &req(
                                    "orders",
                                    kind_of(subject),
                                    subject,
                                    target,
                                    ip,
                                    aal,
                                    guard,
                                    now(),
                                ),
                            );
                            total += 1;
                            let allow1 = d1
                                == pumgye_core::ResourceDecision::Decided(
                                    pumgye_core::Decision::Allow,
                                );
                            let allow2 = d2 == D::Allow;
                            if allow1 != allow2 {
                                if explained.contains(subject) {
                                    explained_mismatch += 1;
                                } else {
                                    outcome_mismatch += 1;
                                    eprintln!(
                                        "unexplained: {subject} {ip} {guard:?} {aal} {p} {class}: v1 {d1:?} v2 {d2:?}"
                                    );
                                }
                            } else if d1 != d2.to_v1() {
                                reason_drift += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(total > 5000, "{total}");
    assert_eq!(outcome_mismatch, 0, "unexplained allow/deny mismatches");
    assert!(
        explained_mismatch > 0,
        "the fixture exercises reported differences"
    );
    eprintln!(
        "parity: {total} decisions, {explained_mismatch} explained, {reason_drift} reason-only drifts"
    );
}

#[test]
fn candidate_diff_reports_rights_changes() {
    let base = policy();
    let mut doc = document();
    doc["bindings"]
        .as_array_mut()
        .unwrap()
        .retain(|b| b["id"] != "bnd_svc_reader");
    doc["bindings"][0]["role"] = json!("admin");
    doc["bindings"].as_array_mut().unwrap().push(json!({"id":"bnd_new_deny","effect":"deny","subjects":[{"kind":"human","ref":H3}],"permissions":["write"],"scope":{"services":["orders"]}}));
    let cand: PolicyV2 = serde_json::from_value(doc).unwrap();
    let (bc, cc) = (base.compile().unwrap(), cand.compile().unwrap());
    let page = diff(
        SideV2 {
            policy: &base,
            compiled: &bc,
        },
        SideV2 {
            policy: &cand,
            compiled: &cc,
        },
        0,
        100,
    );
    let by: BTreeMap<String, &pumgye_core::v2::diff::RightsChange> = page
        .changes
        .iter()
        .map(|c| (format!("{}|{}", c.subject, c.service), c))
        .collect();
    assert_eq!(page.total, 3, "{:#?}", page.changes);
    let alice = by[&format!("human:{H1}|orders")];
    // admin was already reachable through break-glass: same permissions, new conditions.
    assert!(alice.added_permissions.is_empty() && alice.conditions_changed);
    assert_eq!(
        by[&format!("service:{S1}|orders")].removed_permissions,
        ["list", "read"]
    );
    assert_eq!(by[&format!("human:{H3}|orders")].added_denies, ["write"]);
    let first = diff(
        SideV2 {
            policy: &base,
            compiled: &bc,
        },
        SideV2 {
            policy: &cand,
            compiled: &cc,
        },
        0,
        2,
    );
    assert_eq!(first.next_cursor, Some(2));
}

/// A role holding only a higher class (not downward closed) is carried exactly as
/// a compartment, so the catalog fixture keeps v1 decisions.
#[test]
fn compartment_conversion_preserves_unordered_v1_classes() {
    let doc: Value =
        serde_json::from_str(include_str!("../../../examples/resource-catalog.json")).unwrap();
    let mut v1: Policy = serde_json::from_value(doc["policy"].clone()).unwrap();
    let svc = "s_9999999999999999999999999999999999999999999999ff";
    let svc = &svc[..50];
    let users = &mut v1.services.get_mut("orders").unwrap().users;
    let roles = users.remove("fixture").unwrap();
    users.insert(svc.to_owned(), roles);
    let mapping = BTreeMap::new();
    let conv = convert(
        &v1,
        &ConvertOptions {
            classify: &classify_by_prefix,
            workload_mapping: &mapping,
        },
    )
    .unwrap();
    assert!(
        conv.report
            .review
            .iter()
            .any(|i| i.code == "pumgye.migration.class_compartments")
    );
    assert_eq!(conv.document.catalog.levels, ["v1.base"]);
    let (c1, c2) = (v1.compile().unwrap(), conv.document.compile().unwrap());
    let m = MembershipIndex::default();
    for ip in ["192.0.2.9", "203.0.113.1"] {
        for aal in 0..=3u8 {
            for class in ["public", "internal", "v1.secret"] {
                let d1 = c1.evaluate("orders", svc, ip.parse().unwrap(), "read", class, aal, E);
                let d2 = c2.evaluate(
                    &m,
                    &req(
                        "orders",
                        K::Service,
                        svc,
                        perm("read", class),
                        ip,
                        aal,
                        E,
                        now(),
                    ),
                );
                assert_eq!(
                    d1 == pumgye_core::Decision::Allow,
                    d2 == D::Allow,
                    "{ip} {aal} {class}"
                );
            }
            let r1 = c1.evaluate_scoped_resource(
                "orders",
                "db:orders",
                "select",
                svc,
                ip.parse().unwrap(),
                aal,
                E,
            );
            let r2 = c2.evaluate(
                &m,
                &req(
                    "orders",
                    K::Service,
                    svc,
                    res("db:orders", "select"),
                    ip,
                    aal,
                    E,
                    now(),
                ),
            );
            assert_eq!(
                r1 == pumgye_core::ResourceDecision::Decided(pumgye_core::Decision::Allow),
                r2 == D::Allow
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Kubernetes workload principals (Hopae ServiceAccount identity) and AAL3
// ---------------------------------------------------------------------------

const WK: &str = "wk2:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const WK_WIRE: &str = "s_999999999999999999999999999999999999999999999999";
const SPIFFE: &str = "spiffe://cluster.example.test/ns/blue/sa/worker";

#[test]
fn spiffe_ids_are_canonical_serviceaccount_names() {
    use pumgye_core::v2::spiffe_workload as ok;
    assert!(ok(SPIFFE));
    assert!(ok("spiffe://td_1.example/ns/a-b/sa/x.y"));
    for bad in [
        "spiffe://Cluster/ns/blue/sa/worker",
        "spiffe://td/ns/blue/sa/worker/extra",
        "spiffe://td/ns/Blue/sa/worker",
        "spiffe://td/ns//sa/worker",
        "spiffe://td/sa/worker/ns/blue",
        "spiffe:/td/ns/blue/sa/worker",
        "spiffe://td/ns/-blue/sa/worker",
    ] {
        assert!(!ok(bad), "{bad}");
    }
}

fn workload_doc() -> Value {
    let mut doc = document();
    doc["bindings"] = json!([
        {"id":"bnd_wk2","effect":"allow","subjects":[{"kind":"workload","ref":WK}],"role":"reader","scope":{"services":["orders"]}},
        {"id":"bnd_spiffe","effect":"allow","subjects":[{"kind":"workload","ref":SPIFFE}],"role":"writer","scope":{"services":["orders"]},
         "conditions":{"minimum_aal":0}},
    ]);
    // Machine principals present AAL0: drop template AAL minimums for this fixture.
    for t in ["reader", "writer", "admin"] {
        doc["templates"][t]["minimum_aal"] = json!(0);
    }
    doc
}

#[test]
fn workload_wire_subjects_inherit_principal_and_spiffe_bindings() {
    let p: PolicyV2 = serde_json::from_value(workload_doc()).unwrap();
    let c = p.compile().unwrap();
    let r = |subject, permission| {
        req(
            "orders",
            K::Workload,
            subject,
            perm(permission, "internal"),
            "192.0.2.10",
            0,
            E,
            now(),
        )
    };
    let none = MembershipIndex::default();
    assert_eq!(
        c.evaluate(&none, &r(WK_WIRE, "read")),
        D::Guest,
        "no alias known yet"
    );
    let m = MembershipIndex::default().with_workloads(&c, [(WK_WIRE, WK, Some(SPIFFE))]);
    assert_eq!(c.evaluate(&m, &r(WK_WIRE, "read")), D::Allow);
    assert_eq!(
        c.evaluate(&m, &r(WK_WIRE, "write")),
        D::Allow,
        "SPIFFE-name binding applies"
    );
    // Hangang SVID callers are named by SPIFFE ID: name bindings apply, wk2 pins do not.
    assert_eq!(c.evaluate(&m, &r(SPIFFE, "write")), D::Allow);
    assert_eq!(
        c.evaluate(
            &m,
            &req(
                "orders",
                K::Workload,
                SPIFFE,
                perm("read", "internal"),
                "192.0.2.10",
                0,
                E,
                now()
            )
        ),
        D::Allow
    );
    // Aliases never apply to another kind.
    assert_eq!(
        c.evaluate(
            &m,
            &req(
                "orders",
                K::Service,
                WK_WIRE,
                perm("read", "internal"),
                "192.0.2.10",
                0,
                E,
                now()
            )
        ),
        D::Guest
    );
    // A retired principal's bindings are orphaned; the name binding survives re-creation.
    let mut lifecycle = Lifecycle::default();
    lifecycle.deleted.insert(WK.to_owned());
    let c2 = p
        .compile_with(&CompileOptions {
            lifecycle: Some(&lifecycle),
            max_issued_aal: 2,
            now: now(),
        })
        .unwrap();
    assert_eq!(c2.orphaned, ["bnd_wk2"]);
    let m2 = MembershipIndex::default().with_workloads(&c2, [(WK_WIRE, WK, Some(SPIFFE))]);
    assert_eq!(c2.evaluate(&m2, &r(WK_WIRE, "write")), D::Allow);
    // Explain names the aliases.
    let snapshot = SnapshotV2 {
        policy: &p,
        compiled: &c,
        membership: &m,
        revision: 1,
        serving: true,
        membership_fresh: true,
        now: now(),
    };
    let case: CaseV2 = serde_json::from_value(json!({"subject":{"kind":"workload","id":WK_WIRE},"service":"orders","permission":"read","information_class":"internal","ip":"192.0.2.10","guard":"enforced_allow"})).unwrap();
    let e = explain(snapshot, &case, true).unwrap();
    let principal = e.value["trace"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"] == "principal")
        .unwrap()
        .clone();
    assert_eq!(
        principal["detail"]["workload_alias"],
        json!({"principal": WK, "spiffe_id": SPIFFE, "bound": true})
    );
    let case: CaseV2 = serde_json::from_value(json!({"subject":{"kind":"workload","id":SPIFFE},"service":"orders","permission":"write","information_class":"internal","ip":"192.0.2.10","guard":"enforced_allow"})).unwrap();
    assert_eq!(
        explain(snapshot, &case, false).unwrap().decision,
        Some(D::Allow)
    );
}

#[test]
fn aal3_is_evaluated_numerically_and_explained() {
    let f = fixture();
    let snapshot = SnapshotV2 {
        policy: &f.policy,
        compiled: &f.compiled,
        membership: &f.membership,
        revision: 1,
        serving: true,
        membership_fresh: true,
        now: now(),
    };
    let case = |aal: u8| -> CaseV2 {
        serde_json::from_value(json!({"subject":{"kind":"human","id":H1},"service":"orders","permission":"admin","information_class":"internal","ip":"10.1.1.1","aal":aal,"guard":"enforced_allow"})).unwrap()
    };
    let e = explain(snapshot, &case(2), true).unwrap();
    assert_eq!(e.decision, Some(D::AssuranceDenied));
    assert_eq!(e.value["obligations"]["required_aal"], 3);
    let last = e.value["trace"]
        .as_array()
        .unwrap()
        .iter()
        .rfind(|s| s["result"] != "not_evaluated")
        .unwrap()
        .clone();
    assert_eq!(last["detail"], json!({"presented": 2, "required": 3}));
    let e = explain(snapshot, &case(3), true).unwrap();
    assert_eq!(e.decision, Some(D::Allow));
    let last = e.value["trace"]
        .as_array()
        .unwrap()
        .iter()
        .rfind(|s| s["stage"] == "assurance")
        .unwrap()
        .clone();
    assert_eq!(last["detail"], json!({"presented": 3, "required": 3}));
    // Machines cannot present AAL3 (or any human level).
    let bad: Result<CaseV2, _> = serde_json::from_value(
        json!({"subject":{"kind":"workload","id":W1},"service":"orders","permission":"read","information_class":"internal","ip":"10.1.1.1","aal":3,"guard":"enforced_allow"}),
    );
    assert!(bad.unwrap().validate().is_err());
}
