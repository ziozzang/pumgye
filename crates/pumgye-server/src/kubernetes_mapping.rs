//! Explicit administrator-owned RBAC-to-application mapping. Output is a candidate, not a grant receipt.
use crate::kubernetes::{Inventory, Object};
use anyhow::{Result, ensure};
use pumgye_core::Policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    version: u32,
    cluster: String,
    template: Policy,
    grants: Vec<Grant>,
    #[serde(skip)]
    digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    service: String,
    application_role: String,
    #[serde(default)]
    native_subject: String,
    #[serde(default)]
    workload: Option<Workload>,
    source_subject: Subject,
    binding: Pin,
    role: Pin,
    required_rules: Vec<Requirement>,
}
/// Administrator-pinned workload coordinates; authentication is still owned by Hopae.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    issuer: String,
    namespace: String,
    service_account: String,
    service_account_uid: String,
    pod: String,
    pod_uid: String,
}
impl Workload {
    fn subject(&self, cluster: &str) -> Result<String> {
        let issuer = reqwest::Url::parse(&self.issuer)?;
        ensure!(
            issuer.scheme() == "https"
                && issuer.host_str().is_some()
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none()
                && self.issuer.len() <= 256,
            "invalid workload issuer"
        );
        let mut inner = Sha256::new();
        inner.update(b"hopae:kubernetes:pod-subject:v1\0");
        for value in [
            &self.namespace,
            &self.service_account,
            &self.service_account_uid,
            &self.pod,
            &self.pod_uid,
        ] {
            ensure!(
                identifier(value)
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)),
                "invalid workload coordinates"
            );
            inner.update((value.len() as u32).to_be_bytes());
            inner.update(value.as_bytes());
        }
        let workload = format!("w_{:x}", inner.finalize());
        let mut outer = Sha256::new();
        outer.update([2]);
        for value in [&self.issuer, cluster, &workload] {
            outer.update((value.len() as u64).to_be_bytes());
            outer.update(value.as_bytes());
        }
        let digest = outer.finalize();
        Ok(format!(
            "s_{}",
            digest[..24]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    kind: String,
    name: String,
    namespace: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    api_group: String,
    namespace: Option<String>,
    resource: String,
    verb: String,
    resource_name: Option<String>,
}
#[derive(Serialize)]
pub struct Candidate {
    pub version: u32,
    pub mode: &'static str,
    pub mapping_sha256: String,
    pub policy: Policy,
    pub mappings: Vec<Outcome>,
}
#[derive(Serialize)]
pub struct Outcome {
    service: String,
    native_subject: String,
    application_role: String,
    active: bool,
    reason: &'static str,
}
fn identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
}
fn pin_matches(pin: &Pin, o: &Object) -> bool {
    pin.kind == o.kind && pin.namespace == o.namespace && pin.name == o.name && pin.uid == o.uid
}
fn contains(v: &Value, field: &str, expected: &str) -> bool {
    v[field]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(expected)))
}
fn exact_rule(rule: &Value, requirement: &Requirement) -> bool {
    if rule.get("nonResourceURLs").is_some() {
        return false;
    }
    let names = rule.get("resourceNames").and_then(Value::as_array);
    let name_matches = match &requirement.resource_name {
        Some(name) => {
            names.is_none_or(|a| a.is_empty() || a.iter().any(|v| v.as_str() == Some(name)))
        }
        None => names.is_none_or(Vec::is_empty),
    };
    contains(rule, "apiGroups", &requirement.api_group)
        && contains(rule, "resources", &requirement.resource)
        && contains(rule, "verbs", &requirement.verb)
        && name_matches
}
impl Mapping {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 65536, "mapping capacity exceeded");
        let mut mapping: Self = serde_json::from_slice(bytes)?;
        mapping.digest = format!("{:x}", Sha256::digest(bytes));
        ensure!(
            mapping.version == 1 && identifier(&mapping.cluster) && mapping.grants.len() <= 256,
            "invalid mapping version or capacity"
        );
        mapping.template.compile()?;
        ensure!(
            mapping
                .template
                .services
                .values()
                .all(|s| s.users.is_empty()),
            "mapping template cannot contain independent user grants"
        );
        let mut unique = BTreeSet::new();
        for g in &mut mapping.grants {
            if let Some(workload) = &g.workload {
                ensure!(
                    g.native_subject.is_empty(),
                    "workload and native subject are mutually exclusive"
                );
                ensure!(
                    g.source_subject.kind == "ServiceAccount"
                        && g.source_subject.name == workload.service_account
                        && g.source_subject.namespace.as_deref()
                            == Some(workload.namespace.as_str()),
                    "workload must match the RBAC ServiceAccount subject"
                );
                g.native_subject = workload.subject(&mapping.cluster)?;
            }
            ensure!(
                identifier(&g.native_subject),
                "explicit native subject reference required"
            );
            let service = mapping
                .template
                .services
                .get(&g.service)
                .ok_or_else(|| anyhow::anyhow!("unknown target service"))?;
            ensure!(
                service.require_guard && service.roles.contains_key(&g.application_role),
                "mapping requires existing role and enforced network evidence"
            );
            ensure!(
                unique.insert((
                    &g.service,
                    &g.application_role,
                    &g.native_subject,
                    &g.binding.uid
                )),
                "duplicate mapping"
            );
            ensure!(
                ["User", "ServiceAccount"].contains(&g.source_subject.kind.as_str())
                    && identifier(&g.source_subject.name),
                "unsupported source subject"
            );
            ensure!(
                if g.source_subject.kind == "ServiceAccount" {
                    g.source_subject
                        .namespace
                        .as_deref()
                        .is_some_and(identifier)
                } else {
                    g.source_subject.namespace.is_none()
                },
                "invalid source subject namespace"
            );
            for (p, binding) in [(&g.binding, true), (&g.role, false)] {
                let kinds = if binding {
                    ["RoleBinding", "ClusterRoleBinding"]
                } else {
                    ["Role", "ClusterRole"]
                };
                ensure!(
                    kinds.contains(&p.kind.as_str()) && identifier(&p.name) && identifier(&p.uid),
                    "explicit source kind/name/UID required"
                );
                ensure!(
                    if p.kind.starts_with("Cluster") {
                        p.namespace.is_none()
                    } else {
                        p.namespace.as_deref().is_some_and(identifier)
                    },
                    "invalid source pin scope"
                );
            }
            ensure!(
                g.role.kind == "ClusterRole"
                    || (g.binding.kind == "RoleBinding" && g.binding.namespace == g.role.namespace),
                "cross-namespace or cluster binding to Role refused"
            );
            ensure!(
                !g.required_rules.is_empty() && g.required_rules.len() <= 16,
                "explicit rule requirements required"
            );
            for r in &g.required_rules {
                ensure!(
                    r.namespace.as_deref().is_none_or(identifier),
                    "invalid required resource namespace"
                );
                ensure!(
                    g.binding.kind != "RoleBinding" || r.namespace == g.binding.namespace,
                    "RoleBinding cannot supply cluster or foreign namespace access"
                );
                ensure!(
                    r.api_group.len() <= 128
                        && !r.api_group.chars().any(char::is_control)
                        && identifier(&r.resource)
                        && identifier(&r.verb)
                        && r.resource_name.as_deref().is_none_or(identifier),
                    "invalid source rule requirement"
                );
                ensure!(
                    !r.api_group.contains('*')
                        && !r.resource.contains('*')
                        && !r.verb.contains('*')
                        && r.resource_name.as_ref().is_none_or(|n| !n.contains('*')),
                    "wildcard mapping requirements refused"
                );
                ensure!(
                    !["bind", "escalate", "impersonate"].contains(&r.verb.as_str())
                        && r.resource != "serviceaccounts/token",
                    "privileged source capabilities require a separate adapter"
                );
            }
        }
        Ok(mapping)
    }
    pub fn candidate(&self, inventory: &Inventory) -> Result<Candidate> {
        ensure!(inventory.cluster == self.cluster, "source cluster mismatch");
        let mut policy = self.template.clone();
        let mut mappings = Vec::new();
        for g in &self.grants {
            let binding = inventory
                .objects
                .iter()
                .find(|o| pin_matches(&g.binding, o));
            let role = inventory.objects.iter().find(|o| pin_matches(&g.role, o));
            let reason = match (binding, role) {
                (None, _) => "binding_missing_or_recreated",
                (_, None) => "role_missing_or_recreated",
                (Some(binding), Some(role)) => {
                    let reference = binding.role_ref.as_ref().unwrap();
                    if reference["kind"] != g.role.kind || reference["name"] != g.role.name {
                        "role_reference_changed"
                    } else if role.aggregation_rule.is_some() {
                        "aggregated_role_requires_reconciled_authority"
                    } else if !binding
                        .subjects
                        .as_ref()
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|s| {
                            s["kind"] == g.source_subject.kind
                                && s["name"] == g.source_subject.name
                                && s.get("namespace").and_then(Value::as_str)
                                    == g.source_subject.namespace.as_deref()
                        })
                    {
                        "subject_not_bound"
                    } else if !g.required_rules.iter().all(|required| {
                        role.rules
                            .as_ref()
                            .unwrap()
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|r| exact_rule(r, required))
                    }) {
                        "required_native_rule_missing"
                    } else {
                        "matched_explicit_mapping"
                    }
                }
            };
            let active = reason == "matched_explicit_mapping";
            if active {
                let roles = policy
                    .services
                    .get_mut(&g.service)
                    .unwrap()
                    .users
                    .entry(g.native_subject.clone())
                    .or_default();
                if !roles.contains(&g.application_role) {
                    roles.push(g.application_role.clone());
                    roles.sort();
                }
            }
            mappings.push(Outcome {
                service: g.service.clone(),
                native_subject: g.native_subject.clone(),
                application_role: g.application_role.clone(),
                active,
                reason,
            });
        }
        // Recompile the complete resulting policy before returning anything publishable.
        policy.compile()?;
        Ok(Candidate {
            version: 1,
            mode: "candidate_only",
            mapping_sha256: self.digest.clone(),
            policy,
            mappings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kubernetes;
    fn source() -> Value {
        serde_json::json!({"apiVersion":"v1","kind":"List","items":[
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"namespace":"blue","name":"reader","uid":"r1","resourceVersion":"1"},"rules":[{"apiGroups":[""],"resources":["pods/log"],"verbs":["get"],"resourceNames":["worker"]}]},
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"namespace":"blue","name":"workers","uid":"b1","resourceVersion":"2"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},"subjects":[{"kind":"ServiceAccount","name":"worker","namespace":"blue"}]}
        ]})
    }
    fn configuration() -> Value {
        serde_json::json!({"version":1,"cluster":"example-cluster","template":{"version":1,"information_classes":["public"],"services":{"logs":{"permissions":["read"],"roles":{"reader":{"permissions":["read"],"information_classes":["public"],"minimum_aal":0}},"users":{},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}],"require_guard":true}}},"grants":[{"service":"logs","application_role":"reader","native_subject":"native-verified-worker","source_subject":{"kind":"ServiceAccount","name":"worker","namespace":"blue"},"binding":{"kind":"RoleBinding","namespace":"blue","name":"workers","uid":"b1"},"role":{"kind":"Role","namespace":"blue","name":"reader","uid":"r1"},"required_rules":[{"api_group":"","namespace":"blue","resource":"pods/log","verb":"get","resource_name":"worker"}]}]})
    }
    fn candidate(mapping: &Value, source: &Value) -> Candidate {
        Mapping::parse(&serde_json::to_vec(mapping).unwrap())
            .unwrap()
            .candidate(
                &kubernetes::inspect("example-cluster", &serde_json::to_vec(source).unwrap())
                    .unwrap(),
            )
            .unwrap()
    }
    #[test]
    fn workload_binding_is_domain_separated_uid_scoped_and_unambiguous() {
        let mut mapping = configuration();
        mapping["grants"][0]
            .as_object_mut()
            .unwrap()
            .remove("native_subject");
        mapping["grants"][0]["workload"] = serde_json::json!({
            "issuer":"https://issuer.example.test", "namespace":"blue",
            "service_account":"worker", "service_account_uid":"sa-1", "pod":"worker-pod", "pod_uid":"pod-1"
        });
        let original = candidate(&mapping, &source());
        let subject = original.mappings[0].native_subject.clone();
        assert_eq!(
            subject,
            "s_529be5b595ab327853eabe2d1adf52256e262af036510607"
        );
        assert_eq!(
            original.policy.services["logs"].users[&subject],
            vec!["reader"]
        );
        let original_mapping = mapping.clone();
        for (field, replacement) in [
            ("service_account_uid", "sa2"),
            ("pod_uid", "pod2"),
            ("issuer", "https://other.example.test"),
        ] {
            let mut changed = original_mapping.clone();
            changed["grants"][0]["workload"][field] = Value::from(replacement);
            assert_ne!(
                candidate(&changed, &source()).mappings[0].native_subject,
                subject
            );
        }
        for mutation in ["namespace", "service_account"] {
            let mut changed = original_mapping.clone();
            changed["grants"][0]["workload"][mutation] = Value::from("other");
            assert!(Mapping::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        mapping["grants"][0]["native_subject"] = Value::from("conflicting-native-reference");
        assert!(Mapping::parse(&serde_json::to_vec(&mapping).unwrap()).is_err());
        mapping["grants"][0]
            .as_object_mut()
            .unwrap()
            .remove("native_subject");
        mapping["grants"][0]["workload"]["issuer"] =
            Value::from("https://issuer.example.test?token=bad");
        assert!(Mapping::parse(&serde_json::to_vec(&mapping).unwrap()).is_err());
    }
    #[test]
    fn explicit_mapping_still_requires_network_and_guard_and_deletion_removes_grants() {
        use pumgye_core::{Decision, GuardEvidence};
        let c = candidate(&configuration(), &source());
        assert!(c.mappings[0].active);
        let p = c.policy.compile().unwrap();
        let ip = "192.0.2.9".parse().unwrap();
        assert_eq!(
            p.evaluate(
                "logs",
                "native-verified-worker",
                ip,
                "read",
                "public",
                0,
                GuardEvidence::EnforcedAllow
            ),
            Decision::Allow
        );
        assert_ne!(
            p.evaluate(
                "logs",
                "native-verified-worker",
                ip,
                "read",
                "public",
                0,
                GuardEvidence::Deny
            ),
            Decision::Allow
        );
        assert_ne!(
            p.evaluate(
                "logs",
                "native-verified-worker",
                "198.51.100.1".parse().unwrap(),
                "read",
                "public",
                0,
                GuardEvidence::EnforcedAllow
            ),
            Decision::Allow
        );
        let mut deleted = source();
        deleted["items"].as_array_mut().unwrap().pop();
        let c = candidate(&configuration(), &deleted);
        assert!(!c.mappings[0].active && c.policy.services["logs"].users.is_empty());
    }
    #[test]
    fn uid_scope_subject_rule_and_name_constraints_never_widen() {
        for (index, path, value) in [(0, "uid", "r2"), (1, "uid", "b2")] {
            let mut s = source();
            s["items"][index]["metadata"][path] = value.into();
            assert!(!candidate(&configuration(), &s).mappings[0].active);
        }
        let mut s = source();
        s["items"][1]["subjects"][0]["namespace"] = "red".into();
        assert!(!candidate(&configuration(), &s).mappings[0].active);
        let mut s = source();
        s["items"][0]["rules"][0]["verbs"] = serde_json::json!(["*"]);
        assert!(!candidate(&configuration(), &s).mappings[0].active);
        let mut m = configuration();
        m["grants"][0]["required_rules"][0]
            .as_object_mut()
            .unwrap()
            .remove("resource_name");
        assert!(!candidate(&m, &source()).mappings[0].active);
        let mut s = source();
        s["items"][0]["aggregationRule"] = serde_json::json!({"clusterRoleSelectors":[]});
        assert!(!candidate(&configuration(), &s).mappings[0].active);
    }
    #[test]
    fn rejects_implicit_grants_privilege_translation_and_wrong_cluster() {
        let mut m = configuration();
        m["template"]["services"]["logs"]["users"] = serde_json::json!({"unreviewed":["reader"]});
        assert!(Mapping::parse(&serde_json::to_vec(&m).unwrap()).is_err());
        for verb in ["*", "bind", "escalate", "impersonate"] {
            let mut m = configuration();
            m["grants"][0]["required_rules"][0]["verb"] = verb.into();
            assert!(Mapping::parse(&serde_json::to_vec(&m).unwrap()).is_err());
        }
        for namespace in [serde_json::Value::Null, serde_json::json!("red")] {
            let mut m = configuration();
            m["grants"][0]["required_rules"][0]["namespace"] = namespace;
            assert!(Mapping::parse(&serde_json::to_vec(&m).unwrap()).is_err());
        }
        let mut m = configuration();
        m["grants"][0]["source_subject"]["kind"] = "Group".into();
        assert!(Mapping::parse(&serde_json::to_vec(&m).unwrap()).is_err());
        let m = Mapping::parse(&serde_json::to_vec(&configuration()).unwrap()).unwrap();
        let i =
            kubernetes::inspect("other-cluster", &serde_json::to_vec(&source()).unwrap()).unwrap();
        assert!(m.candidate(&i).is_err());
    }
}
