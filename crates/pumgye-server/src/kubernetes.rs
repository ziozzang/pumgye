//! Bounded, read-only RBAC source inspection. Never publishes application grants.
use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_OBJECTS: usize = 4096;
const GROUP: &str = "rbac.authorization.k8s.io";

#[derive(Serialize)]
pub struct Inventory {
    pub version: u32,
    pub cluster: String,
    pub mode: &'static str,
    pub objects: Vec<Object>,
}
#[derive(Serialize)]
pub struct Object {
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    pub rules: Option<Value>,
    pub aggregation_rule: Option<Value>,
    pub role_ref: Option<Value>,
    pub subjects: Option<Value>,
}
fn text(v: &Value, field: &str) -> Result<String> {
    let s = v.get(field).and_then(Value::as_str).unwrap_or_default();
    ensure!(
        !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control),
        "invalid source identifier"
    );
    Ok(s.to_owned())
}
fn strings(v: &Value) -> Result<()> {
    let a = v
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected string array"))?;
    ensure!(
        a.len() <= 128
            && a.iter().all(|s| s.as_str().is_some_and(|s| !s.is_empty()
                && s.len() <= 256
                && !s.chars().any(char::is_control))),
        "invalid rule values"
    );
    Ok(())
}
pub fn inspect(cluster: &str, bytes: &[u8]) -> Result<Inventory> {
    ensure!(
        !cluster.is_empty()
            && cluster.len() <= 128
            && cluster
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "explicit cluster identity required"
    );
    ensure!(bytes.len() <= MAX_BYTES, "RBAC input capacity exceeded");
    let root: Value = serde_json::from_slice(bytes)?;
    ensure!(
        root["kind"] == "List" && root["apiVersion"] == "v1",
        "complete Kubernetes List required"
    );
    let items = root["items"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("List items required"))?;
    ensure!(items.len() <= MAX_OBJECTS, "RBAC object capacity exceeded");
    let mut objects = BTreeMap::new();
    let mut uids = BTreeSet::new();
    for v in items {
        ensure!(
            v["apiVersion"] == "rbac.authorization.k8s.io/v1",
            "unsupported source API"
        );
        let kind = text(v, "kind")?;
        ensure!(
            ["Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"].contains(&kind.as_str()),
            "unsupported source kind"
        );
        let m = &v["metadata"];
        let namespace = if kind.starts_with("Cluster") {
            ensure!(
                m.get("namespace").is_none_or(|s| s.as_str() == Some("")),
                "cluster object has namespace"
            );
            None
        } else {
            Some(text(m, "namespace")?)
        };
        let name = text(m, "name")?;
        let uid = text(m, "uid")?;
        ensure!(uids.insert(uid.clone()), "duplicate source UID");
        let resource_version = text(m, "resourceVersion")?;
        let binding = kind.ends_with("Binding");
        let (rules, aggregation_rule, role_ref, subjects) = if binding {
            let r = &v["roleRef"];
            ensure!(r["apiGroup"] == GROUP, "unsupported role reference group");
            let rk = text(r, "kind")?;
            ensure!(
                rk == "ClusterRole" || (kind == "RoleBinding" && rk == "Role"),
                "invalid reference scope"
            );
            text(r, "name")?;
            let ss = v
                .get("subjects")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            let a = ss
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("subjects array required"))?;
            ensure!(a.len() <= 1024, "subject capacity exceeded");
            for s in a {
                let sk = text(s, "kind")?;
                text(s, "name")?;
                match sk.as_str() {
                    "User" | "Group" => ensure!(
                        s["apiGroup"] == GROUP
                            && s.get("namespace").is_none_or(|v| v.as_str() == Some("")),
                        "invalid human subject scope"
                    ),
                    "ServiceAccount" => {
                        ensure!(
                            s.get("apiGroup").is_none_or(|v| v.as_str() == Some("")),
                            "invalid service-account group"
                        );
                        // Effective namespace must be explicit in an offline inventory.
                        text(s, "namespace")?;
                    }
                    _ => anyhow::bail!("unsupported subject kind"),
                }
            }
            (None, None, Some(r.clone()), Some(ss))
        } else {
            let rs = v
                .get("rules")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            let a = rs
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("rules array required"))?;
            ensure!(a.len() <= 256, "rule capacity exceeded");
            for r in a {
                ensure!(
                    r.as_object().is_some_and(|r| r.keys().all(|k| [
                        "verbs",
                        "apiGroups",
                        "resources",
                        "resourceNames",
                        "nonResourceURLs"
                    ]
                    .contains(&k.as_str()))),
                    "unknown rule field"
                );
                strings(&r["verbs"])?;
                ensure!(!r["verbs"].as_array().unwrap().is_empty(), "empty verbs");
                if r.get("nonResourceURLs").is_some() {
                    ensure!(
                        kind == "ClusterRole"
                            && r.get("resources").is_none()
                            && r.get("apiGroups").is_none()
                            && r.get("resourceNames").is_none(),
                        "invalid non-resource rule"
                    );
                    strings(&r["nonResourceURLs"])?;
                } else {
                    // The empty API group identifies Kubernetes core resources.
                    let groups = r["apiGroups"]
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("apiGroups required"))?;
                    ensure!(
                        !groups.is_empty()
                            && groups.len() <= 128
                            && groups.iter().all(|g| g.as_str().is_some_and(
                                |g| g.len() <= 256 && !g.chars().any(char::is_control)
                            )),
                        "invalid API groups"
                    );
                    strings(&r["resources"])?;
                    ensure!(
                        !r["resources"].as_array().unwrap().is_empty(),
                        "empty resources"
                    );
                    if let Some(names) = r.get("resourceNames") {
                        strings(names)?;
                    }
                }
            }
            (Some(rs), v.get("aggregationRule").cloned(), None, None)
        };
        let key = (kind.clone(), namespace.clone(), name.clone());
        ensure!(
            objects
                .insert(
                    key,
                    Object {
                        kind,
                        namespace,
                        name,
                        uid,
                        resource_version,
                        rules,
                        aggregation_rule,
                        role_ref,
                        subjects
                    }
                )
                .is_none(),
            "duplicate source object"
        );
    }
    // Missing roles may mean a partial collection; do not silently treat it as complete.
    for o in objects.values() {
        if let Some(r) = &o.role_ref {
            let kind = r["kind"].as_str().unwrap().to_owned();
            let ns = if kind == "Role" {
                o.namespace.clone()
            } else {
                None
            };
            ensure!(
                objects.contains_key(&(kind, ns, r["name"].as_str().unwrap().to_owned())),
                "unresolved role reference"
            );
        }
    }
    Ok(Inventory {
        version: 1,
        cluster: cluster.to_owned(),
        mode: "observe",
        objects: objects.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        serde_json::json!({"apiVersion":"v1","kind":"List","items":[
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"namespace":"blue","name":"reader","uid":"r1","resourceVersion":"opaque:rv"},"rules":[{"apiGroups":[""],"resources":["pods/log"],"verbs":["get"],"resourceNames":["worker"]}]},
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"namespace":"blue","name":"workers","uid":"b1","resourceVersion":"9"},"roleRef":{"apiGroup":GROUP,"kind":"Role","name":"reader"},"subjects":[{"kind":"ServiceAccount","name":"worker","namespace":"blue"}]}
        ]})
    }
    fn parse(v: &Value) -> Result<Inventory> {
        inspect("cluster-one", &serde_json::to_vec(v).unwrap())
    }
    #[test]
    fn preserves_native_semantics_and_opaque_provenance() {
        let f = fixture();
        let i = parse(&f).unwrap();
        assert_eq!(i.mode, "observe");
        assert_eq!(i.objects[0].resource_version, "opaque:rv");
        assert_eq!(
            i.objects[0].rules.as_ref().unwrap()[0]["resourceNames"],
            serde_json::json!(["worker"])
        );
        let mut reversed = f;
        reversed["items"].as_array_mut().unwrap().reverse();
        assert_eq!(
            serde_json::to_vec(&i).unwrap(),
            serde_json::to_vec(&parse(&reversed).unwrap()).unwrap()
        );
    }
    #[test]
    fn refuses_cross_namespace_reference_duplicates_and_unknown_rule_semantics() {
        let mut f = fixture();
        f["items"][1]["metadata"]["namespace"] = "red".into();
        assert!(parse(&f).is_err());
        let mut f = fixture();
        let duplicate = f["items"][0].clone();
        f["items"].as_array_mut().unwrap().push(duplicate);
        assert!(parse(&f).is_err());
        let mut f = fixture();
        f["items"][0]["rules"][0]["effect"] = "deny".into();
        assert!(parse(&f).is_err());
        let mut f = fixture();
        f["items"][1]["roleRef"]["apiGroup"] = "attacker.example".into();
        assert!(parse(&f).is_err());
        assert!(inspect("", b"{}").is_err());
        assert!(inspect("cluster-one", &vec![0; MAX_BYTES + 1]).is_err());
    }
}
