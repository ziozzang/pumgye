//! HTTPS read-only source collector. Application authorization is not published here.
use crate::kubernetes::{self, Inventory};
use anyhow::{Result, ensure};
use arc_swap::ArcSwapOption;
use reqwest::{Certificate, Client, Url, header::HeaderValue};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, sync::Arc, time::Duration};

#[derive(Serialize)]
pub struct Observation {
    pub revision: u64,
    pub valid_until_ms: u64,
    pub collection_versions: Vec<(String, String)>,
    pub inventory: Inventory,
}
pub struct Collector {
    origin: Url,
    namespace: Option<String>,
    cluster: String,
    pub view: ArcSwapOption<Observation>,
    revision: u64,
    digest: Option<[u8; 32]>,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "source credential capacity exceeded");
    Ok(bytes)
}
impl Collector {
    pub fn new(origin: &str, namespace: Option<String>, cluster: String) -> Result<Self> {
        let origin = Url::parse(origin)?;
        ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/",
            "Kubernetes API must be an HTTPS origin"
        );
        ensure!(
            namespace.as_deref().is_none_or(identifier),
            "invalid source namespace"
        );
        // Reuse cluster validation without creating or reading authority state.
        kubernetes::inspect(&cluster, br#"{"kind":"List","apiVersion":"v1","items":[]}"#)?;
        Ok(Self {
            origin,
            namespace,
            cluster,
            view: ArcSwapOption::empty(),
            revision: 0,
            digest: None,
        })
    }
    pub async fn refresh(&mut self, ca: &Path, token: &Path, now_ms: u64) -> Result<()> {
        // Fence the old observation before network work; it is never an authorization grant.
        self.view.store(None);
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(15), self.collect(ca, token)).await;
        let (inventory, versions) =
            result.map_err(|_| anyhow::anyhow!("source collection deadline"))??;
        let bytes = serde_json::to_vec(&(&inventory, &versions))?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if self.digest != Some(digest) {
            self.revision = self
                .revision
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("source revision exhausted"))?;
            self.digest = Some(digest);
        }
        let completed = now_ms
            .checked_add(u64::try_from(started.elapsed().as_millis())?)
            .ok_or_else(|| anyhow::anyhow!("source clock exhausted"))?;
        self.view.store(Some(Arc::new(Observation {
            revision: self.revision,
            valid_until_ms: completed
                .checked_add(1000)
                .ok_or_else(|| anyhow::anyhow!("source lease exhausted"))?,
            collection_versions: versions,
            inventory,
        })));
        Ok(())
    }
    pub fn fresh(&self, now_ms: u64) -> Option<Arc<Observation>> {
        self.view.load_full().filter(|v| now_ms < v.valid_until_ms)
    }
    async fn collect(&self, ca: &Path, token: &Path) -> Result<(Inventory, Vec<(String, String)>)> {
        let certificate = Certificate::from_pem(&bounded_file(ca, 65536)?)?;
        let bytes = bounded_file(token, 4096)?;
        let value = std::str::from_utf8(&bytes)?.trim();
        ensure!(
            !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic()),
            "invalid source credential"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {value}"))?;
        authorization.set_sensitive(true);
        let client = Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build()?;
        let mut items = Vec::new();
        let mut versions = Vec::new();
        let mut total_bytes = 0usize;
        for (resource, kind) in [
            ("roles", "Role"),
            ("clusterroles", "ClusterRole"),
            ("rolebindings", "RoleBinding"),
            ("clusterrolebindings", "ClusterRoleBinding"),
        ] {
            let path = if !kind.starts_with("Cluster") {
                self.namespace
                    .as_ref()
                    .map(|ns| {
                        format!("apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/{resource}")
                    })
                    .unwrap_or_else(|| format!("apis/rbac.authorization.k8s.io/v1/{resource}"))
            } else {
                format!("apis/rbac.authorization.k8s.io/v1/{resource}")
            };
            let mut pagination = Pages::new(kind);
            loop {
                let mut url = self.origin.join(&path)?;
                url.query_pairs_mut().append_pair("limit", "256");
                if let Some(c) = &pagination.next {
                    url.query_pairs_mut().append_pair("continue", c);
                }
                let mut response = client
                    .get(url)
                    .header("authorization", authorization.clone())
                    .send()
                    .await?;
                ensure!(
                    response.status().is_success(),
                    "Kubernetes source refused collection"
                );
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    total_bytes = total_bytes
                        .checked_add(chunk.len())
                        .ok_or_else(|| anyhow::anyhow!("source byte overflow"))?;
                    ensure!(
                        total_bytes <= kubernetes::MAX_BYTES,
                        "source response capacity exceeded"
                    );
                    body.extend_from_slice(&chunk);
                }
                let value: Value = serde_json::from_slice(&body)?;
                if !kind.starts_with("Cluster")
                    && let Some(namespace) = &self.namespace
                {
                    ensure!(
                        value["items"].as_array().is_some_and(|page| page
                            .iter()
                            .all(|item| item["metadata"]["namespace"] == *namespace)),
                        "source namespace mismatch"
                    );
                }
                let complete = pagination.accept(&value, &mut items)?;
                if complete {
                    break;
                }
            }
            versions.push((resource.to_owned(), pagination.version.unwrap()));
        }
        let bytes = serde_json::to_vec(
            &serde_json::json!({"apiVersion":"v1","kind":"List","items":items}),
        )?;
        Ok((kubernetes::inspect(&self.cluster, &bytes)?, versions))
    }
}
struct Pages {
    kind: &'static str,
    version: Option<String>,
    next: Option<String>,
    seen: BTreeSet<String>,
    count: usize,
}
impl Pages {
    fn new(kind: &'static str) -> Self {
        Self {
            kind,
            version: None,
            next: None,
            seen: BTreeSet::new(),
            count: 0,
        }
    }
    fn accept(&mut self, v: &Value, items: &mut Vec<Value>) -> Result<bool> {
        self.count += 1;
        ensure!(
            self.count <= 32
                && v["apiVersion"] == "rbac.authorization.k8s.io/v1"
                && v["kind"] == format!("{}List", self.kind),
            "invalid or excessive source pages"
        );
        let rv = v["metadata"]["resourceVersion"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
            .ok_or_else(|| anyhow::anyhow!("missing collection version"))?;
        ensure!(
            self.version
                .as_deref()
                .is_none_or(|previous| previous == rv),
            "collection version changed between pages"
        );
        self.version = Some(rv.to_owned());
        let page = v["items"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("missing source items"))?;
        ensure!(
            items.len() + page.len() <= 4096,
            "source object capacity exceeded"
        );
        for item in page {
            let object = item
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid source object"))?;
            ensure!(
                object.get("kind").is_none_or(|kind| kind == self.kind)
                    && object
                        .get("apiVersion")
                        .is_none_or(|api| api == "rbac.authorization.k8s.io/v1"),
                "source item type contradicts collection"
            );
            let mut object = object.clone();
            object
                .entry("kind")
                .or_insert_with(|| Value::String(self.kind.to_owned()));
            object
                .entry("apiVersion")
                .or_insert_with(|| Value::String("rbac.authorization.k8s.io/v1".to_owned()));
            items.push(Value::Object(object));
        }
        let next = match v["metadata"].get("continue") {
            None => "",
            Some(value) => value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid continuation"))?,
        };
        ensure!(
            next.len() <= 4096 && !next.chars().any(char::is_control),
            "invalid continuation"
        );
        if next.is_empty() {
            self.next = None;
            return Ok(true);
        }
        ensure!(
            !page.is_empty() && self.seen.insert(next.to_owned()),
            "source pagination cycle"
        );
        self.next = Some(next.to_owned());
        Ok(false)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn page(rv: &str, next: &str) -> Value {
        serde_json::json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleList","metadata":{"resourceVersion":rv,"continue":next},"items":[{"kind":"Role"}]})
    }
    #[test]
    fn typed_collection_supplies_omitted_item_type_but_never_overrides_conflicts() {
        let mut value = page("opaque:a", "");
        value["items"] = serde_json::json!([{"metadata":{"name":"reader"}}]);
        let mut objects = Vec::new();
        assert!(Pages::new("Role").accept(&value, &mut objects).unwrap());
        assert_eq!(objects[0]["kind"], "Role");
        assert_eq!(objects[0]["apiVersion"], "rbac.authorization.k8s.io/v1");
        for (field, bad) in [
            ("kind", "ClusterRole"),
            ("apiVersion", "attacker.example/v1"),
        ] {
            let mut invalid = value.clone();
            invalid["items"][0][field] = bad.into();
            assert!(
                Pages::new("Role")
                    .accept(&invalid, &mut Vec::new())
                    .is_err()
            );
        }
    }
    #[test]
    fn pagination_preserves_opaque_version_and_refuses_changed_or_cyclic_pages() {
        let mut p = Pages::new("Role");
        let mut objects = Vec::new();
        assert!(
            !p.accept(&page("opaque:a", "token+a/b="), &mut objects)
                .unwrap()
        );
        assert!(p.accept(&page("opaque:b", ""), &mut objects).is_err());
        let mut p = Pages::new("Role");
        assert!(!p.accept(&page("opaque:a", "one"), &mut Vec::new()).unwrap());
        assert!(p.accept(&page("opaque:a", "one"), &mut Vec::new()).is_err());
        let mut p = Pages::new("Role");
        assert!(p.accept(&page("opaque:a", ""), &mut Vec::new()).unwrap());
    }
    #[tokio::test]
    async fn expired_or_failed_observation_cannot_retain_a_snapshot() {
        let mut collector =
            Collector::new("https://example.test/", None, "example".into()).unwrap();
        let inventory = kubernetes::inspect(
            "example",
            br#"{"kind":"List","apiVersion":"v1","items":[]}"#,
        )
        .unwrap();
        collector.view.store(Some(Arc::new(Observation {
            revision: 1,
            valid_until_ms: 1000,
            collection_versions: Vec::new(),
            inventory,
        })));
        assert!(collector.fresh(999).is_some());
        assert!(collector.fresh(1000).is_none());
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent-credential");
        assert!(collector.refresh(&absent, &absent, 100).await.is_err());
        assert!(collector.view.load_full().is_none());
    }
    #[test]
    fn refuses_untrusted_origins_and_namespaces() {
        for url in [
            "http://127.0.0.1:9080",
            "https://user:pass@example.test/",
            "https://example.test/path",
            "https://example.test/?x=1",
            "https://example.test/#x",
        ] {
            assert!(Collector::new(url, None, "example".into()).is_err());
        }
        assert!(
            Collector::new(
                "https://example.test/",
                Some("../other".into()),
                "example".into()
            )
            .is_err()
        );
    }
}
