//! Pure server-owned SAR mapping metadata. This module authenticates no caller.
//! The adapter must supply its authenticated fixed cluster and fence one policy View.
use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAuthorization {
    pub version: u32,
    pub principals: Vec<PrincipalBinding>,
    pub routes: Vec<RouteBinding>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalBinding {
    pub cluster: String,
    pub user: String,
    pub uid: UidMatch,
    pub required_groups: Vec<String>,
    #[serde(deserialize_with = "unique_extra")]
    pub required_extra: BTreeMap<String, Vec<String>>,
    pub subject: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum UidMatch {
    Absent,
    Exact { value: String },
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteBinding {
    pub cluster: String,
    pub attributes: Attributes,
    pub service: String,
    pub resource: String,
    pub action: String,
}
/// Exact wire attributes only. Selectors and future conditional fields fail decode.
/// No client-provided native service, action, classification, AAL or network context.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Attributes {
    Resource {
        group: String,
        version: String,
        resource: String,
        subresource: String,
        namespace: String,
        name: String,
        verb: String,
    },
    NonResource {
        path: String,
        verb: String,
    },
}
/// Bounded API-server assertion; never authenticated merely by constructing it.
/// Caller cluster is deliberately a separate argument to evaluation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub user: String,
    pub uid: Option<String>,
    pub groups: Vec<String>,
    #[serde(deserialize_with = "unique_extra")]
    pub extra: BTreeMap<String, Vec<String>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingDecision {
    InvalidRequest,
    UnknownPrincipal,
    AmbiguousPrincipal,
    UnknownRoute,
    Decided(ResourceDecision),
}
#[derive(Default)]
pub(super) struct CompiledMapping {
    principals: HashMap<String, HashMap<String, Vec<PrincipalBinding>>>,
    routes: HashMap<String, HashMap<Attributes, RouteBinding>>,
}
fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn cluster(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn atom(value: &str, empty: bool) -> bool {
    (empty || !value.is_empty())
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn values(values: &[String], maximum: usize) -> bool {
    values.len() <= maximum
        && values.iter().all(|v| text(v))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
fn extra(extra: &BTreeMap<String, Vec<String>>) -> bool {
    extra.len() <= 32
        && extra
            .iter()
            .all(|(key, vs)| text(key) && !vs.is_empty() && values(vs, 8))
}
impl Principal {
    fn valid(&self) -> bool {
        text(&self.user)
            && self.user != "system:anonymous"
            && self.uid.as_deref().is_none_or(text)
            && values(&self.groups, 64)
            && extra(&self.extra)
            && !self.groups.iter().any(|g| g == "system:unauthenticated")
    }
}
impl Attributes {
    fn valid(&self) -> bool {
        match self {
            Self::Resource {
                group,
                version,
                resource,
                subresource,
                namespace,
                name,
                verb,
            } => {
                atom(group, true)
                    && atom(version, false)
                    && atom(resource, false)
                    && matches!(subresource.as_str(), "" | "status" | "scale")
                    && atom(namespace, false)
                    && atom(name, false)
                    && matches!(verb.as_str(), "get" | "update" | "patch" | "delete")
            }
            Self::NonResource { path, verb } => {
                path.starts_with('/')
                    && path.len() <= 256
                    && !path.contains("//")
                    && path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
                    && !path.split('/').any(|s| matches!(s, "." | ".."))
                    && matches!(
                        verb.as_str(),
                        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
                    )
            }
        }
    }
}
impl KubernetesAuthorization {
    pub(super) fn compile(&self, policy: &CompiledPolicy) -> Result<CompiledMapping> {
        ensure!(
            self.version == 1 && self.principals.len() <= 4096 && self.routes.len() <= 4096,
            "invalid Kubernetes mapping version or capacity"
        );
        let mut result = CompiledMapping::default();
        for p in &self.principals {
            ensure!(
                cluster(&p.cluster)
                    && text(&p.user)
                    && p.user != "system:anonymous"
                    && values(&p.required_groups, 64)
                    && extra(&p.required_extra)
                    && !p
                        .required_groups
                        .iter()
                        .any(|g| g == "system:unauthenticated")
                    && match &p.uid {
                        UidMatch::Absent => true,
                        UidMatch::Exact { value } => text(value),
                    },
                "invalid Kubernetes principal binding"
            );
            ensure!(
                kubernetes_api_subject(&p.subject)
                    && p.subject.starts_with(&format!("k8sapi:{}:", p.cluster))
                    && p.subject.len() > p.cluster.len() + 8,
                "Kubernetes subject cluster namespace mismatch"
            );
            let candidates = result
                .principals
                .entry(p.cluster.clone())
                .or_default()
                .entry(p.user.clone())
                .or_default();
            ensure!(
                candidates.len() < 64 && !candidates.contains(p),
                "duplicate or excessive Kubernetes principal candidates"
            );
            let mut p = p.clone();
            p.required_groups.sort();
            for vs in p.required_extra.values_mut() {
                vs.sort();
            }
            ensure!(
                !candidates.contains(&p),
                "duplicate Kubernetes principal constraints"
            );
            candidates.push(p);
        }
        for r in &self.routes {
            ensure!(
                cluster(&r.cluster) && r.attributes.valid(),
                "unsupported Kubernetes route attributes"
            );
            let target = policy
                .resources
                .get(&r.resource)
                .ok_or_else(|| anyhow::anyhow!("unknown Kubernetes target resource"))?;
            ensure!(
                target.metadata.service == r.service && target.actions.contains_key(&r.action),
                "invalid Kubernetes target scope or action"
            );
            ensure!(
                policy.services[&r.service].authorization_context
                    == AuthorizationContext::KubernetesApi,
                "Kubernetes route requires explicit API context"
            );
            ensure!(
                result
                    .routes
                    .entry(r.cluster.clone())
                    .or_default()
                    .insert(r.attributes.clone(), r.clone())
                    .is_none(),
                "duplicate Kubernetes route"
            );
        }
        Ok(result)
    }
}
impl CompiledPolicy {
    /// Pure mapping + SAME native grants at AAL0. Caller authenticates the fixed
    /// cluster and owns current-source/publication/deadline checks independently.
    pub fn evaluate_kubernetes_request(
        &self,
        fixed_cluster: &str,
        principal: &Principal,
        attributes: &Attributes,
    ) -> MappingDecision {
        if !cluster(fixed_cluster) || !principal.valid() || !attributes.valid() {
            return MappingDecision::InvalidRequest;
        }
        let Some(candidates) = self
            .kubernetes_authorization
            .principals
            .get(fixed_cluster)
            .and_then(|p| p.get(&principal.user))
        else {
            return MappingDecision::UnknownPrincipal;
        };
        let mut matches = candidates.iter().filter(|p| {
            let uid = match &p.uid {
                UidMatch::Absent => principal.uid.is_none(),
                UidMatch::Exact { value } => principal.uid.as_ref() == Some(value),
            };
            uid && p
                .required_groups
                .iter()
                .all(|g| principal.groups.contains(g))
                && p.required_extra.iter().all(|(k, required)| {
                    principal.extra.get(k).is_some_and(|actual| {
                        actual.len() == required.len()
                            && required.iter().all(|v| actual.contains(v))
                    })
                })
        });
        let Some(binding) = matches.next() else {
            return MappingDecision::UnknownPrincipal;
        };
        if matches.next().is_some() {
            return MappingDecision::AmbiguousPrincipal;
        }
        let Some(route) = self
            .kubernetes_authorization
            .routes
            .get(fixed_cluster)
            .and_then(|r| r.get(attributes))
        else {
            return MappingDecision::UnknownRoute;
        };
        MappingDecision::Decided(self.evaluate_kubernetes_api_resource(
            &route.service,
            &route.resource,
            &route.action,
            KubernetesApiSubject(&binding.subject),
        ))
    }
}

fn unique_extra<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, Vec<String>>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, Vec<String>>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique bounded extra keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, Vec<String>>()? {
                if result.len() >= 32 || result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive extra keys",
                    ));
                }
            }
            Ok(result)
        }
    }
    d.deserialize_map(Unique)
}
