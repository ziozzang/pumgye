//! Deterministic authorization. Callers must authenticate identity and network evidence.
pub mod diff;
pub mod explain;
pub mod kubernetes_authorization;
mod trace;
pub mod v2;
use anyhow::{Context, Result, ensure};
use guard_core::prefix::PrefixTrie;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};
pub use trace::{
    MAX_TRACE_EVENTS, NetworkMatch, NoTrace, RightsView, SubjectMap, TraceEvent, Tracer, VecTrace,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_authorization: Option<kubernetes_authorization::KubernetesAuthorization>,
    pub information_classes: Vec<String>,
    pub services: BTreeMap<String, Service>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, Resource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// Explicit opt-in for API-server authorization without client network evidence.
    #[serde(default, skip_serializing_if = "AuthorizationContext::is_default")]
    pub authorization_context: AuthorizationContext,
    pub permissions: Vec<String>,
    pub roles: BTreeMap<String, Role>,
    pub users: BTreeMap<String, Vec<String>>,
    /// Canonical Hopae Workload subjects only; never falls back to `users`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub workload_users: BTreeMap<String, Vec<String>>,
    /// Canonical Human metadata only; never falls back to other principal maps.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub human_users: BTreeMap<String, Vec<String>>,
    pub networks: Vec<Network>,
    #[serde(default = "yes")]
    pub require_guard: bool,
}
/// Native policy applicability, never selected by request headers or claims.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationContext {
    #[default]
    NetworkAndGuard,
    KubernetesApi,
}
impl AuthorizationContext {
    fn is_default(&self) -> bool {
        *self == Self::NetworkAndGuard
    }
}
/// Metadata label selected by a server-owned Kubernetes API identity mapping.
/// Parsing validates its namespace only: this is NOT authenticated identity,
/// a Hopae principal, a receipt, an assurance claim or an authorization capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KubernetesApiSubject<'a>(&'a str);
impl<'a> KubernetesApiSubject<'a> {
    pub fn parse(subject: &'a str) -> Result<Self> {
        ensure!(
            kubernetes_api_subject(subject),
            "invalid Kubernetes API subject"
        );
        Ok(Self(subject))
    }
    pub fn as_str(self) -> &'a str {
        self.0
    }
}
fn kubernetes_api_subject(subject: &str) -> bool {
    name(subject)
        && subject
            .strip_prefix("k8sapi:")
            .is_some_and(|suffix| !suffix.is_empty())
}
/// Native resource metadata: request callers select an action, never its class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub service: String,
    pub information_class: String,
    pub actions: BTreeMap<String, String>,
    #[serde(default)]
    pub minimum_aal: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceDecision {
    UnknownResource,
    UnknownAction,
    Decided(Decision),
}
struct CompiledResource {
    metadata: Resource,
    actions: HashMap<String, u64>,
    class: u64,
}
fn yes() -> bool {
    true
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub permissions: Vec<String>,
    pub information_classes: Vec<String>,
    #[serde(default)]
    pub inherits: Vec<String>,
    #[serde(default)]
    pub minimum_aal: u8,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub cidr: IpNet,
    pub roles: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardEvidence {
    EnforcedAllow,
    Deny,
    Observe,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    UnknownService,
    Guest,
    NetworkGuest,
    PermissionDenied,
    ClassDenied,
    AssuranceDenied,
    GuardDenied,
    GuardUnavailable,
}
#[derive(Clone, Copy, Default)]
struct Rights {
    permissions: u64,
    classes: u64,
    aal: u8,
}
impl Rights {
    #[inline(always)]
    fn view(self) -> RightsView {
        RightsView {
            permissions: self.permissions,
            classes: self.classes,
            minimum_aal: self.aal,
        }
    }
    fn union(self, other: Self) -> Self {
        Self {
            permissions: self.permissions | other.permissions,
            classes: self.classes | other.classes,
            aal: self.aal.max(other.aal),
        }
    }
}
pub struct CompiledPolicy {
    kubernetes_authorization: kubernetes_authorization::CompiledMapping,
    services: HashMap<String, CompiledService>,
    classes: HashMap<String, u64>,
    resources: HashMap<String, CompiledResource>,
}
/// Network rights plus the source rule index for explain; the index occupies
/// existing padding, so the compiled entry size is unchanged.
#[derive(Clone, Copy)]
struct NetworkRights {
    permissions: u64,
    classes: u64,
    aal: u8,
    rule: u32,
}
impl NetworkRights {
    #[inline(always)]
    fn rights(self) -> Rights {
        Rights {
            permissions: self.permissions,
            classes: self.classes,
            aal: self.aal,
        }
    }
}
const _: () = assert!(std::mem::size_of::<NetworkRights>() == std::mem::size_of::<Rights>());
struct CompiledService {
    permissions: HashMap<String, u64>,
    users: HashMap<String, Rights>,
    workload_users: HashMap<String, Rights>,
    human_users: HashMap<String, Rights>,
    networks: PrefixTrie<NetworkRights>,
    hosts: HashMap<IpAddr, NetworkRights>,
    /// Cold copy of each source network rule's rights, for candidate diff only.
    network_rules: Vec<Rights>,
    require_guard: bool,
    authorization_context: AuthorizationContext,
}
/// AAL presented by Hopae-signed evidence (receipt or permission context) that
/// the caller has verified. Only this form may carry AAL3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedAssurance(u8);
impl SealedAssurance {
    /// Human AAL from a verified Hopae receipt: 1..=3.
    pub fn from_verified_receipt(aal: u8) -> Option<Self> {
        (1..=3).contains(&aal).then_some(Self(aal))
    }
    pub fn level(self) -> u8 {
        self.0
    }
}
/// Source of a Human assurance level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HumanAssurance {
    /// Supplied by a trusted adapter without Hopae-signed evidence: AAL1/2 only.
    Asserted(u8),
    /// Verified Hopae evidence: AAL1–3 (AAL3 only for opted-in applications).
    Sealed(SealedAssurance),
}
impl HumanAssurance {
    pub fn level(self) -> u8 {
        match self {
            HumanAssurance::Asserted(a) => a,
            HumanAssurance::Sealed(s) => s.0,
        }
    }
    fn in_range(self) -> bool {
        match self {
            HumanAssurance::Asserted(a) => matches!(a, 1 | 2),
            HumanAssurance::Sealed(_) => true,
        }
    }
}
/// Canonical Human subject metadata, never authentication or permission evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HumanSubject<'a>(&'a str);
impl<'a> HumanSubject<'a> {
    pub fn parse(subject: &'a str) -> Result<Self> {
        ensure!(
            subject
                .strip_prefix("human1:")
                .is_some_and(|digest| digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "invalid Human subject"
        );
        Ok(Self(subject))
    }
    pub fn as_str(self) -> &'a str {
        self.0
    }
}
/// Canonical public identity encoding, not authentication evidence.
pub fn workload_subject(s: &str) -> bool {
    s.strip_prefix("s_").is_some_and(|digest| {
        digest.len() == 48
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn vocabulary(values: &[String]) -> Result<HashMap<String, u64>> {
    ensure!(
        !values.is_empty() && values.len() <= 64,
        "vocabulary must contain 1..64 entries"
    );
    let mut result = HashMap::new();
    for (i, v) in values.iter().enumerate() {
        ensure!(
            name(v) && result.insert(v.clone(), 1u64 << i).is_none(),
            "invalid or duplicate vocabulary"
        );
    }
    Ok(result)
}
fn mask(values: &[String], vocabulary: &HashMap<String, u64>) -> Result<u64> {
    ensure!(values.len() <= 64, "too many rights");
    let mut seen = BTreeSet::new();
    let mut result = 0;
    for value in values {
        ensure!(seen.insert(value), "duplicate right");
        result |= *vocabulary
            .get(value)
            .ok_or_else(|| anyhow::anyhow!("unknown right"))?;
    }
    Ok(result)
}
fn resolve_role(
    id: &str,
    service: &Service,
    permissions: &HashMap<String, u64>,
    classes: &HashMap<String, u64>,
    visiting: &mut BTreeSet<String>,
    done: &mut HashMap<String, Rights>,
) -> Result<Rights> {
    if id == "guest" {
        return Ok(Rights::default());
    }
    if let Some(rights) = done.get(id) {
        return Ok(*rights);
    }
    ensure!(visiting.insert(id.to_owned()), "role inheritance cycle");
    let role = service
        .roles
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("unknown role"))?;
    ensure!(
        role.inherits.len() <= 8 && role.minimum_aal <= 3,
        "invalid inheritance or assurance"
    );
    let mut rights = Rights {
        permissions: mask(&role.permissions, permissions)?,
        classes: mask(&role.information_classes, classes)?,
        aal: role.minimum_aal,
    };
    let mut parents = BTreeSet::new();
    for parent in &role.inherits {
        ensure!(parents.insert(parent), "duplicate parent");
        rights = rights.union(resolve_role(
            parent,
            service,
            permissions,
            classes,
            visiting,
            done,
        )?);
    }
    visiting.remove(id);
    done.insert(id.to_owned(), rights);
    Ok(rights)
}
fn assignment(ids: &[String], roles: &HashMap<String, Rights>) -> Result<Rights> {
    ensure!(
        !ids.is_empty() && ids.len() <= 8,
        "assignment must contain 1..8 roles"
    );
    ensure!(
        !ids.iter().any(|id| id == "guest") || ids.len() == 1,
        "guest cannot be combined with roles"
    );
    let mut seen = BTreeSet::new();
    let mut rights = Rights::default();
    for id in ids {
        ensure!(seen.insert(id), "duplicate assigned role");
        rights = rights.union(
            *roles
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("unknown assigned role"))?,
        );
    }
    Ok(rights)
}
/// Document location of a compile failure, attached as anyhow context.
#[derive(Debug)]
struct PolicyPath(String);
impl std::fmt::Display for PolicyPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "at {}", self.0)
    }
}
fn at(path: impl Into<String>) -> PolicyPath {
    PolicyPath(path.into())
}
/// Registered validator failure codes (`pumgye.validation.*`), keyed by the
/// compiler's fixed refusal text. Unlisted refusals map to `invalid`.
pub const VALIDATION_CODES: &[(&str, &str)] = &[
    (
        "invalid version or service count",
        "pumgye.validation.version_or_service_count",
    ),
    (
        "vocabulary must contain 1..64 entries",
        "pumgye.validation.vocabulary_size",
    ),
    (
        "invalid or duplicate vocabulary",
        "pumgye.validation.vocabulary_entry",
    ),
    (
        "invalid service or role count",
        "pumgye.validation.service_name_or_role_count",
    ),
    (
        "Kubernetes API context forbids network/guard requirements and typed assignments",
        "pumgye.validation.kubernetes_context",
    ),
    (
        "Kubernetes API context requires namespaced API subjects",
        "pumgye.validation.kubernetes_subject",
    ),
    (
        "policy assignment limit",
        "pumgye.validation.assignment_limit",
    ),
    ("guest is reserved", "pumgye.validation.guest_reserved"),
    ("invalid role name", "pumgye.validation.role_name"),
    ("role inheritance cycle", "pumgye.validation.role_cycle"),
    ("unknown role", "pumgye.validation.unknown_role"),
    (
        "invalid inheritance or assurance",
        "pumgye.validation.role_inheritance_or_assurance",
    ),
    ("too many rights", "pumgye.validation.too_many_rights"),
    ("duplicate right", "pumgye.validation.duplicate_right"),
    ("unknown right", "pumgye.validation.unknown_right"),
    ("duplicate parent", "pumgye.validation.duplicate_parent"),
    (
        "assignment must contain 1..8 roles",
        "pumgye.validation.assignment_size",
    ),
    (
        "guest cannot be combined with roles",
        "pumgye.validation.guest_combined",
    ),
    (
        "duplicate assigned role",
        "pumgye.validation.duplicate_assigned_role",
    ),
    (
        "unknown assigned role",
        "pumgye.validation.unknown_assigned_role",
    ),
    ("invalid subject", "pumgye.validation.subject_name"),
    (
        "invalid workload subject",
        "pumgye.validation.workload_subject",
    ),
    ("invalid Human subject", "pumgye.validation.human_subject"),
    (
        "network has host bits",
        "pumgye.validation.network_host_bits",
    ),
    ("duplicate network", "pumgye.validation.duplicate_network"),
    (
        "resource catalog capacity",
        "pumgye.validation.resource_capacity",
    ),
    (
        "invalid resource metadata",
        "pumgye.validation.resource_metadata",
    ),
    (
        "resource action capacity",
        "pumgye.validation.action_capacity",
    ),
    (
        "unknown resource service",
        "pumgye.validation.resource_service",
    ),
    ("unknown resource class", "pumgye.validation.resource_class"),
    (
        "invalid resource action",
        "pumgye.validation.resource_action",
    ),
    (
        "unknown resource permission",
        "pumgye.validation.resource_permission",
    ),
    ("vocabulary too large", "pumgye.validation.vocabulary_size"),
    (
        "invalid version",
        "pumgye.validation.version_or_service_count",
    ),
    ("service capacity", "pumgye.validation.service_capacity"),
    ("template capacity", "pumgye.validation.template_capacity"),
    ("binding capacity", "pumgye.validation.binding_capacity"),
    ("principal capacity", "pumgye.validation.principal_capacity"),
    (
        "relevant group capacity",
        "pumgye.validation.group_capacity",
    ),
    ("zone capacity", "pumgye.validation.zone_capacity"),
    ("prefix capacity", "pumgye.validation.prefix_capacity"),
    (
        "catalog levels required",
        "pumgye.validation.catalog_levels",
    ),
    ("invalid zone name", "pumgye.validation.zone_name"),
    ("zone needs prefixes", "pumgye.validation.zone_prefixes"),
    ("invalid template name", "pumgye.validation.template_name"),
    ("template inheritance cycle", "pumgye.validation.role_cycle"),
    ("unknown template", "pumgye.validation.unknown_template"),
    (
        "template permission count",
        "pumgye.validation.template_permissions",
    ),
    (
        "invalid or duplicate template permission",
        "pumgye.validation.template_permission",
    ),
    (
        "unknown clearance level",
        "pumgye.validation.clearance_level",
    ),
    (
        "unknown compartment",
        "pumgye.validation.unknown_compartment",
    ),
    (
        "duplicate compartment",
        "pumgye.validation.duplicate_compartment",
    ),
    (
        "invalid service name",
        "pumgye.validation.service_name_or_role_count",
    ),
    (
        "version 2 supports the network_and_guard context only",
        "pumgye.validation.v2_context",
    ),
    (
        "service permissions required",
        "pumgye.validation.vocabulary_size",
    ),
    (
        "unknown mapped permission",
        "pumgye.validation.permission_map",
    ),
    ("unknown zone", "pumgye.validation.unknown_zone"),
    (
        "too many ceiling templates",
        "pumgye.validation.ceiling_templates",
    ),
    (
        "duplicate ceiling template",
        "pumgye.validation.ceiling_templates",
    ),
    (
        "ambiguous ceiling prefix",
        "pumgye.validation.ambiguous_ceiling",
    ),
    (
        "invalid or duplicate binding id",
        "pumgye.validation.binding_id",
    ),
    (
        "binding subject count",
        "pumgye.validation.binding_subjects",
    ),
    ("empty validity window", "pumgye.validation.validity_window"),
    (
        "invalid binding metadata",
        "pumgye.validation.binding_metadata",
    ),
    ("empty zone condition", "pumgye.validation.zone_condition"),
    ("empty service scope", "pumgye.validation.binding_scope"),
    (
        "unknown or duplicate scoped service",
        "pumgye.validation.binding_scope",
    ),
    (
        "allow needs role only; deny needs permissions only",
        "pumgye.validation.binding_effect",
    ),
    (
        "duplicate binding subject",
        "pumgye.validation.binding_subjects",
    ),
    (
        "invalid principal reference",
        "pumgye.validation.principal_reference",
    ),
    (
        "invalid group reference",
        "pumgye.validation.group_reference",
    ),
    (
        "empty deny permissions",
        "pumgye.validation.deny_permissions",
    ),
    (
        "too many bindings for one subject on one service",
        "pumgye.validation.subject_service_grants",
    ),
    (
        "label names must be unique across levels and compartments",
        "pumgye.validation.label_collision",
    ),
];
/// Fallback for refusals without a dedicated code (for example Kubernetes mapping).
pub const VALIDATION_INVALID: &str = "pumgye.validation.invalid";
/// Document schema (deserialization) refusal.
pub const VALIDATION_SCHEMA: &str = "pumgye.validation.schema";
/// A located, coded compile refusal; the code doubles as its message key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyViolation {
    /// Dotted document path (`services.orders.roles.writer`), `$` for the root.
    pub path: String,
    pub code: &'static str,
}
impl PolicyViolation {
    pub fn from_error(error: &anyhow::Error) -> Self {
        let path = error
            .chain()
            .filter_map(|e| e.to_string().strip_prefix("at ").map(str::to_owned))
            .last()
            .unwrap_or_else(|| "$".to_owned());
        let root = error.root_cause().to_string();
        let code = VALIDATION_CODES
            .iter()
            .find(|(text, _)| *text == root)
            .map_or(VALIDATION_INVALID, |(_, code)| code);
        Self { path, code }
    }
}
impl Policy {
    /// Compile, reporting the most specific document path and a registered code.
    pub fn compile_located(&self) -> std::result::Result<CompiledPolicy, PolicyViolation> {
        self.compile().map_err(|e| PolicyViolation::from_error(&e))
    }
    pub fn compile(&self) -> Result<CompiledPolicy> {
        ensure!(
            self.version == 1 && self.services.len() <= 128,
            "invalid version or service count"
        );
        let classes =
            vocabulary(&self.information_classes).with_context(|| at("information_classes"))?;
        let mut services = HashMap::new();
        let mut total_users = 0usize;
        let mut total_networks = 0usize;
        for (id, service) in &self.services {
            let compiled = (|| -> Result<CompiledService> {
            ensure!(
                name(id) && service.roles.len() <= 64,
                "invalid service or role count"
            );
            if service.authorization_context == AuthorizationContext::KubernetesApi {
                ensure!(
                    !service.require_guard
                        && service.networks.is_empty()
                        && service.workload_users.is_empty()
                        && service.human_users.is_empty(),
                    "Kubernetes API context forbids network/guard requirements and typed assignments"
                );
                ensure!(
                    service
                        .users
                        .keys()
                        .all(|subject| kubernetes_api_subject(subject)),
                    "Kubernetes API context requires namespaced API subjects"
                );
            }
            total_users +=
                service.users.len() + service.workload_users.len() + service.human_users.len();
            total_networks += service.networks.len();
            ensure!(
                total_users <= 65536 && total_networks <= 65536,
                "policy assignment limit"
            );
            let permissions = vocabulary(&service.permissions)
                .with_context(|| at(format!("services.{id}.permissions")))?;
            ensure!(!service.roles.contains_key("guest"), "guest is reserved");
            let mut roles = HashMap::from([("guest".to_owned(), Rights::default())]);
            for role in service.roles.keys() {
                (|| -> Result<()> {
                    ensure!(name(role), "invalid role name");
                    resolve_role(
                        role,
                        service,
                        &permissions,
                        &classes,
                        &mut BTreeSet::new(),
                        &mut roles,
                    )?;
                    Ok(())
                })()
                .with_context(|| at(format!("services.{id}.roles.{role}")))?;
            }
            let mut users = HashMap::new();
            for (subject, ids) in &service.users {
                let rights = (|| {
                    ensure!(name(subject), "invalid subject");
                    assignment(ids, &roles)
                })()
                .with_context(|| at(format!("services.{id}.users.{subject}")))?;
                users.insert(subject.clone(), rights);
            }
            let mut workload_users = HashMap::new();
            for (subject, ids) in &service.workload_users {
                let rights = (|| {
                    ensure!(workload_subject(subject), "invalid workload subject");
                    assignment(ids, &roles)
                })()
                .with_context(|| at(format!("services.{id}.workload_users.{subject}")))?;
                workload_users.insert(subject.clone(), rights);
            }
            let mut human_users = HashMap::new();
            for (subject, ids) in &service.human_users {
                let rights = (|| {
                    HumanSubject::parse(subject)?;
                    assignment(ids, &roles)
                })()
                .with_context(|| at(format!("services.{id}.human_users.{subject}")))?;
                human_users.insert(subject.clone(), rights);
            }
            let mut networks = PrefixTrie::default();
            let mut hosts = HashMap::new();
            let mut network_rules = Vec::with_capacity(service.networks.len());
            for (rule, network) in service.networks.iter().enumerate() {
                (|| -> Result<()> {
                let cidr = network.cidr.trunc();
                ensure!(cidr == network.cidr, "network has host bits");
                let rights = assignment(&network.roles, &roles)?;
                network_rules.push(rights);
                let rights = NetworkRights {
                    permissions: rights.permissions,
                    classes: rights.classes,
                    aal: rights.aal,
                    rule: u32::try_from(rule)?,
                };
                let exact = matches!(cidr, IpNet::V4(n) if n.prefix_len() == 32)
                    || matches!(cidr, IpNet::V6(n) if n.prefix_len() == 128);
                let previous = if exact {
                    hosts.insert(cidr.addr().to_canonical(), rights)
                } else {
                    networks.insert(cidr, rights)
                };
                ensure!(previous.is_none(), "duplicate network");
                Ok(())
                })()
                .with_context(|| at(format!("services.{id}.networks[{rule}]")))?;
            }
            Ok(CompiledService {
                    permissions,
                    users,
                    workload_users,
                    human_users,
                    networks,
                    hosts,
                    network_rules,
                    require_guard: service.require_guard,
                    authorization_context: service.authorization_context,
                })
            })()
            .with_context(|| at(format!("services.{id}")))?;
            services.insert(id.clone(), compiled);
        }
        ensure!(self.resources.len() <= 65536, "resource catalog capacity");
        let mut resources = HashMap::new();
        let mut total_actions = 0usize;
        for (id, resource) in &self.resources {
            let compiled = (|| -> Result<CompiledResource> {
                ensure!(
                    name(id)
                        && resource.minimum_aal <= 3
                        && !resource.actions.is_empty()
                        && resource.actions.len() <= 64,
                    "invalid resource metadata"
                );
                total_actions += resource.actions.len();
                ensure!(total_actions <= 65536, "resource action capacity");
                let service = services
                    .get(&resource.service)
                    .ok_or_else(|| anyhow::anyhow!("unknown resource service"))?;
                let class = *classes
                    .get(&resource.information_class)
                    .ok_or_else(|| anyhow::anyhow!("unknown resource class"))?;
                let mut actions = HashMap::new();
                for (action, permission) in &resource.actions {
                    let bit = (|| {
                        ensure!(name(action), "invalid resource action");
                        service
                            .permissions
                            .get(permission)
                            .copied()
                            .ok_or_else(|| anyhow::anyhow!("unknown resource permission"))
                    })()
                    .with_context(|| at(format!("resources.{id}.actions.{action}")))?;
                    actions.insert(action.clone(), bit);
                }
                Ok(CompiledResource {
                    metadata: resource.clone(),
                    actions,
                    class,
                })
            })()
            .with_context(|| at(format!("resources.{id}")))?;
            resources.insert(id.clone(), compiled);
        }
        let mut compiled = CompiledPolicy {
            services,
            classes,
            resources,
            kubernetes_authorization: Default::default(),
        };
        if let Some(mapping) = &self.kubernetes_authorization {
            compiled.kubernetes_authorization = mapping
                .compile(&compiled)
                .with_context(|| at("kubernetes_authorization"))?;
        }
        Ok(compiled)
    }
}
#[derive(Clone, Copy)]
enum Principal<'a> {
    Legacy(&'a str),
    Workload(&'a str),
    Human(&'a str),
}
impl<'a> Principal<'a> {
    #[inline(always)]
    fn lookup(self, service: &CompiledService) -> (SubjectMap, &'a str, Option<&Rights>) {
        match self {
            Principal::Legacy(s) => (SubjectMap::Users, s, service.users.get(s)),
            Principal::Workload(s) => (SubjectMap::WorkloadUsers, s, service.workload_users.get(s)),
            Principal::Human(s) => (SubjectMap::HumanUsers, s, service.human_users.get(s)),
        }
    }
}
/// The one network-and-guard evaluation function. Every gateway entrypoint and
/// explain reach it; only the tracer type differs.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn evaluate_rights<'a, T: Tracer<'a>>(
    service: &CompiledService,
    principal: Principal<'a>,
    ip: IpAddr,
    permission: impl FnOnce() -> Option<u64>,
    class: impl FnOnce() -> Option<u64>,
    assurance: (u8, u8),
    guard: GuardEvidence,
    trace: &mut T,
) -> Decision {
    trace.event(TraceEvent::Context {
        context: service.authorization_context,
        required: AuthorizationContext::NetworkAndGuard,
    });
    if service.authorization_context != AuthorizationContext::NetworkAndGuard {
        return Decision::PermissionDenied;
    }
    trace.event(TraceEvent::Guard {
        evidence: guard,
        require_guard: service.require_guard,
    });
    if guard == GuardEvidence::Deny {
        return Decision::GuardDenied;
    }
    if service.require_guard && guard != GuardEvidence::EnforcedAllow {
        return Decision::GuardUnavailable;
    }
    let (map, subject, user) = principal.lookup(service);
    trace.event(TraceEvent::Subject {
        map,
        subject,
        rights: user.map(|u| u.view()),
    });
    let Some(user) = user else {
        return Decision::Guest;
    };
    if user.permissions == 0 {
        return Decision::Guest;
    }
    let network = service
        .hosts
        .get(&ip.to_canonical())
        .map(|n| (n, true))
        .or_else(|| service.networks.longest(ip).map(|n| (n, false)));
    trace.event(TraceEvent::Network {
        ip,
        matched: network.map(|(n, exact_host)| NetworkMatch {
            rule: n.rule,
            exact_host,
            rights: n.rights().view(),
        }),
    });
    let Some((network, _)) = network else {
        return Decision::NetworkGuest;
    };
    let network = network.rights();
    let effective = Rights {
        permissions: user.permissions & network.permissions,
        classes: user.classes & network.classes,
        aal: user.aal.max(network.aal),
    };
    trace.event(TraceEvent::Entitlements {
        subject: user.view(),
        network: Some(network.view()),
        effective: effective.view(),
    });
    evaluate_entitlements(effective, permission, class, assurance, trace)
}
#[inline(always)]
fn evaluate_entitlements<'a, T: Tracer<'a>>(
    rights: Rights,
    permission: impl FnOnce() -> Option<u64>,
    class: impl FnOnce() -> Option<u64>,
    assurance: (u8, u8),
    trace: &mut T,
) -> Decision {
    let permission = permission();
    trace.event(TraceEvent::Permission {
        requested: permission,
        granted: rights.permissions,
    });
    let Some(permission) = permission else {
        return Decision::PermissionDenied;
    };
    if rights.permissions & permission == 0 {
        return Decision::PermissionDenied;
    }
    let class = class();
    trace.event(TraceEvent::Class {
        requested: class,
        granted: rights.classes,
    });
    let Some(class) = class else {
        return Decision::ClassDenied;
    };
    if rights.classes & class == 0 {
        return Decision::ClassDenied;
    }
    trace.event(TraceEvent::Assurance {
        presented: assurance.0,
        role_minimum: rights.aal,
        resource_minimum: assurance.1,
    });
    if assurance.0 > 3 || assurance.0 < rights.aal.max(assurance.1) {
        return Decision::AssuranceDenied;
    }
    Decision::Allow
}
impl CompiledPolicy {
    /// Evaluate an explicitly network-free Kubernetes API catalog context at AAL0.
    /// The caller must authenticate the API server, resolve an exact server-owned
    /// identity/resource mapping, and fence the current policy/source publication.
    /// This pure compiler method establishes none of those facts. Ordinary services
    /// never enter this path, and it creates no receipt or permission capability.
    pub fn evaluate_kubernetes_api_resource(
        &self,
        service: &str,
        resource: &str,
        action: &str,
        subject: KubernetesApiSubject<'_>,
    ) -> ResourceDecision {
        self.evaluate_kubernetes_api_resource_traced(
            service,
            resource,
            action,
            subject,
            &mut NoTrace,
        )
    }
    /// [`Self::evaluate_kubernetes_api_resource`] with an explain trace sink.
    pub fn evaluate_kubernetes_api_resource_traced<'a, T: Tracer<'a>>(
        &'a self,
        service: &'a str,
        resource: &'a str,
        action: &'a str,
        subject: KubernetesApiSubject<'a>,
        trace: &mut T,
    ) -> ResourceDecision {
        let resource = match self.resource_scope(service, resource, trace) {
            Ok(resource) => resource,
            Err(decision) => return decision,
        };
        let compiled_service = &self.services[&resource.metadata.service];
        trace.event(TraceEvent::Context {
            context: compiled_service.authorization_context,
            required: AuthorizationContext::KubernetesApi,
        });
        if compiled_service.authorization_context != AuthorizationContext::KubernetesApi {
            return ResourceDecision::Decided(Decision::PermissionDenied);
        }
        let permission = resource.actions.get(action);
        trace.event(TraceEvent::Action {
            action,
            permission: permission.copied(),
        });
        let Some(permission) = permission else {
            return ResourceDecision::UnknownAction;
        };
        let user = compiled_service.users.get(subject.as_str());
        trace.event(TraceEvent::Subject {
            map: SubjectMap::Users,
            subject: subject.as_str(),
            rights: user.map(|u| u.view()),
        });
        let Some(user) = user.filter(|user| user.permissions != 0) else {
            return ResourceDecision::Decided(Decision::Guest);
        };
        trace.event(TraceEvent::Entitlements {
            subject: user.view(),
            network: None,
            effective: user.view(),
        });
        ResourceDecision::Decided(evaluate_entitlements(
            *user,
            || Some(*permission),
            || Some(resource.class),
            (0, resource.metadata.minimum_aal),
            trace,
        ))
    }
    pub fn resource_metadata(&self, resource: &str) -> Option<&Resource> {
        self.resources.get(resource).map(|r| &r.metadata)
    }
    #[inline(always)]
    fn resource_lookup<'a, T: Tracer<'a>>(
        &'a self,
        resource: &'a str,
        trace: &mut T,
    ) -> Result<&'a CompiledResource, ResourceDecision> {
        let found = self.resources.get(resource);
        trace.event(TraceEvent::Resource {
            resource,
            owner: found.map(|r| r.metadata.service.as_str()),
        });
        found.ok_or(ResourceDecision::UnknownResource)
    }
    #[inline(always)]
    fn resource_scope<'a, T: Tracer<'a>>(
        &'a self,
        service: &'a str,
        resource: &'a str,
        trace: &mut T,
    ) -> Result<&'a CompiledResource, ResourceDecision> {
        let resource = self.resource_lookup(resource, trace)?;
        trace.event(TraceEvent::Scope {
            requested: service,
            owner: &resource.metadata.service,
        });
        if resource.metadata.service != service {
            return Err(ResourceDecision::Decided(Decision::UnknownService));
        }
        Ok(resource)
    }
    /// Bind a native gateway service scope to the catalog before evaluating rights.
    /// Callers must obtain the service from trusted route/authentication context.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_scoped_resource(
        &self,
        service: &str,
        resource: &str,
        action: &str,
        subject: &str,
        ip: IpAddr,
        aal: u8,
        guard: GuardEvidence,
    ) -> ResourceDecision {
        self.evaluate_scoped_resource_traced(
            service,
            resource,
            action,
            subject,
            ip,
            aal,
            guard,
            &mut NoTrace,
        )
    }
    /// [`Self::evaluate_scoped_resource`] with an explain trace sink.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_scoped_resource_traced<'a, T: Tracer<'a>>(
        &'a self,
        service: &'a str,
        resource: &'a str,
        action: &'a str,
        subject: &'a str,
        ip: IpAddr,
        aal: u8,
        guard: GuardEvidence,
        trace: &mut T,
    ) -> ResourceDecision {
        let resource = match self.resource_scope(service, resource, trace) {
            Ok(resource) => resource,
            Err(decision) => return decision,
        };
        self.evaluate_catalog_entry(
            resource,
            action,
            Principal::Legacy(subject),
            ip,
            aal,
            guard,
            trace,
        )
    }
    /// Resource class and minimum assurance are owned by the compiled catalog.
    pub fn evaluate_resource(
        &self,
        resource: &str,
        action: &str,
        subject: &str,
        ip: IpAddr,
        aal: u8,
        guard: GuardEvidence,
    ) -> ResourceDecision {
        let mut trace = NoTrace;
        let resource = match self.resource_lookup(resource, &mut trace) {
            Ok(resource) => resource,
            Err(decision) => return decision,
        };
        self.evaluate_catalog_entry(
            resource,
            action,
            Principal::Legacy(subject),
            ip,
            aal,
            guard,
            &mut trace,
        )
    }
    /// Native Workload-only resource evaluation. The caller must authenticate the
    /// Workload and bind service/subject before using this deterministic compiler.
    /// Workloads have AAL0; client assurance claims cannot elevate this entrypoint.
    /// Legacy `users` assignments are never consulted.
    pub fn evaluate_scoped_workload_resource(
        &self,
        service: &str,
        resource: &str,
        action: &str,
        subject: &str,
        ip: IpAddr,
        guard: GuardEvidence,
    ) -> ResourceDecision {
        self.evaluate_scoped_workload_resource_traced(
            service,
            resource,
            action,
            subject,
            ip,
            guard,
            &mut NoTrace,
        )
    }
    /// [`Self::evaluate_scoped_workload_resource`] with an explain trace sink.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_scoped_workload_resource_traced<'a, T: Tracer<'a>>(
        &'a self,
        service: &'a str,
        resource: &'a str,
        action: &'a str,
        subject: &'a str,
        ip: IpAddr,
        guard: GuardEvidence,
        trace: &mut T,
    ) -> ResourceDecision {
        let resource = match self.resource_scope(service, resource, trace) {
            Ok(resource) => resource,
            Err(decision) => return decision,
        };
        self.evaluate_catalog_entry(
            resource,
            action,
            Principal::Workload(subject),
            ip,
            0,
            guard,
            trace,
        )
    }
    /// Pure scoped Human metadata evaluation; callers own actual authentication.
    /// Only actual verified AAL1/2 may be supplied at an enforcement boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_scoped_human_resource(
        &self,
        service: &str,
        resource: &str,
        action: &str,
        subject: &str,
        ip: IpAddr,
        aal: u8,
        guard: GuardEvidence,
    ) -> ResourceDecision {
        self.evaluate_scoped_human_resource_traced(
            service,
            resource,
            action,
            subject,
            ip,
            aal,
            guard,
            &mut NoTrace,
        )
    }
    /// [`Self::evaluate_scoped_human_resource`] with an explain trace sink.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_scoped_human_resource_traced<'a, T: Tracer<'a>>(
        &'a self,
        service: &'a str,
        resource: &'a str,
        action: &'a str,
        subject: &'a str,
        ip: IpAddr,
        aal: u8,
        guard: GuardEvidence,
        trace: &mut T,
    ) -> ResourceDecision {
        self.evaluate_scoped_human_assurance_traced(
            service,
            resource,
            action,
            subject,
            ip,
            HumanAssurance::Asserted(aal),
            guard,
            trace,
        )
    }
    /// Human evaluation with assurance from Hopae-sealed evidence: AAL3 is only
    /// accepted from a verified receipt or permission context (Hopae ADR-0018
    /// decision 11), never from an adapter-asserted level.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_scoped_human_sealed_resource(
        &self,
        service: &str,
        resource: &str,
        action: &str,
        subject: &str,
        ip: IpAddr,
        aal: SealedAssurance,
        guard: GuardEvidence,
    ) -> ResourceDecision {
        self.evaluate_scoped_human_assurance_traced(
            service,
            resource,
            action,
            subject,
            ip,
            HumanAssurance::Sealed(aal),
            guard,
            &mut NoTrace,
        )
    }
    /// The one Human evaluation function for both assurance sources.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_scoped_human_assurance_traced<'a, T: Tracer<'a>>(
        &'a self,
        service: &'a str,
        resource: &'a str,
        action: &'a str,
        subject: &'a str,
        ip: IpAddr,
        assurance: HumanAssurance,
        guard: GuardEvidence,
        trace: &mut T,
    ) -> ResourceDecision {
        let aal = assurance.level();
        let resource = match self.resource_scope(service, resource, trace) {
            Ok(resource) => resource,
            Err(decision) => return decision,
        };
        let context = self.services[service].authorization_context;
        trace.event(TraceEvent::Context {
            context,
            required: AuthorizationContext::NetworkAndGuard,
        });
        if context != AuthorizationContext::NetworkAndGuard {
            return ResourceDecision::Decided(Decision::UnknownService);
        }
        let valid = HumanSubject::parse(subject).is_ok();
        trace.event(TraceEvent::PrincipalFormat { valid });
        if !valid {
            return ResourceDecision::Decided(Decision::Guest);
        }
        trace.event(TraceEvent::PrincipalAssurance { aal });
        if !assurance.in_range() {
            return ResourceDecision::Decided(Decision::AssuranceDenied);
        }
        self.evaluate_catalog_entry(
            resource,
            action,
            Principal::Human(subject),
            ip,
            aal,
            guard,
            trace,
        )
    }
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn evaluate_catalog_entry<'a, T: Tracer<'a>>(
        &'a self,
        resource: &'a CompiledResource,
        action: &'a str,
        subject: Principal<'a>,
        ip: IpAddr,
        aal: u8,
        guard: GuardEvidence,
        trace: &mut T,
    ) -> ResourceDecision {
        let permission = resource.actions.get(action);
        trace.event(TraceEvent::Action {
            action,
            permission: permission.copied(),
        });
        let Some(permission) = permission else {
            return ResourceDecision::UnknownAction;
        };
        let service = &self.services[&resource.metadata.service];
        ResourceDecision::Decided(evaluate_rights(
            service,
            subject,
            ip,
            || Some(*permission),
            || Some(resource.class),
            (aal, resource.metadata.minimum_aal),
            guard,
            trace,
        ))
    }
    /// Allocation-free evaluation over immutable policy. Never accept client claims as evidence.
    // Explicit trusted evidence and route scope remain separate at the enforcement boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        service_id: &str,
        subject: &str,
        ip: IpAddr,
        permission: &str,
        information_class: &str,
        aal: u8,
        guard: GuardEvidence,
    ) -> Decision {
        self.evaluate_traced(
            service_id,
            subject,
            ip,
            permission,
            information_class,
            aal,
            guard,
            &mut NoTrace,
        )
    }
    /// [`Self::evaluate`] with an explain trace sink. Identical decision function.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_traced<'a, T: Tracer<'a>>(
        &'a self,
        service_id: &'a str,
        subject: &'a str,
        ip: IpAddr,
        permission: &'a str,
        information_class: &'a str,
        aal: u8,
        guard: GuardEvidence,
        trace: &mut T,
    ) -> Decision {
        let service = self.services.get(service_id);
        trace.event(TraceEvent::Service {
            service: service_id,
            found: service.is_some(),
        });
        let Some(service) = service else {
            return Decision::UnknownService;
        };
        evaluate_rights(
            service,
            Principal::Legacy(subject),
            ip,
            || service.permissions.get(permission).copied(),
            || self.classes.get(information_class).copied(),
            (aal, 0),
            guard,
            trace,
        )
    }
}
