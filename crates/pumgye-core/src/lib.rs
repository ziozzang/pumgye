//! Deterministic authorization. Callers must authenticate identity and network evidence.
use anyhow::{Result, ensure};
use guard_core::prefix::PrefixTrie;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub information_classes: Vec<String>,
    pub services: BTreeMap<String, Service>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, Resource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub permissions: Vec<String>,
    pub roles: BTreeMap<String, Role>,
    pub users: BTreeMap<String, Vec<String>>,
    /// Canonical Hopae Workload subjects only; never falls back to `users`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub workload_users: BTreeMap<String, Vec<String>>,
    pub networks: Vec<Network>,
    #[serde(default = "yes")]
    pub require_guard: bool,
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
    fn union(self, other: Self) -> Self {
        Self {
            permissions: self.permissions | other.permissions,
            classes: self.classes | other.classes,
            aal: self.aal.max(other.aal),
        }
    }
}
pub struct CompiledPolicy {
    services: HashMap<String, CompiledService>,
    classes: HashMap<String, u64>,
    resources: HashMap<String, CompiledResource>,
}
struct CompiledService {
    permissions: HashMap<String, u64>,
    users: HashMap<String, Rights>,
    workload_users: HashMap<String, Rights>,
    networks: PrefixTrie<Rights>,
    hosts: HashMap<IpAddr, Rights>,
    require_guard: bool,
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
impl Policy {
    pub fn compile(&self) -> Result<CompiledPolicy> {
        ensure!(
            self.version == 1 && self.services.len() <= 128,
            "invalid version or service count"
        );
        let classes = vocabulary(&self.information_classes)?;
        let mut services = HashMap::new();
        let mut total_users = 0usize;
        let mut total_networks = 0usize;
        for (id, service) in &self.services {
            ensure!(
                name(id) && service.roles.len() <= 64,
                "invalid service or role count"
            );
            total_users += service.users.len() + service.workload_users.len();
            total_networks += service.networks.len();
            ensure!(
                total_users <= 65536 && total_networks <= 65536,
                "policy assignment limit"
            );
            let permissions = vocabulary(&service.permissions)?;
            ensure!(!service.roles.contains_key("guest"), "guest is reserved");
            let mut roles = HashMap::from([("guest".to_owned(), Rights::default())]);
            for role in service.roles.keys() {
                ensure!(name(role), "invalid role name");
                resolve_role(
                    role,
                    service,
                    &permissions,
                    &classes,
                    &mut BTreeSet::new(),
                    &mut roles,
                )?;
            }
            let mut users = HashMap::new();
            for (subject, ids) in &service.users {
                ensure!(name(subject), "invalid subject");
                users.insert(subject.clone(), assignment(ids, &roles)?);
            }
            let mut workload_users = HashMap::new();
            for (subject, ids) in &service.workload_users {
                ensure!(workload_subject(subject), "invalid workload subject");
                workload_users.insert(subject.clone(), assignment(ids, &roles)?);
            }
            let mut networks = PrefixTrie::default();
            let mut hosts = HashMap::new();
            for network in &service.networks {
                let cidr = network.cidr.trunc();
                ensure!(cidr == network.cidr, "network has host bits");
                let rights = assignment(&network.roles, &roles)?;
                let exact = matches!(cidr, IpNet::V4(n) if n.prefix_len() == 32)
                    || matches!(cidr, IpNet::V6(n) if n.prefix_len() == 128);
                let previous = if exact {
                    hosts.insert(cidr.addr().to_canonical(), rights)
                } else {
                    networks.insert(cidr, rights)
                };
                ensure!(previous.is_none(), "duplicate network");
            }
            services.insert(
                id.clone(),
                CompiledService {
                    permissions,
                    users,
                    workload_users,
                    networks,
                    hosts,
                    require_guard: service.require_guard,
                },
            );
        }
        ensure!(self.resources.len() <= 65536, "resource catalog capacity");
        let mut resources = HashMap::new();
        let mut total_actions = 0usize;
        for (id, resource) in &self.resources {
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
                ensure!(name(action), "invalid resource action");
                actions.insert(
                    action.clone(),
                    *service
                        .permissions
                        .get(permission)
                        .ok_or_else(|| anyhow::anyhow!("unknown resource permission"))?,
                );
            }
            resources.insert(
                id.clone(),
                CompiledResource {
                    metadata: resource.clone(),
                    actions,
                    class,
                },
            );
        }
        Ok(CompiledPolicy {
            services,
            classes,
            resources,
        })
    }
}
enum Principal<'a> {
    Legacy(&'a str),
    Workload(&'a str),
}
fn evaluate_rights(
    service: &CompiledService,
    user: Option<&Rights>,
    ip: IpAddr,
    permission: impl FnOnce() -> Option<u64>,
    class: impl FnOnce() -> Option<u64>,
    assurance: (u8, u8),
    guard: GuardEvidence,
) -> Decision {
    if guard == GuardEvidence::Deny {
        return Decision::GuardDenied;
    }
    if service.require_guard && guard != GuardEvidence::EnforcedAllow {
        return Decision::GuardUnavailable;
    }
    let Some(user) = user else {
        return Decision::Guest;
    };
    if user.permissions == 0 {
        return Decision::Guest;
    }
    let Some(network) = service
        .hosts
        .get(&ip.to_canonical())
        .or_else(|| service.networks.longest(ip))
    else {
        return Decision::NetworkGuest;
    };
    let Some(permission) = permission() else {
        return Decision::PermissionDenied;
    };
    if user.permissions & network.permissions & permission == 0 {
        return Decision::PermissionDenied;
    }
    let Some(class) = class() else {
        return Decision::ClassDenied;
    };
    if user.classes & network.classes & class == 0 {
        return Decision::ClassDenied;
    }
    if assurance.0 > 3 || assurance.0 < user.aal.max(network.aal).max(assurance.1) {
        return Decision::AssuranceDenied;
    }
    Decision::Allow
}
impl CompiledPolicy {
    pub fn resource_metadata(&self, resource: &str) -> Option<&Resource> {
        self.resources.get(resource).map(|r| &r.metadata)
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
        let Some(resource) = self.resources.get(resource) else {
            return ResourceDecision::UnknownResource;
        };
        if resource.metadata.service != service {
            return ResourceDecision::Decided(Decision::UnknownService);
        }
        self.evaluate_catalog_entry(resource, action, Principal::Legacy(subject), ip, aal, guard)
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
        let Some(resource) = self.resources.get(resource) else {
            return ResourceDecision::UnknownResource;
        };
        self.evaluate_catalog_entry(resource, action, Principal::Legacy(subject), ip, aal, guard)
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
        let Some(resource) = self.resources.get(resource) else {
            return ResourceDecision::UnknownResource;
        };
        if resource.metadata.service != service {
            return ResourceDecision::Decided(Decision::UnknownService);
        }
        self.evaluate_catalog_entry(resource, action, Principal::Workload(subject), ip, 0, guard)
    }
    fn evaluate_catalog_entry(
        &self,
        resource: &CompiledResource,
        action: &str,
        subject: Principal<'_>,
        ip: IpAddr,
        aal: u8,
        guard: GuardEvidence,
    ) -> ResourceDecision {
        let Some(permission) = resource.actions.get(action) else {
            return ResourceDecision::UnknownAction;
        };
        let service = &self.services[&resource.metadata.service];
        ResourceDecision::Decided(evaluate_rights(
            service,
            match subject {
                Principal::Legacy(subject) => service.users.get(subject),
                Principal::Workload(subject) => service.workload_users.get(subject),
            },
            ip,
            || Some(*permission),
            || Some(resource.class),
            (aal, resource.metadata.minimum_aal),
            guard,
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
        let Some(service) = self.services.get(service_id) else {
            return Decision::UnknownService;
        };
        evaluate_rights(
            service,
            service.users.get(subject),
            ip,
            || service.permissions.get(permission).copied(),
            || self.classes.get(information_class).copied(),
            (aal, 0),
            guard,
        )
    }
}
