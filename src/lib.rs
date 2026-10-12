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
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub permissions: Vec<String>,
    pub roles: BTreeMap<String, Role>,
    pub users: BTreeMap<String, Vec<String>>,
    pub networks: Vec<Network>,
    #[serde(default = "yes")]
    pub require_guard: bool,
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
}
struct CompiledService {
    permissions: HashMap<String, u64>,
    users: HashMap<String, Rights>,
    networks: PrefixTrie<Rights>,
    require_guard: bool,
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
            total_users += service.users.len();
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
            let mut networks = PrefixTrie::default();
            for network in &service.networks {
                let cidr = network.cidr.trunc();
                ensure!(cidr == network.cidr, "network has host bits");
                ensure!(
                    networks
                        .insert(cidr, assignment(&network.roles, &roles)?)
                        .is_none(),
                    "duplicate network"
                );
            }
            services.insert(
                id.clone(),
                CompiledService {
                    permissions,
                    users,
                    networks,
                    require_guard: service.require_guard,
                },
            );
        }
        Ok(CompiledPolicy { services, classes })
    }
}
impl CompiledPolicy {
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
        if guard == GuardEvidence::Deny {
            return Decision::GuardDenied;
        }
        if service.require_guard && guard != GuardEvidence::EnforcedAllow {
            return Decision::GuardUnavailable;
        }
        let Some(user) = service.users.get(subject) else {
            return Decision::Guest;
        };
        if user.permissions == 0 {
            return Decision::Guest;
        }
        let Some(network) = service.networks.longest(ip) else {
            return Decision::NetworkGuest;
        };
        let Some(permission) = service.permissions.get(permission) else {
            return Decision::PermissionDenied;
        };
        if user.permissions & network.permissions & permission == 0 {
            return Decision::PermissionDenied;
        }
        let Some(class) = self.classes.get(information_class) else {
            return Decision::ClassDenied;
        };
        if user.classes & network.classes & class == 0 {
            return Decision::ClassDenied;
        }
        if aal > 3 || aal < user.aal.max(network.aal) {
            return Decision::AssuranceDenied;
        }
        Decision::Allow
    }
}
