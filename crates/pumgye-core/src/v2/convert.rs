//! Deterministic policy v1 → v2 converter (ADR 0021 "Migration from policy version 1").
//!
//! Fail closed: subjects whose kind cannot be established are reported and not
//! migrated; class sets that are not downward closed in the proposed Catalog order
//! are narrowed (never widened) and reported for review; Kubernetes API services
//! stay on version 1 (ADR 0022). Output order and identifiers are deterministic.
use super::*;
use crate::{Policy, Service};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ReviewItem {
    pub code: &'static str,
    pub path: String,
    pub detail: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unmigrated {
    pub path: String,
    pub subject: String,
    pub reason: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ZoneProposal {
    /// Proposed Sumunjang `NetworkZone` name (owner: Sumunjang).
    pub zone: String,
    pub service: String,
    pub prefixes: Vec<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Structurally identical templates from different services (merge only on confirmation).
    pub merge_candidates: Vec<Vec<String>>,
    pub zone_proposals: Vec<ZoneProposal>,
    /// Proposed Catalog level order (the v1 vocabulary order) for the Catalog owner.
    pub catalog_levels: Vec<String>,
    pub review: Vec<ReviewItem>,
    pub unmigrated: Vec<Unmigrated>,
    /// Services retained on version 1 (Kubernetes API context, ADR 0022).
    pub retained_v1: Vec<String>,
    pub bindings: usize,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Conversion {
    pub document: PolicyV2,
    pub report: Report,
}
/// Converter inputs that only owners can supply.
pub struct ConvertOptions<'a> {
    /// Kind of a generic `users` subject (Hopae lookup). `None`: not migrated.
    pub classify: &'a dyn Fn(&str) -> Option<PrincipalKind>,
    /// Administrator-confirmed legacy workload subject → `wk2:` principal.
    pub workload_mapping: &'a BTreeMap<String, String>,
}
/// Prefix-only classification for offline previews: `s_` service principals and
/// `human1:` Humans; anything else is unresolved (fail closed).
pub fn classify_by_prefix(subject: &str) -> Option<PrincipalKind> {
    if principal_ref_valid(PrincipalKind::Service, subject) {
        Some(PrincipalKind::Service)
    } else if principal_ref_valid(PrincipalKind::Human, subject) {
        Some(PrincipalKind::Human)
    } else if subject.starts_with("wk2:") && principal_ref_valid(PrincipalKind::Workload, subject) {
        Some(PrincipalKind::Workload)
    } else {
        None
    }
}
fn fnv(parts: &[&str]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for p in parts {
        for b in p.bytes().chain([0xff]) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}
fn role_closure<'a>(service: &'a Service, role: &'a str, out: &mut BTreeSet<&'a str>) {
    if role == "guest" || !out.insert(role) {
        return;
    }
    if let Some(r) = service.roles.get(role) {
        for p in &r.inherits {
            role_closure(service, p, out);
        }
    }
}
fn closure_aal(service: &Service, roles: &[String]) -> u8 {
    let mut set = BTreeSet::new();
    for r in roles {
        role_closure(service, r, &mut set);
    }
    set.iter()
        .filter_map(|r| service.roles.get(*r))
        .map(|r| r.minimum_aal)
        .max()
        .unwrap_or(0)
}

/// Base level used when v1 classes are carried as compartments.
pub const BASE_LEVEL: &str = "v1.base";
pub fn convert(v1: &Policy, options: &ConvertOptions<'_>) -> Result<Conversion> {
    v1.compile()
        .context("version 1 document must compile before conversion")?;
    let mut report = Report {
        catalog_levels: v1.information_classes.clone(),
        ..Default::default()
    };
    let order: HashMap<&str, usize> = v1
        .information_classes
        .iter()
        .enumerate()
        .map(|(i, c)| (c.as_str(), i))
        .collect();
    // Levels when every role's class closure is downward closed in the vocabulary
    // order; otherwise each v1 class becomes a compartment under one base level,
    // which reproduces v1's unordered class membership per template exactly.
    let compartment_mode = v1.services.values().any(|service| {
        service.authorization_context != AuthorizationContext::KubernetesApi
            && service.roles.keys().any(|rid| {
                let mut closure = BTreeSet::new();
                role_closure(service, rid, &mut closure);
                let classes: BTreeSet<usize> = closure
                    .iter()
                    .filter_map(|r| service.roles.get(*r))
                    .flat_map(|r| r.information_classes.iter().map(|c| order[c.as_str()]))
                    .collect();
                (0..).take_while(|i| classes.contains(i)).count() != classes.len()
            })
    });
    if compartment_mode {
        report.review.push(ReviewItem {
            code: "pumgye.migration.class_compartments",
            path: "information_classes".into(),
            detail: format!(
                "some role class sets are not downward closed in {:?}; each class became a compartment under level {BASE_LEVEL} until the Catalog owner defines levels",
                v1.information_classes
            ),
        });
    }
    let mut document = PolicyV2 {
        version: 2,
        catalog: Catalog {
            revision: 0,
            levels: if compartment_mode {
                vec![BASE_LEVEL.into()]
            } else {
                v1.information_classes.clone()
            },
            compartments: if compartment_mode {
                v1.information_classes.clone()
            } else {
                vec![]
            },
            resources: BTreeMap::new(),
        },
        zones: Zones::default(),
        templates: BTreeMap::new(),
        services: BTreeMap::new(),
        bindings: vec![],
    };
    let mut ids = BTreeSet::new();
    let mut signatures: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (sid, service) in &v1.services {
        if service.authorization_context == AuthorizationContext::KubernetesApi {
            report.retained_v1.push(sid.clone());
            continue;
        }
        // Templates `<service>.<role>`
        for (rid, role) in &service.roles {
            let tid = format!("{sid}.{rid}");
            let mut closure = BTreeSet::new();
            role_closure(service, rid, &mut closure);
            let classes: BTreeSet<usize> = closure
                .iter()
                .filter_map(|r| service.roles.get(*r))
                .flat_map(|r| r.information_classes.iter().map(|c| order[c.as_str()]))
                .collect();
            let clearance = if compartment_mode {
                (!classes.is_empty()).then(|| Clearance {
                    level: BASE_LEVEL.into(),
                    compartments: classes
                        .iter()
                        .map(|i| v1.information_classes[*i].clone())
                        .collect(),
                })
            } else {
                let prefix = (0..).take_while(|i| classes.contains(i)).count();
                (prefix > 0).then(|| Clearance {
                    level: v1.information_classes[prefix - 1].clone(),
                    compartments: vec![],
                })
            };
            let template = RoleTemplate {
                permissions: role.permissions.clone(),
                inherits: role
                    .inherits
                    .iter()
                    .filter(|p| *p != "guest")
                    .map(|p| format!("{sid}.{p}"))
                    .collect(),
                clearance_ceiling: clearance,
                minimum_aal: role.minimum_aal,
            };
            let signature = format!(
                "{:?}|{:?}|{}|{:?}",
                template.permissions,
                template.clearance_ceiling,
                template.minimum_aal,
                role.inherits
            );
            signatures.entry(signature).or_default().push(tid.clone());
            document.templates.insert(tid, template);
        }
        // Networks → zones (one per distinct role set) + ceilings.
        let mut by_roles: BTreeMap<Vec<String>, Vec<IpNet>> = BTreeMap::new();
        for n in &service.networks {
            let mut roles = n.roles.clone();
            roles.sort();
            by_roles.entry(roles).or_default().push(n.cidr);
        }
        let mut ceilings = Vec::new();
        for (n, (roles, prefixes)) in by_roles.into_iter().enumerate() {
            let zone = format!("legacy.{sid}.{n}");
            report.zone_proposals.push(ZoneProposal {
                zone: zone.clone(),
                service: sid.clone(),
                prefixes: prefixes.iter().map(ToString::to_string).collect(),
            });
            document.zones.zones.insert(zone.clone(), Zone { prefixes });
            let templates: Vec<String> = roles
                .iter()
                .filter(|r| *r != "guest")
                .map(|r| format!("{sid}.{r}"))
                .collect();
            // Ceiling assurance in v1 is the maximum over the rule's roles.
            let aal = closure_aal(service, &roles);
            ceilings.push((zone, templates, aal));
        }
        let network_ceiling = ceilings
            .into_iter()
            .map(|(zone, templates, _aal)| Ceiling {
                zone,
                max: if templates.is_empty() {
                    CeilingMax::One("guest".into())
                } else {
                    CeilingMax::Many(templates)
                },
            })
            .collect();
        document.services.insert(
            sid.clone(),
            ServicePolicy {
                permissions: service.permissions.clone(),
                permission_map: BTreeMap::new(),
                network_ceiling,
                require_guard: service.require_guard,
                authorization_context: AuthorizationContext::NetworkAndGuard,
            },
        );
        // Assignments → one allow binding per (subject, role).
        let maps: [(&str, &BTreeMap<String, Vec<String>>); 3] = [
            ("users", &service.users),
            ("workload_users", &service.workload_users),
            ("human_users", &service.human_users),
        ];
        for (map, assignments) in maps {
            for (subject, roles) in assignments {
                let path = format!("services.{sid}.{map}.{subject}");
                let principal = match map {
                    "users" => match (options.classify)(subject) {
                        Some(kind) => (kind, subject.clone()),
                        None => {
                            report.unmigrated.push(Unmigrated {
                                path,
                                subject: subject.clone(),
                                reason: "pumgye.migration.unresolved_subject_kind",
                            });
                            continue;
                        }
                    },
                    "workload_users" => match options.workload_mapping.get(subject) {
                        Some(wk2)
                            if wk2.starts_with("wk2:")
                                && principal_ref_valid(PrincipalKind::Workload, wk2) =>
                        {
                            (PrincipalKind::Workload, wk2.clone())
                        }
                        _ => {
                            report.review.push(ReviewItem {
                                code: "pumgye.migration.legacy_workload",
                                path: path.clone(),
                                detail: "Pod-bound workload kept as a deprecated legacy principal until its ServiceAccount is confirmed".into(),
                            });
                            (PrincipalKind::Workload, subject.clone())
                        }
                    },
                    _ => (PrincipalKind::Human, subject.clone()),
                };
                let roles_live: Vec<&String> = roles.iter().filter(|r| *r != "guest").collect();
                let aal = closure_aal(service, roles);
                if roles_live.len() > 1 {
                    report.review.push(ReviewItem {
                        code: "pumgye.migration.class_union",
                        path: path.clone(),
                        detail: "v1 unions permissions and classes across roles independently; v2 evaluates clearance per granting template".into(),
                    });
                }
                for role in roles_live {
                    let tid = format!("{sid}.{role}");
                    let own = document
                        .templates
                        .get(&tid)
                        .map_or(0, |_| closure_aal(service, std::slice::from_ref(role)));
                    let mut id = format!("bnd_v1_{:016x}", fnv(&[sid, map, subject, role]));
                    let mut n = 0;
                    while !ids.insert(id.clone()) {
                        n += 1;
                        id = format!("bnd_v1_{:016x}_{n}", fnv(&[sid, map, subject, role]));
                    }
                    document.bindings.push(Binding {
                        id,
                        effect: Effect::Allow,
                        subjects: vec![SubjectRef::Principal {
                            kind: principal.0,
                            reference: principal.1.clone(),
                        }],
                        role: Some(tid),
                        permissions: None,
                        scope: Scope {
                            services: Names::List(vec![sid.clone()]),
                        },
                        conditions: Conditions {
                            // v1 requires the maximum AAL over all of the subject's roles.
                            minimum_aal: if aal > own { aal } else { 0 },
                            ..Default::default()
                        },
                        metadata: Metadata {
                            reason: Some(format!("migrated from policy v1 {map}")),
                            source: Some("migrated:v1".into()),
                            ..Default::default()
                        },
                    });
                }
            }
        }
    }
    // Roles whose closure grants nothing are dropped (v2 templates must grant).
    let mut empty: Vec<String> = Vec::new();
    for (sid, service) in &v1.services {
        for rid in service.roles.keys() {
            let mut closure = BTreeSet::new();
            role_closure(service, rid, &mut closure);
            if closure
                .iter()
                .filter_map(|r| service.roles.get(*r))
                .all(|r| r.permissions.is_empty())
            {
                empty.push(format!("{sid}.{rid}"));
            }
        }
    }
    empty.retain(|t| document.templates.contains_key(t));
    for t in &empty {
        // Keep inheritance intact with a placeholder-free template: drop it and its references.
        report.review.push(ReviewItem {
            code: "pumgye.migration.empty_role",
            path: format!("templates.{t}"),
            detail: "role grants no permission; dropped".into(),
        });
    }
    for t in &empty {
        document.templates.remove(t);
    }
    for t in document.templates.values_mut() {
        t.inherits.retain(|p| !empty.contains(p));
    }
    for s in document.services.values_mut() {
        for c in &mut s.network_ceiling {
            if let CeilingMax::Many(list) = &mut c.max {
                list.retain(|t| !empty.contains(t));
                if list.is_empty() {
                    c.max = CeilingMax::One("guest".into());
                }
            }
        }
    }
    document
        .bindings
        .retain(|b| b.role.as_ref().is_none_or(|r| !empty.contains(r)));
    for (id, r) in &v1.resources {
        if report.retained_v1.contains(&r.service) {
            continue;
        }
        document.catalog.resources.insert(
            id.clone(),
            CatalogResource {
                service: r.service.clone(),
                level: if compartment_mode {
                    BASE_LEVEL.into()
                } else {
                    r.information_class.clone()
                },
                compartments: if compartment_mode {
                    vec![r.information_class.clone()]
                } else {
                    vec![]
                },
                minimum_aal: r.minimum_aal,
                actions: r.actions.clone(),
            },
        );
    }
    if v1.kubernetes_authorization.is_some() {
        report.review.push(ReviewItem {
            code: "pumgye.migration.kubernetes_mapping_retained",
            path: "kubernetes_authorization".into(),
            detail: "the Kubernetes RBAC mapping stays an observe/import adapter on version 1 (ADR 0022)".into(),
        });
    }
    report.merge_candidates = signatures.into_values().filter(|v| v.len() > 1).collect();
    report.bindings = document.bindings.len();
    document
        .compile()
        .context("converted document must compile (report a converter defect)")?;
    Ok(Conversion { document, report })
}
