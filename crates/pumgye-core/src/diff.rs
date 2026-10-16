//! Candidate impact diff: which compiled rights change if a document is published.
//!
//! Comparison is by *names* after role expansion (a reordered vocabulary is not a
//! change), over the effective rights each assignment and network rule compiles
//! to. Output order is deterministic so callers can paginate with an offset cursor
//! over an identical candidate.
use crate::{
    AuthorizationContext, CompiledPolicy, CompiledService, Policy, Rights, Service,
    explain::{RightsNames, bits},
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceSummary {
    pub authorization_context: AuthorizationContext,
    pub require_guard: bool,
    pub permissions: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResourceSummary {
    pub service: String,
    pub information_class: String,
    pub minimum_aal: u8,
    pub actions: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RightsDelta {
    pub added_permissions: Vec<String>,
    pub removed_permissions: Vec<String>,
    pub added_information_classes: Vec<String>,
    pub removed_information_classes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_aal: Option<(u8, u8)>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "entity", rename_all = "snake_case")]
pub enum Change {
    InformationClasses {
        added: Vec<String>,
        removed: Vec<String>,
    },
    Service {
        service: String,
        change: ChangeKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        before: Option<ServiceSummary>,
        #[serde(skip_serializing_if = "Option::is_none")]
        after: Option<ServiceSummary>,
    },
    Assignment {
        service: String,
        map: &'static str,
        subject: String,
        change: ChangeKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        before: Option<RightsNames>,
        #[serde(skip_serializing_if = "Option::is_none")]
        after: Option<RightsNames>,
        delta: RightsDelta,
    },
    Network {
        service: String,
        cidr: String,
        change: ChangeKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        before: Option<RightsNames>,
        #[serde(skip_serializing_if = "Option::is_none")]
        after: Option<RightsNames>,
        delta: RightsDelta,
    },
    Resource {
        resource: String,
        change: ChangeKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        before: Option<ResourceSummary>,
        #[serde(skip_serializing_if = "Option::is_none")]
        after: Option<ResourceSummary>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiffPage {
    /// Total changes over the whole comparison.
    pub total: usize,
    pub changes: Vec<Change>,
    /// Offset for the next page, absent at the end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<usize>,
}
/// One side of the comparison.
#[derive(Clone, Copy)]
pub struct Side<'a> {
    pub policy: &'a Policy,
    pub compiled: &'a CompiledPolicy,
}
struct Pager {
    cursor: usize,
    limit: usize,
    index: usize,
    out: Vec<Change>,
}
impl Pager {
    fn push(&mut self, change: impl FnOnce() -> Change) {
        if self.index >= self.cursor && self.out.len() < self.limit {
            self.out.push(change());
        }
        self.index += 1;
    }
}
fn names(policy: &Policy, service: &Service, rights: Rights) -> RightsNames {
    let mut permissions = bits(&service.permissions, rights.permissions);
    let mut information_classes = bits(&policy.information_classes, rights.classes);
    permissions.sort();
    information_classes.sort();
    RightsNames {
        permissions,
        information_classes,
        minimum_aal: rights.aal,
    }
}
fn set_delta(before: &[String], after: &[String]) -> (Vec<String>, Vec<String>) {
    let b: BTreeSet<_> = before.iter().collect();
    let a: BTreeSet<_> = after.iter().collect();
    (
        a.difference(&b).map(|v| (*v).clone()).collect(),
        b.difference(&a).map(|v| (*v).clone()).collect(),
    )
}
fn delta(before: Option<&RightsNames>, after: Option<&RightsNames>) -> RightsDelta {
    let empty = RightsNames::default();
    let b = before.unwrap_or(&empty);
    let a = after.unwrap_or(&empty);
    let (added_permissions, removed_permissions) = set_delta(&b.permissions, &a.permissions);
    let (added_information_classes, removed_information_classes) =
        set_delta(&b.information_classes, &a.information_classes);
    RightsDelta {
        added_permissions,
        removed_permissions,
        added_information_classes,
        removed_information_classes,
        minimum_aal: (b.minimum_aal != a.minimum_aal).then_some((b.minimum_aal, a.minimum_aal)),
    }
}
fn kind<T>(before: &Option<T>, after: &Option<T>) -> ChangeKind {
    match (before, after) {
        (None, Some(_)) => ChangeKind::Added,
        (Some(_), None) => ChangeKind::Removed,
        _ => ChangeKind::Modified,
    }
}
fn summary(service: &Service) -> ServiceSummary {
    ServiceSummary {
        authorization_context: service.authorization_context,
        require_guard: service.require_guard,
        permissions: service.permissions.clone(),
    }
}
fn resource_summary(resource: &crate::Resource) -> ResourceSummary {
    ResourceSummary {
        service: resource.service.clone(),
        information_class: resource.information_class.clone(),
        minimum_aal: resource.minimum_aal,
        actions: resource.actions.clone(),
    }
}
fn side<'a>(s: Side<'a>, id: &str) -> Option<(&'a Policy, &'a Service, &'a CompiledService)> {
    Some((
        s.policy,
        s.policy.services.get(id)?,
        s.compiled.services.get(id)?,
    ))
}
type Entries = BTreeMap<String, RightsNames>;
fn assignments(side: Option<(&Policy, &Service, &CompiledService)>, map: &'static str) -> Entries {
    let Some((policy, service, compiled)) = side else {
        return Entries::new();
    };
    let (source, rights) = match map {
        "users" => (&service.users, &compiled.users),
        "workload_users" => (&service.workload_users, &compiled.workload_users),
        _ => (&service.human_users, &compiled.human_users),
    };
    source
        .keys()
        .filter_map(|subject| {
            rights
                .get(subject)
                .map(|r| (subject.clone(), names(policy, service, *r)))
        })
        .collect()
}
fn networks(side: Option<(&Policy, &Service, &CompiledService)>) -> Entries {
    let Some((policy, service, compiled)) = side else {
        return Entries::new();
    };
    service
        .networks
        .iter()
        .zip(&compiled.network_rules)
        .map(|(n, r)| (n.cidr.to_string(), names(policy, service, *r)))
        .collect()
}
fn compare(
    before: &Entries,
    after: &Entries,
    mut emit: impl FnMut(&String, Option<&RightsNames>, Option<&RightsNames>),
) {
    let keys: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    for key in keys {
        let (b, a) = (before.get(key), after.get(key));
        if b != a {
            emit(key, b, a);
        }
    }
}
/// Deterministic, offset-paginated diff of `base` → `candidate`.
pub fn diff(base: Side<'_>, candidate: Side<'_>, cursor: usize, limit: usize) -> DiffPage {
    let mut pager = Pager {
        cursor,
        limit,
        index: 0,
        out: Vec::new(),
    };
    let (added, removed) = set_delta(
        &base.policy.information_classes,
        &candidate.policy.information_classes,
    );
    if !added.is_empty() || !removed.is_empty() {
        pager.push(|| Change::InformationClasses { added, removed });
    }
    let services: BTreeSet<&String> = base
        .policy
        .services
        .keys()
        .chain(candidate.policy.services.keys())
        .collect();
    for id in services {
        let (b, a) = (side(base, id), side(candidate, id));
        let (bs, as_) = (b.map(|x| summary(x.1)), a.map(|x| summary(x.1)));
        if bs != as_ {
            pager.push(|| Change::Service {
                service: id.clone(),
                change: kind(&bs, &as_),
                before: bs.clone(),
                after: as_.clone(),
            });
        }
        for map in ["users", "workload_users", "human_users"] {
            compare(
                &assignments(b, map),
                &assignments(a, map),
                |subject, before, after| {
                    pager.push(|| Change::Assignment {
                        service: id.clone(),
                        map,
                        subject: subject.clone(),
                        change: kind(&before, &after),
                        before: before.cloned(),
                        after: after.cloned(),
                        delta: delta(before, after),
                    })
                },
            );
        }
        compare(&networks(b), &networks(a), |cidr, before, after| {
            pager.push(|| Change::Network {
                service: id.clone(),
                cidr: cidr.clone(),
                change: kind(&before, &after),
                before: before.cloned(),
                after: after.cloned(),
                delta: delta(before, after),
            })
        });
    }
    let resources: BTreeSet<&String> = base
        .policy
        .resources
        .keys()
        .chain(candidate.policy.resources.keys())
        .collect();
    for id in resources {
        let b = base.policy.resources.get(id).map(resource_summary);
        let a = candidate.policy.resources.get(id).map(resource_summary);
        if b != a {
            pager.push(|| Change::Resource {
                resource: id.clone(),
                change: kind(&b, &a),
                before: b.clone(),
                after: a.clone(),
            });
        }
    }
    let total = pager.index;
    let end = cursor.saturating_add(pager.out.len());
    DiffPage {
        total,
        next_cursor: (end < total && !pager.out.is_empty()).then_some(end),
        changes: pager.out,
    }
}
