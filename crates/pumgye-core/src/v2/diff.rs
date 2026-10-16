//! Version 2 candidate diff: the (subject, service, permission) rights that change
//! if a candidate is published (ADR 0021 `candidates/{id}/diff`), bounded and
//! offset paginated in a deterministic order.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrantSummary {
    pub binding: String,
    pub effect: Effect,
    pub permissions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clearance: Option<String>,
    pub minimum_aal: u8,
    pub zones: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RightsChange {
    /// `human:<ref>`, `service:<ref>`, `workload:<ref>` or `group:<GroupRef>`.
    pub subject: String,
    pub service: String,
    pub change: crate::diff::ChangeKind,
    /// Allow permissions (any condition) added / removed.
    pub added_permissions: Vec<String>,
    pub removed_permissions: Vec<String>,
    /// Deny permissions added / removed.
    pub added_denies: Vec<String>,
    pub removed_denies: Vec<String>,
    /// Same permissions, different conditions (clearance, AAL, zones, validity).
    pub conditions_changed: bool,
    pub before: Vec<GrantSummary>,
    pub after: Vec<GrantSummary>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiffPageV2 {
    pub total: usize,
    pub changes: Vec<RightsChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<usize>,
}
#[derive(Clone, Copy)]
pub struct SideV2<'a> {
    pub policy: &'a PolicyV2,
    pub compiled: &'a CompiledV2,
}
type Key = (String, String);
fn summaries(side: SideV2<'_>) -> BTreeMap<Key, Vec<GrantSummary>> {
    let mut out: BTreeMap<Key, Vec<GrantSummary>> = BTreeMap::new();
    let services: Vec<(&String, &CompiledServiceV2)> = side.compiled.services.iter().collect();
    let zone_names: Vec<&String> = side.policy.zones.zones.keys().collect();
    let level_names = &side.policy.catalog.levels;
    let mut emit = |label: String, slot: Slot| {
        for s in &side.compiled.slices[slot.start as usize..(slot.start + slot.len) as usize] {
            let Some((sid, svc)) = services.iter().find(|(_, c)| c.index == s.service) else {
                continue;
            };
            let vocab = &side.policy.services[*sid].permissions;
            let _ = svc;
            for g in &side.compiled.grants[s.start as usize..s.start as usize + s.len as usize] {
                let b = &side.policy.bindings[g.binding as usize];
                let mut permissions: Vec<String> = vocab
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| has(&g.perms, *i as u16))
                    .map(|(_, p)| p.clone())
                    .collect();
                permissions.sort();
                out.entry((label.clone(), (*sid).clone()))
                    .or_default()
                    .push(GrantSummary {
                        binding: b.id.clone(),
                        effect: b.effect,
                        permissions,
                        clearance: (!g.deny && g.level != u8::MAX)
                            .then(|| level_names[g.level as usize].clone()),
                        minimum_aal: g.min_aal,
                        zones: if g.zones == ANY_ZONE {
                            vec!["any".into()]
                        } else {
                            zone_names
                                .iter()
                                .enumerate()
                                .filter(|(i, _)| g.zones & (1 << i) != 0)
                                .map(|(_, z)| (*z).clone())
                                .collect()
                        },
                        not_before: (g.not_before != 0).then_some(Timestamp(g.not_before)),
                        expires_at: (g.expires_at != NO_EXPIRY).then_some(Timestamp(g.expires_at)),
                    });
            }
        }
    };
    for kind in PrincipalKind::ALL {
        for (reference, slot) in &side.compiled.principals[kind.index()] {
            emit(format!("{}:{reference}", kind.name()), *slot);
        }
    }
    for (i, g) in side.compiled.group_refs.iter().enumerate() {
        emit(format!("group:{g}"), side.compiled.groups[i]);
    }
    for v in out.values_mut() {
        v.sort_by(|a, b| a.binding.cmp(&b.binding));
    }
    out
}
fn perms(list: &[GrantSummary], effect: Effect) -> BTreeSet<String> {
    list.iter()
        .filter(|g| g.effect == effect)
        .flat_map(|g| g.permissions.iter().cloned())
        .collect()
}
pub fn diff(base: SideV2<'_>, candidate: SideV2<'_>, cursor: usize, limit: usize) -> DiffPageV2 {
    let (b, c) = (summaries(base), summaries(candidate));
    let keys: BTreeSet<&Key> = b.keys().chain(c.keys()).collect();
    let mut total = 0;
    let mut changes = Vec::new();
    for key in keys {
        let empty = Vec::new();
        let (before, after) = (b.get(key).unwrap_or(&empty), c.get(key).unwrap_or(&empty));
        let strip = |v: &Vec<GrantSummary>| -> Vec<GrantSummary> {
            v.iter()
                .map(|g| GrantSummary {
                    binding: String::new(),
                    ..g.clone()
                })
                .collect()
        };
        if strip(before) == strip(after) {
            continue;
        }
        if total >= cursor && changes.len() < limit {
            let (ba, aa) = (perms(before, Effect::Allow), perms(after, Effect::Allow));
            let (bd, ad) = (perms(before, Effect::Deny), perms(after, Effect::Deny));
            let added_permissions: Vec<String> = aa.difference(&ba).cloned().collect();
            let removed_permissions: Vec<String> = ba.difference(&aa).cloned().collect();
            let added_denies: Vec<String> = ad.difference(&bd).cloned().collect();
            let removed_denies: Vec<String> = bd.difference(&ad).cloned().collect();
            changes.push(RightsChange {
                subject: key.0.clone(),
                service: key.1.clone(),
                change: match (before.is_empty(), after.is_empty()) {
                    (true, _) => crate::diff::ChangeKind::Added,
                    (_, true) => crate::diff::ChangeKind::Removed,
                    _ => crate::diff::ChangeKind::Modified,
                },
                conditions_changed: added_permissions.is_empty()
                    && removed_permissions.is_empty()
                    && added_denies.is_empty()
                    && removed_denies.is_empty(),
                added_permissions,
                removed_permissions,
                added_denies,
                removed_denies,
                before: before.clone(),
                after: after.clone(),
            });
        }
        total += 1;
    }
    let end = cursor.saturating_add(changes.len());
    DiffPageV2 {
        total,
        next_cursor: (end < total && !changes.is_empty()).then_some(end),
        changes,
    }
}
