//! Version 2 explain: the same evaluation function with a recording tracer,
//! rendered as an ordered stage trace with binding provenance (ADR 0021
//! `POST /v2/admin/explain`).
use super::*;
use crate::explain::{CaseError, GuardInput, Stage, StageResult, UNAVAILABLE_REASON, reason_v2};
use serde_json::{Value, json};

/// Maximum allow grants recorded for provenance per explanation.
pub const MAX_RECORDED_GRANTS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectV2 {
    pub kind: PrincipalKind,
    pub id: String,
}
/// One simulated request against a version 2 snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub subject: SubjectV2,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub information_class: Option<String>,
    pub ip: IpAddr,
    #[serde(default)]
    pub aal: u8,
    pub guard: GuardInput,
    #[serde(default)]
    pub minimum_revision: u64,
    /// Simulated authority time (default: now).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<Timestamp>,
    /// Hypothetical Human group set replacing the projection for this case only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothetical_groups: Option<Vec<String>>,
}
fn ident(v: &str) -> bool {
    name(v)
}
impl CaseV2 {
    pub fn validate(&self) -> std::result::Result<(), (CaseError, &'static str)> {
        if let Some(l) = &self.label
            && (l.len() > 64 || !ident(l))
        {
            return Err((CaseError::InvalidLabel, "label"));
        }
        for (path, v) in [
            ("subject.id", Some(&self.subject.id)),
            ("service", Some(&self.service)),
            ("resource", self.resource.as_ref()),
            ("action", self.action.as_ref()),
            ("permission", self.permission.as_ref()),
            ("information_class", self.information_class.as_ref()),
        ] {
            if v.is_some_and(|v| !ident(v)) {
                return Err((CaseError::InvalidName, path));
            }
        }
        if self.minimum_revision > i64::MAX as u64 {
            return Err((CaseError::RevisionOutOfRange, "minimum_revision"));
        }
        if self.aal > 3 || (self.subject.kind != PrincipalKind::Human && self.aal != 0) {
            return Err((CaseError::AssuranceOutOfRange, "aal"));
        }
        match (
            &self.resource,
            &self.action,
            &self.permission,
            &self.information_class,
        ) {
            (Some(_), Some(_), None, None) | (None, None, Some(_), Some(_)) => {}
            _ => return Err((CaseError::AmbiguousTarget, "permission")),
        }
        if let Some(groups) = &self.hypothetical_groups
            && (self.subject.kind != PrincipalKind::Human
                || groups.len() > limits::GROUPS
                || !groups.iter().all(|g| group_ref_valid(g)))
        {
            return Err((CaseError::InvalidName, "hypothetical_groups"));
        }
        Ok(())
    }
    pub fn target(&self) -> TargetV2<'_> {
        match (&self.resource, &self.action) {
            (Some(resource), Some(action)) => TargetV2::Resource { resource, action },
            _ => TargetV2::Permission {
                permission: self.permission.as_deref().unwrap_or_default(),
                level: self.information_class.as_deref().unwrap_or_default(),
            },
        }
    }
}
/// A compiled version 2 snapshot with the membership it was paired with.
#[derive(Clone, Copy)]
pub struct SnapshotV2<'a> {
    pub policy: &'a PolicyV2,
    pub compiled: &'a CompiledV2,
    pub membership: &'a MembershipIndex,
    pub revision: u64,
    /// False when the authority would not decide (unhealthy).
    pub serving: bool,
    /// False when the policy references groups and no fresh projection is held.
    pub membership_fresh: bool,
    pub now: u64,
}
#[derive(Default)]
struct Recorder {
    events: Vec<TraceV2Event>,
    grants: Vec<(u32, bool)>,
    truncated: bool,
}
impl TracerV2 for Recorder {
    fn event(&mut self, event: TraceV2Event) {
        if self.events.len() < 32 {
            self.events.push(event);
        } else {
            self.truncated = true;
        }
    }
    fn grant(&mut self, binding: u32, contributes: bool) {
        if self.grants.len() < MAX_RECORDED_GRANTS {
            self.grants.push((binding, contributes));
        } else {
            self.truncated = true;
        }
    }
}
/// Result of one version 2 explanation.
pub struct ExplanationV2 {
    pub decision: Option<DecisionV2>,
    pub value: Value,
}
const PATH: [Stage; 12] = [
    Stage::Fence,
    Stage::Service,
    Stage::Context,
    Stage::Guard,
    Stage::Catalog,
    Stage::Principal,
    Stage::ExplicitDeny,
    Stage::AllowSet,
    Stage::NetworkCeiling,
    Stage::Permission,
    Stage::Clearance,
    Stage::Assurance,
];
fn stage_name(stage: Stage) -> Value {
    serde_json::to_value(stage).unwrap_or(Value::Null)
}
fn entry(stage: Stage, deny: bool, code: &'static str, detail: Value) -> Value {
    let mut v = json!({
        "stage": stage_name(stage),
        "result": if deny { StageResult::Deny } else { StageResult::Pass },
        "code": code,
        "label_key": stage.message_key(),
    });
    if !detail.is_null() {
        v["detail"] = detail;
    }
    v
}
fn provenance(policy: &PolicyV2, binding: u32) -> Value {
    let Some(b) = policy.bindings.get(binding as usize) else {
        return Value::Null;
    };
    let mut v =
        json!({"id": b.id, "effect": b.effect, "subjects": b.subjects, "metadata": b.metadata});
    if let Some(role) = &b.role {
        v["role"] = json!(role);
    }
    if let Some(p) = &b.permissions {
        v["permissions"] = json!(p);
    }
    v["conditions"] = json!(b.conditions);
    v
}
fn mask_names(mask: u64, names: &[&String]) -> Vec<String> {
    names
        .iter()
        .enumerate()
        .filter(|(i, _)| *i < 64 && mask & (1 << i) != 0)
        .map(|(_, n)| (*n).clone())
        .collect()
}
pub fn explain(
    snapshot: SnapshotV2<'_>,
    case: &CaseV2,
    trace: bool,
) -> std::result::Result<ExplanationV2, CaseError> {
    case.validate().map_err(|e| e.0)?;
    let reason_json = |r: crate::explain::Reason| json!({"reason_code": r.code, "message_key": r.message_key, "hint_key": r.hint_key});
    let fence_detail = json!({"revision": snapshot.revision, "minimum_revision": case.minimum_revision, "serving": snapshot.serving, "membership_fresh": snapshot.membership_fresh});
    let refused = if !snapshot.serving {
        Some("pumgye.detail.snapshot_unavailable")
    } else if snapshot.revision < case.minimum_revision {
        Some("pumgye.detail.revision_floor")
    } else if !snapshot.membership_fresh && case.hypothetical_groups.is_none() {
        Some("pumgye.detail.membership_unavailable")
    } else {
        None
    };
    let pad = |entries: &mut Vec<Value>, deciding: Stage| {
        let at = PATH
            .iter()
            .position(|s| *s == deciding)
            .unwrap_or(PATH.len());
        for s in &PATH[at + 1..] {
            entries.push(json!({"stage": stage_name(*s), "result": StageResult::NotEvaluated, "code": "pumgye.detail.not_evaluated", "label_key": s.message_key()}));
        }
    };
    if let Some(code) = refused {
        let mut entries = vec![entry(Stage::Fence, true, code, fence_detail)];
        pad(&mut entries, Stage::Fence);
        let mut outcome = reason_json(UNAVAILABLE_REASON);
        outcome["decision"] = Value::Null;
        outcome["allow"] = json!(false);
        outcome["deciding_stage"] = stage_name(Stage::Fence);
        outcome["detail_code"] = json!(code);
        let mut value = json!({"outcome": outcome});
        if trace {
            value["trace"] = json!(entries);
        }
        if let Some(l) = &case.label {
            value["label"] = json!(l);
        }
        return Ok(ExplanationV2 {
            decision: None,
            value,
        });
    }
    let hypothetical;
    let membership = match &case.hypothetical_groups {
        Some(groups) => {
            let set: BTreeSet<String> = groups.iter().cloned().collect();
            hypothetical =
                MembershipIndex::build(snapshot.compiled, [(case.subject.id.as_str(), &set)]);
            &hypothetical
        }
        None => snapshot.membership,
    };
    let now = case.at.map_or(snapshot.now, |t| t.0);
    let request = RequestV2 {
        service: &case.service,
        kind: case.subject.kind,
        subject: &case.subject.id,
        target: case.target(),
        ip: case.ip,
        aal: case.aal,
        guard: case.guard.into(),
        now,
    };
    let mut rec = Recorder::default();
    let decision = snapshot
        .compiled
        .evaluate_traced(membership, &request, &mut rec);
    let policy = snapshot.policy;
    let zone_names: Vec<&String> = policy.zones.zones.keys().collect();
    let mut entries = vec![entry(
        Stage::Fence,
        false,
        "pumgye.detail.fence_satisfied",
        fence_detail,
    )];
    let allow = decision == DecisionV2::Allow;
    let last = rec.events.len().saturating_sub(1);
    let mut obligations = Value::Null;
    let mut request_zones = 0u64;
    let mut deny_seen = false;
    for (i, event) in rec.events.iter().enumerate() {
        let failed = i == last && !allow;
        let pick = |pass: &'static str, deny: &'static str| if failed { deny } else { pass };
        match *event {
            TraceV2Event::Service { .. } => entries.push(entry(
                Stage::Service,
                failed,
                pick(
                    "pumgye.detail.service_found",
                    "pumgye.detail.service_not_found",
                ),
                json!({"service": case.service}),
            )),
            TraceV2Event::Context { context } => entries.push(entry(
                Stage::Context,
                failed,
                pick(
                    "pumgye.detail.context_matched",
                    "pumgye.detail.context_mismatch",
                ),
                json!({"context": context, "required": AuthorizationContext::NetworkAndGuard}),
            )),
            TraceV2Event::Guard {
                evidence,
                require_guard,
            } => {
                let code = match (failed, evidence) {
                    (true, GuardEvidence::Deny) => "pumgye.detail.guard_denied",
                    (true, _) => "pumgye.detail.guard_not_enforced",
                    (false, GuardEvidence::EnforcedAllow) => "pumgye.detail.guard_enforced_allow",
                    (false, _) => "pumgye.detail.guard_not_required",
                };
                entries.push(entry(Stage::Guard, failed, code, json!({"evidence": GuardInput::from_evidence(evidence), "require_guard": require_guard})));
            }
            TraceV2Event::Catalog {
                resource_found,
                scope_ok,
                permission,
                level,
                compartments,
                resource_min_aal,
            } => {
                let code = if !failed {
                    "pumgye.detail.catalog_resolved"
                } else if resource_found == Some(false) {
                    "pumgye.detail.resource_not_found"
                } else if !scope_ok {
                    "pumgye.detail.scope_mismatch"
                } else if permission.is_none() {
                    if resource_found.is_some() {
                        "pumgye.detail.action_unknown"
                    } else {
                        "pumgye.detail.permission_unknown"
                    }
                } else {
                    "pumgye.detail.class_unknown"
                };
                let svc = policy.services.get(&case.service);
                let permission_name = permission
                    .and_then(|p| svc.and_then(|s| s.permissions.get(p as usize)).cloned());
                let compartment_names: Vec<String> = policy
                    .catalog
                    .compartments
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| compartments & (1 << i) != 0)
                    .map(|(_, c)| c.clone())
                    .collect();
                entries.push(entry(Stage::Catalog, failed, code, json!({
                    "resource": case.resource, "action": case.action,
                    "permission": permission_name.or(case.permission.clone()),
                    "label": {"level": level.and_then(|l| policy.catalog.levels.get(l as usize)).cloned().or(case.information_class.clone()), "compartments": compartment_names},
                    "label_source": if case.resource.is_some() { "catalog" } else { "request" },
                    "resource_minimum_aal": resource_min_aal,
                })));
            }
            TraceV2Event::Principal {
                valid,
                direct,
                groups,
            } => {
                let code = if !failed {
                    "pumgye.detail.principal_matched"
                } else if !valid {
                    "pumgye.detail.principal_invalid"
                } else {
                    "pumgye.detail.principal_not_bound"
                };
                let names: Vec<&String> = snapshot
                    .compiled
                    .group_refs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| groups[i / 64] & (1 << (i % 64)) != 0)
                    .map(|(_, g)| g)
                    .collect();
                entries.push(entry(Stage::Principal, failed, code, json!({
                    "kind": case.subject.kind, "id": case.subject.id, "direct_bindings": direct, "groups": names,
                    "membership": if case.hypothetical_groups.is_some() { "hypothetical" } else { "projection" },
                })));
            }
            TraceV2Event::ZoneSet { zones } => request_zones = zones,
            TraceV2Event::Deny { binding } => {
                deny_seen = true;
                entries.push(entry(
                    Stage::ExplicitDeny,
                    true,
                    "pumgye.detail.explicit_denied",
                    json!({"binding": provenance(policy, binding)}),
                ));
            }
            TraceV2Event::AllowSet {
                candidates,
                live,
                zoned,
            } => {
                if !deny_seen {
                    entries.push(entry(
                        Stage::ExplicitDeny,
                        false,
                        "pumgye.detail.explicit_deny_none",
                        Value::Null,
                    ));
                }
                let code = if !failed {
                    "pumgye.detail.allow_set_live"
                } else if candidates == 0 {
                    "pumgye.detail.allow_set_none"
                } else if live == 0 {
                    "pumgye.detail.allow_set_expired"
                } else {
                    "pumgye.detail.allow_set_zone_mismatch"
                };
                entries.push(entry(Stage::AllowSet, failed, code, json!({
                    "candidates": candidates, "live": live, "zone_matched": zoned,
                    "request_zones": mask_names(request_zones, &zone_names), "at": Timestamp(now),
                })));
            }
            TraceV2Event::Ceiling { rule, exact_host } => {
                let ceiling = rule.and_then(|r| {
                    policy
                        .services
                        .get(&case.service)
                        .and_then(|s| s.network_ceiling.get(r as usize))
                });
                entries.push(entry(Stage::NetworkCeiling, failed, pick("pumgye.detail.ceiling_matched", "pumgye.detail.ceiling_no_match"), json!({
                    "ip": case.ip, "index": rule, "zone": ceiling.map(|c| &c.zone), "max": ceiling.map(|c| &c.max), "exact_host": exact_host,
                })));
            }
            TraceV2Event::Permission { granted } => {
                let code = if !failed {
                    "pumgye.detail.permission_granted"
                } else if rec.grants.is_empty() {
                    "pumgye.detail.permission_missing_subject"
                } else {
                    "pumgye.detail.permission_removed_by_network"
                };
                let _ = granted;
                let holders: Vec<Value> = rec
                    .grants
                    .iter()
                    .map(|(b, _)| provenance(policy, *b))
                    .collect();
                entries.push(entry(
                    Stage::Permission,
                    failed,
                    code,
                    json!({"bindings_granting_permission": holders}),
                ));
            }
            TraceV2Event::Clearance { .. } => {
                let contributing: Vec<Value> = rec
                    .grants
                    .iter()
                    .filter(|(_, c)| *c)
                    .map(|(b, _)| provenance(policy, *b))
                    .collect();
                entries.push(entry(
                    Stage::Clearance,
                    failed,
                    pick(
                        "pumgye.detail.clearance_granted",
                        "pumgye.detail.clearance_exceeded",
                    ),
                    json!({"contributing_bindings": contributing}),
                ));
            }
            TraceV2Event::Assurance {
                presented,
                required,
            } => {
                let code = match (failed, presented > 3) {
                    (false, _) => "pumgye.detail.assurance_satisfied",
                    (true, true) => "pumgye.detail.assurance_out_of_range",
                    (true, false) => "pumgye.detail.assurance_below_required",
                };
                if failed && presented < required && required <= 3 {
                    obligations = json!({"required_aal": required});
                }
                entries.push(entry(
                    Stage::Assurance,
                    failed,
                    code,
                    json!({"presented": presented, "required": required}),
                ));
            }
        }
    }
    let deciding = entries.last().cloned().unwrap_or(Value::Null);
    let deciding_stage = PATH
        .iter()
        .copied()
        .find(|s| stage_name(*s) == deciding["stage"])
        .unwrap_or(Stage::Fence);
    pad(&mut entries, deciding_stage);
    let mut outcome = reason_json(reason_v2(decision));
    outcome["decision"] = json!(decision.name());
    outcome["allow"] = json!(allow);
    outcome["v1_decision"] = json!(crate::explain::decision_name(decision.to_v1()));
    outcome["deciding_stage"] = deciding["stage"].clone();
    outcome["detail_code"] = deciding["code"].clone();
    let mut value = json!({"outcome": outcome});
    if !obligations.is_null() {
        value["obligations"] = obligations;
    }
    if allow {
        value["contributing_bindings"] = json!(
            rec.grants
                .iter()
                .filter(|(_, c)| *c)
                .map(|(b, _)| policy.bindings[*b as usize].id.clone())
                .collect::<Vec<_>>()
        );
    }
    if trace {
        value["trace"] = json!(entries);
    }
    if rec.truncated {
        value["trace_truncated"] = json!(true);
    }
    if let Some(l) = &case.label {
        value["label"] = json!(l);
    }
    Ok(ExplanationV2 {
        decision: Some(decision),
        value,
    })
}
