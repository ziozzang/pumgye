//! Administrative explain ("policy troubleshooter") and candidate diff.
//!
//! Explain never re-implements authorization: it calls the public `*_traced`
//! entrypoints with a [`VecTrace`] sink and renders the recorded facts. The decision
//! in an [`Explanation`] is therefore the exact return value of the enforcement
//! function for the same compiled snapshot and inputs. Names (roles, CIDRs,
//! permission and class labels) are resolved afterwards from the source document
//! that produced the compiled snapshot.
use crate::{
    AuthorizationContext, CompiledPolicy, Decision, GuardEvidence, KubernetesApiSubject,
    NetworkMatch, Policy, ResourceDecision, RightsView, Service, SubjectMap, TraceEvent, VecTrace,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

/// Explain wire/schema version.
pub const EXPLAIN_VERSION: u32 = 1;
/// Maximum shadowed network rules reported per network stage.
pub const MAX_SHADOWED_RULES: usize = 8;

// ---------------------------------------------------------------------------
// Reason and message-key registry (ADR 0019: namespaced, en/ko keyed)
// ---------------------------------------------------------------------------

/// Registered final outcome codes. Each has `pumgye.reason.<suffix>` and
/// `pumgye.hint.<suffix>` message keys in both catalogs.
pub const REASON_CODES: &[&str] = &[
    "pumgye.allow",
    "pumgye.unknown_service",
    "pumgye.guest",
    "pumgye.network_guest",
    "pumgye.permission_denied",
    "pumgye.class_denied",
    "pumgye.assurance_denied",
    "pumgye.guard_denied",
    "pumgye.guard_unavailable",
    "pumgye.unknown_resource",
    "pumgye.unknown_action",
    "pumgye.unavailable",
];

/// Registered stage detail codes; each code is also its own message key.
pub const DETAIL_CODES: &[&str] = &[
    "pumgye.detail.fence_satisfied",
    "pumgye.detail.revision_floor",
    "pumgye.detail.snapshot_unavailable",
    "pumgye.detail.service_found",
    "pumgye.detail.service_not_found",
    "pumgye.detail.resource_found",
    "pumgye.detail.resource_not_found",
    "pumgye.detail.scope_matched",
    "pumgye.detail.scope_mismatch",
    "pumgye.detail.context_matched",
    "pumgye.detail.context_mismatch",
    "pumgye.detail.principal_valid",
    "pumgye.detail.principal_invalid",
    "pumgye.detail.principal_assurance_valid",
    "pumgye.detail.principal_assurance_invalid",
    "pumgye.detail.action_mapped",
    "pumgye.detail.action_unknown",
    "pumgye.detail.guard_enforced_allow",
    "pumgye.detail.guard_not_required",
    "pumgye.detail.guard_denied",
    "pumgye.detail.guard_not_enforced",
    "pumgye.detail.subject_assigned",
    "pumgye.detail.subject_not_assigned",
    "pumgye.detail.subject_guest_only",
    "pumgye.detail.network_matched",
    "pumgye.detail.network_no_match",
    "pumgye.detail.roles_intersected",
    "pumgye.detail.permission_granted",
    "pumgye.detail.permission_unknown",
    "pumgye.detail.permission_missing_subject",
    "pumgye.detail.permission_removed_by_network",
    "pumgye.detail.class_granted",
    "pumgye.detail.class_unknown",
    "pumgye.detail.class_missing_subject",
    "pumgye.detail.class_removed_by_network",
    "pumgye.detail.assurance_satisfied",
    "pumgye.detail.assurance_out_of_range",
    "pumgye.detail.assurance_below_required",
    "pumgye.detail.not_evaluated",
];

/// Every key the en/ko catalogs must define (and nothing else).
pub fn message_keys() -> Vec<String> {
    let mut keys = Vec::new();
    for code in REASON_CODES {
        let suffix = code.trim_start_matches("pumgye.");
        keys.push(format!("pumgye.reason.{suffix}"));
        keys.push(format!("pumgye.hint.{suffix}"));
    }
    keys.extend(DETAIL_CODES.iter().map(|c| (*c).to_owned()));
    keys.extend(Stage::ALL.iter().map(|s| s.message_key().to_owned()));
    keys.sort();
    keys
}

/// Stable final-outcome descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reason {
    pub code: &'static str,
    pub message_key: &'static str,
    pub hint_key: &'static str,
}
macro_rules! reason {
    ($s:literal) => {
        Reason {
            code: concat!("pumgye.", $s),
            message_key: concat!("pumgye.reason.", $s),
            hint_key: concat!("pumgye.hint.", $s),
        }
    };
}
/// Exact variant name, identical to the `reason` field of decision responses.
pub fn decision_name(decision: ResourceDecision) -> &'static str {
    match decision {
        ResourceDecision::UnknownResource => "UnknownResource",
        ResourceDecision::UnknownAction => "UnknownAction",
        ResourceDecision::Decided(d) => match d {
            Decision::Allow => "Allow",
            Decision::UnknownService => "UnknownService",
            Decision::Guest => "Guest",
            Decision::NetworkGuest => "NetworkGuest",
            Decision::PermissionDenied => "PermissionDenied",
            Decision::ClassDenied => "ClassDenied",
            Decision::AssuranceDenied => "AssuranceDenied",
            Decision::GuardDenied => "GuardDenied",
            Decision::GuardUnavailable => "GuardUnavailable",
        },
    }
}
pub fn reason(decision: ResourceDecision) -> Reason {
    match decision {
        ResourceDecision::UnknownResource => reason!("unknown_resource"),
        ResourceDecision::UnknownAction => reason!("unknown_action"),
        ResourceDecision::Decided(d) => match d {
            Decision::Allow => reason!("allow"),
            Decision::UnknownService => reason!("unknown_service"),
            Decision::Guest => reason!("guest"),
            Decision::NetworkGuest => reason!("network_guest"),
            Decision::PermissionDenied => reason!("permission_denied"),
            Decision::ClassDenied => reason!("class_denied"),
            Decision::AssuranceDenied => reason!("assurance_denied"),
            Decision::GuardDenied => reason!("guard_denied"),
            Decision::GuardUnavailable => reason!("guard_unavailable"),
        },
    }
}
const UNAVAILABLE: Reason = reason!("unavailable");

// ---------------------------------------------------------------------------
// Stages
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Fence,
    Service,
    Resource,
    ServiceScope,
    Context,
    PrincipalFormat,
    PrincipalAssurance,
    Action,
    Guard,
    Subject,
    Network,
    RoleExpansion,
    Permission,
    InformationClass,
    Assurance,
}
impl Stage {
    pub const ALL: [Stage; 15] = [
        Stage::Fence,
        Stage::Service,
        Stage::Resource,
        Stage::ServiceScope,
        Stage::Context,
        Stage::PrincipalFormat,
        Stage::PrincipalAssurance,
        Stage::Action,
        Stage::Guard,
        Stage::Subject,
        Stage::Network,
        Stage::RoleExpansion,
        Stage::Permission,
        Stage::InformationClass,
        Stage::Assurance,
    ];
    pub fn message_key(self) -> &'static str {
        match self {
            Stage::Fence => "pumgye.stage.fence",
            Stage::Service => "pumgye.stage.service",
            Stage::Resource => "pumgye.stage.resource",
            Stage::ServiceScope => "pumgye.stage.service_scope",
            Stage::Context => "pumgye.stage.context",
            Stage::PrincipalFormat => "pumgye.stage.principal_format",
            Stage::PrincipalAssurance => "pumgye.stage.principal_assurance",
            Stage::Action => "pumgye.stage.action",
            Stage::Guard => "pumgye.stage.guard",
            Stage::Subject => "pumgye.stage.subject",
            Stage::Network => "pumgye.stage.network",
            Stage::RoleExpansion => "pumgye.stage.role_expansion",
            Stage::Permission => "pumgye.stage.permission",
            Stage::InformationClass => "pumgye.stage.information_class",
            Stage::Assurance => "pumgye.stage.assurance",
        }
    }
}
/// Canonical evaluation order per entrypoint (stages after the deciding one are
/// reported as `not_evaluated`).
const PERMISSION_PATH: &[Stage] = &[
    Stage::Fence,
    Stage::Service,
    Stage::Context,
    Stage::Guard,
    Stage::Subject,
    Stage::Network,
    Stage::RoleExpansion,
    Stage::Permission,
    Stage::InformationClass,
    Stage::Assurance,
];
const RESOURCE_PATH: &[Stage] = &[
    Stage::Fence,
    Stage::Resource,
    Stage::ServiceScope,
    Stage::Action,
    Stage::Context,
    Stage::Guard,
    Stage::Subject,
    Stage::Network,
    Stage::RoleExpansion,
    Stage::Permission,
    Stage::InformationClass,
    Stage::Assurance,
];
const HUMAN_PATH: &[Stage] = &[
    Stage::Fence,
    Stage::Resource,
    Stage::ServiceScope,
    Stage::Context,
    Stage::PrincipalFormat,
    Stage::PrincipalAssurance,
    Stage::Action,
    Stage::Guard,
    Stage::Subject,
    Stage::Network,
    Stage::RoleExpansion,
    Stage::Permission,
    Stage::InformationClass,
    Stage::Assurance,
];
const KUBERNETES_API_PATH: &[Stage] = &[
    Stage::Fence,
    Stage::Resource,
    Stage::ServiceScope,
    Stage::Context,
    Stage::Action,
    Stage::Subject,
    Stage::RoleExpansion,
    Stage::Permission,
    Stage::InformationClass,
    Stage::Assurance,
];

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// Which hot-path entrypoint and subject map the case simulates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// Generic `users` map (`/v1/decision`, PPG1, `/v1/resource/decision`).
    User,
    /// `workload_users` map (Workload resource entrypoint, AAL0).
    Workload,
    /// `human_users` map (Human resource entrypoint, AAL1/2).
    Human,
    /// `users` map of a `kubernetes_api` service (SAR entrypoint, no network/guard).
    KubernetesApi,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectInput {
    pub id: String,
    pub kind: SubjectKind,
}
/// Simulated Sumunjang evidence; never fetched from Sumunjang by explain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardInput {
    EnforcedAllow,
    Deny,
    Observe,
    Unavailable,
}
impl From<GuardInput> for GuardEvidence {
    fn from(value: GuardInput) -> Self {
        match value {
            GuardInput::EnforcedAllow => GuardEvidence::EnforcedAllow,
            GuardInput::Deny => GuardEvidence::Deny,
            GuardInput::Observe => GuardEvidence::Observe,
            GuardInput::Unavailable => GuardEvidence::Unavailable,
        }
    }
}
fn guard_name(evidence: GuardEvidence) -> &'static str {
    match evidence {
        GuardEvidence::EnforcedAllow => "enforced_allow",
        GuardEvidence::Deny => "deny",
        GuardEvidence::Observe => "observe",
        GuardEvidence::Unavailable => "unavailable",
    }
}
/// One simulated request. Target is either `resource`+`action` (catalog
/// entrypoints) or `permission`+`information_class` (`/v1/decision`/PPG1).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Optional caller correlation label (1..64 identifier bytes), echoed back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub subject: SubjectInput,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub information_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(default)]
    pub aal: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<GuardInput>,
    #[serde(default)]
    pub minimum_revision: u64,
}
/// Validation refusal of a case; never a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseError {
    InvalidName,
    InvalidLabel,
    AmbiguousTarget,
    MissingNetworkEvidence,
    UnexpectedNetworkEvidence,
    AssuranceOutOfRange,
    UnsupportedCombination,
    RevisionOutOfRange,
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
#[derive(Clone, Copy)]
enum Target<'a> {
    Permission { permission: &'a str, class: &'a str },
    Resource { resource: &'a str, action: &'a str },
}
impl Case {
    /// Same bounds as the decision APIs: identifier charset, 128 bytes, AAL 0..3.
    pub fn validate(&self) -> Result<(), CaseError> {
        self.target().map(|_| ())
    }
    fn target(&self) -> Result<Target<'_>, CaseError> {
        if let Some(label) = &self.label
            && (label.len() > 64 || !identifier(label))
        {
            return Err(CaseError::InvalidLabel);
        }
        if self.minimum_revision > i64::MAX as u64 {
            return Err(CaseError::RevisionOutOfRange);
        }
        let names = [
            Some(&self.subject.id),
            Some(&self.service),
            self.resource.as_ref(),
            self.action.as_ref(),
            self.permission.as_ref(),
            self.information_class.as_ref(),
        ];
        if !names.iter().flatten().all(|v| identifier(v)) {
            return Err(CaseError::InvalidName);
        }
        if self.aal > 3 {
            return Err(CaseError::AssuranceOutOfRange);
        }
        let target = match (
            &self.resource,
            &self.action,
            &self.permission,
            &self.information_class,
        ) {
            (Some(resource), Some(action), None, None) => Target::Resource { resource, action },
            (None, None, Some(permission), Some(class)) => Target::Permission { permission, class },
            _ => return Err(CaseError::AmbiguousTarget),
        };
        let network = self.ip.is_some() && self.guard.is_some();
        match (self.subject.kind, target) {
            (SubjectKind::KubernetesApi, Target::Resource { .. }) => {
                if self.ip.is_some() || self.guard.is_some() {
                    return Err(CaseError::UnexpectedNetworkEvidence);
                }
                if self.aal != 0 {
                    return Err(CaseError::AssuranceOutOfRange);
                }
                if KubernetesApiSubject::parse(&self.subject.id).is_err() {
                    return Err(CaseError::InvalidName);
                }
            }
            (SubjectKind::User, _)
            | (SubjectKind::Workload | SubjectKind::Human, Target::Resource { .. }) => {
                if !network {
                    return Err(CaseError::MissingNetworkEvidence);
                }
                if self.subject.kind == SubjectKind::Workload && self.aal != 0 {
                    return Err(CaseError::AssuranceOutOfRange);
                }
            }
            _ => return Err(CaseError::UnsupportedCombination),
        }
        Ok(target)
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Outcome {
    /// Exact `pumgye_core::Decision` variant name, or `UnknownResource` /
    /// `UnknownAction`; absent when the snapshot fence refused evaluation.
    pub decision: Option<&'static str>,
    pub allow: bool,
    pub reason_code: &'static str,
    pub message_key: &'static str,
    pub hint_key: &'static str,
    pub deciding_stage: Stage,
    pub detail_code: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Obligations {
    /// Assurance level the subject must present (step-up) for this target.
    pub required_aal: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageResult {
    Pass,
    Deny,
    NotEvaluated,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StageEntry {
    pub stage: Stage,
    pub result: StageResult,
    /// Registered detail code; also its message key.
    pub code: &'static str,
    pub label_key: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<StageDetail>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RightsNames {
    pub permissions: Vec<String>,
    pub information_classes: Vec<String>,
    pub minimum_aal: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoleNode {
    pub role: String,
    /// Absent for directly assigned roles; otherwise the role that inherits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherited_from: Option<String>,
    pub permissions: Vec<String>,
    pub information_classes: Vec<String>,
    pub minimum_aal: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetworkRule {
    pub index: u32,
    pub cidr: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub exact_host: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum StageDetail {
    Fence {
        revision: u64,
        minimum_revision: u64,
        serving: bool,
    },
    Service {
        service: String,
    },
    Resource {
        resource: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
    },
    Scope {
        requested: String,
        owner: String,
    },
    Context {
        context: AuthorizationContext,
        required: AuthorizationContext,
    },
    PrincipalAssurance {
        aal: u8,
    },
    Action {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        permission: Option<String>,
    },
    Guard {
        evidence: &'static str,
        require_guard: bool,
    },
    Subject {
        map: &'static str,
        subject: String,
        roles: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rights: Option<RightsNames>,
    },
    Network {
        ip: IpAddr,
        #[serde(skip_serializing_if = "Option::is_none")]
        matched: Option<NetworkRule>,
        /// Less specific rules that also contain the address but lost.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        shadowed: Vec<NetworkRule>,
    },
    RoleExpansion {
        subject_roles: Vec<RoleNode>,
        #[serde(skip_serializing_if = "Option::is_none")]
        network_roles: Option<Vec<RoleNode>>,
        subject: RightsNames,
        #[serde(skip_serializing_if = "Option::is_none")]
        network: Option<RightsNames>,
        effective: RightsNames,
    },
    Check {
        requested: String,
        known: bool,
        source: &'static str,
        granted_by_subject_roles: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        granted_by_network_roles: Option<Vec<String>>,
    },
    Assurance {
        presented: u8,
        required: u8,
        role_minimum: u8,
        resource_minimum: u8,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Explanation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obligations: Option<Obligations>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Vec<StageEntry>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub trace_truncated: bool,
}

/// A compiled snapshot plus the document that produced it.
#[derive(Clone, Copy)]
pub struct Snapshot<'a> {
    pub policy: &'a Policy,
    pub compiled: &'a CompiledPolicy,
    /// Revision that `minimum_revision` is compared with (a candidate uses the
    /// revision it would receive on publication).
    pub revision: u64,
    /// False when enforcement would refuse to decide (unhealthy or expired source).
    pub serving: bool,
}

// ---------------------------------------------------------------------------
// Explain
// ---------------------------------------------------------------------------

fn stage_entry(
    stage: Stage,
    result: StageResult,
    code: &'static str,
    detail: Option<StageDetail>,
) -> StageEntry {
    StageEntry {
        stage,
        result,
        code,
        label_key: stage.message_key(),
        detail,
    }
}
/// Explain one validated case. `Err` only for invalid input.
pub fn explain(snapshot: Snapshot<'_>, case: &Case, trace: bool) -> Result<Explanation, CaseError> {
    let target = case.target()?;
    let path = match (case.subject.kind, target) {
        (SubjectKind::User, Target::Permission { .. }) => PERMISSION_PATH,
        (SubjectKind::Human, _) => HUMAN_PATH,
        (SubjectKind::KubernetesApi, _) => KUBERNETES_API_PATH,
        _ => RESOURCE_PATH,
    };
    let fence = StageDetail::Fence {
        revision: snapshot.revision,
        minimum_revision: case.minimum_revision,
        serving: snapshot.serving,
    };
    let refused = if !snapshot.serving {
        Some("pumgye.detail.snapshot_unavailable")
    } else if snapshot.revision < case.minimum_revision {
        Some("pumgye.detail.revision_floor")
    } else {
        None
    };
    if let Some(code) = refused {
        let mut entries = vec![stage_entry(
            Stage::Fence,
            StageResult::Deny,
            code,
            Some(fence),
        )];
        pad(&mut entries, path, Stage::Fence);
        return Ok(Explanation {
            label: case.label.clone(),
            outcome: Outcome {
                decision: None,
                allow: false,
                reason_code: UNAVAILABLE.code,
                message_key: UNAVAILABLE.message_key,
                hint_key: UNAVAILABLE.hint_key,
                deciding_stage: Stage::Fence,
                detail_code: code,
            },
            obligations: None,
            trace: trace.then_some(entries),
            trace_truncated: false,
        });
    }
    let compiled = snapshot.compiled;
    let mut sink = VecTrace::default();
    let subject = case.subject.id.as_str();
    let ip = case.ip.unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let guard = case.guard.map_or(GuardEvidence::Unavailable, Into::into);
    let decision = match (case.subject.kind, target) {
        (SubjectKind::User, Target::Permission { permission, class }) => {
            ResourceDecision::Decided(compiled.evaluate_traced(
                &case.service,
                subject,
                ip,
                permission,
                class,
                case.aal,
                guard,
                &mut sink,
            ))
        }
        (SubjectKind::User, Target::Resource { resource, action }) => compiled
            .evaluate_scoped_resource_traced(
                &case.service,
                resource,
                action,
                subject,
                ip,
                case.aal,
                guard,
                &mut sink,
            ),
        (SubjectKind::Workload, Target::Resource { resource, action }) => compiled
            .evaluate_scoped_workload_resource_traced(
                &case.service,
                resource,
                action,
                subject,
                ip,
                guard,
                &mut sink,
            ),
        (SubjectKind::Human, Target::Resource { resource, action }) => compiled
            .evaluate_scoped_human_resource_traced(
                &case.service,
                resource,
                action,
                subject,
                ip,
                case.aal,
                guard,
                &mut sink,
            ),
        (SubjectKind::KubernetesApi, Target::Resource { resource, action }) => compiled
            .evaluate_kubernetes_api_resource_traced(
                &case.service,
                resource,
                action,
                KubernetesApiSubject::parse(subject).map_err(|_| CaseError::InvalidName)?,
                &mut sink,
            ),
        _ => return Err(CaseError::UnsupportedCombination),
    };
    let mut render = Renderer {
        policy: snapshot.policy,
        case,
        target,
        subject_rights: None,
        network: None,
        trace,
    };
    for event in sink.events() {
        match *event {
            TraceEvent::Subject { rights, .. } => render.subject_rights = rights,
            TraceEvent::Network { matched, .. } => render.network = matched,
            _ => {}
        }
    }
    let mut entries = vec![stage_entry(
        Stage::Fence,
        StageResult::Pass,
        "pumgye.detail.fence_satisfied",
        Some(fence),
    )];
    let events = sink.events();
    let allow = decision == ResourceDecision::Decided(Decision::Allow);
    let mut obligations = None;
    for (i, event) in events.iter().enumerate() {
        let last = i + 1 == events.len();
        let failed = last && !allow;
        // The Human entrypoint checks the context before the shared evaluator
        // repeats it; report the first (deciding) check only.
        if matches!(event, TraceEvent::Context { .. })
            && entries.iter().any(|e| e.stage == Stage::Context)
            && !failed
        {
            continue;
        }
        let entry = render.entry(event, failed);
        if let (
            true,
            TraceEvent::Assurance {
                presented,
                role_minimum,
                resource_minimum,
            },
        ) = (failed, event)
        {
            let required = (*role_minimum).max(*resource_minimum);
            if *presented < required && required <= 3 {
                obligations = Some(Obligations {
                    required_aal: required,
                });
            }
        }
        entries.push(entry);
    }
    let deciding = entries.last().expect("fence entry");
    let (deciding_stage, detail_code) = (deciding.stage, deciding.code);
    pad(&mut entries, path, deciding_stage);
    let reason = reason(decision);
    Ok(Explanation {
        label: case.label.clone(),
        outcome: Outcome {
            decision: Some(decision_name(decision)),
            allow,
            reason_code: reason.code,
            message_key: reason.message_key,
            hint_key: reason.hint_key,
            deciding_stage,
            detail_code,
        },
        obligations,
        trace: trace.then_some(entries),
        trace_truncated: sink.truncated(),
    })
}
fn pad(entries: &mut Vec<StageEntry>, path: &[Stage], deciding: Stage) {
    if let Some(position) = path.iter().position(|s| *s == deciding) {
        for stage in &path[position + 1..] {
            entries.push(stage_entry(
                *stage,
                StageResult::NotEvaluated,
                "pumgye.detail.not_evaluated",
                None,
            ));
        }
    }
}
struct Renderer<'a> {
    policy: &'a Policy,
    case: &'a Case,
    target: Target<'a>,
    subject_rights: Option<RightsView>,
    network: Option<NetworkMatch>,
    /// Detail is rendered only for traced explanations; codes are always derived.
    trace: bool,
}
impl Renderer<'_> {
    fn service(&self) -> Option<&Service> {
        self.policy.services.get(&self.case.service)
    }
    fn names(&self, rights: RightsView) -> RightsNames {
        let Some(service) = self.service() else {
            return RightsNames::default();
        };
        RightsNames {
            permissions: bits(&service.permissions, rights.permissions),
            information_classes: bits(&self.policy.information_classes, rights.classes),
            minimum_aal: rights.minimum_aal,
        }
    }
    fn assigned_roles(&self, map: SubjectMap, subject: &str) -> Vec<String> {
        let Some(service) = self.service() else {
            return Vec::new();
        };
        let map = match map {
            SubjectMap::Users => &service.users,
            SubjectMap::WorkloadUsers => &service.workload_users,
            SubjectMap::HumanUsers => &service.human_users,
        };
        map.get(subject).cloned().unwrap_or_default()
    }
    fn subject_roles(&self) -> Vec<String> {
        let map = match self.case.subject.kind {
            SubjectKind::Workload => SubjectMap::WorkloadUsers,
            SubjectKind::Human => SubjectMap::HumanUsers,
            _ => SubjectMap::Users,
        };
        self.assigned_roles(map, &self.case.subject.id)
    }
    fn network_rule(&self, matched: &NetworkMatch) -> Option<NetworkRule> {
        let network = self.service()?.networks.get(matched.rule as usize)?;
        Some(NetworkRule {
            index: matched.rule,
            cidr: network.cidr.to_string(),
            exact_host: matched.exact_host,
            roles: network.roles.clone(),
        })
    }
    fn network_roles(&self, rule: u32) -> Vec<String> {
        self.service()
            .and_then(|s| s.networks.get(rule as usize))
            .map(|n| n.roles.clone())
            .unwrap_or_default()
    }
    /// Role closure in breadth-first order with the inheriting role recorded.
    fn expand(&self, roots: &[String]) -> Vec<RoleNode> {
        let Some(service) = self.service() else {
            return Vec::new();
        };
        let mut seen = BTreeSet::new();
        let mut queue: std::collections::VecDeque<(String, Option<String>)> =
            roots.iter().map(|r| (r.clone(), None)).collect();
        let mut nodes = Vec::new();
        while let Some((id, parent)) = queue.pop_front() {
            if !seen.insert(id.clone()) || nodes.len() >= 128 {
                continue;
            }
            let role = service.roles.get(&id);
            nodes.push(RoleNode {
                role: id.clone(),
                inherited_from: parent,
                permissions: role.map(|r| r.permissions.clone()).unwrap_or_default(),
                information_classes: role
                    .map(|r| r.information_classes.clone())
                    .unwrap_or_default(),
                minimum_aal: role.map_or(0, |r| r.minimum_aal),
            });
            if let Some(role) = role {
                for child in &role.inherits {
                    queue.push_back((child.clone(), Some(id.clone())));
                }
            }
        }
        nodes
    }
    fn granting(nodes: &[RoleNode], name: &str, permission: bool) -> Vec<String> {
        nodes
            .iter()
            .filter(|n| {
                if permission {
                    n.permissions.iter().any(|p| p == name)
                } else {
                    n.information_classes.iter().any(|c| c == name)
                }
            })
            .map(|n| n.role.clone())
            .collect()
    }
    fn requested_permission(&self, bit: Option<u64>) -> String {
        match self.target {
            Target::Permission { permission, .. } => permission.to_owned(),
            Target::Resource { .. } => self
                .service()
                .and_then(|s| bit.and_then(|b| bits(&s.permissions, b).into_iter().next()))
                .unwrap_or_default(),
        }
    }
    fn requested_class(&self) -> (String, &'static str) {
        match self.target {
            Target::Permission { class, .. } => (class.to_owned(), "request"),
            Target::Resource { resource, .. } => (
                self.policy
                    .resources
                    .get(resource)
                    .map(|r| r.information_class.clone())
                    .unwrap_or_default(),
                "resource_catalog",
            ),
        }
    }
    fn network_role_nodes(&self) -> Option<Vec<RoleNode>> {
        self.network
            .map(|m| self.expand(&self.network_roles(m.rule)))
    }
    fn check_code(&self, failed: bool, requested: Option<u64>, permission: bool) -> &'static str {
        let subject = self.subject_rights.unwrap_or_default();
        let held = if permission {
            subject.permissions
        } else {
            subject.classes
        };
        match (failed, requested, permission) {
            (false, _, true) => "pumgye.detail.permission_granted",
            (false, _, false) => "pumgye.detail.class_granted",
            (true, None, true) => "pumgye.detail.permission_unknown",
            (true, None, false) => "pumgye.detail.class_unknown",
            (true, Some(bit), true) if held & bit == 0 => {
                "pumgye.detail.permission_missing_subject"
            }
            (true, Some(bit), false) if held & bit == 0 => "pumgye.detail.class_missing_subject",
            (true, Some(_), true) => "pumgye.detail.permission_removed_by_network",
            (true, Some(_), false) => "pumgye.detail.class_removed_by_network",
        }
    }
    fn check_detail(
        &self,
        requested: String,
        known: bool,
        source: &'static str,
        permission: bool,
    ) -> StageDetail {
        let subject = self.expand(&self.subject_roles());
        StageDetail::Check {
            granted_by_subject_roles: Self::granting(&subject, &requested, permission),
            granted_by_network_roles: self
                .network_role_nodes()
                .map(|nodes| Self::granting(&nodes, &requested, permission)),
            requested,
            known,
            source,
        }
    }
    fn entry(&self, event: &TraceEvent<'_>, failed: bool) -> StageEntry {
        let result = if failed {
            StageResult::Deny
        } else {
            StageResult::Pass
        };
        let pick = |pass: &'static str, deny: &'static str| if failed { deny } else { pass };
        match *event {
            TraceEvent::Service { service, .. } => stage_entry(
                Stage::Service,
                result,
                pick(
                    "pumgye.detail.service_found",
                    "pumgye.detail.service_not_found",
                ),
                Some(StageDetail::Service {
                    service: service.to_owned(),
                }),
            ),
            TraceEvent::Resource { resource, owner } => stage_entry(
                Stage::Resource,
                result,
                pick(
                    "pumgye.detail.resource_found",
                    "pumgye.detail.resource_not_found",
                ),
                Some(StageDetail::Resource {
                    resource: resource.to_owned(),
                    owner: owner.map(str::to_owned),
                }),
            ),
            TraceEvent::Scope { requested, owner } => stage_entry(
                Stage::ServiceScope,
                result,
                pick(
                    "pumgye.detail.scope_matched",
                    "pumgye.detail.scope_mismatch",
                ),
                Some(StageDetail::Scope {
                    requested: requested.to_owned(),
                    owner: owner.to_owned(),
                }),
            ),
            TraceEvent::Context { context, required } => stage_entry(
                Stage::Context,
                result,
                pick(
                    "pumgye.detail.context_matched",
                    "pumgye.detail.context_mismatch",
                ),
                Some(StageDetail::Context { context, required }),
            ),
            TraceEvent::PrincipalFormat { .. } => stage_entry(
                Stage::PrincipalFormat,
                result,
                pick(
                    "pumgye.detail.principal_valid",
                    "pumgye.detail.principal_invalid",
                ),
                None,
            ),
            TraceEvent::PrincipalAssurance { aal } => stage_entry(
                Stage::PrincipalAssurance,
                result,
                pick(
                    "pumgye.detail.principal_assurance_valid",
                    "pumgye.detail.principal_assurance_invalid",
                ),
                Some(StageDetail::PrincipalAssurance { aal }),
            ),
            TraceEvent::Action { action, permission } => stage_entry(
                Stage::Action,
                result,
                pick(
                    "pumgye.detail.action_mapped",
                    "pumgye.detail.action_unknown",
                ),
                Some(StageDetail::Action {
                    action: action.to_owned(),
                    permission: permission.map(|b| self.requested_permission(Some(b))),
                }),
            ),
            TraceEvent::Guard {
                evidence,
                require_guard,
            } => {
                let code = match (failed, evidence) {
                    (true, GuardEvidence::Deny) => "pumgye.detail.guard_denied",
                    (true, _) => "pumgye.detail.guard_not_enforced",
                    (false, GuardEvidence::EnforcedAllow) => "pumgye.detail.guard_enforced_allow",
                    (false, _) => "pumgye.detail.guard_not_required",
                };
                stage_entry(
                    Stage::Guard,
                    result,
                    code,
                    Some(StageDetail::Guard {
                        evidence: guard_name(evidence),
                        require_guard,
                    }),
                )
            }
            TraceEvent::Subject {
                map,
                subject,
                rights,
            } => {
                let code = match (failed, rights) {
                    (false, _) => "pumgye.detail.subject_assigned",
                    (true, None) => "pumgye.detail.subject_not_assigned",
                    (true, Some(_)) => "pumgye.detail.subject_guest_only",
                };
                stage_entry(
                    Stage::Subject,
                    result,
                    code,
                    Some(StageDetail::Subject {
                        map: match map {
                            SubjectMap::Users => "users",
                            SubjectMap::WorkloadUsers => "workload_users",
                            SubjectMap::HumanUsers => "human_users",
                        },
                        subject: subject.to_owned(),
                        roles: self.assigned_roles(map, subject),
                        rights: rights.map(|r| self.names(r)),
                    }),
                )
            }
            TraceEvent::Network { ip, matched } => {
                let shadowed = self
                    .service()
                    .filter(|_| self.trace)
                    .map(|s| {
                        let mut rules: Vec<_> = s
                            .networks
                            .iter()
                            .enumerate()
                            .filter(|(i, n)| {
                                n.cidr.contains(&ip.to_canonical())
                                    && matched.is_none_or(|m| m.rule as usize != *i)
                            })
                            .map(|(i, n)| NetworkRule {
                                index: i as u32,
                                cidr: n.cidr.to_string(),
                                exact_host: false,
                                roles: n.roles.clone(),
                            })
                            .collect();
                        rules.truncate(MAX_SHADOWED_RULES);
                        rules
                    })
                    .unwrap_or_default();
                stage_entry(
                    Stage::Network,
                    result,
                    pick(
                        "pumgye.detail.network_matched",
                        "pumgye.detail.network_no_match",
                    ),
                    Some(StageDetail::Network {
                        ip,
                        matched: matched.and_then(|m| self.network_rule(&m)),
                        shadowed,
                    }),
                )
            }
            TraceEvent::Entitlements {
                subject,
                network,
                effective,
            } => stage_entry(
                Stage::RoleExpansion,
                StageResult::Pass,
                "pumgye.detail.roles_intersected",
                Some(StageDetail::RoleExpansion {
                    subject_roles: self.expand(&self.subject_roles()),
                    network_roles: self.network_role_nodes(),
                    subject: self.names(subject),
                    network: network.map(|n| self.names(n)),
                    effective: self.names(effective),
                }),
            ),
            TraceEvent::Permission { requested, .. } => {
                let name = self.requested_permission(requested);
                let known = requested.is_some();
                let code = self.check_code(failed, requested, true);
                stage_entry(
                    Stage::Permission,
                    result,
                    code,
                    Some(self.check_detail(name, known, "service_vocabulary", true)),
                )
            }
            TraceEvent::Class { requested, .. } => {
                let (name, source) = self.requested_class();
                let known = requested.is_some();
                let code = self.check_code(failed, requested, false);
                stage_entry(
                    Stage::InformationClass,
                    result,
                    code,
                    Some(self.check_detail(name, known, source, false)),
                )
            }
            TraceEvent::Assurance {
                presented,
                role_minimum,
                resource_minimum,
            } => {
                let code = match (failed, presented > 3) {
                    (false, _) => "pumgye.detail.assurance_satisfied",
                    (true, true) => "pumgye.detail.assurance_out_of_range",
                    (true, false) => "pumgye.detail.assurance_below_required",
                };
                stage_entry(
                    Stage::Assurance,
                    result,
                    code,
                    Some(StageDetail::Assurance {
                        presented,
                        required: role_minimum.max(resource_minimum),
                        role_minimum,
                        resource_minimum,
                    }),
                )
            }
        }
    }
}
pub(crate) fn bits(vocabulary: &[String], mask: u64) -> Vec<String> {
    vocabulary
        .iter()
        .enumerate()
        .filter(|(i, _)| *i < 64 && mask & (1u64 << i) != 0)
        .map(|(_, v)| v.clone())
        .collect()
}
