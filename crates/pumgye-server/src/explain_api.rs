//! Administrative explain / what-if / candidate diff API (read-only simulation).
//!
//! Admin credential only; the decision credential is refused by the request gate
//! and again here. Simulations evaluate the in-memory published snapshot or a
//! caller-supplied candidate document that is validated and compiled but never
//! stored. They never touch the decision counters, permit signers, observed
//! permit owners or the publication table; each one appends a `simulation`
//! audit row before its result is released.
use crate::{Authority, PeerIdentity, View, authorized, store};
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use pumgye_core::{
    CompiledPolicy, Policy,
    diff::{DiffPage, Side, diff},
    explain::{Case, EXPLAIN_VERSION, Explanation, Outcome, Snapshot, explain},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex, atomic::Ordering},
    time::Instant,
};

/// Maximum cases per batch request.
pub const MAX_BATCH_CASES: usize = 256;
/// Maximum cases per batch request when full traces are requested.
pub const MAX_TRACED_BATCH_CASES: usize = 32;
/// Maximum diff entries per page.
pub const MAX_DIFF_PAGE: usize = 500;
/// Request body bound: one maximal candidate document plus case payload.
pub const BODY_LIMIT: usize = store::MAX_POLICY_BYTES + 256 * 1024;
/// Token bucket shared by all simulation endpoints (cost = cases, plus a
/// candidate compilation surcharge).
pub const BUDGET_CAPACITY: f64 = 1024.0;
pub const BUDGET_REFILL_PER_SECOND: f64 = 256.0;
pub const CANDIDATE_COST: f64 = 64.0;

/// Process-wide simulation rate budget, independent of decision admission.
pub struct Budget {
    state: Mutex<(f64, Instant)>,
    pub(crate) simulations: std::sync::atomic::AtomicU64,
    /// Simulation audit rows older than this are trimmed on insert.
    pub(crate) retention_seconds: u64,
}
/// Default simulation audit age bound.
pub const DEFAULT_RETENTION_DAYS: u64 = 30;
impl Default for Budget {
    fn default() -> Self {
        Self::with_retention_days(DEFAULT_RETENTION_DAYS)
    }
}
impl Budget {
    pub fn with_retention_days(days: u64) -> Self {
        Self {
            state: Mutex::new((BUDGET_CAPACITY, Instant::now())),
            simulations: Default::default(),
            retention_seconds: days.saturating_mul(86_400),
        }
    }
    fn take(&self, cost: f64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let now = Instant::now();
        let refill = now.duration_since(state.1).as_secs_f64() * BUDGET_REFILL_PER_SECOND;
        state.0 = (state.0 + refill).min(BUDGET_CAPACITY);
        state.1 = now;
        if state.0 < cost {
            return false;
        }
        state.0 -= cost;
        true
    }
    #[cfg(test)]
    pub(crate) fn drain(&self) {
        let mut state = self.state.lock().unwrap();
        *state = (0.0, Instant::now());
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
enum Selector {
    /// The current published snapshot; `revision` pins it (409 on mismatch).
    Published {
        #[serde(default)]
        revision: Option<u64>,
    },
    /// An unpublished document evaluated against `base_revision` (409 on mismatch).
    Candidate {
        base_revision: u64,
        policy: serde_json::Value,
    },
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainRequest {
    #[serde(default)]
    snapshot: Option<Selector>,
    case: Case,
    #[serde(default = "yes")]
    trace: bool,
    #[serde(default)]
    on_behalf_of: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRequest {
    #[serde(default)]
    snapshot: Option<Selector>,
    cases: Vec<Case>,
    #[serde(default)]
    trace: bool,
    #[serde(default)]
    on_behalf_of: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiffRequest {
    base_revision: u64,
    policy: serde_json::Value,
    #[serde(default)]
    cursor: usize,
    #[serde(default = "page")]
    limit: usize,
    #[serde(default)]
    on_behalf_of: Option<String>,
}
fn yes() -> bool {
    true
}
fn page() -> usize {
    100
}

#[derive(Serialize)]
struct SnapshotLabel {
    source: &'static str,
    /// Published: the evaluated revision. Candidate: the revision it would get.
    revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_sha256: Option<String>,
    serving: bool,
}
#[derive(Serialize)]
struct Comparison {
    published: Outcome,
    changed: bool,
}
#[derive(Serialize)]
struct CaseResult {
    #[serde(flatten)]
    explanation: Explanation,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<Comparison>,
}
#[derive(Default, Serialize)]
struct Summary {
    cases: u64,
    allowed: u64,
    denied: u64,
    unavailable: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    changed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_to_deny: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_to_allow: Option<u64>,
}

struct Candidate {
    policy: Policy,
    compiled: CompiledPolicy,
    sha256: String,
}
struct Resolved {
    view: Arc<View>,
    serving: bool,
    candidate: Option<(u64, Candidate)>,
}
impl Resolved {
    fn published(&self) -> Snapshot<'_> {
        Snapshot {
            policy: &self.view.document.policy,
            compiled: &self.view.compiled,
            revision: self.view.document.revision,
            serving: self.serving,
        }
    }
    fn evaluated(&self) -> Snapshot<'_> {
        match &self.candidate {
            Some((base, c)) => Snapshot {
                policy: &c.policy,
                compiled: &c.compiled,
                revision: base.saturating_add(1),
                serving: true,
            },
            None => self.published(),
        }
    }
    fn label(&self) -> SnapshotLabel {
        match &self.candidate {
            Some((base, c)) => SnapshotLabel {
                source: "candidate",
                revision: base.saturating_add(1),
                base_revision: Some(*base),
                candidate_sha256: Some(c.sha256.clone()),
                serving: true,
            },
            None => SnapshotLabel {
                source: "published",
                revision: self.view.document.revision,
                base_revision: None,
                candidate_sha256: None,
                serving: self.serving,
            },
        }
    }
}

/// One located cause of a refusal.
#[derive(Debug, Serialize)]
pub(crate) struct ErrorDetail {
    path: String,
    code: &'static str,
    message_key: &'static str,
}
fn detail(path: impl Into<String>, code: &'static str) -> ErrorDetail {
    ErrorDetail {
        path: path.into(),
        code,
        message_key: code,
    }
}
/// Refusal of a simulation request. Coded refusals (400/409/413/422/429) carry a
/// structured body; authentication, media type and availability stay bare.
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: Option<&'static str>,
    details: Vec<ErrorDetail>,
    current_revision: Option<u64>,
}
/// Maximum details reported per refusal.
pub const MAX_ERROR_DETAILS: usize = 32;
impl ApiError {
    fn coded(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code: Some(code),
            details: Vec::new(),
            current_revision: None,
        }
    }
    fn with(mut self, detail: ErrorDetail) -> Self {
        if self.details.len() < MAX_ERROR_DETAILS {
            self.details.push(detail);
        }
        self
    }
    fn conflict(path: &str, current: u64) -> Self {
        let mut error = Self::coded(StatusCode::CONFLICT, "pumgye.error.revision_conflict")
            .with(detail(path, "pumgye.error.revision_conflict"));
        error.current_revision = Some(current);
        error
    }
    fn malformed(path: String) -> Self {
        let path = if path.is_empty() {
            "$".to_owned()
        } else {
            path
        };
        Self::coded(StatusCode::BAD_REQUEST, "pumgye.error.malformed_request")
            .with(detail(path, "pumgye.error.malformed_request"))
    }
}
impl From<StatusCode> for ApiError {
    fn from(status: StatusCode) -> Self {
        Self {
            status,
            code: None,
            details: Vec::new(),
            current_revision: None,
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = match self.code {
            Some(code) => {
                let mut error = serde_json::json!({"code": code, "message_key": code});
                if !self.details.is_empty() {
                    error["details"] = serde_json::json!(self.details);
                }
                if let Some(revision) = self.current_revision {
                    error["current_revision"] = revision.into();
                }
                (self.status, Json(serde_json::json!({ "error": error }))).into_response()
            }
            None => self.status.into_response(),
        };
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
        }
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        response
    }
}
fn join(prefix: &str, path: &str) -> String {
    match path {
        "" | "." => prefix.to_owned(),
        _ if prefix.is_empty() => path.to_owned(),
        _ if path.starts_with('[') => format!("{prefix}{path}"),
        _ => format!("{prefix}.{path}"),
    }
}
fn invalid_candidate(path: String, code: &'static str) -> ApiError {
    ApiError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "pumgye.error.candidate_invalid",
    )
    .with(detail(path, code))
}
/// Validate and compile a candidate exactly as publication would, never storing it.
/// `prefix` is the request path of the document, for located refusals.
fn candidate(value: serde_json::Value, prefix: &str) -> Result<Candidate, ApiError> {
    let policy: Policy = serde_path_to_error::deserialize(value).map_err(|e| {
        invalid_candidate(
            join(prefix, &e.path().to_string()),
            pumgye_core::VALIDATION_SCHEMA,
        )
    })?;
    let bytes = serde_json::to_vec(&policy).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if bytes.len() > store::MAX_POLICY_BYTES {
        return Err(ApiError::coded(
            StatusCode::PAYLOAD_TOO_LARGE,
            "pumgye.error.candidate_too_large",
        )
        .with(detail(prefix, "pumgye.error.candidate_too_large")));
    }
    let compiled = policy
        .compile_located()
        .map_err(|v| invalid_candidate(join(prefix, &v.path.replace('$', "")), v.code))?;
    Ok(Candidate {
        policy,
        compiled,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}
fn resolve(a: &Authority, selector: Option<Selector>, prefix: &str) -> Result<Resolved, ApiError> {
    let view = a.view.load_full();
    let serving = a.healthy.load(Ordering::Acquire) && a.source_remaining(&view).is_some();
    let current = view.document.revision;
    let candidate = match selector.unwrap_or(Selector::Published { revision: None }) {
        Selector::Published { revision } => {
            if revision.is_some_and(|r| r != current) {
                return Err(ApiError::conflict(&join(prefix, "revision"), current));
            }
            None
        }
        Selector::Candidate {
            base_revision,
            policy,
        } => {
            if base_revision != current {
                return Err(ApiError::conflict(&join(prefix, "base_revision"), current));
            }
            Some((base_revision, candidate(policy, &join(prefix, "policy"))?))
        }
    };
    Ok(Resolved {
        view,
        serving,
        candidate,
    })
}
fn delegated(value: &Option<String>) -> Result<(), ApiError> {
    match value {
        Some(v)
            if v.is_empty()
                || v.len() > 128
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:@-".contains(&b)) =>
        {
            Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                "pumgye.error.invalid_delegated_actor",
            )
            .with(detail(
                "on_behalf_of",
                "pumgye.error.invalid_delegated_actor",
            )))
        }
        _ => Ok(()),
    }
}
fn json_body(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}
type Body = Result<Bytes, axum::extract::rejection::BytesRejection>;
fn admit<T: for<'de> Deserialize<'de>>(
    a: &Authority,
    headers: &HeaderMap,
    body: Body,
) -> Result<(T, Bytes), ApiError> {
    if !authorized(headers, &a.admin) {
        return Err(StatusCode::UNAUTHORIZED.into());
    }
    if !json_body(headers) {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into());
    }
    let body = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::coded(
                StatusCode::PAYLOAD_TOO_LARGE,
                "pumgye.error.payload_too_large",
            )
        } else {
            ApiError::from(StatusCode::BAD_REQUEST)
        }
    })?;
    let request =
        serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(&body))
            .map_err(|e| ApiError::malformed(join("", &e.path().to_string())))?;
    Ok((request, body))
}
/// Refuse every invalid case with its located field (bounded).
fn validate_cases<'a>(cases: impl IntoIterator<Item = (String, &'a Case)>) -> Result<(), ApiError> {
    let mut error = ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.invalid_case");
    for (prefix, case) in cases {
        if let Err(e) = case.validate() {
            error = error.with(detail(join(&prefix, case.error_path(e)), e.code()));
        }
    }
    if error.details.is_empty() {
        Ok(())
    } else {
        Err(error)
    }
}
fn rate_limited() -> ApiError {
    ApiError::coded(StatusCode::TOO_MANY_REQUESTS, "pumgye.error.rate_limited")
}
struct Audit {
    actor: String,
    on_behalf_of: Option<String>,
    operation: &'static str,
    request_sha256: String,
}
fn record(
    a: &Authority,
    audit: Audit,
    resolved: &Resolved,
    summary: &Summary,
) -> Result<u64, ApiError> {
    let label = resolved.label();
    let mut store = a
        .store
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    store
        .record_simulation(
            &store::SimulationRecord {
                id: 0,
                at_unix: 0,
                kind: "simulation",
                actor: audit.actor,
                on_behalf_of: audit.on_behalf_of,
                operation: audit.operation.into(),
                source: label.source.into(),
                revision: label.base_revision.unwrap_or(label.revision),
                candidate_sha256: label.candidate_sha256,
                request_sha256: audit.request_sha256,
                cases: summary.cases,
                allowed: summary.allowed,
                denied: summary.denied,
                unavailable: summary.unavailable,
                changed: summary.changed.unwrap_or(0),
            },
            a.simulation_budget.retention_seconds,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into())
}
fn evaluate(
    resolved: &Resolved,
    cases: &[Case],
    trace: bool,
) -> Result<(Vec<CaseResult>, Summary), ApiError> {
    let compare = resolved.candidate.is_some();
    let mut summary = Summary {
        changed: compare.then_some(0),
        allow_to_deny: compare.then_some(0),
        deny_to_allow: compare.then_some(0),
        ..Default::default()
    };
    let refused = |_| ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.invalid_case");
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let explanation = explain(resolved.evaluated(), case, trace).map_err(refused)?;
        summary.cases += 1;
        match (explanation.outcome.decision, explanation.outcome.allow) {
            (None, _) => summary.unavailable += 1,
            (_, true) => summary.allowed += 1,
            (_, false) => summary.denied += 1,
        }
        let comparison = if compare {
            let published = explain(resolved.published(), case, false)
                .map_err(refused)?
                .outcome;
            let changed = published.decision != explanation.outcome.decision;
            if changed {
                *summary.changed.as_mut().unwrap() += 1;
                if published.allow && !explanation.outcome.allow {
                    *summary.allow_to_deny.as_mut().unwrap() += 1;
                }
                if !published.allow && explanation.outcome.allow {
                    *summary.deny_to_allow.as_mut().unwrap() += 1;
                }
            }
            Some(Comparison { published, changed })
        } else {
            None
        };
        results.push(CaseResult {
            explanation,
            comparison,
        });
    }
    Ok((results, summary))
}
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| ApiError::from(StatusCode::SERVICE_UNAVAILABLE))?
}
fn finish(value: Result<serde_json::Value, ApiError>) -> Response {
    match value {
        Ok(value) => ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response(),
        Err(error) => error.into_response(),
    }
}
fn digest(body: &Bytes) -> String {
    format!("{:x}", Sha256::digest(body))
}
fn json(value: serde_json::Value) -> Result<serde_json::Value, ApiError> {
    Ok(value)
}

/// `POST /v1/explain`: one case with a full ordered stage trace by default.
pub(crate) async fn explain_one(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(explain_one_inner(a, headers, peer, body).await)
}
async fn explain_one_inner(
    a: Arc<Authority>,
    headers: HeaderMap,
    peer: PeerIdentity,
    body: Body,
) -> Result<serde_json::Value, ApiError> {
    let (request, body): (ExplainRequest, _) = admit(&a, &headers, body)?;
    delegated(&request.on_behalf_of)?;
    validate_cases([("case".to_owned(), &request.case)])?;
    let cost = 1.0
        + if matches!(request.snapshot, Some(Selector::Candidate { .. })) {
            CANDIDATE_COST
        } else {
            0.0
        };
    if !a.simulation_budget.take(cost) {
        return Err(rate_limited());
    }
    let audit = Audit {
        actor: peer.0,
        on_behalf_of: request.on_behalf_of,
        operation: "explain",
        request_sha256: digest(&body),
    };
    blocking(move || {
        let resolved = resolve(&a, request.snapshot, "snapshot")?;
        let (mut results, summary) = evaluate(
            &resolved,
            std::slice::from_ref(&request.case),
            request.trace,
        )?;
        let audit_id = record(&a, audit, &resolved, &summary)?;
        a.simulation_budget
            .simulations
            .fetch_add(1, Ordering::Relaxed);
        let result = results
            .pop()
            .ok_or(ApiError::from(StatusCode::INTERNAL_SERVER_ERROR))?;
        json(serde_json::json!({
            "version": EXPLAIN_VERSION,
            "kind": "simulation",
            "audit_id": audit_id,
            "snapshot": resolved.label(),
            "result": result,
        }))
    })
    .await
}

/// `POST /v1/explain/batch`: up to 256 cases (32 with traces) on one snapshot.
pub(crate) async fn explain_batch(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(explain_batch_inner(a, headers, peer, body).await)
}
async fn explain_batch_inner(
    a: Arc<Authority>,
    headers: HeaderMap,
    peer: PeerIdentity,
    body: Body,
) -> Result<serde_json::Value, ApiError> {
    let (request, body): (BatchRequest, _) = admit(&a, &headers, body)?;
    let limit = if request.trace {
        MAX_TRACED_BATCH_CASES
    } else {
        MAX_BATCH_CASES
    };
    if request.cases.len() > limit {
        return Err(ApiError::coded(
            StatusCode::PAYLOAD_TOO_LARGE,
            "pumgye.error.batch_too_large",
        )
        .with(detail("cases", "pumgye.error.batch_too_large")));
    }
    if request.cases.is_empty() {
        return Err(
            ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.empty_batch")
                .with(detail("cases", "pumgye.error.empty_batch")),
        );
    }
    delegated(&request.on_behalf_of)?;
    validate_cases(
        request
            .cases
            .iter()
            .enumerate()
            .map(|(i, c)| (format!("cases[{i}]"), c)),
    )?;
    let candidate = matches!(request.snapshot, Some(Selector::Candidate { .. }));
    let cost = request.cases.len() as f64 * if candidate { 2.0 } else { 1.0 }
        + if candidate { CANDIDATE_COST } else { 0.0 };
    if !a.simulation_budget.take(cost) {
        return Err(rate_limited());
    }
    let audit = Audit {
        actor: peer.0,
        on_behalf_of: request.on_behalf_of,
        operation: "explain_batch",
        request_sha256: digest(&body),
    };
    blocking(move || {
        let resolved = resolve(&a, request.snapshot, "snapshot")?;
        let (results, summary) = evaluate(&resolved, &request.cases, request.trace)?;
        let audit_id = record(&a, audit, &resolved, &summary)?;
        a.simulation_budget
            .simulations
            .fetch_add(1, Ordering::Relaxed);
        json(serde_json::json!({
            "version": EXPLAIN_VERSION,
            "kind": "simulation",
            "audit_id": audit_id,
            "snapshot": resolved.label(),
            "summary": summary,
            "results": results,
        }))
    })
    .await
}

/// `POST /v1/explain/diff`: role-expanded rights that change if a candidate is published.
pub(crate) async fn explain_diff(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(explain_diff_inner(a, headers, peer, body).await)
}
async fn explain_diff_inner(
    a: Arc<Authority>,
    headers: HeaderMap,
    peer: PeerIdentity,
    body: Body,
) -> Result<serde_json::Value, ApiError> {
    let (request, body): (DiffRequest, _) = admit(&a, &headers, body)?;
    let page = |path| {
        ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.invalid_page")
            .with(detail(path, "pumgye.error.invalid_page"))
    };
    if request.limit == 0 || request.limit > MAX_DIFF_PAGE {
        return Err(page("limit"));
    }
    if request.cursor > 1 << 24 {
        return Err(page("cursor"));
    }
    delegated(&request.on_behalf_of)?;
    if !a.simulation_budget.take(CANDIDATE_COST * 2.0) {
        return Err(rate_limited());
    }
    let audit = Audit {
        actor: peer.0,
        on_behalf_of: request.on_behalf_of,
        operation: "diff",
        request_sha256: digest(&body),
    };
    blocking(move || {
        let resolved = resolve(
            &a,
            Some(Selector::Candidate {
                base_revision: request.base_revision,
                policy: request.policy,
            }),
            "",
        )?;
        let (_, c) = resolved
            .candidate
            .as_ref()
            .ok_or(ApiError::from(StatusCode::INTERNAL_SERVER_ERROR))?;
        let page: DiffPage = diff(
            Side {
                policy: &resolved.view.document.policy,
                compiled: &resolved.view.compiled,
            },
            Side {
                policy: &c.policy,
                compiled: &c.compiled,
            },
            request.cursor,
            request.limit,
        );
        let summary = Summary {
            changed: Some(page.total as u64),
            ..Default::default()
        };
        let audit_id = record(&a, audit, &resolved, &summary)?;
        a.simulation_budget
            .simulations
            .fetch_add(1, Ordering::Relaxed);
        json(serde_json::json!({
            "version": EXPLAIN_VERSION,
            "kind": "simulation",
            "audit_id": audit_id,
            "snapshot": resolved.label(),
            "total": page.total,
            "next_cursor": page.next_cursor,
            "changes": page.changes,
        }))
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SimulationCursor {
    #[serde(default)]
    after_id: u64,
}
/// `GET /v1/audit/simulations?after_id=N`: up to 100 simulation audit rows.
pub(crate) async fn simulation_audit(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    cursor: Result<
        axum::extract::Query<SimulationCursor>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response {
    if !authorized(&headers, &a.admin) {
        return ApiError::from(StatusCode::UNAUTHORIZED).into_response();
    }
    let invalid = || {
        ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.invalid_cursor")
            .with(detail("after_id", "pumgye.error.invalid_cursor"))
            .into_response()
    };
    let Ok(axum::extract::Query(cursor)) = cursor else {
        return invalid();
    };
    if cursor.after_id > i64::MAX as u64 {
        return invalid();
    }
    match blocking(move || {
        let store = a
            .store
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        store
            .simulations_after(cursor.after_id)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into())
    })
    .await
    {
        Ok(rows) => ([(header::CACHE_CONTROL, "no-store")], Json(rows)).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) fn routes() -> axum::Router<Arc<Authority>> {
    use axum::{extract::DefaultBodyLimit, routing};
    axum::Router::new()
        .route(
            "/v1/explain",
            routing::post(explain_one).layer(DefaultBodyLimit::max(BODY_LIMIT)),
        )
        .route(
            "/v1/explain/batch",
            routing::post(explain_batch).layer(DefaultBodyLimit::max(BODY_LIMIT)),
        )
        .route(
            "/v1/explain/diff",
            routing::post(explain_diff).layer(DefaultBodyLimit::max(BODY_LIMIT)),
        )
        .route("/v1/audit/simulations", routing::get(simulation_audit))
}
/// Paths that require the administrator credential and management admission.
pub(crate) const ADMIN_PATHS: [&str; 4] = [
    "/v1/explain",
    "/v1/explain/batch",
    "/v1/explain/diff",
    "/v1/audit/simulations",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Document, request_gate};
    use axum::{Router, body::Body, http::Request};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    const ADMIN: &str = "fixture-admin-credential";
    const DECISION: &str = "fixture-decision-credential";

    fn document() -> Value {
        json!({"version":1,"information_classes":["public","internal"],
         "services":{"orders":{"permissions":["read","write"],"require_guard":true,
           "roles":{"reader":{"permissions":["read"],"information_classes":["public"]},
                    "writer":{"permissions":["write"],"information_classes":["internal"],"inherits":["reader"],"minimum_aal":2}},
           "users":{"u_reader":["reader"],"u_writer":["writer"]},
           "networks":[{"cidr":"192.0.2.0/24","roles":["writer"]}]}},
         "resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read","update":"write"},"minimum_aal":1}}})
    }
    fn owner() -> (tempfile::TempDir, Arc<Authority>, Router) {
        let root = tempfile::tempdir().unwrap();
        let a = crate::tests::authority(root.path());
        let policy: Policy = serde_json::from_value(document()).unwrap();
        a.view.store(Arc::new(View {
            compiled: policy.compile().unwrap(),
            document: Document {
                revision: 1,
                policy,
            },
            source_lifetime: None,
        }));
        let router = Router::new()
            .route(
                "/v1/decision",
                axum::routing::post(crate::decide)
                    .layer(axum::extract::DefaultBodyLimit::max(2048)),
            )
            .route("/v1/resource/decision", crate::resource_route())
            .route("/v1/audit", axum::routing::get(crate::audit_records))
            .route("/v1/status", axum::routing::get(crate::status))
            .merge(routes())
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
            .layer(axum::middleware::from_fn_with_state(
                a.clone(),
                request_gate,
            ))
            .layer(axum::Extension(PeerIdentity("mtls:fixture".into())))
            .with_state(a.clone());
        (root, a, router)
    }
    fn post(path: &str, token: &str, body: &Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .unwrap()
    }
    fn get(path: &str, token: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }
    async fn call(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    fn case(subject: &str, permission: &str, class: &str, aal: u8) -> Value {
        json!({"subject":{"id":subject,"kind":"user"},"service":"orders","permission":permission,
               "information_class":class,"ip":"192.0.2.1","aal":aal,"guard":"enforced_allow"})
    }
    fn candidate() -> Value {
        let mut doc = document();
        doc["services"]["orders"]["users"]["u_reader"] = json!(["writer"]);
        doc
    }

    #[tokio::test]
    async fn only_the_administrator_credential_reaches_simulation() {
        let (_root, a, router) = owner();
        let body = json!({"case":case("u_writer","write","internal",2)});
        for path in ADMIN_PATHS {
            for token in [DECISION, "wrong-credential-value"] {
                let request = if path == "/v1/audit/simulations" {
                    get(path, token)
                } else {
                    post(path, token, &body)
                };
                assert_eq!(
                    call(&router, request).await.0,
                    StatusCode::UNAUTHORIZED,
                    "{path}"
                );
            }
        }
        let (status, value) = call(&router, post("/v1/explain", ADMIN, &body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["result"]["outcome"]["decision"], "Allow");
        // Rejected attempts were not audited; the accepted one was.
        assert_eq!(
            a.store.lock().unwrap().simulations_after(0).unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn explain_reports_trace_snapshot_and_audit_without_touching_decisions() {
        let (_root, a, router) = owner();
        let (status, value) = call(
            &router,
            post(
                "/v1/explain",
                ADMIN,
                &json!({"case":case("u_writer","write","internal",1),"on_behalf_of":"console:alice@example.test"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["version"], 1);
        assert_eq!(value["kind"], "simulation");
        assert_eq!(
            value["snapshot"],
            json!({"source":"published","revision":1,"serving":true})
        );
        let outcome = &value["result"]["outcome"];
        assert_eq!(outcome["decision"], "AssuranceDenied");
        assert_eq!(outcome["reason_code"], "pumgye.assurance_denied");
        assert_eq!(outcome["message_key"], "pumgye.reason.assurance_denied");
        assert_eq!(outcome["deciding_stage"], "assurance");
        assert_eq!(value["result"]["obligations"]["required_aal"], 2);
        let stages: Vec<&str> = value["result"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["stage"].as_str().unwrap())
            .collect();
        assert_eq!(
            stages,
            [
                "fence",
                "service",
                "context",
                "guard",
                "subject",
                "network",
                "role_expansion",
                "permission",
                "information_class",
                "assurance"
            ]
        );
        // Simulations never count as decisions and never publish.
        assert_eq!(a.queries.load(Ordering::Relaxed), 0);
        assert_eq!(a.view.load().document.revision, 1);
        let (_, status_body) = call(&router, get("/v1/status", ADMIN)).await;
        assert_eq!(status_body["decision_queries"], 0);
        assert_eq!(status_body["simulation_queries"], 1);
        let (_, publications) = call(&router, get("/v1/audit", ADMIN)).await;
        assert_eq!(publications.as_array().unwrap().len(), 1, "bootstrap only");
        let (status, audit) = call(&router, get("/v1/audit/simulations", ADMIN)).await;
        assert_eq!(status, StatusCode::OK);
        let row = &audit[0];
        assert_eq!(row["kind"], "simulation");
        assert_eq!(row["actor"], "mtls:fixture");
        assert_eq!(row["on_behalf_of"], "console:alice@example.test");
        assert_eq!(row["operation"], "explain");
        assert_eq!(row["source"], "published");
        assert_eq!(row["revision"], 1);
        assert_eq!(row["cases"], 1);
        assert_eq!(row["denied"], 1);
        assert_eq!(row["request_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(value["audit_id"], row["id"]);
        let (_, empty) = call(
            &router,
            get(
                &format!("/v1/audit/simulations?after_id={}", row["id"]),
                ADMIN,
            ),
        )
        .await;
        assert_eq!(empty, json!([]));
    }

    #[tokio::test]
    async fn explain_matches_decision_endpoints_for_the_same_snapshot() {
        let (_root, _a, router) = owner();
        for (subject, permission, class, aal, guard, ip) in [
            (
                "u_writer",
                "write",
                "internal",
                2,
                "enforced_allow",
                "192.0.2.1",
            ),
            (
                "u_writer",
                "write",
                "internal",
                1,
                "enforced_allow",
                "192.0.2.1",
            ),
            (
                "u_reader",
                "write",
                "public",
                2,
                "enforced_allow",
                "192.0.2.1",
            ),
            (
                "u_reader",
                "read",
                "internal",
                2,
                "enforced_allow",
                "192.0.2.1",
            ),
            (
                "u_reader",
                "read",
                "public",
                2,
                "enforced_allow",
                "203.0.113.1",
            ),
            ("u_none", "read", "public", 2, "enforced_allow", "192.0.2.1"),
            ("u_reader", "read", "public", 2, "deny", "192.0.2.1"),
            ("u_reader", "read", "public", 2, "observe", "192.0.2.1"),
            ("u_reader", "read", "nope", 2, "enforced_allow", "192.0.2.1"),
        ] {
            let (_, decided) = call(
                &router,
                post(
                    "/v1/decision",
                    DECISION,
                    &json!({"service_id":"orders","subject":subject,"ip":ip,"permission":permission,
                            "information_class":class,"aal":aal,"guard":guard}),
                ),
            )
            .await;
            let (_, explained) = call(
                &router,
                post(
                    "/v1/explain",
                    ADMIN,
                    &json!({"trace":false,"case":{"subject":{"id":subject,"kind":"user"},"service":"orders",
                        "permission":permission,"information_class":class,"ip":ip,"aal":aal,"guard":guard}}),
                ),
            )
            .await;
            assert_eq!(
                decided["reason"],
                explained["result"]["outcome"]["decision"]
            );
            assert_eq!(decided["allow"], explained["result"]["outcome"]["allow"]);
            assert_eq!(decided["revision"], explained["snapshot"]["revision"]);
            assert!(explained["result"].get("trace").is_none());
        }
        for (action, aal) in [("select", 2), ("update", 2), ("update", 1), ("drop", 2)] {
            let (_, decided) = call(
                &router,
                post(
                    "/v1/resource/decision",
                    DECISION,
                    &json!({"service_id":"orders","resource":"db:orders","action":action,"subject":"u_writer",
                            "ip":"192.0.2.1","aal":aal,"guard":"enforced_allow"}),
                ),
            )
            .await;
            let (_, explained) = call(
                &router,
                post(
                    "/v1/explain",
                    ADMIN,
                    &json!({"case":{"subject":{"id":"u_writer","kind":"user"},"service":"orders","resource":"db:orders",
                        "action":action,"ip":"192.0.2.1","aal":aal,"guard":"enforced_allow"}}),
                ),
            )
            .await;
            assert_eq!(
                decided["reason"],
                explained["result"]["outcome"]["decision"]
            );
        }
    }

    #[tokio::test]
    async fn revision_pins_and_candidate_bases_are_compare_and_swap() {
        let (_root, a, router) = owner();
        let explain = |snapshot: Value| {
            post(
                "/v1/explain",
                ADMIN,
                &json!({"snapshot":snapshot,"case":case("u_reader","write","internal",2)}),
            )
        };
        assert_eq!(
            call(&router, explain(json!({"source":"published","revision":1})))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            call(&router, explain(json!({"source":"published","revision":2})))
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(
                &router,
                explain(json!({"source":"candidate","base_revision":0,"policy":candidate()}))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let mut invalid = candidate();
        invalid["services"]["orders"]["users"]["u_reader"] = json!(["missing-role"]);
        assert_eq!(
            call(
                &router,
                explain(json!({"source":"candidate","base_revision":1,"policy":invalid}))
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut unknown = candidate();
        unknown["groups"] = json!({});
        assert_eq!(
            call(
                &router,
                explain(json!({"source":"candidate","base_revision":1,"policy":unknown}))
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            call(&router, explain(json!({"source":"draft"}))).await.0,
            StatusCode::BAD_REQUEST
        );
        // Nothing was stored: same revision, same document.
        assert_eq!(a.view.load().document.revision, 1);
        assert_eq!(
            serde_json::to_value(&a.view.load().document.policy).unwrap(),
            serde_json::to_value(serde_json::from_value::<Policy>(document()).unwrap()).unwrap()
        );
    }

    #[tokio::test]
    async fn what_if_candidate_reports_comparison_and_is_never_published() {
        let (_root, a, router) = owner();
        let (status, value) = call(
            &router,
            post(
                "/v1/explain",
                ADMIN,
                &json!({"snapshot":{"source":"candidate","base_revision":1,"policy":candidate()},
                        "case":case("u_reader","write","internal",2)}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["snapshot"]["source"], "candidate");
        assert_eq!(value["snapshot"]["base_revision"], 1);
        assert_eq!(value["snapshot"]["revision"], 2);
        assert_eq!(
            value["snapshot"]["candidate_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(value["result"]["outcome"]["decision"], "Allow");
        assert_eq!(
            value["result"]["comparison"]["published"]["decision"],
            "PermissionDenied"
        );
        assert_eq!(value["result"]["comparison"]["changed"], true);
        assert_eq!(a.view.load().document.revision, 1);
        let (_, decided) = call(
            &router,
            post(
                "/v1/decision",
                DECISION,
                &json!({"service_id":"orders","subject":"u_reader","ip":"192.0.2.1","permission":"write",
                        "information_class":"internal","aal":2,"guard":"enforced_allow"}),
            ),
        )
        .await;
        assert_eq!(decided["reason"], "PermissionDenied");
        let audit = a.store.lock().unwrap().simulations_after(0).unwrap();
        assert_eq!(audit[0].source, "candidate");
        assert_eq!(audit[0].changed, 1);
        assert_eq!(
            Some(audit[0].candidate_sha256.clone().unwrap()),
            value["snapshot"]["candidate_sha256"]
                .as_str()
                .map(str::to_owned)
        );
    }

    #[tokio::test]
    async fn batch_bounds_summary_and_impact_counts() {
        let (_root, a, router) = owner();
        let cases: Vec<Value> = (0..4)
            .map(|i| {
                let mut c = case(["u_reader", "u_writer"][i % 2], "write", "internal", 2);
                c["label"] = json!(format!("case-{i}"));
                c
            })
            .collect();
        let (status, value) = call(
            &router,
            post(
                "/v1/explain/batch",
                ADMIN,
                &json!({"snapshot":{"source":"candidate","base_revision":1,"policy":candidate()},"cases":cases}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            value["summary"],
            json!({"cases":4,"allowed":4,"denied":0,"unavailable":0,"changed":2,"allow_to_deny":0,"deny_to_allow":2})
        );
        assert_eq!(value["results"][1]["label"], "case-1");
        assert!(value["results"][0].get("trace").is_none());
        let audit = a.store.lock().unwrap().simulations_after(0).unwrap();
        assert_eq!(
            (audit[0].operation.as_str(), audit[0].cases),
            ("explain_batch", 4)
        );

        let many = |n: usize| -> Vec<Value> {
            (0..n)
                .map(|_| case("u_reader", "read", "public", 1))
                .collect()
        };
        let batch = |cases: Vec<Value>, trace: bool| {
            post(
                "/v1/explain/batch",
                ADMIN,
                &json!({"cases":cases,"trace":trace}),
            )
        };
        assert_eq!(
            call(&router, batch(many(MAX_BATCH_CASES), false)).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&router, batch(many(MAX_BATCH_CASES + 1), false))
                .await
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            call(&router, batch(many(MAX_TRACED_BATCH_CASES), true))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            call(&router, batch(many(MAX_TRACED_BATCH_CASES + 1), true))
                .await
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            call(&router, batch(vec![], false)).await.0,
            StatusCode::BAD_REQUEST
        );
        let mut bad = many(2);
        bad[1]["aal"] = json!(9);
        assert_eq!(
            call(&router, batch(bad, false)).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn size_media_and_schema_limits_are_enforced() {
        let (_root, _a, router) = owner();
        // Body above the route bound.
        let huge = json!({"case":case("u_reader","read","public",1),"on_behalf_of":"x".repeat(BODY_LIMIT)});
        assert_eq!(
            call(&router, post("/v1/explain", ADMIN, &huge)).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // Candidate above the stored-policy bound but within the body bound.
        let mut large = document();
        let resources = large["resources"].as_object_mut().unwrap();
        for i in 0..12_000 {
            resources.insert(
                format!("db:padding-resource-{i:05}"),
                json!({"service":"orders","information_class":"public","actions":{"select":"read"}}),
            );
        }
        let body = json!({"snapshot":{"source":"candidate","base_revision":1,"policy":large},
                          "case":case("u_reader","read","public",1)});
        let length = body.to_string().len();
        assert!(
            length > store::MAX_POLICY_BYTES && length < BODY_LIMIT,
            "{length}"
        );
        assert_eq!(
            call(&router, post("/v1/explain", ADMIN, &body)).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // Unknown fields, invalid names, wrong media type.
        assert_eq!(
            call(
                &router,
                post(
                    "/v1/explain",
                    ADMIN,
                    &json!({"case":case("u_reader","read","public",1),"cache":true})
                )
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let mut name = case("u_reader", "read", "public", 1);
        name["service"] = json!("orders/../x");
        assert_eq!(
            call(&router, post("/v1/explain", ADMIN, &json!({"case":name})))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &router,
                post(
                    "/v1/explain",
                    ADMIN,
                    &json!({"case":case("u_reader","read","public",1),"on_behalf_of":"a b"})
                )
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let request = Request::builder()
            .method("POST")
            .uri("/v1/explain")
            .header("content-type", "text/plain")
            .header("authorization", format!("Bearer {ADMIN}"))
            .body(Body::from(
                json!({"case":case("u_reader","read","public",1)}).to_string(),
            ))
            .unwrap();
        assert_eq!(
            call(&router, request).await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[tokio::test]
    async fn rate_limit_and_audit_failure_fail_closed() {
        let (_root, a, router) = owner();
        let body = json!({"case":case("u_reader","read","public",1)});
        a.simulation_budget.drain();
        let response = router
            .clone()
            .oneshot(post("/v1/explain", ADMIN, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        let (_root2, b, router) = owner();
        b.store.lock().unwrap().reject_writes();
        let (status, value) = call(&router, post("/v1/explain", ADMIN, &body)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(value, Value::Null, "no unaudited result is released");
        // Audit failure of a simulation does not fence enforcement.
        assert!(b.healthy.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn unhealthy_snapshot_explains_as_unavailable() {
        let (_root, a, router) = owner();
        a.healthy.store(false, Ordering::Release);
        let (status, value) = call(
            &router,
            post(
                "/v1/explain",
                ADMIN,
                &json!({"case":case("u_writer","write","internal",2)}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["snapshot"]["serving"], false);
        assert_eq!(value["result"]["outcome"]["decision"], Value::Null);
        assert_eq!(
            value["result"]["outcome"]["reason_code"],
            "pumgye.unavailable"
        );
        assert_eq!(
            value["result"]["outcome"]["detail_code"],
            "pumgye.detail.snapshot_unavailable"
        );
    }

    #[tokio::test]
    async fn candidate_diff_is_paginated_and_audited() {
        let (_root, a, router) = owner();
        let mut doc = candidate();
        doc["services"]["orders"]["users"]["u_new"] = json!(["reader"]);
        let diff = |cursor: usize, limit: usize, base: u64| {
            post(
                "/v1/explain/diff",
                ADMIN,
                &json!({"base_revision":base,"policy":doc.clone(),"cursor":cursor,"limit":limit}),
            )
        };
        let (status, all) = call(&router, diff(0, 100, 1)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(all["total"], 2);
        assert_eq!(all["next_cursor"], Value::Null);
        assert_eq!(all["changes"][0]["entity"], "assignment");
        assert_eq!(all["changes"][0]["subject"], "u_new");
        assert_eq!(all["changes"][0]["change"], "added");
        assert_eq!(all["changes"][1]["subject"], "u_reader");
        assert_eq!(
            all["changes"][1]["delta"]["added_permissions"],
            json!(["write"])
        );
        let (_, first) = call(&router, diff(0, 1, 1)).await;
        assert_eq!(first["next_cursor"], 1);
        let (_, second) = call(&router, diff(1, 1, 1)).await;
        assert_eq!(second["changes"][0], all["changes"][1]);
        assert_eq!(call(&router, diff(0, 1, 7)).await.0, StatusCode::CONFLICT);
        assert_eq!(
            call(&router, diff(0, 0, 1)).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&router, diff(0, MAX_DIFF_PAGE + 1, 1)).await.0,
            StatusCode::BAD_REQUEST
        );
        let audit = a.store.lock().unwrap().simulations_after(0).unwrap();
        assert_eq!(audit.len(), 3);
        assert!(
            audit
                .iter()
                .all(|r| r.operation == "diff" && r.changed == 2)
        );
        assert_eq!(a.view.load().document.revision, 1);
    }

    async fn error(router: &Router, request: Request<Body>) -> (StatusCode, Value) {
        let (status, body) = call(router, request).await;
        (status, body["error"].clone())
    }

    #[tokio::test]
    async fn coded_refusals_carry_located_actionable_errors() {
        let (_root, a, router) = owner();
        let explain = |body: Value| post("/v1/explain", ADMIN, &body);
        // 409: revision conflict names the field and the current revision.
        let (status, e) = error(
            &router,
            explain(json!({"snapshot":{"source":"published","revision":9},"case":case("u_reader","read","public",1)})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            e,
            json!({"code":"pumgye.error.revision_conflict","message_key":"pumgye.error.revision_conflict",
                   "details":[{"path":"snapshot.revision","code":"pumgye.error.revision_conflict","message_key":"pumgye.error.revision_conflict"}],
                   "current_revision":1})
        );
        // 422: the validator's specific failure, located in the request.
        let mut invalid = candidate();
        invalid["services"]["orders"]["users"]["u_reader"] = json!(["missing-role"]);
        let (status, e) = error(
            &router,
            explain(json!({"snapshot":{"source":"candidate","base_revision":1,"policy":invalid},"case":case("u_reader","read","public",1)})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(e["code"], "pumgye.error.candidate_invalid");
        assert_eq!(
            e["details"],
            json!([{"path":"snapshot.policy.services.orders.users.u_reader",
                    "code":"pumgye.validation.unknown_assigned_role","message_key":"pumgye.validation.unknown_assigned_role"}])
        );
        let mut schema = candidate();
        schema["services"]["orders"]["roles"]["reader"]["minimum_aal"] = json!("high");
        let (status, e) = error(
            &router,
            explain(json!({"snapshot":{"source":"candidate","base_revision":1,"policy":schema},"case":case("u_reader","read","public",1)})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(e["details"][0]["code"], "pumgye.validation.schema");
        assert_eq!(
            e["details"][0]["path"],
            "snapshot.policy.services.orders.roles.reader.minimum_aal"
        );
        // 400: every invalid batch case is located.
        let mut bad = vec![case("u_reader", "read", "public", 1); 3];
        bad[1]["aal"] = json!(9);
        bad[2]["service"] = json!("no spaces");
        let (status, e) = error(
            &router,
            post("/v1/explain/batch", ADMIN, &json!({"cases":bad})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(e["code"], "pumgye.error.invalid_case");
        let details: Vec<(String, String)> = e["details"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["path"].as_str().unwrap().into(),
                    d["code"].as_str().unwrap().into(),
                )
            })
            .collect();
        assert_eq!(
            details,
            [
                (
                    "cases[1].aal".into(),
                    "pumgye.case.assurance_out_of_range".into()
                ),
                ("cases[2].service".into(), "pumgye.case.invalid_name".into())
            ]
        );
        // 400: schema errors in the request itself are located.
        let mut kind = case("u_reader", "read", "public", 1);
        kind["subject"]["kind"] = json!("root");
        let (status, e) = error(&router, explain(json!({"case":kind}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(e["code"], "pumgye.error.malformed_request");
        assert_eq!(e["details"][0]["path"], "case.subject.kind");
        let (_, e) = error(
            &router,
            explain(json!({"case":case("u_reader","read","public",1),"on_behalf_of":"a b"})),
        )
        .await;
        assert_eq!(e["details"][0]["path"], "on_behalf_of");
        let (_, e) = error(
            &router,
            post("/v1/explain/batch", ADMIN, &json!({"cases":[]})),
        )
        .await;
        assert_eq!(e["code"], "pumgye.error.empty_batch");
        // 413s are distinguished.
        let (status, e) = error(
            &router,
            post(
                "/v1/explain/batch",
                ADMIN,
                &json!({"cases":vec![case("u_reader","read","public",1); MAX_BATCH_CASES + 1]}),
            ),
        )
        .await;
        assert_eq!(
            (status, e["code"].as_str()),
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                Some("pumgye.error.batch_too_large")
            )
        );
        let (status, e) = error(
            &router,
            explain(json!({"case":case("u_reader","read","public",1),"on_behalf_of":"x".repeat(BODY_LIMIT)})),
        )
        .await;
        assert_eq!(
            (status, e["code"].as_str()),
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                Some("pumgye.error.payload_too_large")
            )
        );
        // Diff refusals.
        let (status, e) = error(
            &router,
            post(
                "/v1/explain/diff",
                ADMIN,
                &json!({"base_revision":4,"policy":candidate()}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(e["details"][0]["path"], "base_revision");
        assert_eq!(e["current_revision"], 1);
        let (_, e) = error(
            &router,
            post(
                "/v1/explain/diff",
                ADMIN,
                &json!({"base_revision":1,"policy":candidate(),"limit":0}),
            ),
        )
        .await;
        assert_eq!(
            (e["code"].as_str(), e["details"][0]["path"].as_str()),
            (Some("pumgye.error.invalid_page"), Some("limit"))
        );
        let (status, e) = error(&router, get("/v1/audit/simulations?after_id=x", ADMIN)).await;
        assert_eq!(
            (status, e["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("pumgye.error.invalid_cursor"))
        );
        // 429 carries a code and Retry-After.
        a.simulation_budget.drain();
        let (status, e) = error(
            &router,
            explain(json!({"case":case("u_reader","read","public",1)})),
        )
        .await;
        assert_eq!(
            (status, e["code"].as_str()),
            (
                StatusCode::TOO_MANY_REQUESTS,
                Some("pumgye.error.rate_limited")
            )
        );
        // Every emitted code is registered in the en/ko catalogs.
        for code in [
            "pumgye.error.revision_conflict",
            "pumgye.error.candidate_invalid",
            "pumgye.validation.unknown_assigned_role",
            "pumgye.validation.schema",
        ] {
            assert!(pumgye_core::explain::message_keys().contains(&code.to_owned()));
        }
        // Authentication and media-type refusals stay bare.
        assert_eq!(
            call(&router, post("/v1/explain", DECISION, &json!({}))).await,
            (StatusCode::UNAUTHORIZED, Value::Null)
        );
    }
}
