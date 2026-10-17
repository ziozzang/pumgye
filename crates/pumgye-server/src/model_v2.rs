//! Policy model version 2 in the authority (ADR 0021 P0): publication with
//! server-stamped assignment metadata, Hopae membership/lifecycle owners, shadow
//! evaluation beside version 1 with persisted mismatch counters, the
//! zero-unexplained-mismatch cutover gate, rollback, and the `/v2` admin and
//! explain APIs. Version 1 remains authoritative until an approved cutover.
use crate::{
    Authority, Document, PeerIdentity, View, authorized,
    explain_api::{
        ApiError, Body, admit, blocking, delegated, detail, digest, finish, rate_limited,
    },
    store,
};
use arc_swap::{ArcSwap, ArcSwapOption};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use pumgye_core::{
    PolicyViolation, ResourceDecision,
    v2::{
        CompileOptions, CompiledV2, DecisionV2, MembershipIndex, PolicyV2, PrincipalKind,
        RequestV2, Timestamp,
        convert::{ConvertOptions, classify_by_prefix, convert},
        diff::{SideV2, diff},
        explain::{CaseV2, SnapshotV2, explain},
    },
};
use pumgye_server::hopae_owner;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
/// Principal kind of a generic (`users`-map) subject on version 1 entrypoints,
/// which carry no typed evidence; typed entrypoints pass their own kind.
#[inline]
pub(crate) fn kind_of(subject: &str) -> PrincipalKind {
    if subject.starts_with("human1:") {
        PrincipalKind::Human
    } else if subject.starts_with("wk2:") {
        PrincipalKind::Workload
    } else {
        PrincipalKind::Service
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DocumentV2 {
    pub revision: u64,
    pub policy: PolicyV2,
}
pub(crate) struct V2View {
    pub document: DocumentV2,
    pub compiled: CompiledV2,
    pub membership: ArcSwap<MembershipIndex>,
    pub membership_needed: bool,
    /// Version-1-shaped Catalog metadata for permit owners in v2 mode.
    pub resources_v1: HashMap<String, pumgye_core::Resource>,
}

// ---------------------------------------------------------------------------
// Shadow evaluation
// ---------------------------------------------------------------------------

const V1_SLOTS: usize = 12;
const V2_SLOTS: usize = 13;
const SAMPLES: usize = 64;
type Text = ([u8; 128], u8);
fn text(s: &str) -> Text {
    let mut out = [0u8; 128];
    let n = s.len().min(128);
    out[..n].copy_from_slice(&s.as_bytes()[..n]);
    (out, n as u8)
}
fn untext(t: &Text) -> String {
    String::from_utf8_lossy(&t.0[..t.1 as usize]).into_owned()
}
fn v1_index(d: Option<ResourceDecision>) -> usize {
    use pumgye_core::Decision as D;
    match d {
        None => 11,
        Some(ResourceDecision::UnknownResource) => 9,
        Some(ResourceDecision::UnknownAction) => 10,
        Some(ResourceDecision::Decided(d)) => match d {
            D::Allow => 0,
            D::UnknownService => 1,
            D::Guest => 2,
            D::NetworkGuest => 3,
            D::PermissionDenied => 4,
            D::ClassDenied => 5,
            D::AssuranceDenied => 6,
            D::GuardDenied => 7,
            D::GuardUnavailable => 8,
        },
    }
}
const V1_NAMES: [&str; V1_SLOTS] = [
    "Allow",
    "UnknownService",
    "Guest",
    "NetworkGuest",
    "PermissionDenied",
    "ClassDenied",
    "AssuranceDenied",
    "GuardDenied",
    "GuardUnavailable",
    "UnknownResource",
    "UnknownAction",
    "Unavailable",
];
fn v2_index(d: Option<DecisionV2>) -> usize {
    d.map_or(12, |d| {
        DecisionV2::ALL.iter().position(|x| *x == d).unwrap_or(12)
    })
}
fn v2_name(i: usize) -> &'static str {
    DecisionV2::ALL.get(i).map_or("Unavailable", |d| d.name())
}
#[derive(Clone, Copy)]
struct Rule {
    service: Option<Text>,
    v1: Option<u8>,
    v2: Option<u8>,
}
#[derive(Clone, Copy)]
struct Sample {
    at: u64,
    service: Text,
    subject: Text,
    v1: u8,
    v2: u8,
    explained: bool,
}
const EMPTY_SAMPLE: Sample = Sample {
    at: 0,
    service: ([0; 128], 0),
    subject: ([0; 128], 0),
    v1: 0,
    v2: 0,
    explained: false,
};
struct Samples {
    ring: Vec<Sample>,
    next: usize,
    len: usize,
}
pub(crate) struct Shadow {
    started_unix: AtomicU64,
    v1_revision: AtomicU64,
    v2_revision: AtomicU64,
    decisions: AtomicU64,
    mismatches: AtomicU64,
    explained: AtomicU64,
    unexplained: AtomicU64,
    drift: AtomicU64,
    pairs: [[AtomicU64; V2_SLOTS]; V1_SLOTS],
    samples: Mutex<Samples>,
    rules: ArcSwap<Vec<Rule>>,
}
#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    v1_revision: u64,
    v2_revision: u64,
    started_unix: u64,
    decisions: u64,
    mismatches: u64,
    explained: u64,
    unexplained: u64,
    drift: u64,
    pairs: Vec<Vec<u64>>,
}
impl Default for Shadow {
    fn default() -> Self {
        Self {
            started_unix: AtomicU64::new(0),
            v1_revision: AtomicU64::new(0),
            v2_revision: AtomicU64::new(0),
            decisions: AtomicU64::new(0),
            mismatches: AtomicU64::new(0),
            explained: AtomicU64::new(0),
            unexplained: AtomicU64::new(0),
            drift: AtomicU64::new(0),
            pairs: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            samples: Mutex::new(Samples {
                ring: vec![EMPTY_SAMPLE; SAMPLES],
                next: 0,
                len: 0,
            }),
            rules: ArcSwap::from_pointee(Vec::new()),
        }
    }
}
impl Shadow {
    /// Allocation-free comparison of the two models' decisions for one request.
    #[inline]
    pub(crate) fn record(
        &self,
        service: &str,
        subject: &str,
        v1: Option<ResourceDecision>,
        v2: Option<DecisionV2>,
        now: u64,
    ) {
        let (i, j) = (v1_index(v1), v2_index(v2));
        self.decisions.fetch_add(1, Ordering::Relaxed);
        self.pairs[i][j].fetch_add(1, Ordering::Relaxed);
        let allow1 = i == 0;
        let allow2 = j == 0;
        if allow1 == allow2 {
            if v1 != v2.map(DecisionV2::to_v1) {
                self.drift.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        self.mismatches.fetch_add(1, Ordering::Relaxed);
        let rules = self.rules.load();
        let explained = rules.iter().any(|r| {
            r.v1.is_none_or(|x| x as usize == i)
                && r.v2.is_none_or(|x| x as usize == j)
                && r.service
                    .is_none_or(|s| &s.0[..s.1 as usize] == service.as_bytes())
        });
        if explained {
            self.explained.fetch_add(1, Ordering::Relaxed);
        } else {
            self.unexplained.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut s) = self.samples.try_lock() {
            let at = s.next;
            s.ring[at] = Sample {
                at: now,
                service: text(service),
                subject: text(subject),
                v1: i as u8,
                v2: j as u8,
                explained,
            };
            s.next = (at + 1) % SAMPLES;
            s.len = (s.len + 1).min(SAMPLES);
        }
    }
    fn zero(&self) {
        for c in [
            &self.decisions,
            &self.mismatches,
            &self.explained,
            &self.unexplained,
            &self.drift,
        ] {
            c.store(0, Ordering::Relaxed);
        }
        for row in &self.pairs {
            for c in row {
                c.store(0, Ordering::Relaxed);
            }
        }
        if let Ok(mut s) = self.samples.lock() {
            s.len = 0;
            s.next = 0;
        }
    }
    /// A new revision pair starts a new observation window.
    pub(crate) fn reset(&self, v1: u64, v2: u64, now: u64) {
        self.zero();
        self.v1_revision.store(v1, Ordering::Relaxed);
        self.v2_revision.store(v2, Ordering::Relaxed);
        self.started_unix.store(now, Ordering::Relaxed);
    }
    pub(crate) fn ensure_window(&self, v1: u64, v2: u64, now: u64) {
        if self.v1_revision.load(Ordering::Relaxed) != v1
            || self.v2_revision.load(Ordering::Relaxed) != v2
        {
            self.reset(v1, v2, now);
        }
    }
    fn persisted(&self) -> Persisted {
        Persisted {
            v1_revision: self.v1_revision.load(Ordering::Relaxed),
            v2_revision: self.v2_revision.load(Ordering::Relaxed),
            started_unix: self.started_unix.load(Ordering::Relaxed),
            decisions: self.decisions.load(Ordering::Relaxed),
            mismatches: self.mismatches.load(Ordering::Relaxed),
            explained: self.explained.load(Ordering::Relaxed),
            unexplained: self.unexplained.load(Ordering::Relaxed),
            drift: self.drift.load(Ordering::Relaxed),
            pairs: self
                .pairs
                .iter()
                .map(|r| r.iter().map(|c| c.load(Ordering::Relaxed)).collect())
                .collect(),
        }
    }
    fn restore(&self, p: &Persisted) {
        self.reset(p.v1_revision, p.v2_revision, p.started_unix);
        for (c, v) in [
            (&self.decisions, p.decisions),
            (&self.mismatches, p.mismatches),
            (&self.explained, p.explained),
            (&self.unexplained, p.unexplained),
            (&self.drift, p.drift),
        ] {
            c.store(v, Ordering::Relaxed);
        }
        for (i, row) in p.pairs.iter().enumerate().take(V1_SLOTS) {
            for (j, v) in row.iter().enumerate().take(V2_SLOTS) {
                self.pairs[i][j].store(*v, Ordering::Relaxed);
            }
        }
    }
    pub(crate) fn gate(&self, window_secs: u64, now: u64) -> Value {
        let started = self.started_unix.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(started);
        let decisions = self.decisions.load(Ordering::Relaxed);
        let unexplained = self.unexplained.load(Ordering::Relaxed);
        json!({
            "window_secs": window_secs, "started_at": Timestamp(started), "elapsed_secs": elapsed,
            "v1_revision": self.v1_revision.load(Ordering::Relaxed), "v2_revision": self.v2_revision.load(Ordering::Relaxed),
            "decisions": decisions, "mismatches": self.mismatches.load(Ordering::Relaxed),
            "explained": self.explained.load(Ordering::Relaxed), "unexplained": unexplained,
            "reason_drift": self.drift.load(Ordering::Relaxed),
            "satisfied": started > 0 && elapsed >= window_secs && decisions > 0 && unexplained == 0,
        })
    }
    fn report(&self) -> Value {
        let mut pairs = Vec::new();
        for (i, row) in self.pairs.iter().enumerate() {
            for (j, c) in row.iter().enumerate() {
                let n = c.load(Ordering::Relaxed);
                if n > 0 {
                    pairs.push(json!({"v1": V1_NAMES[i], "v2": v2_name(j), "count": n, "outcome_mismatch": (i == 0) != (j == 0)}));
                }
            }
        }
        let samples = self.samples.lock().map_or_else(
            |_| vec![],
            |s| {
                (0..s.len)
                    .map(|k| s.ring[(s.next + SAMPLES - 1 - k) % SAMPLES])
                    .map(|x| json!({"at": Timestamp(x.at), "service": untext(&x.service), "subject": untext(&x.subject),
                        "v1": V1_NAMES[x.v1 as usize], "v2": v2_name(x.v2 as usize), "explained": x.explained}))
                    .collect()
            },
        );
        json!({"pairs": pairs, "recent_mismatches": samples})
    }
    fn set_rules(&self, rules: &[store::Explanation]) {
        let parsed = rules
            .iter()
            .filter_map(|(_, _, _, rule, _)| {
                let r: RuleInput = serde_json::from_str(rule).ok()?;
                Some(Rule {
                    service: r.service.as_deref().map(text),
                    v1: r
                        .v1_decision
                        .as_deref()
                        .and_then(|n| V1_NAMES.iter().position(|x| *x == n))
                        .map(|x| x as u8),
                    v2: r
                        .v2_decision
                        .as_deref()
                        .and_then(|n| (0..V2_SLOTS).position(|k| v2_name(k) == n))
                        .map(|x| x as u8),
                })
            })
            .collect();
        self.rules.store(Arc::new(parsed));
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    v1_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    v2_decision: Option<String>,
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

pub(crate) struct Runtime {
    pub view: ArcSwapOption<V2View>,
    model_v2: AtomicBool,
    membership_valid_until: AtomicU64,
    pub shadow: Shadow,
    projection: Mutex<Option<hopae_owner::Projection>>,
    lifecycle: Mutex<Option<hopae_owner::Lifecycle>>,
    pub owner: Option<Arc<hopae_owner::Client>>,
    pub production: bool,
    pub window_secs: AtomicU64,
    /// Serializes v2 publication, cutover, rollback and owner recompiles.
    pub install: Arc<tokio::sync::Mutex<()>>,
}
impl Runtime {
    pub(crate) fn new(
        owner: Option<Arc<hopae_owner::Client>>,
        production: bool,
        window_secs: u64,
    ) -> Self {
        Self {
            view: ArcSwapOption::empty(),
            model_v2: AtomicBool::new(false),
            membership_valid_until: AtomicU64::new(0),
            shadow: Shadow::default(),
            projection: Mutex::new(None),
            lifecycle: Mutex::new(None),
            owner,
            production,
            window_secs: AtomicU64::new(window_secs),
            install: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
    #[cfg(test)]
    pub(crate) fn set_projection(&self, projection: hopae_owner::Projection, valid_until: u64) {
        if let Some(view) = self.view.load_full() {
            let index = MembershipIndex::build(
                &view.compiled,
                projection.members.iter().map(|(k, v)| (k.as_str(), v)),
            );
            view.membership
                .store(Arc::new(self.with_workloads(index, &view.compiled)));
        }
        *self.projection.lock().unwrap() = Some(projection);
        self.membership_valid_until
            .store(valid_until, Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn set_lifecycle(&self, lifecycle: hopae_owner::Lifecycle) {
        *self.lifecycle.lock().unwrap() = Some(lifecycle);
    }
    #[inline]
    pub(crate) fn v2_authoritative(&self) -> bool {
        self.model_v2.load(Ordering::Acquire)
    }
    /// Membership fence (ADR 0021 stage 1): group-dependent snapshots need a
    /// fresh verified projection, else the decision is unavailable.
    #[inline]
    pub(crate) fn decide(&self, view: &V2View, request: &RequestV2<'_>) -> Option<DecisionV2> {
        if view.membership_needed
            && request.now > self.membership_valid_until.load(Ordering::Acquire)
        {
            return None;
        }
        Some(view.compiled.evaluate(&view.membership.load(), request))
    }
    fn membership_fresh(&self, view: &V2View, now: u64) -> bool {
        !view.membership_needed || now <= self.membership_valid_until.load(Ordering::Acquire)
    }
    fn max_issued_aal(&self) -> u8 {
        self.projection
            .lock()
            .ok()
            .and_then(|p| p.as_ref().map(|p| p.max_aal))
            .unwrap_or(3)
    }
    fn lifecycle_view(&self) -> Option<pumgye_core::v2::Lifecycle> {
        self.lifecycle
            .lock()
            .ok()
            .and_then(|l| l.as_ref().map(hopae_owner::Lifecycle::view))
    }
    fn compile(&self, document: &DocumentV2) -> Result<CompiledV2, PolicyViolation> {
        let lifecycle = self.lifecycle_view();
        document.policy.compile_located(&CompileOptions {
            lifecycle: lifecycle.as_ref(),
            max_issued_aal: self.max_issued_aal(),
            now: now_unix(),
        })
    }
    /// Pair a compiled document with the current projection when its vocabulary matches.
    fn view_for(&self, document: DocumentV2, compiled: CompiledV2) -> V2View {
        let needed = !compiled.group_vocabulary().is_empty();
        let digest = hopae_owner::vocabulary_digest(compiled.group_vocabulary());
        let membership = self
            .projection
            .lock()
            .ok()
            .and_then(|p| {
                p.as_ref().filter(|p| p.digest == digest).map(|p| {
                    MembershipIndex::build(
                        &compiled,
                        p.members.iter().map(|(k, v)| (k.as_str(), v)),
                    )
                })
            })
            .unwrap_or_default();
        let membership = self.with_workloads(membership, &compiled);
        let resources_v1 = document
            .policy
            .catalog
            .resources
            .iter()
            .map(|(id, r)| {
                (
                    id.clone(),
                    pumgye_core::Resource {
                        service: r.service.clone(),
                        information_class: r.level.clone(),
                        actions: r.actions.clone(),
                        minimum_aal: r.minimum_aal,
                    },
                )
            })
            .collect();
        V2View {
            document,
            compiled,
            membership: ArcSwap::from_pointee(membership),
            membership_needed: needed,
            resources_v1,
        }
    }
    /// Attach the active workload aliases Hopae reported to a membership index.
    fn with_workloads(&self, index: MembershipIndex, compiled: &CompiledV2) -> MembershipIndex {
        let workloads = self
            .lifecycle
            .lock()
            .ok()
            .and_then(|l| l.as_ref().map(|l| l.workloads.clone()))
            .unwrap_or_default();
        index.with_workloads(compiled, workloads.active())
    }
    fn workloads(&self) -> hopae_owner::Workloads {
        self.lifecycle
            .lock()
            .ok()
            .and_then(|l| l.as_ref().map(|l| l.workloads.clone()))
            .unwrap_or_default()
    }
    fn install_view(&self, view: V2View) {
        self.view.store(Some(Arc::new(view)));
    }
}

/// Startup: restore the v2 document, authoritative model and shadow window.
pub(crate) fn restore(a: &Authority, store: &store::Store) -> anyhow::Result<()> {
    if let Some((revision, text)) = store.load_v2()? {
        let document: DocumentV2 = serde_json::from_str(&text)?;
        anyhow::ensure!(document.revision == revision, "stored v2 revision mismatch");
        let compiled = a
            .v2
            .compile(&document)
            .map_err(|v| anyhow::anyhow!("stored v2 policy refused at {}: {}", v.path, v.code))?;
        a.v2.install_view(a.v2.view_for(document, compiled));
    }
    // Workload principals are known only from the feed: restore them so aliases
    // and retirements survive a restart (the lifecycle snapshot keeps them).
    if let Some(text) = store.load_workloads()? {
        let workloads: hopae_owner::Workloads = serde_json::from_str(&text)?;
        if let Ok(mut slot) = a.v2.lifecycle.lock() {
            *slot = Some(hopae_owner::Lifecycle {
                workloads,
                ..Default::default()
            });
        }
        if let Some(view) = a.v2.view.load_full() {
            let document = view.document.clone();
            let compiled = a.v2.compile(&document).map_err(|v| {
                anyhow::anyhow!("stored v2 policy refused at {}: {}", v.path, v.code)
            })?;
            a.v2.install_view(a.v2.view_for(document, compiled));
        }
    }
    let model = store.model()?;
    anyhow::ensure!(
        model == "v1" || a.v2.view.load().is_some(),
        "v2 model without a v2 document"
    );
    a.v2.model_v2.store(model == "v2", Ordering::Release);
    a.v2.shadow.set_rules(&store.explanations()?);
    let v1 = a.view.load().document.revision;
    let v2 = a.v2.view.load().as_ref().map_or(0, |v| v.document.revision);
    match store
        .load_shadow()?
        .and_then(|s| serde_json::from_str::<Persisted>(&s).ok())
    {
        Some(p) if p.v1_revision == v1 && p.v2_revision == v2 => a.v2.shadow.restore(&p),
        _ => a.v2.shadow.reset(v1, v2, now_unix()),
    }
    Ok(())
}
/// Persist shadow counters so the observation window survives restarts.
pub(crate) fn persist_shadow(a: &Authority) {
    if let Ok(state) = serde_json::to_string(&a.v2.shadow.persisted())
        && let Ok(store) = a.store.lock()
    {
        let _ = store.save_shadow(&state);
    }
}
pub(crate) async fn run_background(a: Arc<Authority>) {
    let mut persist = tokio::time::interval(std::time::Duration::from_secs(30));
    let poll =
        a.v2.owner
            .as_ref()
            .and_then(|o| {
                o.projection
                    .as_ref()
                    .map(|p| p.poll_interval_secs)
                    .or(o.lifecycle.as_ref().map(|l| l.poll_interval_secs))
            })
            .unwrap_or(30);
    let mut owner = tokio::time::interval(std::time::Duration::from_secs(poll));
    let mut last_reconcile = 0u64;
    loop {
        tokio::select! {
            _ = persist.tick() => {
                let a = a.clone();
                let _ = tokio::task::spawn_blocking(move || persist_shadow(&a)).await;
            }
            _ = owner.tick() => {
                if let Some(client) = a.v2.owner.clone() {
                    refresh_owners(&a, &client, &mut last_reconcile).await;
                }
            }
        }
    }
}
async fn refresh_owners(
    a: &Arc<Authority>,
    client: &hopae_owner::Client,
    last_reconcile: &mut u64,
) {
    let now = now_unix();
    let mut recompile = false;
    if let Some(config) = &client.lifecycle {
        let current = a.v2.lifecycle.lock().ok().and_then(|l| l.clone());
        let full = current.as_ref().is_none_or(|c| !c.complete)
            || now.saturating_sub(*last_reconcile) >= config.reconcile_interval_secs;
        // Workload principals exist only in the feed: before a reconcile snapshot
        // (which restarts at a new watermark) drain the feed from the old cursor
        // so no workload change between the two positions is skipped.
        let before = current
            .as_ref()
            .map(|c| c.workloads.clone())
            .unwrap_or_default();
        let mut seed = before.clone();
        if full
            && let Some(mut previous) = current.clone().filter(|c| c.complete)
            && client.lifecycle_follow(&mut previous).await.is_ok()
        {
            seed = previous.workloads;
        }
        let result = match current {
            Some(mut state) if !full => match client.lifecycle_follow(&mut state).await {
                Err(hopae_owner::Refusal::CursorExpired) => {
                    client.lifecycle_snapshot(seed.clone()).await
                }
                r => r.map(|_| state),
            },
            _ => client.lifecycle_snapshot(seed.clone()).await,
        };
        if let Ok(state) = result {
            if full {
                *last_reconcile = now;
            }
            let workloads_changed = state.workloads != before;
            if let Ok(mut slot) = a.v2.lifecycle.lock() {
                recompile |= slot
                    .as_ref()
                    .map(hopae_owner::Lifecycle::view)
                    .map(|v| (v.deleted, v.disabled))
                    != Some((state.view().deleted, state.view().disabled));
                recompile |= workloads_changed;
                *slot = Some(state.clone());
            }
            if workloads_changed {
                // Workload principals are only in the feed: persist them.
                if let Ok(text) = serde_json::to_string(&state.workloads) {
                    let owner = a.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        owner.store.lock().ok().map(|s| s.save_workloads(&text))
                    })
                    .await;
                }
            }
        }
    }
    if let (Some(config), Some(view)) = (&client.projection, a.v2.view.load_full()) {
        let vocabulary = view.compiled.group_vocabulary().to_vec();
        if !vocabulary.is_empty() {
            let digest = hopae_owner::vocabulary_digest(&vocabulary);
            let current =
                a.v2.projection
                    .lock()
                    .ok()
                    .and_then(|p| p.clone())
                    .filter(|p| p.digest == digest);
            let result = match current {
                Some(mut p) => match client.follow(&mut p).await {
                    Ok(()) => Ok(p),
                    Err(hopae_owner::Refusal::CursorExpired | hopae_owner::Refusal::Continuity) => {
                        client.snapshot(&vocabulary).await
                    }
                    Err(e) => Err(e),
                },
                None => client.snapshot(&vocabulary).await,
            };
            if let Ok(p) = result {
                let aal_changed =
                    a.v2.projection
                        .lock()
                        .ok()
                        .and_then(|x| x.as_ref().map(|x| x.max_aal))
                        != Some(p.max_aal);
                let index = a.v2.with_workloads(
                    MembershipIndex::build(
                        &view.compiled,
                        p.members.iter().map(|(k, v)| (k.as_str(), v)),
                    ),
                    &view.compiled,
                );
                if let Ok(mut slot) = a.v2.projection.lock() {
                    *slot = Some(p);
                }
                view.membership.store(Arc::new(index));
                a.v2.membership_valid_until
                    .store(now + config.max_staleness_secs, Ordering::Release);
                recompile |= aal_changed;
            }
        }
    }
    if recompile {
        let _guard = a.v2.install.clone().lock_owned().await;
        if let Some(view) = a.v2.view.load_full() {
            let document = view.document.clone();
            let owner = a.clone();
            let _ = tokio::task::spawn_blocking(move || {
                if let Ok(compiled) = owner.v2.compile(&document) {
                    owner.v2.install_view(owner.v2.view_for(document, compiled));
                }
            })
            .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

fn stamps_cleared(b: &pumgye_core::v2::Binding) -> pumgye_core::v2::Binding {
    let mut b = b.clone();
    b.metadata.granted_by = None;
    b.metadata.revision = None;
    b.metadata.created_at = None;
    b
}
/// `granted_by`/`revision`/`created_at` come from the authenticated publisher,
/// never from the body: unchanged bindings keep their stamps.
fn stamp(
    previous: Option<&PolicyV2>,
    next: &mut PolicyV2,
    actor: &str,
    revision: u64,
    now: u64,
) -> Vec<usize> {
    let prior: HashMap<&str, &pumgye_core::v2::Binding> = previous.map_or_else(HashMap::new, |p| {
        p.bindings.iter().map(|b| (b.id.as_str(), b)).collect()
    });
    let mut changed = Vec::new();
    for (i, b) in next.bindings.iter_mut().enumerate() {
        match prior.get(b.id.as_str()) {
            Some(p) if stamps_cleared(p) == stamps_cleared(b) => {
                b.metadata.granted_by = p.metadata.granted_by.clone();
                b.metadata.revision = p.metadata.revision;
                b.metadata.created_at = p.metadata.created_at;
            }
            p => {
                b.metadata.granted_by = Some(actor.to_owned());
                b.metadata.revision = Some(revision);
                b.metadata.created_at = p
                    .and_then(|p| p.metadata.created_at)
                    .or(Some(Timestamp(now)));
                changed.push(i);
            }
        }
    }
    changed
}
fn unprocessable(path: String, code: &'static str) -> ApiError {
    ApiError::coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "pumgye.error.candidate_invalid",
    )
    .with(detail(path, code))
}
/// Publication policy beyond compilation: production reasons and resolvable references.
fn admission(
    a: &Authority,
    policy: &PolicyV2,
    changed: &[usize],
    prefix: &str,
) -> Result<(), ApiError> {
    let lifecycle = a.v2.lifecycle.lock().ok().and_then(|l| l.clone());
    for i in changed {
        let b = &policy.bindings[*i];
        if a.v2.production
            && b.effect == pumgye_core::v2::Effect::Allow
            && b.conditions.expires_at.is_none()
            && b.metadata.reason.is_none()
        {
            return Err(unprocessable(
                format!("{prefix}bindings[{i}].metadata.reason"),
                "pumgye.validation.reason_required",
            ));
        }
        // Retired ServiceAccount principals never come back (UIDs are not reused).
        if let Some(l) = lifecycle.as_ref() {
            for s in &b.subjects {
                if let pumgye_core::v2::SubjectRef::Principal {
                    kind: PrincipalKind::Workload,
                    reference,
                } = s
                    && l.workloads
                        .principals
                        .get(reference)
                        .is_some_and(|w| w.status == "retired")
                {
                    return Err(unprocessable(
                        format!("{prefix}bindings[{i}].subjects"),
                        "pumgye.validation.subject_retired",
                    ));
                }
            }
        }
        if let Some(l) = lifecycle.as_ref().filter(|l| l.complete) {
            for s in &b.subjects {
                if let pumgye_core::v2::SubjectRef::Principal {
                    kind: PrincipalKind::Human,
                    reference,
                } = s
                {
                    match l.statuses.get(reference).map(String::as_str) {
                        Some("deleted") => {
                            return Err(unprocessable(
                                format!("{prefix}bindings[{i}].subjects"),
                                "pumgye.validation.subject_deleted",
                            ));
                        }
                        None => {
                            return Err(unprocessable(
                                format!("{prefix}bindings[{i}].subjects"),
                                "pumgye.validation.subject_unresolved",
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}
fn if_match(headers: &HeaderMap) -> Result<u64, ApiError> {
    let mut values = headers.get_all("if-match").iter();
    let expected = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix('"'))
        .and_then(|v| v.strip_suffix('"'))
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or(ApiError::from(StatusCode::PRECONDITION_REQUIRED))?;
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    Ok(expected)
}
fn global_revision(a: &Authority) -> u64 {
    let v1 = a.view.load().document.revision;
    let v2 = a.v2.view.load().as_ref().map_or(0, |v| v.document.revision);
    a.store
        .lock()
        .ok()
        .and_then(|s| s.global_revision().ok())
        .unwrap_or(0)
        .max(v1)
        .max(v2)
}
fn next_revision(a: &Authority) -> Result<u64, ApiError> {
    global_revision(a)
        .checked_add(1)
        .filter(|r| *r <= i64::MAX as u64)
        .ok_or(ApiError::from(StatusCode::SERVICE_UNAVAILABLE))
}

/// `GET /v2/policy`
pub(crate) async fn read(State(a): State<Arc<Authority>>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &a.admin) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match a.v2.view.load_full() {
        Some(v) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(v.document.clone()),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
/// `PUT /v2/policy` with `If-Match: "<v2 revision>"` (`"0"` for the first document).
pub(crate) async fn publish(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(publish_inner(a, headers, peer, body).await)
}
async fn publish_inner(
    a: Arc<Authority>,
    headers: HeaderMap,
    peer: PeerIdentity,
    body: Body,
) -> Result<Value, ApiError> {
    let (next, _): (DocumentV2, _) = admit(&a, &headers, body)?;
    if a.kubernetes_owned {
        return Err(StatusCode::CONFLICT.into());
    }
    let expected = if_match(&headers)?;
    if next.revision != expected {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    if !a.healthy.load(Ordering::Acquire) {
        return Err(StatusCode::SERVICE_UNAVAILABLE.into());
    }
    let _guard = a.v2.install.clone().lock_owned().await;
    blocking(move || publish_document(&a, expected, next, &peer.0, "policy.")).await
}
/// CAS-publish a v2 document (caller holds the install lock): stamp metadata
/// from the authenticated actor, admit, compile, persist, install, reset shadow.
fn publish_document(
    a: &Authority,
    expected: u64,
    mut next: DocumentV2,
    actor: &str,
    prefix: &str,
) -> Result<Value, ApiError> {
    {
        let current = a.v2.view.load_full();
        let current_revision = current.as_ref().map_or(0, |v| v.document.revision);
        if current_revision != expected {
            return Err(ApiError::conflict("revision", current_revision));
        }
        let revision = next_revision(a)?;
        let changed = stamp(
            current.as_ref().map(|v| &v.document.policy),
            &mut next.policy,
            actor,
            revision,
            now_unix(),
        );
        admission(a, &next.policy, &changed, prefix)?;
        next.revision = revision;
        let compiled = a.v2.compile(&next).map_err(|v| {
            unprocessable(
                format!("policy.{}", v.path.trim_start_matches('$'))
                    .trim_end_matches('.')
                    .to_owned(),
                v.code,
            )
        })?;
        let text = serde_json::to_string(&next).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if text.len() > store::MAX_POLICY_BYTES {
            return Err(ApiError::coded(
                StatusCode::PAYLOAD_TOO_LARGE,
                "pumgye.error.candidate_too_large",
            ));
        }
        {
            let mut store = a
                .store
                .lock()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if store
                .publish_v2(expected, revision, &text, actor, None)
                .is_err()
            {
                a.healthy.store(false, Ordering::Release);
                return Err(StatusCode::SERVICE_UNAVAILABLE.into());
            }
        }
        let warnings = compiled.warnings.clone();
        let orphaned = compiled.orphaned.clone();
        a.v2.install_view(a.v2.view_for(next.clone(), compiled));
        a.v2.shadow
            .reset(a.view.load().document.revision, revision, now_unix());
        Ok(
            json!({"revision": revision, "policy": next.policy, "warnings": warnings, "orphaned": orphaned}),
        )
    }
}

// ---------------------------------------------------------------------------
// Kubernetes workload principals: status and legacy re-grants
// ---------------------------------------------------------------------------

fn fnv_hex(parts: &[&str]) -> String {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for p in parts {
        for b in p.bytes().chain([0xff]) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}
/// Report-only proposals: re-grant each binding that names a Pod-bound legacy
/// workload subject to the ServiceAccount principal Hopae mapped it to
/// (`workload_legacy_mapped`). Legacy bindings are kept until retired explicitly.
fn regrant_proposals(
    policy: &PolicyV2,
    workloads: &hopae_owner::Workloads,
) -> Vec<(String, pumgye_core::v2::Binding, Value)> {
    let existing: std::collections::BTreeSet<&str> =
        policy.bindings.iter().map(|b| b.id.as_str()).collect();
    let mut out = Vec::new();
    for b in &policy.bindings {
        for s in &b.subjects {
            let pumgye_core::v2::SubjectRef::Principal {
                kind: PrincipalKind::Workload,
                reference,
            } = s
            else {
                continue;
            };
            let Some(principal) = workloads.legacy.get(reference) else {
                continue;
            };
            let Some(record) = workloads
                .principals
                .get(principal)
                .filter(|w| w.status == "active")
            else {
                continue;
            };
            let hash = fnv_hex(&[&b.id, reference, principal]);
            let id = format!("bnd_rg_{hash}");
            if existing.contains(id.as_str()) {
                continue;
            }
            let mut proposed = b.clone();
            proposed.id = id;
            proposed.subjects = vec![pumgye_core::v2::SubjectRef::Principal {
                kind: PrincipalKind::Workload,
                reference: principal.clone(),
            }];
            proposed.metadata = pumgye_core::v2::Metadata {
                source: Some("migrated:legacy-pod".into()),
                ..Default::default()
            };
            let evidence = json!({"legacy_binding": b.id, "legacy_subject": reference, "principal": principal,
                "spiffe_id": record.spiffe_id, "namespace": record.namespace, "service_account": record.service_account});
            out.push((format!("rg_{hash}"), proposed, evidence));
        }
    }
    out
}
/// `GET /v2/workloads`: principals, legacy mappings and re-grant proposals.
pub(crate) async fn workloads(State(a): State<Arc<Authority>>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &a.admin) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let w = a.v2.workloads();
    let view = a.v2.view.load_full();
    let proposals = view
        .as_ref()
        .map_or_else(Vec::new, |v| regrant_proposals(&v.document.policy, &w));
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            // CAS base for `POST /v2/workloads/regrants/apply` (`base_revision`):
            // the version 2 document the proposals were computed from (null
            // without one). `model` is the model serving decisions.
            "policy_revision": view.as_ref().map(|v| v.document.revision),
            "model": if a.v2.v2_authoritative() { "v2" } else { "v1" },
            "v1_revision": a.view.load().document.revision,
            "principals": w.principals.values().collect::<Vec<_>>(),
            "legacy_mappings": w.legacy,
            "regrant_proposals": proposals.iter().map(|(id, b, e)| json!({"id": id, "binding": b, "evidence": e})).collect::<Vec<_>>(),
        })),
    )
        .into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegrantRequest {
    base_revision: u64,
    proposals: Vec<String>,
    reason: String,
    #[serde(default)]
    approval_ref: Option<String>,
}
/// `POST /v2/workloads/regrants/apply`: explicit, reasoned application of proposals.
pub(crate) async fn apply_regrants(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(
        async move {
            let (r, _): (RegrantRequest, _) = admit(&a, &headers, body)?;
            reason_ok(&r.reason)?;
            if r.proposals.is_empty() || r.proposals.len() > 1024 {
                return Err(ApiError::coded(
                    StatusCode::BAD_REQUEST,
                    "pumgye.error.malformed_request",
                )
                .with(detail("proposals", "pumgye.error.malformed_request")));
            }
            if a.kubernetes_owned {
                return Err(StatusCode::CONFLICT.into());
            }
            let _guard = a.v2.install.clone().lock_owned().await;
            blocking(move || {
                let view = a.v2.view.load_full().ok_or_else(|| {
                    ApiError::coded(StatusCode::CONFLICT, "pumgye.error.no_v2_document")
                })?;
                if view.document.revision != r.base_revision {
                    return Err(ApiError::conflict("base_revision", view.document.revision));
                }
                let proposals = regrant_proposals(&view.document.policy, &a.v2.workloads());
                let mut next = view.document.clone();
                for (i, id) in r.proposals.iter().enumerate() {
                    let (_, mut binding, _) = proposals
                        .iter()
                        .find(|(pid, _, _)| pid == id)
                        .cloned()
                        .ok_or_else(|| {
                            ApiError::coded(StatusCode::CONFLICT, "pumgye.error.regrant_unknown")
                                .with(detail(
                                    format!("proposals[{i}]"),
                                    "pumgye.error.regrant_unknown",
                                ))
                        })?;
                    binding.metadata.reason = Some(r.reason.clone());
                    binding.metadata.approval_ref = r.approval_ref.clone();
                    next.policy.bindings.push(binding);
                }
                let expected = next.revision;
                publish_document(&a, expected, next, &peer.0, "policy.")
            })
            .await
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// Status, shadow, cutover, rollback
// ---------------------------------------------------------------------------

pub(crate) fn status_value(a: &Authority) -> Value {
    let now = now_unix();
    let view = a.v2.view.load_full();
    let projection = a.v2.projection.lock().ok().and_then(|p| p.clone());
    let lifecycle = a.v2.lifecycle.lock().ok().and_then(|l| l.clone());
    let v2 = view.as_ref().map(|v| {
        let expired: Vec<&String> = v
            .document
            .policy
            .bindings
            .iter()
            .filter(|b| b.conditions.expires_at.is_some_and(|t| t.0 <= now))
            .map(|b| &b.id)
            .collect();
        json!({
            "revision": v.document.revision, "bindings": v.document.policy.bindings.len(), "grants": v.compiled.grant_count(),
            "warnings": v.compiled.warnings, "orphaned_bindings": v.compiled.orphaned, "subject_disabled_bindings": v.compiled.subject_disabled,
            "expired_bindings": expired, "next_validity_boundary": v.compiled.next_boundary.map(Timestamp),
            "relevant_groups": v.compiled.group_vocabulary().len(),
            "membership": {"needed": v.membership_needed, "fresh": a.v2.membership_fresh(v, now),
                "valid_until": Timestamp(a.v2.membership_valid_until.load(Ordering::Acquire).min(253_402_300_799)),
                "principals": v.membership.load().len()},
        })
    });
    json!({
        "authoritative_model": if a.v2.v2_authoritative() { "v2" } else { "v1" },
        "v1_revision": a.view.load().document.revision,
        "v2": v2,
        "projection": projection.map(|p| json!({"store": p.store, "cursor": p.cursor, "max_aal": p.max_aal, "vocabulary": p.vocabulary.len(), "issued_at_ms": p.issued_at_ms})),
        "lifecycle": lifecycle.map(|l| { let v = l.view(); json!({"complete": l.complete, "cursor": l.cursor, "subjects": l.statuses.len(), "deleted": v.deleted.len(), "disabled": v.disabled.len()}) }),
        "owner_configured": a.v2.owner.is_some(),
        "production_mode": a.v2.production,
        "shadow": a.v2.shadow.gate(a.v2.window_secs.load(Ordering::Relaxed), now),
    })
}
pub(crate) async fn status(State(a): State<Arc<Authority>>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &a.admin) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(status_value(&a)),
    )
        .into_response()
}
pub(crate) async fn shadow(State(a): State<Arc<Authority>>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &a.admin) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut v = a.v2.shadow.report();
    v["gate"] =
        a.v2.shadow
            .gate(a.v2.window_secs.load(Ordering::Relaxed), now_unix());
    let owner = a.clone();
    let explanations = tokio::task::spawn_blocking(move || {
        owner
            .store
            .lock()
            .ok()
            .and_then(|s| s.explanations().ok())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    v["explanations"] = json!(explanations.iter().map(|(id, at, actor, rule, reason)| json!({"id": id, "at": Timestamp(*at), "actor": actor,
        "rule": serde_json::from_str::<Value>(rule).unwrap_or_default(), "reason": reason})).collect::<Vec<_>>());
    ([(header::CACHE_CONTROL, "no-store")], Json(v)).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplanationRequest {
    #[serde(flatten)]
    rule: RuleInput,
    reason: String,
}
fn reason_ok(reason: &str) -> Result<(), ApiError> {
    if reason.is_empty() || reason.len() > 512 || reason.chars().any(char::is_control) {
        return Err(
            ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.malformed_request")
                .with(detail("reason", "pumgye.error.malformed_request")),
        );
    }
    Ok(())
}
/// `POST /v2/shadow/explanations`: record why a class of mismatches is expected.
/// Applies to mismatches observed from now on; it does not rewrite the window.
pub(crate) async fn explain_mismatch(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(
        async move {
            let (r, _): (ExplanationRequest, _) = admit(&a, &headers, body)?;
            reason_ok(&r.reason)?;
            let names_ok = r
                .rule
                .v1_decision
                .as_deref()
                .is_none_or(|n| V1_NAMES.contains(&n))
                && r.rule
                    .v2_decision
                    .as_deref()
                    .is_none_or(|n| (0..V2_SLOTS).any(|k| v2_name(k) == n))
                && r.rule
                    .service
                    .as_deref()
                    .is_none_or(|s| !s.is_empty() && s.len() <= 128);
            if !names_ok
                || (r.rule.v1_decision.is_none()
                    && r.rule.v2_decision.is_none()
                    && r.rule.service.is_none())
            {
                return Err(ApiError::coded(
                    StatusCode::BAD_REQUEST,
                    "pumgye.error.malformed_request",
                )
                .with(detail("rule", "pumgye.error.malformed_request")));
            }
            blocking(move || {
                let store = a
                    .store
                    .lock()
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                let rule = serde_json::to_string(&r.rule)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                let id = store
                    .add_explanation(&peer.0, &rule, &r.reason)
                    .map_err(|_| {
                        ApiError::coded(StatusCode::CONFLICT, "pumgye.error.malformed_request")
                    })?;
                a.v2.shadow.set_rules(
                    &store
                        .explanations()
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                );
                Ok(json!({"id": id}))
            })
            .await
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasonRequest {
    reason: String,
    #[serde(default)]
    approval_ref: Option<String>,
}
/// `POST /v2/shadow/reset`: start a new observation window.
pub(crate) async fn reset_shadow(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    finish(
        async move {
            let (r, _): (ReasonRequest, _) = admit(&a, &headers, body)?;
            reason_ok(&r.reason)?;
            let v2 = a.v2.view.load().as_ref().map_or(0, |v| v.document.revision);
            a.v2.shadow
                .reset(a.view.load().document.revision, v2, now_unix());
            let owner = a.clone();
            let _ = tokio::task::spawn_blocking(move || persist_shadow(&owner)).await;
            Ok(a.v2
                .shadow
                .gate(a.v2.window_secs.load(Ordering::Relaxed), now_unix()))
        }
        .await,
    )
}
/// `POST /v2/cutover {approval_ref, reason}`: make v2 authoritative after the
/// shadow gate (zero unexplained outcome mismatches over the window). The v2
/// document is republished at a new revision so client revision floors stay monotonic.
pub(crate) async fn cutover(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(
        async move {
            let (r, _): (ReasonRequest, _) = admit(&a, &headers, body)?;
            reason_ok(&r.reason)?;
            let approval = r
                .approval_ref
                .clone()
                .filter(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
                .ok_or_else(|| {
                    ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.malformed_request")
                        .with(detail("approval_ref", "pumgye.error.malformed_request"))
                })?;
            if a.kubernetes_owned || a.v2.v2_authoritative() {
                return Err(StatusCode::CONFLICT.into());
            }
            let gate =
                a.v2.shadow
                    .gate(a.v2.window_secs.load(Ordering::Relaxed), now_unix());
            if gate["satisfied"] != true {
                return Err(ApiError::coded(
                    StatusCode::CONFLICT,
                    "pumgye.error.shadow_gate_unsatisfied",
                )
                .with(detail("shadow", "pumgye.error.shadow_gate_unsatisfied")));
            }
            let _guard = a.v2.install.clone().lock_owned().await;
            blocking(move || {
                let view =
                    a.v2.view
                        .load_full()
                        .ok_or(ApiError::from(StatusCode::NOT_FOUND))?;
                let mut document = view.document.clone();
                let expected = document.revision;
                let revision = next_revision(&a)?;
                document.revision = revision;
                let compiled =
                    a.v2.compile(&document)
                        .map_err(|v| unprocessable(v.path, v.code))?;
                let text = serde_json::to_string(&document)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                let gate_text = gate.to_string();
                {
                    let mut store = a
                        .store
                        .lock()
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    if store
                        .publish_v2(
                            expected,
                            revision,
                            &text,
                            &peer.0,
                            Some(("v2", Some(&approval), &r.reason, &gate_text)),
                        )
                        .is_err()
                    {
                        a.healthy.store(false, Ordering::Release);
                        return Err(StatusCode::SERVICE_UNAVAILABLE.into());
                    }
                }
                a.v2.install_view(a.v2.view_for(document, compiled));
                a.v2.model_v2.store(true, Ordering::Release);
                a.v2.shadow
                    .reset(a.view.load().document.revision, revision, now_unix());
                Ok(json!({"authoritative_model": "v2", "revision": revision, "gate": gate}))
            })
            .await
        }
        .await,
    )
}
/// `POST /v2/rollback {reason}`: republish the retained v1 document at a new
/// revision and make v1 authoritative again (ADR 0021 rollback).
pub(crate) async fn rollback(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(
        async move {
            let (r, _): (ReasonRequest, _) = admit(&a, &headers, body)?;
            reason_ok(&r.reason)?;
            if a.kubernetes_owned || !a.v2.v2_authoritative() {
                return Err(StatusCode::CONFLICT.into());
            }
            let _guard = a.v2.install.clone().lock_owned().await;
            blocking(move || {
                let view = a.view.load_full();
                let expected = view.document.revision;
                let mut next: Document = view.document.clone();
                next.revision = next_revision(&a)?;
                let compiled = next
                    .policy
                    .compile()
                    .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
                {
                    let mut store = a
                        .store
                        .lock()
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    if store
                        .rollback_v1(expected, &next, &peer.0, &r.reason)
                        .is_err()
                    {
                        a.healthy.store(false, Ordering::Release);
                        return Err(StatusCode::SERVICE_UNAVAILABLE.into());
                    }
                }
                let revision = next.revision;
                a.view.store(Arc::new(View {
                    document: next,
                    compiled,
                    source_lifetime: None,
                }));
                a.v2.model_v2.store(false, Ordering::Release);
                let v2 = a.v2.view.load().as_ref().map_or(0, |v| v.document.revision);
                a.v2.shadow.reset(revision, v2, now_unix());
                Ok(json!({"authoritative_model": "v1", "revision": revision}))
            })
            .await
        }
        .await,
    )
}
pub(crate) async fn history(State(a): State<Arc<Authority>>, headers: HeaderMap) -> Response {
    if !authorized(&headers, &a.admin) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let owner = a.clone();
    match tokio::task::spawn_blocking(move || {
        owner.store.lock().ok().and_then(|s| s.model_history().ok())
    })
    .await
    {
        Ok(Some(rows)) => ([(header::CACHE_CONTROL, "no-store")], Json(rows)).into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Explain, candidate diff and migration preview
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
enum Selector {
    Published {
        #[serde(default)]
        revision: Option<u64>,
    },
    Candidate {
        base_revision: u64,
        policy: Value,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainRequest {
    #[serde(default)]
    snapshot: Option<Selector>,
    #[serde(default)]
    case: Option<CaseV2>,
    #[serde(default)]
    cases: Option<Vec<CaseV2>>,
    #[serde(default)]
    trace: Option<bool>,
    #[serde(default)]
    on_behalf_of: Option<String>,
}
struct Candidate {
    document: DocumentV2,
    compiled: CompiledV2,
    membership: MembershipIndex,
    membership_fresh: bool,
    sha256: String,
}
fn candidate(a: &Authority, base: u64, value: Value, prefix: &str) -> Result<Candidate, ApiError> {
    let located = |path: &str| {
        let path = path.trim_start_matches('$').trim_start_matches('.');
        if path.is_empty() {
            prefix.to_owned()
        } else {
            format!("{prefix}.{path}")
        }
    };
    let policy: PolicyV2 = serde_path_to_error::deserialize(value).map_err(|e| {
        unprocessable(
            located(&e.path().to_string()),
            pumgye_core::VALIDATION_SCHEMA,
        )
    })?;
    let document = DocumentV2 {
        revision: base.saturating_add(1),
        policy,
    };
    let bytes =
        serde_json::to_vec(&document.policy).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if bytes.len() > store::MAX_POLICY_BYTES {
        return Err(ApiError::coded(
            StatusCode::PAYLOAD_TOO_LARGE,
            "pumgye.error.candidate_too_large",
        ));
    }
    let compiled =
        a.v2.compile(&document)
            .map_err(|v| unprocessable(located(&v.path), v.code))?;
    let digest = hopae_owner::vocabulary_digest(compiled.group_vocabulary());
    let projection = a.v2.projection.lock().ok().and_then(|p| {
        p.as_ref().filter(|p| p.digest == digest).map(|p| {
            MembershipIndex::build(&compiled, p.members.iter().map(|(k, v)| (k.as_str(), v)))
        })
    });
    let fresh_now = a.v2.membership_valid_until.load(Ordering::Acquire) >= now_unix();
    Ok(Candidate {
        membership_fresh: compiled.group_vocabulary().is_empty()
            || (projection.is_some() && fresh_now),
        membership: a
            .v2
            .with_workloads(projection.unwrap_or_default(), &compiled),
        document,
        compiled,
        sha256: format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&bytes)),
    })
}
fn case_error(prefix: &str, case: &CaseV2) -> Option<crate::explain_api::ErrorDetail> {
    case.validate()
        .err()
        .map(|(e, path)| detail(format!("{prefix}.{path}"), e.code()))
}
/// `POST /v2/explain` (`case`) and `/v2/explain/batch` (`cases`): the v2
/// evaluation function with a recording tracer; read-only and audited.
pub(crate) async fn explain_v2(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    uri: axum::http::Uri,
    body: Body,
) -> Response {
    finish(explain_inner(a, headers, peer, uri.path() == "/v2/explain/batch", body).await)
}
async fn explain_inner(
    a: Arc<Authority>,
    headers: HeaderMap,
    peer: PeerIdentity,
    batch: bool,
    body: Body,
) -> Result<Value, ApiError> {
    use crate::explain_api::{MAX_BATCH_CASES, MAX_TRACED_BATCH_CASES};
    let (request, body): (ExplainRequest, _) = admit(&a, &headers, body)?;
    let (cases, prefix): (Vec<CaseV2>, &str) = match (batch, request.case, request.cases) {
        (false, Some(c), None) => (vec![c], "case"),
        (true, None, Some(c)) => (c, "cases"),
        _ => {
            return Err(
                ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.malformed_request").with(
                    detail(
                        if batch { "cases" } else { "case" },
                        "pumgye.error.malformed_request",
                    ),
                ),
            );
        }
    };
    let trace = request.trace.unwrap_or(!batch);
    let limit = if trace {
        MAX_TRACED_BATCH_CASES
    } else {
        MAX_BATCH_CASES
    };
    if cases.len() > limit {
        return Err(ApiError::coded(
            StatusCode::PAYLOAD_TOO_LARGE,
            "pumgye.error.batch_too_large",
        )
        .with(detail("cases", "pumgye.error.batch_too_large")));
    }
    if cases.is_empty() {
        return Err(
            ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.empty_batch")
                .with(detail("cases", "pumgye.error.empty_batch")),
        );
    }
    delegated(&request.on_behalf_of)?;
    let mut invalid = ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.invalid_case");
    let mut any = false;
    for (i, c) in cases.iter().enumerate() {
        let p = if batch {
            format!("cases[{i}]")
        } else {
            prefix.to_owned()
        };
        if let Some(d) = case_error(&p, c) {
            invalid = invalid.with(d);
            any = true;
        }
    }
    if any {
        return Err(invalid);
    }
    let is_candidate = matches!(request.snapshot, Some(Selector::Candidate { .. }));
    if !a.simulation_budget.take(
        cases.len() as f64 * if is_candidate { 2.0 } else { 1.0 }
            + if is_candidate {
                crate::explain_api::CANDIDATE_COST
            } else {
                0.0
            },
    ) {
        return Err(rate_limited());
    }
    let audit_digest = digest(&body);
    blocking(move || {
        let published = a.v2.view.load_full().ok_or_else(|| ApiError::coded(StatusCode::CONFLICT, "pumgye.error.no_v2_document"))?;
        let now = now_unix();
        let serving = a.healthy.load(Ordering::Acquire) && a.source_remaining(&a.view.load()).is_some();
        let pub_membership = published.membership.load_full();
        let pub_snapshot = SnapshotV2 {
            policy: &published.document.policy,
            compiled: &published.compiled,
            membership: &pub_membership,
            revision: published.document.revision,
            serving,
            membership_fresh: a.v2.membership_fresh(&published, now),
            now,
        };
        let cand = match request.snapshot {
            None | Some(Selector::Published { revision: None }) => None,
            Some(Selector::Published { revision: Some(r) }) if r == published.document.revision => None,
            Some(Selector::Published { .. }) => return Err(ApiError::conflict("snapshot.revision", published.document.revision)),
            Some(Selector::Candidate { base_revision, policy }) => {
                if base_revision != published.document.revision {
                    return Err(ApiError::conflict("snapshot.base_revision", published.document.revision));
                }
                Some(candidate(&a, base_revision, policy, "snapshot.policy")?)
            }
        };
        let evaluated = cand.as_ref().map_or(pub_snapshot, |c| SnapshotV2 {
            policy: &c.document.policy,
            compiled: &c.compiled,
            membership: &c.membership,
            revision: c.document.revision,
            serving: true,
            membership_fresh: c.membership_fresh,
            now,
        });
        let (mut allowed, mut denied, mut unavailable, mut changed) = (0u64, 0u64, 0u64, 0u64);
        let mut results = Vec::with_capacity(cases.len());
        for c in &cases {
            let e = explain(evaluated, c, trace).map_err(|_| ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.invalid_case"))?;
            match e.decision {
                None => unavailable += 1,
                Some(DecisionV2::Allow) => allowed += 1,
                Some(_) => denied += 1,
            }
            let mut value = e.value;
            if cand.is_some() {
                let p = explain(pub_snapshot, c, false).map_err(|_| ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.invalid_case"))?;
                let differs = p.decision != e.decision;
                changed += u64::from(differs);
                value["comparison"] = json!({"published": p.value["outcome"], "changed": differs});
            }
            results.push(value);
        }
        let label = match &cand {
            Some(c) => json!({"source": "candidate", "model": "v2", "revision": c.document.revision, "base_revision": published.document.revision, "candidate_sha256": c.sha256}),
            None => json!({"source": "published", "model": "v2", "revision": published.document.revision, "serving": serving}),
        };
        let audit_id = a
            .store
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .record_simulation(
                &store::SimulationRecord {
                    id: 0,
                    at_unix: 0,
                    kind: "simulation",
                    actor: peer.0,
                    on_behalf_of: request.on_behalf_of,
                    operation: if batch { "explain_v2_batch".into() } else { "explain_v2".into() },
                    source: label["source"].as_str().unwrap_or_default().into(),
                    revision: published.document.revision,
                    candidate_sha256: cand.as_ref().map(|c| c.sha256.clone()),
                    request_sha256: audit_digest,
                    cases: cases.len() as u64,
                    allowed,
                    denied,
                    unavailable,
                    changed,
                },
                a.simulation_budget.retention_seconds,
            )
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        a.simulation_budget.simulations.fetch_add(1, Ordering::Relaxed);
        let mut out = json!({"version": 2, "kind": "simulation", "audit_id": audit_id, "snapshot": label});
        if batch {
            out["summary"] = json!({"cases": cases.len(), "allowed": allowed, "denied": denied, "unavailable": unavailable});
            if cand.is_some() {
                out["summary"]["changed"] = json!(changed);
            }
            out["results"] = json!(results);
        } else {
            out["result"] = results.pop().unwrap_or_default();
        }
        Ok(out)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiffRequest {
    base_revision: u64,
    policy: Value,
    #[serde(default)]
    cursor: usize,
    #[serde(default = "page")]
    limit: usize,
    #[serde(default)]
    on_behalf_of: Option<String>,
}
fn page() -> usize {
    100
}
/// `POST /v2/candidates/diff`: (subject, service, permission) rights that change.
pub(crate) async fn candidate_diff(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    body: Body,
) -> Response {
    finish(
        async move {
            let (r, body): (DiffRequest, _) = admit(&a, &headers, body)?;
            if r.limit == 0 || r.limit > crate::explain_api::MAX_DIFF_PAGE || r.cursor > 1 << 24 {
                return Err(ApiError::coded(StatusCode::BAD_REQUEST, "pumgye.error.invalid_page").with(detail("limit", "pumgye.error.invalid_page")));
            }
            delegated(&r.on_behalf_of)?;
            if !a.simulation_budget.take(crate::explain_api::CANDIDATE_COST * 2.0) {
                return Err(rate_limited());
            }
            let audit_digest = digest(&body);
            blocking(move || {
                let published = a.v2.view.load_full().ok_or_else(|| ApiError::coded(StatusCode::CONFLICT, "pumgye.error.no_v2_document"))?;
                if r.base_revision != published.document.revision {
                    return Err(ApiError::conflict("base_revision", published.document.revision));
                }
                let c = candidate(&a, r.base_revision, r.policy, "policy")?;
                let page = diff(
                    SideV2 { policy: &published.document.policy, compiled: &published.compiled },
                    SideV2 { policy: &c.document.policy, compiled: &c.compiled },
                    r.cursor,
                    r.limit,
                );
                let audit_id = a
                    .store
                    .lock()
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                    .record_simulation(
                        &store::SimulationRecord {
                            id: 0, at_unix: 0, kind: "simulation", actor: peer.0, on_behalf_of: r.on_behalf_of,
                            operation: "diff_v2".into(), source: "candidate".into(), revision: published.document.revision,
                            candidate_sha256: Some(c.sha256.clone()), request_sha256: audit_digest, cases: 0, allowed: 0, denied: 0,
                            unavailable: 0, changed: page.total as u64,
                        },
                        a.simulation_budget.retention_seconds,
                    )
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                Ok(json!({"version": 2, "kind": "simulation", "audit_id": audit_id,
                    "snapshot": {"source": "candidate", "base_revision": published.document.revision, "revision": c.document.revision, "candidate_sha256": c.sha256},
                    "warnings": c.compiled.warnings, "orphaned": c.compiled.orphaned,
                    "total": page.total, "next_cursor": page.next_cursor, "changes": page.changes}))
            })
            .await
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationRequest {
    /// Administrator-confirmed legacy workload subject → `wk2:` principal.
    #[serde(default)]
    workload_mapping: BTreeMap<String, String>,
}
/// `POST /v2/migration/preview`: convert the current v1 document (never stored).
pub(crate) async fn migration_preview(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    finish(
        async move {
            let (r, _): (MigrationRequest, _) = admit(&a, &headers, body)?;
            if r.workload_mapping.len() > 65_536 {
                return Err(ApiError::coded(StatusCode::PAYLOAD_TOO_LARGE, "pumgye.error.payload_too_large"));
            }
            if !a.simulation_budget.take(crate::explain_api::CANDIDATE_COST * 2.0) {
                return Err(rate_limited());
            }
            blocking(move || {
                let v1 = a.view.load_full();
                // Owner lookup: Human subjects must be known to the Hopae lifecycle when it is configured.
                let lifecycle = a.v2.lifecycle.lock().ok().and_then(|l| l.clone()).filter(|l| l.complete);
                let classify = |s: &str| {
                    classify_by_prefix(s).filter(|k| *k != PrincipalKind::Human || lifecycle.as_ref().is_none_or(|l| l.knows(s)))
                };
                let conversion = convert(&v1.document.policy, &ConvertOptions { classify: &classify, workload_mapping: &r.workload_mapping })
                    .map_err(|_| ApiError::coded(StatusCode::UNPROCESSABLE_ENTITY, "pumgye.error.candidate_invalid").with(detail("policy", pumgye_core::VALIDATION_INVALID)))?;
                // Hopae-observed Pod → ServiceAccount mappings for v1 workload subjects:
                // a proposal only; pass it back as `workload_mapping` to apply it.
                let observed = a.v2.workloads();
                let proposed: BTreeMap<&String, &String> = v1
                    .document
                    .policy
                    .services
                    .values()
                    .flat_map(|s| s.workload_users.keys())
                    .filter_map(|legacy| observed.legacy.get(legacy).map(|p| (legacy, p)))
                    .collect();
                Ok(json!({"version": 2, "v1_revision": v1.document.revision, "document": {"revision": 0, "policy": conversion.document},
                    "report": conversion.report, "observed_workload_mapping": proposed}))
            })
            .await
        }
        .await,
    )
}

pub(crate) fn routes() -> axum::Router<Arc<Authority>> {
    use axum::{extract::DefaultBodyLimit, routing};
    let limit = DefaultBodyLimit::max(crate::explain_api::BODY_LIMIT);
    axum::Router::new()
        .route("/v2/policy", routing::get(read).put(publish).layer(limit))
        .route("/v2/status", routing::get(status))
        .route("/v2/explain", routing::post(explain_v2).layer(limit))
        .route("/v2/explain/batch", routing::post(explain_v2).layer(limit))
        .route(
            "/v2/candidates/diff",
            routing::post(candidate_diff).layer(limit),
        )
        .route("/v2/migration/preview", routing::post(migration_preview))
        .route("/v2/shadow", routing::get(shadow))
        .route("/v2/shadow/explanations", routing::post(explain_mismatch))
        .route("/v2/shadow/reset", routing::post(reset_shadow))
        .route("/v2/cutover", routing::post(cutover))
        .route("/v2/rollback", routing::post(rollback))
        .route("/v2/model/history", routing::get(history))
        .route("/v2/workloads", routing::get(workloads))
        .route(
            "/v2/workloads/regrants/apply",
            routing::post(apply_regrants),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_gate;
    use axum::{Router, body::Body as HttpBody, http::Request};
    use tower::ServiceExt;

    const ADMIN: &str = "fixture-admin-credential";
    const DECISION: &str = "fixture-decision-credential";
    const SA: &str = "s_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SB: &str = "s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const H1: &str = "human1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const G1: &str = "grp1:00000000000000000000000000";

    fn v1() -> Value {
        json!({"version":1,"information_classes":["public","internal"],
         "services":{"orders":{"permissions":["read","write"],"require_guard":true,
           "roles":{"reader":{"permissions":["read"],"information_classes":["public"]},
                    "writer":{"permissions":["write"],"information_classes":["public","internal"],"inherits":["reader"],"minimum_aal":2}},
           "users":{SA:["reader"],SB:["writer"]},"human_users":{H1:["reader"]},
           "networks":[{"cidr":"192.0.2.0/24","roles":["writer"]}]}},
         "resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read","update":"write"},"minimum_aal":1}}})
    }
    fn owner() -> (tempfile::TempDir, Arc<Authority>, Router) {
        let root = tempfile::tempdir().unwrap();
        let a = crate::tests::authority(root.path());
        let policy: pumgye_core::Policy = serde_json::from_value(v1()).unwrap();
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
            .merge(routes())
            .layer(axum::middleware::from_fn_with_state(
                a.clone(),
                request_gate,
            ))
            .layer(axum::Extension(PeerIdentity("mtls:publisher".into())))
            .with_state(a.clone());
        (root, a, router)
    }
    fn converted() -> Value {
        let policy: pumgye_core::Policy = serde_json::from_value(v1()).unwrap();
        let mapping = BTreeMap::new();
        let c = convert(
            &policy,
            &ConvertOptions {
                classify: &classify_by_prefix,
                workload_mapping: &mapping,
            },
        )
        .unwrap();
        serde_json::to_value(c.document).unwrap()
    }
    fn request(
        method: &str,
        path: &str,
        token: &str,
        body: Option<&Value>,
        if_match: Option<u64>,
    ) -> Request<HttpBody> {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"));
        if let Some(m) = if_match {
            b = b.header("if-match", format!("\"{m}\""));
        }
        match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(HttpBody::from(v.to_string()))
                .unwrap(),
            None => b.body(HttpBody::empty()).unwrap(),
        }
    }
    async fn call(router: &Router, r: Request<HttpBody>) -> (StatusCode, Value) {
        let response = router.clone().oneshot(r).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    async fn publish_v2(router: &Router, expected: u64, policy: &Value) -> (StatusCode, Value) {
        call(
            router,
            request(
                "PUT",
                "/v2/policy",
                ADMIN,
                Some(&json!({"revision": expected, "policy": policy})),
                Some(expected),
            ),
        )
        .await
    }
    async fn decide(
        router: &Router,
        subject: &str,
        permission: &str,
        class: &str,
        aal: u8,
    ) -> Value {
        call(
            router,
            request(
                "POST",
                "/v1/decision",
                DECISION,
                Some(
                    &json!({"service_id":"orders","subject":subject,"ip":"192.0.2.1",
            "permission":permission,"information_class":class,"aal":aal,"guard":"enforced_allow"}),
                ),
                None,
            ),
        )
        .await
        .1
    }

    #[tokio::test]
    async fn publication_is_admin_only_cas_and_stamps_metadata_from_the_transport() {
        let (_root, a, router) = owner();
        let mut policy = converted();
        policy["bindings"][0]["metadata"]["granted_by"] = json!("forged-by-body");
        assert_eq!(
            call(
                &router,
                request(
                    "PUT",
                    "/v2/policy",
                    DECISION,
                    Some(&json!({"revision":0,"policy":policy})),
                    Some(0)
                )
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &router,
                request(
                    "PUT",
                    "/v2/policy",
                    ADMIN,
                    Some(&json!({"revision":0,"policy":policy})),
                    None
                )
            )
            .await
            .0,
            StatusCode::PRECONDITION_REQUIRED
        );
        let (status, body) = publish_v2(&router, 0, &policy).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["revision"], 2,
            "one revision sequence with v1 revision 1"
        );
        assert!(
            body["policy"]["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|b| b["metadata"]["granted_by"] == "mtls:publisher"
                    && b["metadata"]["revision"] == 2)
        );
        // Stale CAS is a located conflict with the current revision.
        let (status, body) = publish_v2(&router, 0, &policy).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["current_revision"], 2);
        // Unchanged bindings keep stamps; a changed binding is re-stamped.
        let (_, current) = call(&router, request("GET", "/v2/policy", ADMIN, None, None)).await;
        let mut next = current["policy"].clone();
        next["bindings"][1]["conditions"] = json!({"expires_at":"2099-01-01T00:00:00Z"});
        let (status, body) = publish_v2(&router, 2, &next).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["revision"], 3);
        assert_eq!(body["policy"]["bindings"][0]["metadata"]["revision"], 2);
        assert_eq!(body["policy"]["bindings"][1]["metadata"]["revision"], 3);
        // Invalid documents are located; v1 publication continues the same sequence.
        let mut bad = next.clone();
        bad["bindings"][0]["subjects"] = json!([{"group":"grp1:NOTCANONICALNOTCANONICAL00"}]);
        let (status, body) = publish_v2(&router, 3, &bad).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["error"]["details"][0],
            json!({"path":"policy.bindings[0]","code":"pumgye.validation.group_reference","message_key":"pumgye.validation.group_reference"})
        );
        let (_, audit) = call(&router, request("GET", "/v1/audit", ADMIN, None, None)).await;
        let kinds: Vec<(u64, String)> = audit
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["revision"].as_u64().unwrap(),
                    r["document"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            kinds,
            [(1, "v1".to_owned()), (2, "v2".into()), (3, "v2".into())]
        );
        assert!(!a.v2.v2_authoritative());
    }

    #[tokio::test]
    async fn production_mode_and_lifecycle_admission() {
        let root = tempfile::tempdir().unwrap();
        let _ = root;
        let (_root, a, router) = owner();
        let mut lifecycle = hopae_owner::Lifecycle {
            complete: true,
            ..Default::default()
        };
        lifecycle.statuses.insert(H1.into(), "deleted".into());
        a.v2.set_lifecycle(lifecycle);
        let (status, body) = publish_v2(&router, 0, &converted()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["error"]["details"][0]["code"],
            "pumgye.validation.subject_deleted"
        );
        let mut lifecycle = hopae_owner::Lifecycle {
            complete: true,
            ..Default::default()
        };
        lifecycle.statuses.insert(
            "human1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            "active".into(),
        );
        a.v2.set_lifecycle(lifecycle);
        let (status, body) = publish_v2(&router, 0, &converted()).await;
        assert_eq!(
            body["error"]["details"][0]["code"], "pumgye.validation.subject_unresolved",
            "{status}"
        );
    }

    #[tokio::test]
    async fn shadow_gate_cutover_and_rollback() {
        let (_root, a, router) = owner();
        let mut policy = converted();
        // v2 adds an explicit deny that v1 cannot express: a known, explainable difference.
        policy["bindings"].as_array_mut().unwrap().push(json!({"id":"bnd_freeze","effect":"deny","subjects":[{"kind":"service","ref":SB}],
            "permissions":["write"],"scope":{"services":["orders"]},"metadata":{"reason":"change freeze"}}));
        assert_eq!(publish_v2(&router, 0, &policy).await.0, StatusCode::OK);
        assert_eq!(
            decide(&router, SA, "read", "public", 2).await["allow"],
            true
        );
        let v = decide(&router, SB, "write", "internal", 2).await;
        assert_eq!(
            (v["allow"].clone(), v["revision"].clone()),
            (json!(true), json!(1)),
            "v1 stays authoritative"
        );
        let (_, shadow) = call(&router, request("GET", "/v2/shadow", ADMIN, None, None)).await;
        assert_eq!(shadow["gate"]["decisions"], 2);
        assert_eq!(shadow["gate"]["unexplained"], 1);
        assert_eq!(shadow["recent_mismatches"][0]["v2"], "ExplicitDenied");
        a.v2.window_secs.store(0, Ordering::Relaxed);
        let cut = json!({"approval_ref":"CAB-42","reason":"v2 cutover"});
        let (status, body) = call(
            &router,
            request("POST", "/v2/cutover", ADMIN, Some(&cut), None),
        )
        .await;
        assert_eq!(
            (status, body["error"]["code"].clone()),
            (
                StatusCode::CONFLICT,
                json!("pumgye.error.shadow_gate_unsatisfied")
            )
        );
        // Explain the class of mismatch, restart the window, observe again.
        let rule = json!({"service":"orders","v1_decision":"Allow","v2_decision":"ExplicitDenied","reason":"freeze is v2-only"});
        assert_eq!(
            call(
                &router,
                request("POST", "/v2/shadow/explanations", ADMIN, Some(&rule), None)
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &router,
                request(
                    "POST",
                    "/v2/shadow/reset",
                    ADMIN,
                    Some(&json!({"reason":"explained freeze"})),
                    None
                )
            )
            .await
            .0,
            StatusCode::OK
        );
        decide(&router, SB, "write", "internal", 2).await;
        decide(&router, SA, "read", "public", 2).await;
        let (_, shadow) = call(&router, request("GET", "/v2/shadow", ADMIN, None, None)).await;
        assert_eq!(
            (
                shadow["gate"]["explained"].clone(),
                shadow["gate"]["unexplained"].clone()
            ),
            (json!(1), json!(0))
        );
        assert_eq!(
            call(
                &router,
                request(
                    "POST",
                    "/v2/cutover",
                    ADMIN,
                    Some(&json!({"reason":"no approval"})),
                    None
                )
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let (status, body) = call(
            &router,
            request("POST", "/v2/cutover", ADMIN, Some(&cut), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["revision"], 3);
        assert!(a.v2.v2_authoritative());
        // v2 decides now; ExplicitDenied reaches v1 peers as PermissionDenied at the v2 revision.
        let v = decide(&router, SB, "write", "internal", 2).await;
        assert_eq!(
            (
                v["allow"].clone(),
                v["reason"].clone(),
                v["revision"].clone()
            ),
            (json!(false), json!("PermissionDenied"), json!(3))
        );
        assert_eq!(
            decide(&router, SA, "read", "public", 2).await["revision"],
            3
        );
        let (status, body) = call(
            &router,
            request(
                "POST",
                "/v2/rollback",
                ADMIN,
                Some(&json!({"reason":"rollback drill"})),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["revision"], 4,
            "v1 republished above every issued revision"
        );
        let v = decide(&router, SB, "write", "internal", 2).await;
        assert_eq!(
            (v["allow"].clone(), v["revision"].clone()),
            (json!(true), json!(4))
        );
        let (_, history) = call(
            &router,
            request("GET", "/v2/model/history", ADMIN, None, None),
        )
        .await;
        assert_eq!(
            history
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h["model"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["v1", "v2"]
        );
        assert_eq!(history[1]["approval_ref"], "CAB-42");
        assert_eq!(history[1]["actor"], "mtls:publisher");
    }

    #[tokio::test]
    async fn group_grants_need_a_fresh_verified_projection() {
        let (_root, a, router) = owner();
        let mut policy = converted();
        policy["bindings"] = json!([{"id":"bnd_group_reader","effect":"allow","subjects":[{"group":G1}],"role":"orders.writer","scope":{"services":["orders"]}}]);
        assert_eq!(publish_v2(&router, 0, &policy).await.0, StatusCode::OK);
        a.v2.window_secs.store(0, Ordering::Relaxed);
        let explain = |case: Value| {
            request(
                "POST",
                "/v2/explain",
                ADMIN,
                Some(&json!({"case": case})),
                None,
            )
        };
        let case = json!({"subject":{"kind":"human","id":H1},"service":"orders","resource":"db:orders","action":"select","ip":"192.0.2.1","aal":2,"guard":"enforced_allow"});
        let (_, body) = call(&router, explain(case.clone())).await;
        assert_eq!(
            body["result"]["outcome"]["detail_code"],
            "pumgye.detail.membership_unavailable"
        );
        // A verified projection (as applied by the owner loop) makes the group grant live.
        let mut p = hopae_owner::Projection::default();
        p.digest = hopae_owner::vocabulary_digest(&[G1.into()]);
        p.vocabulary = vec![G1.into()];
        p.max_aal = 2;
        p.members.insert(H1.into(), [G1.to_owned()].into());
        a.v2.set_projection(p, now_unix() + 60);
        let (_, body) = call(&router, explain(case.clone())).await;
        assert_eq!(body["result"]["outcome"]["decision"], "Allow", "{body}");
        let principal = body["result"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stage"] == "principal")
            .unwrap()
            .clone();
        assert_eq!(principal["detail"]["groups"], json!([G1]));
        // Expired projection fails closed again.
        a.v2.membership_valid_until.store(1, Ordering::Release);
        let (_, body) = call(&router, explain(case)).await;
        assert_eq!(body["result"]["outcome"]["decision"], Value::Null);
        let (_, status) = call(&router, request("GET", "/v2/status", ADMIN, None, None)).await;
        assert_eq!(status["v2"]["membership"]["fresh"], false);
        assert_eq!(status["projection"]["max_aal"], 2);
    }

    #[tokio::test]
    async fn explain_diff_and_migration_preview_are_admin_simulations() {
        let (_root, a, router) = owner();
        assert_eq!(publish_v2(&router, 0, &converted()).await.0, StatusCode::OK);
        let case = json!({"subject":{"kind":"service","id":SB},"service":"orders","permission":"write","information_class":"internal","ip":"192.0.2.1","aal":0,"guard":"enforced_allow"});
        assert_eq!(
            call(
                &router,
                request(
                    "POST",
                    "/v2/explain",
                    DECISION,
                    Some(&json!({"case":case})),
                    None
                )
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (status, body) = call(
            &router,
            request(
                "POST",
                "/v2/explain",
                ADMIN,
                Some(&json!({"case":case})),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["snapshot"]["model"], "v2");
        assert_eq!(body["result"]["outcome"]["decision"], "AssuranceDenied");
        assert_eq!(body["result"]["obligations"]["required_aal"], 2);
        // Spoofed group input is not part of any request shape.
        let mut spoof = case.clone();
        spoof["groups"] = json!([G1]);
        assert_eq!(
            call(
                &router,
                request(
                    "POST",
                    "/v2/explain",
                    ADMIN,
                    Some(&json!({"case":spoof})),
                    None
                )
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let mut header = json!({"service_id":"orders","subject":SA,"ip":"192.0.2.1","permission":"read","information_class":"public","aal":1,"guard":"enforced_allow"});
        header["groups"] = json!([G1]);
        assert!(
            call(
                &router,
                request("POST", "/v1/decision", DECISION, Some(&header), None)
            )
            .await
            .0
            .is_client_error()
        );
        // Candidate what-if with comparison, and the candidate diff.
        let mut cand = converted();
        cand["bindings"].as_array_mut().unwrap().push(json!({"id":"bnd_freeze","effect":"deny","subjects":[{"kind":"service","ref":SB}],"permissions":"all","scope":{"services":"all"}}));
        let (status, body) = call(&router, request("POST", "/v2/explain/batch", ADMIN, Some(&json!({"snapshot":{"source":"candidate","base_revision":2,"policy":cand},"cases":[case]})), None)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["results"][0]["outcome"]["decision"], "ExplicitDenied");
        assert_eq!(body["results"][0]["comparison"]["changed"], true);
        let (status, body) = call(&router, request("POST", "/v2/explain", ADMIN, Some(&json!({"snapshot":{"source":"candidate","base_revision":1,"policy":cand},"case":case})), None)).await;
        assert_eq!(
            (status, body["error"]["current_revision"].clone()),
            (StatusCode::CONFLICT, json!(2))
        );
        let (status, body) = call(
            &router,
            request(
                "POST",
                "/v2/candidates/diff",
                ADMIN,
                Some(&json!({"base_revision":2,"policy":cand})),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 1);
        assert_eq!(body["changes"][0]["added_denies"], json!(["read", "write"]));
        let (status, body) = call(
            &router,
            request(
                "POST",
                "/v2/migration/preview",
                ADMIN,
                Some(&json!({})),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["v1_revision"], 1);
        assert!(body["report"]["review"].as_array().is_some());
        let audit = a.store.lock().unwrap().simulations_after(0).unwrap();
        assert_eq!(
            audit
                .iter()
                .map(|r| r.operation.as_str())
                .collect::<Vec<_>>(),
            ["explain_v2", "explain_v2_batch", "diff_v2"]
        );
        assert_eq!(
            a.view.load().document.revision,
            1,
            "simulations never publish"
        );
    }

    #[tokio::test]
    async fn v2_state_survives_restart() {
        let root = tempfile::tempdir().unwrap();
        {
            let a = crate::tests::authority(root.path());
            let router = Router::new()
                .merge(routes())
                .layer(axum::middleware::from_fn_with_state(
                    a.clone(),
                    request_gate,
                ))
                .layer(axum::Extension(PeerIdentity("mtls:publisher".into())))
                .with_state(a.clone());
            let policy: pumgye_core::Policy = serde_json::from_value(v1()).unwrap();
            let mapping = BTreeMap::new();
            let doc = convert(
                &policy,
                &ConvertOptions {
                    classify: &classify_by_prefix,
                    workload_mapping: &mapping,
                },
            )
            .unwrap()
            .document;
            let doc = json!({"version":2,"catalog":doc.catalog,"zones":doc.zones,"templates":doc.templates,"services":doc.services});
            let (status, body) = publish_v2(&router, 0, &doc).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            a.v2.shadow
                .record("orders", SA, None, Some(DecisionV2::Allow), now_unix());
            persist_shadow(&a);
        }
        let a = crate::tests::authority(root.path());
        restore(&a, &a.store.lock().unwrap()).unwrap();
        assert_eq!(a.v2.view.load().as_ref().unwrap().document.revision, 2);
        assert_eq!(a.v2.shadow.gate(0, now_unix())["mismatches"], 1);
    }

    const WK: &str = "wk2:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const WK_OLD: &str = "wk2:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const WIRE: &str = "s_999999999999999999999999999999999999999999999999";
    const LEGACY: &str = "s_111111111111111111111111111111111111111111111111";
    const SPIFFE: &str = "spiffe://cluster.example.test/ns/blue/sa/worker";

    fn workload_lifecycle() -> hopae_owner::Lifecycle {
        let mut l = hopae_owner::Lifecycle {
            complete: true,
            ..Default::default()
        };
        l.statuses.insert(H1.into(), "active".into());
        let w = |principal: &str, status: &str| hopae_owner::Workload {
            principal: principal.into(),
            subject_ref: WIRE.into(),
            spiffe_id: Some(SPIFFE.into()),
            cluster: "c".into(),
            namespace: "blue".into(),
            service_account: "worker".into(),
            service_account_uid: "uid".into(),
            status: status.into(),
            cause: None,
            replacement: None,
        };
        l.workloads.principals.insert(WK.into(), w(WK, "active"));
        l.workloads.principals.insert(
            WK_OLD.into(),
            hopae_owner::Workload {
                subject_ref: "s_888888888888888888888888888888888888888888888888".into(),
                ..w(WK_OLD, "retired")
            },
        );
        l.workloads.legacy.insert(LEGACY.into(), WK.into());
        l
    }
    fn workload_policy() -> Value {
        let mut doc = converted();
        doc["bindings"] = json!([
            {"id":"bnd_legacy_pod","effect":"allow","subjects":[{"kind":"workload","ref":LEGACY}],"role":"orders.writer","scope":{"services":["orders"]},"metadata":{"reason":"pod-bound grant"}},
            {"id":"bnd_by_name","effect":"allow","subjects":[{"kind":"workload","ref":SPIFFE}],"role":"orders.writer","scope":{"services":["orders"]},"metadata":{"reason":"name grant"}},
        ]);
        doc
    }
    fn explain_case(subject: &str, kind: &str, aal: u8) -> Value {
        json!({"case":{"subject":{"kind":kind,"id":subject},"service":"orders","resource":"db:orders","action":"select","ip":"192.0.2.1","aal":aal,"guard":"enforced_allow"}})
    }

    #[tokio::test]
    async fn workload_principals_aliases_regrants_and_retirement() {
        let (_root, a, router) = owner();
        a.v2.set_lifecycle(workload_lifecycle());
        let (status, body) = publish_v2(&router, 0, &workload_policy()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // Retired principals cannot be granted again.
        let mut retired = workload_policy();
        retired["bindings"].as_array_mut().unwrap().push(json!({"id":"bnd_retired","effect":"allow","subjects":[{"kind":"workload","ref":WK_OLD}],"role":"orders.writer","scope":{"services":["orders"]}}));
        let (status, body) = publish_v2(&router, 2, &retired).await;
        assert_eq!(
            (status, body["error"]["details"][0]["code"].clone()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!("pumgye.validation.subject_retired")
            )
        );
        // The wire subject of the active principal inherits the SPIFFE-name binding.
        let (_, e) = call(
            &router,
            request(
                "POST",
                "/v2/explain",
                ADMIN,
                Some(&explain_case(WIRE, "workload", 0)),
                None,
            ),
        )
        .await;
        assert_eq!(e["result"]["outcome"]["decision"], "AssuranceDenied", "{e}");
        let principal = e["result"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stage"] == "principal")
            .unwrap()
            .clone();
        assert_eq!(
            principal["detail"]["workload_alias"],
            json!({"principal": WK, "spiffe_id": SPIFFE, "bound": true})
        );
        // Re-grant proposals from the Hopae legacy mapping are report-only until applied.
        let (_, w) = call(&router, request("GET", "/v2/workloads", ADMIN, None, None)).await;
        let proposals = w["regrant_proposals"].as_array().unwrap().clone();
        assert_eq!(proposals.len(), 1, "{w}");
        // The CAS base comes with the listing (no GET /v2/policy needed).
        let (_, policy) = call(&router, request("GET", "/v2/policy", ADMIN, None, None)).await;
        assert_eq!(w["policy_revision"], policy["revision"], "{w}");
        assert!(w["policy_revision"].is_u64());
        assert!(matches!(w["model"].as_str(), Some("v1" | "v2")));
        assert!(w["v1_revision"].is_u64());
        assert_eq!(proposals[0]["evidence"]["legacy_subject"], LEGACY);
        assert_eq!(
            proposals[0]["binding"]["subjects"],
            json!([{"kind":"workload","ref":WK}])
        );
        assert_eq!(
            a.v2.view
                .load()
                .as_ref()
                .unwrap()
                .document
                .policy
                .bindings
                .len(),
            2,
            "nothing applied yet"
        );
        let apply = |base: u64, reason: &str| json!({"base_revision": base, "proposals": [proposals[0]["id"]], "reason": reason, "approval_ref": "CHG-7"});
        assert_eq!(
            call(
                &router,
                request(
                    "POST",
                    "/v2/workloads/regrants/apply",
                    ADMIN,
                    Some(&apply(2, "")),
                    None
                )
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &router,
                request(
                    "POST",
                    "/v2/workloads/regrants/apply",
                    ADMIN,
                    Some(&apply(1, "migrate pods")),
                    None
                )
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (status, body) = call(
            &router,
            request(
                "POST",
                "/v2/workloads/regrants/apply",
                ADMIN,
                Some(&apply(2, "migrate pods")),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let added = body["policy"]["bindings"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert_eq!(added["metadata"]["reason"], "migrate pods");
        assert_eq!(added["metadata"]["approval_ref"], "CHG-7");
        assert_eq!(added["metadata"]["source"], "migrated:legacy-pod");
        assert_eq!(added["metadata"]["granted_by"], "mtls:publisher");
        let (_, w) = call(&router, request("GET", "/v2/workloads", ADMIN, None, None)).await;
        assert_eq!(
            w["regrant_proposals"],
            json!([]),
            "applied proposals disappear"
        );
        // Retiring the active principal orphans its pinned binding; the name binding remains.
        let mut l = workload_lifecycle();
        l.workloads.principals.get_mut(WK).unwrap().status = "retired".into();
        a.v2.set_lifecycle(l);
        let document = a.v2.view.load().as_ref().unwrap().document.clone();
        let compiled = a.v2.compile(&document).unwrap();
        a.v2.install_view(a.v2.view_for(document, compiled));
        let (_, status) = call(&router, request("GET", "/v2/status", ADMIN, None, None)).await;
        assert!(
            status["v2"]["orphaned_bindings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b.as_str().unwrap().starts_with("bnd_rg_")),
            "{status}"
        );
        let (_, e) = call(
            &router,
            request(
                "POST",
                "/v2/explain",
                ADMIN,
                Some(&explain_case(SPIFFE, "workload", 0)),
                None,
            ),
        )
        .await;
        assert_eq!(
            e["result"]["outcome"]["deciding_stage"], "assurance",
            "name binding still applies: {e}"
        );
    }

    #[tokio::test]
    async fn aal3_simulation_requires_and_reports_level_three() {
        let (_root, a, router) = owner();
        let mut lifecycle = hopae_owner::Lifecycle {
            complete: true,
            ..Default::default()
        };
        lifecycle.statuses.insert(H1.into(), "active".into());
        a.v2.set_lifecycle(lifecycle);
        let mut doc = converted();
        doc["catalog"]["resources"]["db:orders"]["minimum_aal"] = json!(3);
        doc["bindings"] = json!([{"id":"bnd_h1","effect":"allow","subjects":[{"kind":"human","ref":H1}],"role":"orders.writer","scope":{"services":["orders"]}}]);
        let (status, body) = publish_v2(&router, 0, &doc).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, e) = call(
            &router,
            request(
                "POST",
                "/v2/explain",
                ADMIN,
                Some(&explain_case(H1, "human", 2)),
                None,
            ),
        )
        .await;
        assert_eq!(e["result"]["outcome"]["decision"], "AssuranceDenied");
        assert_eq!(e["result"]["obligations"]["required_aal"], 3);
        let (_, e) = call(
            &router,
            request(
                "POST",
                "/v2/explain",
                ADMIN,
                Some(&explain_case(H1, "human", 3)),
                None,
            ),
        )
        .await;
        let assurance = e["result"]["trace"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stage"] == "assurance")
            .unwrap()
            .clone();
        assert_eq!(assurance["detail"], json!({"presented": 3, "required": 3}));
        assert_eq!(e["result"]["outcome"]["decision"], "Allow");
    }
}
