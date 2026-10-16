//! Prometheus text-format metrics (`GET /metrics`). Hot-path recording is a
//! fixed set of relaxed atomic increments: no allocation, no locks, and no
//! subject, IP, service or resource labels (bounded cardinality by
//! construction). Rendering happens only at scrape time.
use pumgye_core::{Decision, ResourceDecision};
use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Instant,
};

/// Content type of [`render`] output (Prometheus text exposition 0.0.4).
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Decision context (which evaluation entrypoint decided).
#[derive(Clone, Copy, Debug)]
pub enum Context {
    Permission = 0,
    Resource = 1,
    WorkloadResource = 2,
    HumanResource = 3,
}
const CONTEXTS: [&str; 4] = [
    "permission",
    "resource",
    "workload_resource",
    "human_resource",
];
/// (reason, outcome) per reason code index.
const REASONS: [(&str, &str); 12] = [
    ("allow", "allow"),
    ("unknown_service", "deny"),
    ("guest", "deny"),
    ("network_guest", "deny"),
    ("permission_denied", "deny"),
    ("class_denied", "deny"),
    ("assurance_denied", "deny"),
    ("guard_denied", "deny"),
    ("guard_unavailable", "unavailable"),
    ("unknown_resource", "deny"),
    ("unknown_action", "deny"),
    ("unavailable", "unavailable"),
];
#[inline]
fn decision_index(d: Decision) -> usize {
    match d {
        Decision::Allow => 0,
        Decision::UnknownService => 1,
        Decision::Guest => 2,
        Decision::NetworkGuest => 3,
        Decision::PermissionDenied => 4,
        Decision::ClassDenied => 5,
        Decision::AssuranceDenied => 6,
        Decision::GuardDenied => 7,
        Decision::GuardUnavailable => 8,
    }
}

/// Request transport for latency histograms.
#[derive(Clone, Copy, Debug)]
pub enum Transport {
    Http = 0,
    Ppg1 = 1,
    Grpc = 2,
    Sar = 3,
}
const TRANSPORTS: [&str; 4] = ["http", "ppg1", "grpc", "sar"];
/// Histogram upper bounds in microseconds.
const BUCKETS_US: [u64; 12] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 100_000, 1_000_000, 5_000_000,
];
const BUCKET_LABELS: [&str; 12] = [
    "0.00005", "0.0001", "0.00025", "0.0005", "0.001", "0.0025", "0.005", "0.01", "0.025", "0.1",
    "1", "5",
];
struct Histogram {
    buckets: [AtomicU64; 12],
    count: AtomicU64,
    sum_us: AtomicU64,
}
impl Histogram {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; 12],
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }
}

/// Policy publication model and outcome.
#[derive(Clone, Copy, Debug)]
pub enum Model {
    V1 = 0,
    V2 = 1,
}
#[derive(Clone, Copy, Debug)]
pub enum Publication {
    Applied = 0,
    Conflict = 1,
    Rejected = 2,
}
const PUBLICATIONS: [&str; 3] = ["applied", "conflict", "rejected"];

/// Hopae owner feeds.
#[derive(Clone, Copy, Debug)]
pub enum Feed {
    Projection = 0,
    Lifecycle = 1,
}
const FEEDS: [&str; 2] = ["projection", "lifecycle"];

/// Observed permit kinds.
#[derive(Clone, Copy, Debug)]
pub enum PermitKind {
    Service = 0,
    Workload = 1,
    Human = 2,
}
const PERMIT_KINDS: [&str; 3] = ["service", "workload", "human"];
const PERMIT_OUTCOMES: [&str; 6] = [
    "issued",
    "permission_denied",
    "unavailable",
    "invalid_argument",
    "unauthenticated",
    "other",
];

pub struct Metrics {
    decisions: [[AtomicU64; 12]; 4],
    latency: [Histogram; 4],
    publications: [[AtomicU64; 3]; 2],
    hopae_success_unix: [AtomicU64; 2],
    hopae_failures: [AtomicU64; 2],
    hopae_cursor_expired: [AtomicU64; 2],
    simulation_rows: AtomicU64,
    observed_permits: [[AtomicU64; 6]; 3],
    kubernetes_credential_reloads: AtomicU64,
}
/// The process-wide metrics.
pub static METRICS: Metrics = Metrics {
    decisions: [const { [const { AtomicU64::new(0) }; 12] }; 4],
    latency: [const { Histogram::new() }; 4],
    publications: [const { [const { AtomicU64::new(0) }; 3] }; 2],
    hopae_success_unix: [const { AtomicU64::new(0) }; 2],
    hopae_failures: [const { AtomicU64::new(0) }; 2],
    hopae_cursor_expired: [const { AtomicU64::new(0) }; 2],
    simulation_rows: AtomicU64::new(0),
    observed_permits: [const { [const { AtomicU64::new(0) }; 6] }; 3],
    kubernetes_credential_reloads: AtomicU64::new(0),
};

impl Metrics {
    /// A v1 permission decision (`None` = unavailable).
    #[inline]
    pub fn decision(&self, context: Context, decision: Option<Decision>) {
        let i = decision.map_or(11, decision_index);
        self.decisions[context as usize][i].fetch_add(1, Relaxed);
    }
    /// A resource decision (`None` = unavailable).
    #[inline]
    pub fn resource_decision(&self, context: Context, decision: Option<ResourceDecision>) {
        let i = match decision {
            None => 11,
            Some(ResourceDecision::UnknownResource) => 9,
            Some(ResourceDecision::UnknownAction) => 10,
            Some(ResourceDecision::Decided(d)) => decision_index(d),
        };
        self.decisions[context as usize][i].fetch_add(1, Relaxed);
    }
    /// Request latency since `started`.
    #[inline]
    pub fn observe(&self, transport: Transport, started: Instant) {
        let us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let h = &self.latency[transport as usize];
        if let Some(i) = BUCKETS_US.iter().position(|b| us <= *b) {
            h.buckets[i].fetch_add(1, Relaxed);
        }
        h.count.fetch_add(1, Relaxed);
        h.sum_us.fetch_add(us, Relaxed);
    }
    pub fn publication(&self, model: Model, outcome: Publication) {
        self.publications[model as usize][outcome as usize].fetch_add(1, Relaxed);
    }
    pub fn hopae_success(&self, feed: Feed, now_unix: u64) {
        self.hopae_success_unix[feed as usize].store(now_unix, Relaxed);
    }
    pub fn hopae_failure(&self, feed: Feed) {
        self.hopae_failures[feed as usize].fetch_add(1, Relaxed);
    }
    pub fn hopae_cursor_expired(&self, feed: Feed) {
        self.hopae_cursor_expired[feed as usize].fetch_add(1, Relaxed);
    }
    pub fn simulation_row(&self) {
        self.simulation_rows.fetch_add(1, Relaxed);
    }
    /// Observed permit issuance result; refusals by gRPC status code class.
    pub fn observed_permit(&self, kind: PermitKind, refusal: Option<tonic::Code>) {
        let i = match refusal {
            None => 0,
            Some(tonic::Code::PermissionDenied) => 1,
            Some(tonic::Code::Unavailable) => 2,
            Some(tonic::Code::InvalidArgument) => 3,
            Some(tonic::Code::Unauthenticated) => 4,
            Some(_) => 5,
        };
        self.observed_permits[kind as usize][i].fetch_add(1, Relaxed);
    }
    pub fn kubernetes_credential_reload(&self) {
        self.kubernetes_credential_reloads.fetch_add(1, Relaxed);
    }
    /// Kubernetes API credential reloads so far.
    pub fn kubernetes_credential_reloads(&self) -> u64 {
        self.kubernetes_credential_reloads.load(Relaxed)
    }
    /// Test/introspection read of one decision counter.
    pub fn decisions_for(&self, context: Context, reason: &str) -> u64 {
        REASONS
            .iter()
            .position(|(r, _)| *r == reason)
            .map_or(0, |i| self.decisions[context as usize][i].load(Relaxed))
    }
}

/// Write `# HELP`/`# TYPE` headers.
pub fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}
/// One sample line; `labels` is preformatted (`a="b",c="d"`) or empty.
pub fn sample(out: &mut String, name: &str, labels: &str, value: impl std::fmt::Display) {
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
    } else {
        let _ = writeln!(out, "{name}{{{labels}}} {value}");
    }
}

/// Render the process-wide metrics plus TLS reload state.
pub fn render(out: &mut String, now_unix: u64) {
    let m = &METRICS;
    header(
        out,
        "pumgye_decisions_total",
        "counter",
        "Authorization decisions by context, outcome and reason code.",
    );
    for (c, context) in CONTEXTS.iter().enumerate() {
        for (i, (reason, outcome)) in REASONS.iter().enumerate() {
            sample(
                out,
                "pumgye_decisions_total",
                &format!("context=\"{context}\",outcome=\"{outcome}\",reason=\"{reason}\""),
                m.decisions[c][i].load(Relaxed),
            );
        }
    }
    header(
        out,
        "pumgye_request_duration_seconds",
        "histogram",
        "Decision request latency per transport.",
    );
    for (t, transport) in TRANSPORTS.iter().enumerate() {
        let h = &m.latency[t];
        let mut cumulative = 0;
        for (i, le) in BUCKET_LABELS.iter().enumerate() {
            cumulative += h.buckets[i].load(Relaxed);
            sample(
                out,
                "pumgye_request_duration_seconds_bucket",
                &format!("transport=\"{transport}\",le=\"{le}\""),
                cumulative,
            );
        }
        let count = h.count.load(Relaxed);
        sample(
            out,
            "pumgye_request_duration_seconds_bucket",
            &format!("transport=\"{transport}\",le=\"+Inf\""),
            count,
        );
        sample(
            out,
            "pumgye_request_duration_seconds_sum",
            &format!("transport=\"{transport}\""),
            h.sum_us.load(Relaxed) as f64 / 1e6,
        );
        sample(
            out,
            "pumgye_request_duration_seconds_count",
            &format!("transport=\"{transport}\""),
            count,
        );
    }
    header(
        out,
        "pumgye_policy_publications_total",
        "counter",
        "Policy publications by model and outcome (conflict = If-Match CAS conflict).",
    );
    for (model_i, model) in ["v1", "v2"].iter().enumerate() {
        for (i, outcome) in PUBLICATIONS.iter().enumerate() {
            sample(
                out,
                "pumgye_policy_publications_total",
                &format!("model=\"{model}\",outcome=\"{outcome}\""),
                m.publications[model_i][i].load(Relaxed),
            );
        }
    }
    header(
        out,
        "pumgye_hopae_last_success_timestamp_seconds",
        "gauge",
        "Unix time of the last successful Hopae owner sync per feed (0 = never).",
    );
    for (f, feed) in FEEDS.iter().enumerate() {
        sample(
            out,
            "pumgye_hopae_last_success_timestamp_seconds",
            &format!("feed=\"{feed}\""),
            m.hopae_success_unix[f].load(Relaxed),
        );
    }
    header(
        out,
        "pumgye_hopae_staleness_seconds",
        "gauge",
        "Seconds since the last successful Hopae owner sync per feed (-1 = never).",
    );
    for (f, feed) in FEEDS.iter().enumerate() {
        let at = m.hopae_success_unix[f].load(Relaxed);
        let age = if at == 0 {
            -1
        } else {
            now_unix.saturating_sub(at) as i64
        };
        sample(
            out,
            "pumgye_hopae_staleness_seconds",
            &format!("feed=\"{feed}\""),
            age,
        );
    }
    header(
        out,
        "pumgye_hopae_sync_failures_total",
        "counter",
        "Failed Hopae owner sync rounds per feed.",
    );
    for (f, feed) in FEEDS.iter().enumerate() {
        sample(
            out,
            "pumgye_hopae_sync_failures_total",
            &format!("feed=\"{feed}\""),
            m.hopae_failures[f].load(Relaxed),
        );
    }
    header(
        out,
        "pumgye_hopae_cursor_expired_total",
        "counter",
        "Hopae 410 cursor_expired answers per feed (followed by a resnapshot).",
    );
    for (f, feed) in FEEDS.iter().enumerate() {
        sample(
            out,
            "pumgye_hopae_cursor_expired_total",
            &format!("feed=\"{feed}\""),
            m.hopae_cursor_expired[f].load(Relaxed),
        );
    }
    header(
        out,
        "pumgye_simulation_audit_rows_appended_total",
        "counter",
        "Simulation audit rows written (explain, batch explain, candidate diff).",
    );
    sample(
        out,
        "pumgye_simulation_audit_rows_appended_total",
        "",
        m.simulation_rows.load(Relaxed),
    );
    header(
        out,
        "pumgye_observed_permits_total",
        "counter",
        "Observed permit issuance by principal kind and outcome.",
    );
    for (k, kind) in PERMIT_KINDS.iter().enumerate() {
        for (i, outcome) in PERMIT_OUTCOMES.iter().enumerate() {
            sample(
                out,
                "pumgye_observed_permits_total",
                &format!("kind=\"{kind}\",outcome=\"{outcome}\""),
                m.observed_permits[k][i].load(Relaxed),
            );
        }
    }
    header(
        out,
        "pumgye_kubernetes_credential_reloads_total",
        "counter",
        "Kubernetes API CA/token content changes picked up on relist.",
    );
    sample(
        out,
        "pumgye_kubernetes_credential_reloads_total",
        "",
        m.kubernetes_credential_reloads.load(Relaxed),
    );
    let tls = crate::tls_reload::registry().statuses();
    header(
        out,
        "pumgye_tls_reloads_total",
        "counter",
        "Applied TLS material reloads per listener/client.",
    );
    for s in &tls {
        sample(
            out,
            "pumgye_tls_reloads_total",
            &format!("name=\"{}\"", s.name),
            s.reloads,
        );
    }
    header(
        out,
        "pumgye_tls_reload_failures_total",
        "counter",
        "Refused (invalid) TLS material per listener/client.",
    );
    for s in &tls {
        sample(
            out,
            "pumgye_tls_reload_failures_total",
            &format!("name=\"{}\"", s.name),
            s.failures,
        );
    }
    header(
        out,
        "pumgye_tls_reload_failing",
        "gauge",
        "1 while the newest TLS material is invalid and the previous one is served.",
    );
    for s in &tls {
        sample(
            out,
            "pumgye_tls_reload_failing",
            &format!("name=\"{}\"", s.name),
            u8::from(s.failing),
        );
    }
    header(
        out,
        "pumgye_tls_leaf_expiry_seconds",
        "gauge",
        "Seconds until the served leaf certificate expires (negative = expired).",
    );
    for s in &tls {
        if let Some(at) = s.leaf.not_after {
            sample(
                out,
                "pumgye_tls_leaf_expiry_seconds",
                &format!("name=\"{}\"", s.name),
                at as i64 - now_unix as i64,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn render_is_well_formed_and_bounded() {
        METRICS.decision(Context::Permission, Some(Decision::Allow));
        METRICS.resource_decision(Context::Resource, None);
        METRICS.observe(Transport::Grpc, Instant::now());
        let mut out = String::new();
        render(&mut out, 100);
        assert!(out.contains(
            "pumgye_decisions_total{context=\"permission\",outcome=\"allow\",reason=\"allow\"}"
        ));
        assert!(
            out.contains("pumgye_request_duration_seconds_bucket{transport=\"grpc\",le=\"+Inf\"}")
        );
        for line in out.lines().filter(|l| !l.starts_with('#')) {
            let (_, value) = line.rsplit_once(' ').unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
        // Fixed series count: no data-dependent labels outside TLS names.
        let series = out
            .lines()
            .filter(|l| l.starts_with("pumgye_decisions_total"))
            .count();
        assert_eq!(series, 4 * 12);
    }
}
