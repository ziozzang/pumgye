//! Standalone Pumgye control/decision authority.
mod kubernetes;
mod kubernetes_api;
mod store;
mod transport;
use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;
use pumgye_core::{CompiledPolicy, GuardEvidence, Policy};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
#[derive(Parser)]
#[command(name = "pumgye", version)]
struct Args {
    /// Continuously collect read-only Kubernetes RBAC observations over verified HTTPS.
    #[arg(long, requires_all = ["kubernetes_cluster", "kubernetes_api", "kubernetes_ca", "kubernetes_token"], conflicts_with = "inspect_kubernetes_rbac")]
    observe_kubernetes_rbac: bool,
    #[arg(long, requires = "observe_kubernetes_rbac")]
    kubernetes_api: Option<String>,
    #[arg(long, requires = "observe_kubernetes_rbac")]
    kubernetes_ca: Option<PathBuf>,
    #[arg(long, requires = "observe_kubernetes_rbac")]
    kubernetes_token: Option<PathBuf>,
    #[arg(long, requires = "observe_kubernetes_rbac")]
    kubernetes_namespace: Option<String>,
    /// Inspect a bounded complete RBAC List without opening the database or listeners.
    #[arg(long, requires = "kubernetes_cluster")]
    inspect_kubernetes_rbac: Option<PathBuf>,
    #[arg(long)]
    kubernetes_cluster: Option<String>,
    #[arg(long, default_value = "127.0.0.1:9084")]
    listen: SocketAddr,
    /// Persistent PPG1 decision endpoint (mTLS mandatory outside loopback).
    #[arg(long)]
    decision_listen: Option<SocketAddr>,
    #[arg(long, requires_all = ["tls_key", "client_ca"])]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires_all = ["tls_cert", "client_ca"])]
    tls_key: Option<PathBuf>,
    #[arg(long, requires_all = ["tls_cert", "tls_key"])]
    client_ca: Option<PathBuf>,
    #[arg(long, default_value = "pumgye.sqlite3")]
    database: PathBuf,
    /// Initial policy for an empty database; ignored on subsequent starts.
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long, default_value = "PUMGYE_ADMIN_TOKEN")]
    admin_token_env: String,
    #[arg(long, default_value = "PUMGYE_DECISION_TOKEN")]
    decision_token_env: String,
}
#[derive(Clone)]
struct PeerIdentity(String);
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    revision: u64,
    policy: Policy,
}
struct View {
    document: Document,
    compiled: CompiledPolicy,
}
struct Authority {
    view: ArcSwap<View>,
    store: std::sync::Mutex<store::Store>,
    admin: String,
    decision: String,
    queries: AtomicU64,
    healthy: AtomicBool,
    publications: Arc<tokio::sync::Semaphore>,
    requests: Arc<tokio::sync::Semaphore>,
    management: Arc<tokio::sync::Semaphore>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    service_id: String,
    subject: String,
    ip: IpAddr,
    permission: String,
    information_class: String,
    aal: u8,
    guard: String,
    #[serde(default)]
    minimum_revision: u64,
}
fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all("authorization").iter();
    let Some(value) = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    if values.next().is_some() || value.len() != expected.len() {
        return false;
    }
    credential_matches(value.as_bytes(), expected.as_bytes())
}
fn credential_matches(value: &[u8], expected: &[u8]) -> bool {
    value.len() == expected.len()
        && value
            .iter()
            .zip(expected)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}
impl Authority {
    fn evaluate(&self, q: &pumgye_protocol::Query<'_>) -> pumgye_protocol::Reply {
        let view = self.view.load();
        let decision = if !self.healthy.load(Ordering::Acquire)
            || view.document.revision < q.minimum_revision
        {
            None
        } else {
            Some(view.compiled.evaluate(
                q.service_id,
                q.subject,
                q.ip,
                q.permission,
                q.information_class,
                q.aal,
                q.guard,
            ))
        };
        self.queries.fetch_add(1, Ordering::Relaxed);
        pumgye_protocol::Reply {
            request_id: q.request_id,
            revision: view.document.revision,
            decision,
        }
    }
}

async fn request_gate(
    State(a): State<Arc<Authority>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let expected = match request.uri().path() {
        "/v1/policy" | "/v1/status" | "/v1/audit" => Some(&a.admin),
        "/v1/decision" => Some(&a.decision),
        _ => None,
    };
    if expected.is_some_and(|token| !authorized(request.headers(), token)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(_request) = a.requests.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let _management = if matches!(
        request.uri().path(),
        "/v1/policy" | "/v1/status" | "/v1/audit"
    ) {
        match a.management.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
    }
}

async fn read(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
) -> Result<Json<Document>, StatusCode> {
    if !authorized(&headers, &a.admin) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !a.healthy.load(Ordering::Acquire) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(a.view.load().document.clone()))
}
async fn publish(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    axum::Extension(peer): axum::Extension<PeerIdentity>,
    Json(mut next): Json<Document>,
) -> Result<Json<Document>, StatusCode> {
    if !authorized(&headers, &a.admin) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut values = headers.get_all("if-match").iter();
    let expected = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix('"'))
        .and_then(|v| v.strip_suffix('"'))
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or(StatusCode::PRECONDITION_REQUIRED)?;
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if next.revision != expected {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !a.healthy.load(Ordering::Acquire) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let permit = a
        .publications
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    // Compilation and durable publication continue even if the HTTP request is cancelled.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let compiled = next
            .policy
            .compile()
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
        let mut store = a.store.lock().map_err(|_| {
            a.healthy.store(false, Ordering::Release);
            StatusCode::SERVICE_UNAVAILABLE
        })?;
        if !a.healthy.load(Ordering::Acquire) {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        if a.view.load().document.revision != expected {
            return Err(StatusCode::CONFLICT);
        }
        next.revision = expected
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        if store.publish(expected, &next, &peer.0).is_err() {
            a.healthy.store(false, Ordering::Release);
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        a.view.store(Arc::new(View {
            document: next.clone(),
            compiled,
        }));
        Ok(Json(next))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditCursor {
    #[serde(default)]
    after_revision: u64,
}
async fn audit_records(
    State(a): State<Arc<Authority>>,
    axum::extract::Query(cursor): axum::extract::Query<AuditCursor>,
) -> Result<Json<Vec<store::AuditRecord>>, StatusCode> {
    if cursor.after_revision > i64::MAX as u64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    tokio::task::spawn_blocking(move || {
        let store = a
            .store
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        store
            .audit_after(cursor.after_revision)
            .map(Json)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
}
async fn status(State(a): State<Arc<Authority>>) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"version":1,"policy_revision":a.view.load().document.revision,"healthy":a.healthy.load(Ordering::Acquire),"decision_queries":a.queries.load(Ordering::Relaxed),"cache_ttl_ms":0}),
    )
}

async fn decide(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    Json(q): Json<Query>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &a.decision) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if [
        &q.service_id,
        &q.subject,
        &q.permission,
        &q.information_class,
    ]
    .iter()
    .any(|v| v.len() > 128)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let guard = match q.guard.as_str() {
        "enforced_allow" => GuardEvidence::EnforcedAllow,
        "deny" => GuardEvidence::Deny,
        "observe" => GuardEvidence::Observe,
        "unavailable" => GuardEvidence::Unavailable,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let query = pumgye_protocol::Query {
        request_id: 0,
        minimum_revision: q.minimum_revision,
        ip: q.ip,
        aal: q.aal,
        guard,
        service_id: &q.service_id,
        subject: &q.subject,
        permission: &q.permission,
        information_class: &q.information_class,
    };
    query
        .encode(&mut [0; pumgye_protocol::MAX_QUERY])
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let result = a.evaluate(&query);
    let decision = result.decision.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(
        serde_json::json!({"version":1,"revision":result.revision,"allow":decision==pumgye_core::Decision::Allow,"reason":format!("{decision:?}"),"ttl_ms":0}),
    ))
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(path) = &args.inspect_kubernetes_rbac {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take((kubernetes::MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        let inventory = kubernetes::inspect(args.kubernetes_cluster.as_deref().unwrap(), &bytes)?;
        println!("{}", serde_json::to_string_pretty(&inventory)?);
        return Ok(());
    }
    if args.observe_kubernetes_rbac {
        let mut collector = kubernetes_api::Collector::new(
            args.kubernetes_api.as_deref().unwrap(),
            args.kubernetes_namespace,
            args.kubernetes_cluster.unwrap(),
        )?;
        let epoch = std::time::Instant::now();
        loop {
            let now = u64::try_from(epoch.elapsed().as_millis())?;
            let refresh = collector.refresh(
                args.kubernetes_ca.as_deref().unwrap(),
                args.kubernetes_token.as_deref().unwrap(),
                now,
            );
            let result = tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok(()),
                result = refresh => result,
            };
            if result.is_ok() {
                let now = u64::try_from(epoch.elapsed().as_millis())?;
                if let Some(view) = collector.fresh(now) {
                    println!("{}", serde_json::to_string(&*view)?);
                }
            } else {
                // Never print upstream bodies, credentials or token-bearing request URLs.
                println!(r#"{{"version":1,"mode":"observe","available":false}}"#);
            }
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok(()),
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
            }
        }
    }
    anyhow::ensure!(
        args.tls_cert.is_some()
            || (args.listen.ip().is_loopback()
                && args.decision_listen.is_none_or(|a| a.ip().is_loopback())),
        "remote listeners require the authenticated TLS transport gate"
    );
    let admin = std::env::var(args.admin_token_env)?;
    let decision = std::env::var(args.decision_token_env)?;
    anyhow::ensure!(
        admin.len() >= 16
            && admin.len() <= 4096
            && decision.len() >= 16
            && decision.len() <= 4096
            && admin != decision
            && admin
                .bytes()
                .chain(decision.bytes())
                .all(|b| (0x21..=0x7e).contains(&b)),
        "distinct bounded administrator and decision credentials are required"
    );
    let (http_tls, native_tls) = if let (Some(cert), Some(key), Some(ca)) =
        (&args.tls_cert, &args.tls_key, &args.client_ca)
    {
        (
            Some(transport::tls_config(cert, key, ca, &[b"h2", b"http/1.1"])?),
            Some(transport::tls_config(cert, key, ca, &[b"ppg1"])?),
        )
    } else {
        (None, None)
    };
    let (store, document) = store::Store::open(&args.database, args.policy.as_deref())?;
    let compiled = document.policy.compile()?;
    let authority = Arc::new(Authority {
        view: ArcSwap::from_pointee(View { document, compiled }),
        store: std::sync::Mutex::new(store),
        admin,
        decision,
        queries: AtomicU64::new(0),
        healthy: AtomicBool::new(true),
        publications: Arc::new(tokio::sync::Semaphore::new(4)),
        requests: Arc::new(tokio::sync::Semaphore::new(4096)),
        management: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    let health = authority.clone();
    let router = Router::new()
        .route(
            "/healthz",
            get(move || {
                let health = health.clone();
                async move {
                    if health.healthy.load(Ordering::Acquire) {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }
            }),
        )
        .route("/v1/policy", get(read).put(publish))
        .route("/v1/status", get(status))
        .route("/v1/audit", get(audit_records))
        .route(
            "/v1/decision",
            post(decide).layer(axum::extract::DefaultBodyLimit::max(2048)),
        )
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            authority.clone(),
            request_gate,
        ))
        .with_state(authority.clone());
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    if let Some(address) = args.decision_listen {
        let native = tokio::net::TcpListener::bind(address).await?;
        tokio::try_join!(
            transport::http(listener, http_tls, router),
            transport::native(native, native_tls, authority)
        )?;
    } else {
        transport::http(listener, http_tls, router).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn authority(root: &std::path::Path) -> Arc<Authority> {
        let initial = root.join("initial.json");
        std::fs::write(&initial,r#"{"revision":0,"policy":{"version":1,"information_classes":["public"],"services":{}}}"#).unwrap();
        let (store, document) =
            store::Store::open(&root.join("authority.sqlite3"), Some(&initial)).unwrap();
        let compiled = document.policy.compile().unwrap();
        Arc::new(Authority {
            view: ArcSwap::from_pointee(View { document, compiled }),
            store: std::sync::Mutex::new(store),
            admin: "fixture-admin-credential".into(),
            decision: "fixture-decision-credential".into(),
            queries: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
            publications: Arc::new(tokio::sync::Semaphore::new(4)),
            requests: Arc::new(tokio::sync::Semaphore::new(4096)),
            management: Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            "Bearer fixture-admin-credential".parse().unwrap(),
        );
        h.insert("if-match", "\"1\"".parse().unwrap());
        h
    }
    #[tokio::test]
    async fn persistence_failure_fences_old_view() {
        let root = tempfile::tempdir().unwrap();
        let a = authority(root.path());
        a.store.lock().unwrap().reject_writes();
        let doc = a.view.load().document.clone();
        assert!(matches!(
            publish(
                State(a.clone()),
                headers(),
                axum::Extension(PeerIdentity("fixture-owner".into())),
                Json(doc)
            )
            .await,
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
        assert!(!a.healthy.load(Ordering::Acquire));
        assert_eq!(a.view.load().document.revision, 1);
        let q = pumgye_protocol::Query {
            request_id: 1,
            minimum_revision: 1,
            ip: "192.0.2.8".parse().unwrap(),
            aal: 1,
            guard: GuardEvidence::EnforcedAllow,
            service_id: "orders",
            subject: "fixture",
            permission: "read",
            information_class: "public",
        };
        assert!(a.evaluate(&q).decision.is_none());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_publication_keeps_durable_and_memory_revisions_together() {
        let root = tempfile::tempdir().unwrap();
        let a = authority(root.path());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocked = a.clone();
        let blocker = tokio::task::spawn_blocking(move || {
            let _lock = blocked.store.lock().unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        ready_rx.await.unwrap();
        let doc = a.view.load().document.clone();
        let active = a.clone();
        let request = tokio::spawn(async move {
            publish(
                State(active),
                headers(),
                axum::Extension(PeerIdentity("fixture-owner".into())),
                Json(doc),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while a.publications.available_permits() == 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        request.abort();
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while a.view.load().document.revision != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(a.healthy.load(Ordering::Acquire));
        let _ = request.await;
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while Arc::strong_count(&a) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(a);
        let (_, recovered) =
            store::Store::open(&root.path().join("authority.sqlite3"), None).unwrap();
        assert_eq!(recovered.revision, 2);
    }
}
