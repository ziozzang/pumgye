use super::*;
use serde_json::{Value, json};
use std::{
    path::Path,
    pin::Pin,
    sync::atomic::{AtomicU64, AtomicUsize},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
const TOKEN: &str = "owned-sar-caller-credential-at-least-32bytes";
fn policy() -> crate::Policy {
    serde_json::from_value(json!({"version":1,"information_classes":["public"],"services":{"api":{"authorization_context":"kubernetes_api","permissions":["read"],"roles":{"reader":{"permissions":["read"],"information_classes":["public"]}},"users":{"k8sapi:owned-cluster:reader":["reader"]},"networks":[],"require_guard":false}},"resources":{"settings":{"service":"api","information_class":"public","actions":{"read":"read"}}},"kubernetes_authorization":{"version":1,"principals":[{"cluster":"owned-cluster","user":"owned-reader","uid":{"mode":"exact","value":"owned-user-uid"},"required_groups":["owned-readers"],"required_extra":{},"subject":"k8sapi:owned-cluster:reader"}],"routes":[{"cluster":"owned-cluster","attributes":{"kind":"resource","group":"","version":"v1","resource":"configmaps","subresource":"","namespace":"owned-blue","name":"owned-settings","verb":"get"},"service":"api","resource":"settings","action":"read"}]}})).unwrap()
}
fn body() -> Vec<u8> {
    include_bytes!("../../tests/fixtures/sar-v1-generated-shape.json").to_vec()
}
fn input() -> (
    pumgye_core::kubernetes_authorization::Principal,
    pumgye_core::kubernetes_authorization::Attributes,
) {
    match sar_wire::decode(&body()).unwrap() {
        sar_wire::Decoded::Supported {
            principal,
            attributes,
        } => (principal, attributes),
        _ => panic!("fixture"),
    }
}
async fn publication(a: &Arc<Authority>, policy: crate::Policy) {
    let revision = a.view.load().document.revision;
    let mut headers = crate::HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", a.admin).parse().unwrap(),
    );
    headers.insert("if-match", format!("\"{revision}\"").parse().unwrap());
    let _ = crate::publish(
        crate::State(a.clone()),
        headers,
        axum::Extension(crate::PeerIdentity("owned-sar-test-publisher".into())),
        crate::Json(crate::Document { revision, policy }),
    )
    .await
    .unwrap();
}
fn setup() -> (tempfile::TempDir, Arc<Authority>) {
    let d = tempfile::tempdir().unwrap();
    let a = crate::tests::authority(d.path());
    (d, a)
}
#[tokio::test]
async fn captured_authority_fences_same_revision_callback_health_and_original_budget() {
    let (_dir, a) = setup();
    publication(&a, policy()).await;
    let (p, v) = input();
    let budget = Budget::new(Duration::from_secs(1)).unwrap();
    let old = owner::authorize(&a, "owned-cluster", &p, &v, budget.clone()).unwrap();
    assert!(old.current());
    let replacement = || {
        let old = a.view.load_full();
        a.view.store(Arc::new(crate::View {
            document: old.document.clone(),
            compiled: old.document.policy.compile().unwrap(),
            source_lifetime: None,
        }));
    };
    assert!(owner::after(&a, "owned-cluster", &p, &v, budget.clone(), replacement).is_none());
    assert!(!old.current());
    let capture = owner::authorize(&a, "owned-cluster", &p, &v, budget).unwrap();
    a.healthy.store(false, Ordering::Release);
    assert!(!capture.current());
    a.healthy.store(true, Ordering::Release);
    assert!(!capture.current());
    let elapsed = Arc::new(AtomicU64::new(0));
    let budget = Budget::controlled(Duration::from_secs(1), {
        let elapsed = elapsed.clone();
        Arc::new(move || Some(Duration::from_millis(elapsed.load(Ordering::Acquire))))
    });
    assert!(
        owner::after(&a, "owned-cluster", &p, &v, budget.clone(), || {
            elapsed.store(1000, Ordering::Release);
        })
        .is_none()
    );
    elapsed.store(0, Ordering::Release);
    assert!(!budget.current());
}
#[test]
fn strict_http1_framing_auth_precedes_body_and_ambiguous_inputs_refuse() {
    let base = format!(
        "POST /v1/kubernetes/subjectaccessreviews HTTP/1.1\r\nHost: sar.test\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n"
    );
    assert_eq!(
        wire::parse_header(base.as_bytes(), "sar.test", TOKEN)
            .unwrap()
            .length,
        4
    );
    for (from, to) in [
        (
            "Content-Length: 4",
            "Content-Length: 4\r\ncontent-length: 4",
        ),
        ("Content-Length: 4", "Content-Length: 04"),
        ("Content-Length: 4", "Content-Length: +4"),
        ("Content-Length: 4", "Content-Length: 4,4"),
        ("Content-Length: 4", "Content-Length: 32769"),
        (
            "Content-Length: 4",
            "Transfer-Encoding: chunked\r\nContent-Length: 4",
        ),
        (
            "Content-Length: 4",
            "Content-Length: 4\r\nExpect: 100-continue",
        ),
        ("Host: sar.test", "Host: sar.test\r\nhost: sar.test"),
        (
            "Content-Length: 4",
            "Content-Length: 4\r\nConnection: Authorization",
        ),
        ("HTTP/1.1", "HTTP/1.0"),
        ("Content-Length: 4", "Content-Length: 4\r\nUpgrade: h2c"),
        (
            "/v1/kubernetes/subjectaccessreviews",
            "https://sar.test/v1/kubernetes/subjectaccessreviews",
        ),
    ] {
        assert!(
            wire::parse_header(base.replace(from, to).as_bytes(), "sar.test", TOKEN).is_err(),
            "{to}"
        );
    }
    assert_eq!(
        wire::parse_header(base.replace(TOKEN, "wrong").as_bytes(), "sar.test", TOKEN).err(),
        Some(401)
    );
    let base = base.replace("application/json", "text/plain");
    assert_eq!(
        wire::parse_header(base.as_bytes(), "sar.test", TOKEN).err(),
        Some(415)
    );
}
fn tls_files(path: &Path) {
    let command = |args: &[&str]| {
        let out = std::process::Command::new("openssl")
            .args(args)
            .current_dir(path)
            .output()
            .unwrap();
        assert!(out.status.success(), "TLS fixture setup failed");
    };
    command(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=owned-ca",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]);
    for (name, usage) in [
        ("server", "serverAuth"),
        ("client", "clientAuth"),
        ("wrong", "clientAuth"),
    ] {
        command(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            "/CN=owned-peer",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
        ]);
        std::fs::write(path.join(format!("{name}.ext")),format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=DNS:sar.test\n")).unwrap();
        command(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ]);
    }
}
fn config_value(path: &Path) -> Value {
    let der =
        rustls_pemfile::certs(&mut std::fs::read(path.join("client.pem")).unwrap().as_slice())
            .next()
            .unwrap()
            .unwrap();
    json!({"version":1,"listen":"127.0.0.1:0","cluster":"owned-cluster","authority":"sar.test","certificate":path.join("server.pem"),"key":path.join("server.key"),"client_ca":path.join("ca.pem"),"client_sha256":[format!("{:x}",Sha256::digest(der.as_ref()))],"caller_token_env":"OWNED_SAR_TOKEN"})
}
fn configuration(path: &Path) -> config::Configuration {
    let v = config_value(path);
    let p = path.join("sar.json");
    std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    load(
        &p,
        &|name| (name == "OWNED_SAR_TOKEN").then(|| TOKEN.into()),
        &["admin", "decision"],
    )
    .unwrap()
}
fn client_alpn(
    path: &Path,
    name: Option<&str>,
    protocols: Vec<Vec<u8>>,
) -> tokio_rustls::TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::fs::read(path.join("ca.pem")).unwrap().as_slice()) {
        roots.add(c.unwrap()).unwrap();
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let mut config = if let Some(name) = name {
        let certs = rustls_pemfile::certs(
            &mut std::fs::read(path.join(format!("{name}.pem")))
                .unwrap()
                .as_slice(),
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(
            &mut std::fs::read(path.join(format!("{name}.key")))
                .unwrap()
                .as_slice(),
        )
        .unwrap()
        .unwrap();
        builder.with_client_auth_cert(certs, key).unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = protocols;
    tokio_rustls::TlsConnector::from(Arc::new(config))
}
fn client(path: &Path, name: Option<&str>) -> tokio_rustls::TlsConnector {
    client_alpn(path, name, vec![b"http/1.1".to_vec()])
}
fn request(token: &str, body: &[u8]) -> Vec<u8> {
    let mut out=format!("POST /v1/kubernetes/subjectaccessreviews HTTP/1.1\r\nHost: sar.test\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}
async fn reply<S: AsyncRead + Unpin>(stream: &mut S) -> (u16, Vec<u8>) {
    let first = stream.read_u8().await.unwrap();
    let header = wire::read_header(stream, first).await.unwrap();
    let text = std::str::from_utf8(&header).unwrap();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = text
        .split("Content-Length: ")
        .nth(1)
        .unwrap()
        .split('\r')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    (status, body)
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn actual_verified_mtls_persistent_same_connection_native_allow_deny_allow_and_caller_isolation()
 {
    let (dir, a) = setup();
    tls_files(dir.path());
    publication(&a, policy()).await;
    let server = Server::new(configuration(dir.path()), a.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(server.clone().serve(listener, async {
        let _ = stopped.await;
    }));
    let mut stream = client(dir.path(), Some("client"))
        .connect(
            "sar.test".try_into().unwrap(),
            tokio::net::TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    for allow in [true, false, true] {
        if !allow {
            let mut p = policy();
            p.services.get_mut("api").unwrap().users.clear();
            publication(&a, p).await;
        } else if a.view.load().document.revision > 1 {
            publication(&a, policy()).await;
        }
        stream.write_all(&request(TOKEN, &body())).await.unwrap();
        stream.flush().await.unwrap();
        let (status, raw) = reply(&mut stream).await;
        assert_eq!(status, 200);
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["status"]["allowed"], allow);
        assert_eq!(value["status"]["denied"], !allow);
    }
    assert_eq!(server.connections.load(Ordering::Relaxed), 1);
    assert_eq!(a.queries.load(Ordering::Relaxed), 3);
    drop(stream);
    let mut no_alpn = client_alpn(dir.path(), Some("client"), vec![])
        .connect(
            "sar.test".try_into().unwrap(),
            tokio::net::TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert!(no_alpn.get_ref().1.alpn_protocol().is_none());
    no_alpn.write_all(&request(TOKEN, &body())).await.unwrap();
    no_alpn.flush().await.unwrap();
    assert_eq!(reply(&mut no_alpn).await.0, 200);
    drop(no_alpn);
    assert_eq!(server.connections.load(Ordering::Relaxed), 2);

    for who in [Some("wrong"), None] {
        if let Ok(mut stream) = client(dir.path(), who)
            .connect(
                "sar.test".try_into().unwrap(),
                tokio::net::TcpStream::connect(addr).await.unwrap(),
            )
            .await
        {
            let _ = stream.write_all(&request(TOKEN, &body())).await;
            let _ = stream.flush().await;
            let mut raw = vec![];
            let _ =
                tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut raw)).await;
            assert!(!raw.windows(7).any(|b| b == b"200 OK\r"));
        }
    }
    // An authenticated peer with wrong/duplicate caller credential is refused
    // WITHOUT a body: status arrives immediately, native evaluator stays unchanged.
    for auth in [
        "Bearer wrong".to_owned(),
        format!("Bearer {TOKEN}\r\nauthorization: Bearer {TOKEN}"),
    ] {
        let mut stream = client(dir.path(), Some("client"))
            .connect(
                "sar.test".try_into().unwrap(),
                tokio::net::TcpStream::connect(addr).await.unwrap(),
            )
            .await
            .unwrap();
        let header = format!(
            "POST /v1/kubernetes/subjectaccessreviews HTTP/1.1\r\nHost: sar.test\r\nAuthorization: {auth}\r\nContent-Type: application/json\r\nContent-Length: 32768\r\n\r\n"
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let (status, _) = tokio::time::timeout(Duration::from_millis(500), reply(&mut stream))
            .await
            .unwrap();
        assert!(status == 400 || status == 401);
    }
    assert_eq!(a.queries.load(Ordering::Relaxed), 4);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert!(!server.active.load(Ordering::Acquire));
    assert_eq!(server.requests.available_permits(), 128);
}
// A real TLS transport can accept all plaintext while ciphertext stays Pending.
struct Stall<S> {
    socket: S,
    blocked: Arc<AtomicBool>,
    waker: Arc<std::sync::Mutex<Option<Waker>>>,
    written: Arc<AtomicUsize>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Stall<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Stall<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let t = self.get_mut();
        if t.blocked.load(Ordering::Acquire) {
            *t.waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match Pin::new(&mut t.socket).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                t.written.fetch_add(n, Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn actual_tls_plaintext_accepted_pending_flush_withdraw_never_moves_old_bytes_to_new_owner() {
    for action in ["withdraw", "shutdown", "cancel"] {
        let (dir, a) = setup();
        tls_files(dir.path());
        publication(&a, policy()).await;
        let server = Server::new(configuration(dir.path()), a.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let blocked = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(std::sync::Mutex::new(None));
        let written = Arc::new(AtomicUsize::new(0));
        let task = {
            let server = server.clone();
            let blocked = blocked.clone();
            let waker = waker.clone();
            let written = written.clone();
            tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                server
                    .connection(Stall {
                        socket,
                        blocked,
                        waker,
                        written,
                    })
                    .await
            })
        };
        let mut stream = client(dir.path(), Some("client"))
            .connect(
                "sar.test".try_into().unwrap(),
                tokio::net::TcpStream::connect(addr).await.unwrap(),
            )
            .await
            .unwrap();
        until(|| server.connections.load(Ordering::Relaxed) == 1).await;
        blocked.store(true, Ordering::Release);
        let before = written.load(Ordering::Relaxed);
        stream.write_all(&request(TOKEN, &body())).await.unwrap();
        stream.flush().await.unwrap();
        until(|| {
            server.accepted_responses.load(Ordering::Relaxed) == 1
                && waker.lock().unwrap().is_some()
        })
        .await;
        assert_eq!(written.load(Ordering::Relaxed), before);
        // A queued second request MUST NOT be admitted while first output is pending.
        stream.write_all(&request(TOKEN, &body())).await.unwrap();
        stream.flush().await.unwrap();
        match action {
            "withdraw" => publication(&a, policy()).await,
            "shutdown" => server.retire(),
            "cancel" => task.abort(),
            _ => unreachable!(),
        }
        blocked.store(false, Ordering::Release);
        waker.lock().unwrap().take().unwrap().wake();
        if action == "cancel" {
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert!(task.await.unwrap().is_err());
        }
        assert_eq!(written.load(Ordering::Relaxed), before);
        let mut raw = vec![];
        let _ = stream.read_to_end(&mut raw).await;
        assert!(raw.is_empty());
        assert_eq!(a.queries.load(Ordering::Relaxed), 1);
        assert_eq!(server.requests.available_permits(), 128);
    }
}
#[tokio::test]
async fn raw_gate_shutdown_during_clock_callback_denies_all_io_and_cannot_revive() {
    let active = Arc::new(AtomicBool::new(true));
    let trigger = Arc::new(AtomicBool::new(false));
    let budget = Budget::controlled(Duration::from_secs(1), {
        let active = active.clone();
        let trigger = trigger.clone();
        Arc::new(move || {
            if trigger.load(Ordering::Acquire) {
                active.store(false, Ordering::Release);
            }
            Some(Duration::ZERO)
        })
    });
    let (mut stream, mut peer) = tokio::io::duplex(64);
    let mut gate = Guarded {
        socket: &mut stream,
        active: active.clone(),
        mode: Mode::Budget(budget),
        connection: Budget::new(Duration::from_secs(5)).unwrap(),
    };
    trigger.store(true, Ordering::Release);
    assert!(gate.write_all(b"secret").await.is_err());
    active.store(true, Ordering::Release);
    trigger.store(false, Ordering::Release);
    assert!(gate.write_all(b"secret").await.is_err());
    assert!(
        gate.write_vectored(&[std::io::IoSlice::new(b"secret")])
            .await
            .is_err()
    );
    assert!(gate.flush().await.is_err());
    assert!(gate.shutdown().await.is_err());
    drop(gate);
    drop(stream);
    let mut bytes = vec![];
    peer.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}
#[tokio::test]
async fn configuration_and_cli_preflight_default_off_and_fixed_caller_pins() {
    use clap::Parser;
    let dir = tempfile::tempdir().unwrap();
    tls_files(dir.path());
    let p = dir.path().join("preflight.json");
    let original = config_value(dir.path());
    for (key, value) in [
        ("cluster", json!("owned:other")),
        ("authority", json!(":")),
        ("version", json!(2)),
        ("client_sha256", json!([])),
        ("caller_token_env", json!("BAD\nREFERENCE")),
        ("unknown", json!(true)),
    ] {
        let mut v = original.clone();
        v[key] = value;
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(load(&p, &|_| Some(TOKEN.into()), &["admin", "decision"]).is_err());
    }
    std::fs::write(&p, serde_json::to_vec(&original).unwrap()).unwrap();
    assert!(load(&p, &|_| Some(TOKEN.into()), &[TOKEN, "decision"]).is_err());
    assert!(load(&p, &|_| None, &[]).is_err());
    assert!(load(&p, &|_| Some(TOKEN.into()), &["admin", "decision"]).is_ok());
    let args = crate::Args::try_parse_from(["pumgye"]).unwrap();
    assert!(args.kubernetes_authorization_config.is_none());
    assert!(!args.check_kubernetes_authorization);
    assert!(crate::Args::try_parse_from(["pumgye", "--check-kubernetes-authorization"]).is_err());
    assert!(
        crate::Args::try_parse_from([
            "pumgye",
            "--kubernetes-authorization-config",
            p.to_str().unwrap(),
            "--check-kubernetes-authorization"
        ])
        .is_ok()
    );
    assert!(!dir.path().join("pumgye.sqlite3").exists());
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_source_lifetime_cannot_be_renewed_by_capture_or_connection_reuse() {
    let (_dir, mut a) = setup();
    publication(&a, policy()).await;
    Arc::get_mut(&mut a).unwrap().kubernetes_owned = true;
    a.source_ready.store(true, Ordering::Release);
    let remaining = Arc::new(AtomicU64::new(500));
    let life = crate::source_lifetime::Lifetime::controlled(a.source_clock.as_ref().unwrap(), {
        let remaining = remaining.clone();
        Arc::new(move || Some(Duration::from_millis(remaining.load(Ordering::Acquire))))
    });
    let old = a.view.load_full();
    a.view.store(Arc::new(crate::View {
        document: old.document.clone(),
        compiled: old.document.policy.compile().unwrap(),
        source_lifetime: Some(life),
    }));
    let (p, v) = input();
    let capture = owner::authorize(
        &a,
        "owned-cluster",
        &p,
        &v,
        Budget::new(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    assert!(capture.current());
    remaining.store(0, Ordering::Release);
    assert!(!capture.current());
    remaining.store(500, Ordering::Release);
    assert!(!capture.current());
    assert!(
        owner::authorize(
            &a,
            "owned-cluster",
            &p,
            &v,
            Budget::new(Duration::from_secs(1)).unwrap()
        )
        .is_none()
    );
}
#[tokio::test]
async fn aborting_owned_listener_retires_generation_and_releases_its_active_connection() {
    let (dir, a) = setup();
    tls_files(dir.path());
    publication(&a, policy()).await;
    let server = Server::new(configuration(dir.path()), a.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(server.clone().serve(listener, std::future::pending()));
    let mut stream = client(dir.path(), Some("client"))
        .connect(
            "sar.test".try_into().unwrap(),
            tokio::net::TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    until(|| server.connections.load(Ordering::Relaxed) == 1).await;
    stream.write_all(&request(TOKEN, &body())).await.unwrap();
    stream.flush().await.unwrap();
    assert_eq!(reply(&mut stream).await.0, 200);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!server.active.load(Ordering::Acquire));
    until(|| server.requests.available_permits() == 128).await;
    let mut bytes = vec![];
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(bytes.is_empty());
}
#[test]
fn clock_failure_or_reversal_never_revives_original_operation() {
    for failure in [false, true] {
        let value = Arc::new(AtomicU64::new(100));
        let read = value.clone();
        let budget = Budget::controlled(
            Duration::from_secs(1),
            Arc::new(move || {
                let n = read.load(Ordering::Acquire);
                (n != u64::MAX).then(|| Duration::from_millis(n))
            }),
        );
        assert!(budget.current());
        value.store(if failure { u64::MAX } else { 99 }, Ordering::Release);
        assert!(!budget.current());
        value.store(101, Ordering::Release);
        assert!(!budget.current());
    }
}
