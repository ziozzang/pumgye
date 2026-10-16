//! Polling TLS material reload (no inotify): certificate, key and CA files are
//! re-read on an interval, compared by content digest, and a rebuilt rustls
//! configuration is swapped atomically. New handshakes use the new material;
//! established connections keep the configuration they were accepted with.
//! Invalid new material keeps the previous configuration and raises an alert
//! (`/v1/status` → `tls`), logged once per distinct file content.
use anyhow::{Result, ensure};
use arc_swap::ArcSwap;
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Bound for one PEM file (same as the existing loaders).
pub const MAX_PEM_BYTES: u64 = 1024 * 1024;
/// Default polling interval.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);

fn read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_PEM_BYTES,
        "TLS material missing or above bound"
    );
    Ok(bytes)
}
fn digest(paths: &[PathBuf]) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    for p in paths {
        let bytes = read(p)?;
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
    }
    Ok(hash.finalize().into())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Leaf certificate identity: serial (hex) and SHA-256 fingerprint of the DER.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct LeafInfo {
    pub serial: String,
    pub sha256: String,
}
fn der_item(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
        rest = &rest[n..];
        len
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}
/// First certificate of a PEM bundle: serial number and fingerprint.
pub fn leaf_info(pem: &[u8]) -> Option<LeafInfo> {
    let der = rustls_pemfile::certs(&mut &pem[..]).next()?.ok()?;
    let (_, certificate, _) = der_item(der.as_ref())?;
    let (_, tbs, _) = der_item(certificate)?;
    let (mut tag, mut value, mut rest) = der_item(tbs)?;
    if tag == 0xa0 {
        (tag, value, rest) = der_item(rest)?;
    }
    let _ = rest;
    (tag == 0x02).then(|| LeafInfo {
        serial: value.iter().map(|b| format!("{b:02x}")).collect(),
        sha256: format!("{:x}", Sha256::digest(der.as_ref())),
    })
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Status {
    pub name: String,
    pub leaf: LeafInfo,
    pub loaded_at: u64,
    pub reloads: u64,
    pub failures: u64,
    /// True while the newest file content is invalid and the previous
    /// configuration is still served (alert).
    pub failing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}
struct State {
    applied: [u8; 32],
    rejected: Option<[u8; 32]>,
    status: Status,
}
type Builder<T> = Box<dyn Fn() -> Result<T> + Send + Sync>;
/// A configuration rebuilt from files when their content changes.
pub struct Reloading<T> {
    paths: Vec<PathBuf>,
    certificate: Option<PathBuf>,
    build: Builder<T>,
    current: ArcSwap<T>,
    state: Mutex<State>,
}
impl<T: Send + Sync + 'static> Reloading<T> {
    /// Build once (refusing invalid material) and register for polling.
    pub fn new(
        name: impl Into<String>,
        paths: Vec<PathBuf>,
        certificate: Option<PathBuf>,
        build: impl Fn() -> Result<T> + Send + Sync + 'static,
    ) -> Result<Arc<Self>> {
        let applied = digest(&paths)?;
        let value = build()?;
        let leaf = certificate
            .as_deref()
            .and_then(|p| read(p).ok())
            .and_then(|pem| leaf_info(&pem))
            .unwrap_or_default();
        let this = Arc::new(Self {
            paths,
            certificate,
            build: Box::new(build),
            current: ArcSwap::from_pointee(value),
            state: Mutex::new(State {
                applied,
                rejected: None,
                status: Status {
                    name: name.into(),
                    leaf,
                    loaded_at: now(),
                    ..Default::default()
                },
            }),
        });
        registry().register(this.clone());
        Ok(this)
    }
    /// The configuration for the next handshake.
    pub fn current(&self) -> Arc<T> {
        self.current.load_full()
    }
}
/// Poll target (type-erased).
pub trait Poll: Send + Sync {
    /// Returns true when new material was applied.
    fn poll(&self) -> bool;
    fn status(&self) -> Status;
}
impl<T: Send + Sync + 'static> Poll for Reloading<T> {
    fn poll(&self) -> bool {
        let Ok(next) = digest(&self.paths) else {
            // Unreadable files (for example mid-rotation): keep serving; the next
            // poll sees the completed write. Reported only if it persists.
            if let Ok(mut s) = self.state.lock() {
                s.status.last_error = Some("material unreadable".into());
            }
            return false;
        };
        let mut s = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };
        if next == s.applied || Some(next) == s.rejected {
            if next == s.applied {
                // Rolled back to the served material: the alert clears.
                s.rejected = None;
                s.status.failing = false;
                s.status.last_error = None;
            }
            return false;
        }
        match (self.build)() {
            Ok(value) => {
                self.current.store(Arc::new(value));
                s.applied = next;
                s.rejected = None;
                s.status.leaf = self
                    .certificate
                    .as_deref()
                    .and_then(|p| read(p).ok())
                    .and_then(|pem| leaf_info(&pem))
                    .unwrap_or_default();
                s.status.loaded_at = now();
                s.status.reloads += 1;
                s.status.failing = false;
                s.status.last_error = None;
                eprintln!(
                    "{}",
                    serde_json::json!({"event": "tls_reloaded", "name": s.status.name,
                        "serial": s.status.leaf.serial, "sha256": s.status.leaf.sha256})
                );
                true
            }
            Err(error) => {
                s.rejected = Some(next);
                s.status.failures += 1;
                s.status.failing = true;
                s.status.last_error = Some(error.to_string());
                eprintln!(
                    "{}",
                    serde_json::json!({"event": "tls_reload_refused", "name": s.status.name,
                        "error": error.to_string(), "serving_serial": s.status.leaf.serial})
                );
                false
            }
        }
    }
    fn status(&self) -> Status {
        self.state
            .lock()
            .map(|s| s.status.clone())
            .unwrap_or_default()
    }
}

/// Process-wide set of reloadable TLS configurations.
#[derive(Default)]
pub struct Registry {
    items: Mutex<Vec<std::sync::Weak<dyn Poll>>>,
}
impl Registry {
    fn register(&self, item: Arc<dyn Poll>) {
        if let Ok(mut items) = self.items.lock() {
            items.retain(|w| w.strong_count() > 0);
            items.push(Arc::downgrade(&item));
        }
    }
    fn live(&self) -> Vec<Arc<dyn Poll>> {
        self.items
            .lock()
            .map(|items| items.iter().filter_map(std::sync::Weak::upgrade).collect())
            .unwrap_or_default()
    }
    /// Poll every live configuration once; returns how many were reloaded.
    pub fn poll_all(&self) -> usize {
        self.live().iter().filter(|i| i.poll()).count()
    }
    pub fn statuses(&self) -> Vec<Status> {
        let mut out: Vec<Status> = self.live().iter().map(|i| i.status()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
    pub fn failing(&self) -> bool {
        self.live().iter().any(|i| i.status().failing)
    }
}
pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}
/// Background poller (blocking file reads run off the async workers).
pub async fn run(interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let _ = tokio::task::spawn_blocking(|| registry().poll_all()).await;
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// Reloading mTLS server configuration (client certificates required).
pub fn server(
    name: &str,
    cert: &Path,
    key: &Path,
    ca: &Path,
    alpn: &'static [&'static [u8]],
) -> Result<Arc<Reloading<ServerConfig>>> {
    let (c, k, a) = (cert.to_owned(), key.to_owned(), ca.to_owned());
    Reloading::new(
        name,
        vec![cert.to_owned(), key.to_owned(), ca.to_owned()],
        Some(cert.to_owned()),
        move || hangang_runtime::tls_config(&c, &k, &a, alpn).map(Arc::unwrap_or_clone),
    )
}
/// rustls client configuration with a pinned CA and a client identity.
pub fn client_config(
    ca: &[u8],
    certificate: &[u8],
    key: &[u8],
    alpn: &[&[u8]],
) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &ca[..]) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "CA must not be empty");
    let chain =
        rustls_pemfile::certs(&mut &certificate[..]).collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!chain.is_empty(), "client certificate missing");
    let key = rustls_pemfile::private_key(&mut &key[..])?
        .ok_or_else(|| anyhow::anyhow!("client key missing"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}
/// Reloading mTLS client configuration from files.
pub fn client(
    name: &str,
    ca: &Path,
    certificate: &Path,
    key: &Path,
    alpn: &'static [&'static [u8]],
) -> Result<Arc<Reloading<ClientConfig>>> {
    let (a, c, k) = (ca.to_owned(), certificate.to_owned(), key.to_owned());
    Reloading::new(
        name,
        vec![ca.to_owned(), certificate.to_owned(), key.to_owned()],
        Some(certificate.to_owned()),
        move || client_config(&read(&a)?, &read(&c)?, &read(&k)?, alpn),
    )
}
/// Static (non-reloading) client material, for embedded PEM such as tests.
pub fn client_static(
    ca: &[u8],
    certificate: &[u8],
    key: &[u8],
    alpn: &'static [&'static [u8]],
) -> Result<Arc<Reloading<ClientConfig>>> {
    let config = client_config(ca, certificate, key, alpn)?;
    Ok(Arc::new(Reloading {
        paths: vec![],
        certificate: None,
        build: Box::new(|| Err(anyhow::anyhow!("static TLS material"))),
        current: ArcSwap::from_pointee(config),
        state: Mutex::new(State {
            applied: [0; 32],
            rejected: None,
            status: Status {
                name: "static".into(),
                leaf: leaf_info(certificate).unwrap_or_default(),
                loaded_at: now(),
                ..Default::default()
            },
        }),
    }))
}

/// tonic connector performing the TLS handshake with the current client
/// configuration, so a Channel picks up rotated material on reconnect.
#[derive(Clone)]
pub struct Connector {
    tls: Arc<Reloading<ClientConfig>>,
    server_name: ServerName<'static>,
}
impl Connector {
    pub fn new(tls: Arc<Reloading<ClientConfig>>, server_name: &str) -> Result<Self> {
        Ok(Self {
            tls,
            server_name: ServerName::try_from(server_name.to_owned())?,
        })
    }
}
type Io = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
impl tonic::codegen::Service<tonic::codegen::http::Uri> for Connector {
    type Response = Io;
    type Error = std::io::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Io>> + Send>>;
    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: tonic::codegen::http::Uri) -> Self::Future {
        let config = self.tls.current();
        let name = self.server_name.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| std::io::Error::other("missing host"))?;
            let port = uri.port_u16().unwrap_or(443);
            let tcp = tokio::net::TcpStream::connect((host.trim_matches(['[', ']']), port)).await?;
            tcp.set_nodelay(true)?;
            let tls = tokio_rustls::TlsConnector::from(config)
                .connect(name, tcp)
                .await?;
            Ok(hyper_util::rt::TokioIo::new(tls))
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A throwaway CA and leaves (rcgen-free: rustls test material is minted with ring).
    pub(crate) struct Pki {
        pub dir: tempfile::TempDir,
    }
    pub(crate) fn openssl(args: &[&str], dir: &Path) {
        let ok = std::process::Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
    }
    /// CA + server leaf (`name`, serial `serial`) + client leaf, via the openssl CLI.
    pub(crate) fn pki() -> Pki {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        openssl(
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "2",
                "-subj",
                "/CN=reload-ca",
            ],
            d,
        );
        Pki { dir }
    }
    impl Pki {
        pub(crate) fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }
        /// Issue `<name>.pem`/`<name>.key` with `serial` (hex) for localhost.
        pub(crate) fn leaf(&self, name: &str, serial: &str) {
            let d = self.dir.path();
            std::fs::write(d.join("ext.cnf"), "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n").unwrap();
            openssl(
                &[
                    "req",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-keyout",
                    &format!("{name}.key.new"),
                    "-out",
                    &format!("{name}.csr"),
                    "-subj",
                    &format!("/CN={name}"),
                ],
                d,
            );
            openssl(
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{name}.csr"),
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-set_serial",
                    &format!("0x{serial}"),
                    "-days",
                    "1",
                    "-extfile",
                    "ext.cnf",
                    "-out",
                    &format!("{name}.pem.new"),
                ],
                d,
            );
            // Rename into place like a Secret volume update.
            std::fs::rename(
                d.join(format!("{name}.key.new")),
                d.join(format!("{name}.key")),
            )
            .unwrap();
            std::fs::rename(
                d.join(format!("{name}.pem.new")),
                d.join(format!("{name}.pem")),
            )
            .unwrap();
        }
    }

    #[test]
    fn leaf_serials_and_digests_track_rotation_and_invalid_material_is_kept_out() {
        let pki = pki();
        pki.leaf("server", "1a2b");
        let reload = server(
            "test-server",
            &pki.path("server.pem"),
            &pki.path("server.key"),
            &pki.path("ca.pem"),
            &[b"h2"],
        )
        .unwrap();
        assert_eq!(reload.status().leaf.serial, "1a2b");
        let before = reload.current();
        assert!(!reload.poll(), "unchanged files are not reloaded");
        pki.leaf("server", "3c4d");
        assert!(reload.poll());
        assert_eq!(reload.status().leaf.serial, "3c4d");
        assert_eq!(reload.status().reloads, 1);
        assert!(!Arc::ptr_eq(&before, &reload.current()));
        // A truncated key keeps the previous configuration and raises the alert once.
        let serving = reload.current();
        std::fs::write(
            pki.path("server.key"),
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(!reload.poll());
        assert!(Arc::ptr_eq(&serving, &reload.current()));
        let s = reload.status();
        assert!(s.failing && s.failures == 1 && s.last_error.is_some());
        assert!(!reload.poll());
        assert_eq!(
            reload.status().failures,
            1,
            "the same rejected content is not retried"
        );
        assert!(registry().failing());
        pki.leaf("server", "5e6f");
        assert!(reload.poll());
        assert!(!reload.status().failing);
        assert!(
            registry()
                .statuses()
                .iter()
                .any(|s| s.name == "test-server" && s.leaf.serial == "5e6f")
        );
    }

    fn pem(der: &[u8]) -> Vec<u8> {
        use base64::Engine;
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
        .into_bytes()
    }
    /// The outbound connector uses rotated client material for new connections.
    #[tokio::test]
    async fn outbound_connector_presents_rotated_client_certificate() {
        use tonic::codegen::Service;
        let pki = pki();
        pki.leaf("server", "0101");
        pki.leaf("client", "0a0a");
        let server = super::server(
            "connector-test-server",
            &pki.path("server.pem"),
            &pki.path("server.key"),
            &pki.path("ca.pem"),
            &[b"h2"],
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, mut seen) = tokio::sync::mpsc::channel(8);
        let accept = server.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let tls = tokio_rustls::TlsAcceptor::from(accept.current());
                let seen_tx = seen_tx.clone();
                tokio::spawn(async move {
                    if let Ok(stream) = tls.accept(tcp).await {
                        let der = stream.get_ref().1.peer_certificates().unwrap()[0]
                            .as_ref()
                            .to_vec();
                        let _ = seen_tx.send(leaf_info(&pem(&der)).unwrap().serial).await;
                    }
                });
            }
        });
        let client = super::client(
            "connector-test-client",
            &pki.path("ca.pem"),
            &pki.path("client.pem"),
            &pki.path("client.key"),
            &[b"h2"],
        )
        .unwrap();
        let mut connector = Connector::new(client.clone(), "localhost").unwrap();
        let uri: tonic::codegen::http::Uri = format!("https://127.0.0.1:{}", address.port())
            .parse()
            .unwrap();
        let _first = connector.call(uri.clone()).await.unwrap();
        assert_eq!(seen.recv().await.unwrap(), "0a0a");
        pki.leaf("client", "0b0b");
        assert!(client.poll());
        let _second = connector.call(uri).await.unwrap();
        assert_eq!(seen.recv().await.unwrap(), "0b0b");
    }
}
