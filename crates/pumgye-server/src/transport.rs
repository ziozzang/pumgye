//! Authenticated remote decision/management listeners. Only the separate readiness
//! router may use plaintext outside loopback; it never exposes domain APIs.
use crate::{Authority, PeerIdentity};
use anyhow::{Result, ensure};
use axum::Router;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

pub use hangang_runtime::tls_config;
pub async fn http(
    listener: TcpListener,
    config: Option<Arc<pumgye_server::tls_reload::Reloading<ServerConfig>>>,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    hangang_runtime::serve_connections(
        listener,
        std::num::NonZeroUsize::new(2048).unwrap(),
        Duration::from_secs(5),
        move |stream, _peer| {
            let config = config.clone();
            let router = router.clone();
            async move {
                if let Some(config) = config {
                    if let Ok(Ok(tls)) = timeout(
                        Duration::from_secs(3),
                        TlsAcceptor::from(config.current()).accept(stream),
                    )
                    .await
                    {
                        let Some(cert) =
                            tls.get_ref().1.peer_certificates().and_then(|c| c.first())
                        else {
                            return;
                        };
                        let peer =
                            PeerIdentity(format!("mtls:{:x}", Sha256::digest(cert.as_ref())));
                        serve_http(tls, router, peer).await;
                    }
                } else {
                    serve_http(
                        stream,
                        router,
                        PeerIdentity("loopback-administrator".into()),
                    )
                    .await;
                }
            }
        },
        shutdown,
    )
    .await?;
    Ok(())
}
async fn serve_http<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    router: Router,
    peer: PeerIdentity,
) {
    let service = TowerToHyperService::new(router.layer(axum::Extension(peer)));
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .max_buf_size(32 * 1024);
    builder
        .http2()
        .max_concurrent_streams(64)
        .max_header_list_size(16 * 1024);
    let _ = timeout(
        Duration::from_secs(300),
        builder.serve_connection(TokioIo::new(stream), service),
    )
    .await;
}
pub async fn native(
    listener: TcpListener,
    config: Option<Arc<pumgye_server::tls_reload::Reloading<ServerConfig>>>,
    authority: Arc<Authority>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    hangang_runtime::serve_connections(
        listener,
        std::num::NonZeroUsize::new(4096).unwrap(),
        Duration::from_secs(5),
        move |stream, _peer| {
            let config = config.clone();
            let authority = authority.clone();
            async move {
                if let Some(config) = config {
                    if let Ok(Ok(tls)) = timeout(
                        Duration::from_secs(3),
                        TlsAcceptor::from(config.current()).accept(stream),
                    )
                    .await
                        && tls.get_ref().1.alpn_protocol() == Some(b"ppg1")
                    {
                        let _ =
                            timeout(Duration::from_secs(300), native_session(tls, authority)).await;
                    }
                } else {
                    let _ =
                        timeout(Duration::from_secs(300), native_session(stream, authority)).await;
                }
            }
        },
        shutdown,
    )
    .await?;
    Ok(())
}
async fn native_session<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    a: Arc<Authority>,
) -> Result<()> {
    // Authenticate once per connection, only after remote mTLS verification.
    timeout(Duration::from_secs(3), async {
        let mut magic = [0; 4];
        stream.read_exact(&mut magic).await?;
        ensure!(&magic == pumgye_protocol::HELLO, "invalid native handshake");
        let len = stream.read_u16().await? as usize;
        ensure!((16..=4096).contains(&len), "invalid credential size");
        let mut token = vec![0; len];
        stream.read_exact(&mut token).await?;
        ensure!(
            crate::credential_matches(&token, a.decision.as_bytes()),
            "invalid native credential"
        );
        stream.write_all(pumgye_protocol::ACK).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let mut reader = BufReader::with_capacity(16 * 1024, stream);
    let mut query = [0; pumgye_protocol::MAX_QUERY];
    let mut replies = [0; pumgye_protocol::REPLY_SIZE * 64];
    let mut pending = 0;
    loop {
        let len = match timeout(Duration::from_secs(30), reader.read_u16()).await? {
            Ok(n) => n as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        ensure!(
            (40..=query.len()).contains(&len),
            "invalid native frame size"
        );
        timeout(Duration::from_secs(5), reader.read_exact(&mut query[..len])).await??;
        let started = std::time::Instant::now();
        let q = pumgye_protocol::Query::decode(&query[..len])?;
        let reply = a.evaluate(&q).encode();
        pumgye_server::metrics::METRICS.observe(pumgye_server::metrics::Transport::Ppg1, started);
        replies[pending..pending + reply.len()].copy_from_slice(&reply);
        pending += reply.len();
        if reader.buffer().is_empty() || pending == replies.len() {
            timeout(
                Duration::from_secs(5),
                reader.get_mut().write_all(&replies[..pending]),
            )
            .await??;
            pending = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn shutdown_finishes_an_inflight_http_response_before_returning() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(tokio::sync::Notify::new());
        let started = entered.clone();
        let release = released.clone();
        let router = Router::new().route(
            "/owned",
            axum::routing::get(move || {
                let started = started.clone();
                let release = release.clone();
                async move {
                    started.notify_one();
                    release.notified().await;
                    "completed-owned-response"
                }
            }),
        );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(http(listener, None, router, async {
            let _ = stopped.await;
        }));
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket
            .write_all(
                b"GET /owned HTTP/1.1\r\nHost: owned.example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        stop.send(()).unwrap();
        // The response cannot complete until the already-entered handler is released.
        tokio::task::yield_now().await;
        assert!(!running.is_finished());
        released.notify_one();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), socket.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"completed-owned-response"));
        timeout(Duration::from_secs(2), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn cancelling_native_owner_closes_authenticated_connection() {
        let root = tempfile::tempdir().unwrap();
        let authority = crate::tests::authority(root.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let credential = authority.decision.clone();
        let running = tokio::spawn(native(listener, None, authority, std::future::pending()));
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket.write_all(pumgye_protocol::HELLO).await.unwrap();
        socket.write_u16(credential.len() as u16).await.unwrap();
        socket.write_all(credential.as_bytes()).await.unwrap();
        let mut ack = [0; 4];
        timeout(Duration::from_secs(2), socket.read_exact(&mut ack))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ack, pumgye_protocol::ACK);
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());
        assert_eq!(
            timeout(Duration::from_secs(2), socket.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

#[cfg(test)]
pub(crate) mod reload_tests {
    use super::*;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fresh EC P-256 test CA (`ca.pem`, `ca.key`) in `dir`.
    pub(crate) fn ca(dir: &Path, name: &str) {
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
                &format!("/CN={name}"),
            ],
            dir,
        );
    }
    pub(crate) fn openssl(args: &[&str], dir: &Path) {
        let out = std::process::Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    pub(crate) fn leaf(dir: &Path, name: &str, serial: &str) {
        std::fs::write(
            dir.join("ext.cnf"),
            "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n",
        )
        .unwrap();
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
            dir,
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
            dir,
        );
        std::fs::rename(
            dir.join(format!("{name}.key.new")),
            dir.join(format!("{name}.key")),
        )
        .unwrap();
        std::fs::rename(
            dir.join(format!("{name}.pem.new")),
            dir.join(format!("{name}.pem")),
        )
        .unwrap();
    }
    fn serial_of(stream: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> String {
        use base64::Engine;
        let der = stream.get_ref().1.peer_certificates().unwrap()[0]
            .as_ref()
            .to_vec();
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        );
        pumgye_server::tls_reload::leaf_info(pem.as_bytes())
            .unwrap()
            .serial
    }
    async fn get(stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> String {
        stream
            .write_all(b"GET /x HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    /// cert-manager style rotation: the listener presents the new certificate to
    /// new connections without a restart; established connections keep working;
    /// invalid material keeps the previous certificate and raises the alert.
    #[tokio::test]
    async fn listener_serves_rotated_certificate_without_restart() {
        let root = tempfile::tempdir().unwrap();
        let d = root.path();
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
                "/CN=listener-ca",
            ],
            d,
        );
        leaf(d, "server", "1001");
        leaf(d, "client", "2002");
        let reload = pumgye_server::tls_reload::server(
            "test http listener",
            &d.join("server.pem"),
            &d.join("server.key"),
            &d.join("ca.pem"),
            &[b"http/1.1"],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new().route("/x", axum::routing::get(|| async { "ok" }));
        tokio::spawn(http(
            listener,
            Some(reload.clone()),
            router,
            std::future::pending(),
        ));
        let client = Arc::new(
            pumgye_server::tls_reload::client_config(
                &std::fs::read(d.join("ca.pem")).unwrap(),
                &std::fs::read(d.join("client.pem")).unwrap(),
                &std::fs::read(d.join("client.key")).unwrap(),
                &[b"http/1.1"],
            )
            .unwrap(),
        );
        let connect = || {
            let client = client.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
                tokio_rustls::TlsConnector::from(client)
                    .connect(
                        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                        tcp,
                    )
                    .await
                    .unwrap()
            }
        };
        let mut old = connect().await;
        assert_eq!(serial_of(&old), "1001");
        assert!(get(&mut old).await.contains("200 OK"));
        leaf(d, "server", "1002");
        assert_eq!(pumgye_server::tls_reload::registry().poll_all(), 1);
        let mut new = connect().await;
        assert_eq!(
            serial_of(&new),
            "1002",
            "new handshakes use the rotated certificate"
        );
        assert!(get(&mut new).await.contains("200 OK"));
        assert!(
            get(&mut old).await.contains("200 OK"),
            "established connections are unaffected"
        );
        std::fs::write(
            d.join("server.pem"),
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        pumgye_server::tls_reload::registry().poll_all();
        assert_eq!(
            serial_of(&connect().await),
            "1002",
            "invalid material keeps the previous certificate"
        );
        let status = pumgye_server::tls_reload::registry().statuses();
        let mine = status
            .iter()
            .find(|s| s.name == "test http listener")
            .unwrap();
        assert!(mine.failing && mine.leaf.serial == "1002");
    }
}
