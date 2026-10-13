//! Authenticated remote listeners. Plaintext is restricted to loopback.
use crate::{Authority, PeerIdentity};
use anyhow::{Result, ensure};
use axum::Router;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

pub fn tls_config(cert: &Path, key: &Path, ca: &Path, alpn: &[&[u8]]) -> Result<Arc<ServerConfig>> {
    fn bytes(path: &Path) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "TLS material exceeds bound");
        Ok(bytes)
    }
    let cert_bytes = bytes(cert)?;
    let key_bytes = bytes(key)?;
    let ca_bytes = bytes(ca)?;
    let certs =
        rustls_pemfile::certs(&mut cert_bytes.as_slice()).collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("missing TLS private key"))?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_bytes.as_slice()) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "client CA must not be empty");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}
pub async fn http(
    listener: TcpListener,
    config: Option<Arc<ServerConfig>>,
    router: Router,
) -> Result<()> {
    let capacity = Arc::new(Semaphore::new(2048));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            continue;
        };
        stream.set_nodelay(true)?;
        let config = config.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(config) = config {
                if let Ok(Ok(tls)) = timeout(
                    Duration::from_secs(3),
                    TlsAcceptor::from(config).accept(stream),
                )
                .await
                {
                    let Some(cert) = tls.get_ref().1.peer_certificates().and_then(|c| c.first())
                    else {
                        return;
                    };
                    let peer = PeerIdentity(format!("mtls:{:x}", Sha256::digest(cert.as_ref())));
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
        });
    }
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
    config: Option<Arc<ServerConfig>>,
    authority: Arc<Authority>,
) -> Result<()> {
    let capacity = Arc::new(Semaphore::new(4096));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            continue;
        };
        stream.set_nodelay(true)?;
        let config = config.clone();
        let authority = authority.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(config) = config {
                if let Ok(Ok(tls)) = timeout(
                    Duration::from_secs(3),
                    TlsAcceptor::from(config).accept(stream),
                )
                .await
                    && tls.get_ref().1.alpn_protocol() == Some(b"ppg1")
                {
                    let _ = timeout(Duration::from_secs(300), native_session(tls, authority)).await;
                }
            } else {
                let _ = timeout(Duration::from_secs(300), native_session(stream, authority)).await;
            }
        });
    }
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
        let q = pumgye_protocol::Query::decode(&query[..len])?;
        let reply = a.evaluate(&q).encode();
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
