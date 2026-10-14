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
    config: Option<Arc<ServerConfig>>,
    router: Router,
) -> Result<()> {
    hangang_runtime::serve_connections(
        listener,
        std::num::NonZeroUsize::new(2048).unwrap(),
        Duration::ZERO,
        move |stream, _peer| {
            let config = config.clone();
            let router = router.clone();
            async move {
                if let Some(config) = config {
                    if let Ok(Ok(tls)) = timeout(
                        Duration::from_secs(3),
                        TlsAcceptor::from(config).accept(stream),
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
        std::future::pending(),
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
    config: Option<Arc<ServerConfig>>,
    authority: Arc<Authority>,
) -> Result<()> {
    hangang_runtime::serve_connections(
        listener,
        std::num::NonZeroUsize::new(4096).unwrap(),
        Duration::ZERO,
        move |stream, _peer| {
            let config = config.clone();
            let authority = authority.clone();
            async move {
                if let Some(config) = config {
                    if let Ok(Ok(tls)) = timeout(
                        Duration::from_secs(3),
                        TlsAcceptor::from(config).accept(stream),
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
        std::future::pending(),
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelling_native_owner_closes_authenticated_connection() {
        let root = tempfile::tempdir().unwrap();
        let authority = crate::tests::authority(root.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let credential = authority.decision.clone();
        let running = tokio::spawn(native(listener, None, authority));
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
