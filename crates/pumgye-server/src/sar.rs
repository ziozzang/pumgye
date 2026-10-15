//! Default-off authenticated persistent SAR HTTP/1 listener; same native Authority.
mod config;
mod io;
mod owner;
mod wire;
use crate::{Authority, sar_wire};
pub(crate) use config::load;
use io::{Guarded, Mode};
use owner::{Budget, Capture};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};
fn io_error() -> std::io::Error {
    std::io::Error::other("SAR operation unavailable")
}
pub(crate) struct Server {
    config: Arc<config::Configuration>,
    authority: Arc<Authority>,
    active: Arc<AtomicBool>,
    requests: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    accepted_responses: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    connections: std::sync::atomic::AtomicU64,
}
// Retire on normal shutdown, listener failure AND dropped/aborted serve future.
struct Retirement(Arc<AtomicBool>);
impl Drop for Retirement {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Server {
    pub(crate) fn new(config: config::Configuration, authority: Arc<Authority>) -> Arc<Self> {
        Arc::new(Self {
            config: Arc::new(config),
            authority,
            active: Arc::new(AtomicBool::new(true)),
            requests: Arc::new(tokio::sync::Semaphore::new(128)),
            #[cfg(test)]
            accepted_responses: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            connections: std::sync::atomic::AtomicU64::new(0),
        })
    }
    pub(crate) fn address(&self) -> std::net::SocketAddr {
        self.config.listen
    }
    pub(crate) fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }
    pub(crate) async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        let _retirement = Retirement(self.active.clone());
        let retiring = self.clone();
        hangang_runtime::serve_connections(
            listener,
            std::num::NonZeroUsize::new(128).unwrap(),
            Duration::from_secs(5),
            move |socket, _| {
                let server = self.clone();
                async move {
                    let _ = server.connection(socket).await;
                }
            },
            async move {
                shutdown.await;
                retiring.retire();
            },
        )
        .await?;
        Ok(())
    }
    async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        socket: S,
    ) -> std::io::Result<()> {
        let gate = Guarded {
            socket,
            mode: Mode::Budget(Budget::new(Duration::from_secs(3))?),
            active: self.active.clone(),
            connection: Budget::new(Duration::from_secs(300))?,
        };
        let mut tls = tokio::time::timeout(
            Duration::from_secs(3),
            tokio_rustls::TlsAcceptor::from(self.config.tls.clone()).accept(gate),
        )
        .await
        .map_err(|_| io_error())??;
        if !matches!(tls.get_ref().1.alpn_protocol(), None | Some(b"http/1.1")) {
            return Err(io_error());
        }
        let Some(leaf) = tls.get_ref().1.peer_certificates().and_then(|p| p.first()) else {
            return Err(io_error());
        };
        let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        if !self.config.fingerprints.contains(&digest) {
            return Err(io_error());
        }
        tls.get_mut().1.set_buffer_limit(Some(16 * 1024));
        tls.flush().await?;
        if tls.get_ref().1.is_handshaking() || tls.get_ref().1.wants_write() {
            return Err(io_error());
        }
        #[cfg(test)]
        self.connections.fetch_add(1, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(300), self.requests(&mut tls))
            .await
            .map_err(|_| io_error())?
    }
    async fn requests<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        tls: &mut tokio_rustls::server::TlsStream<Guarded<S>>,
    ) -> std::io::Result<()> {
        for n in 0..4096 {
            tls.get_mut()
                .0
                .change(Mode::Budget(Budget::new(Duration::from_secs(30))?))?;
            let (first, budget) = tokio::time::timeout(
                Duration::from_secs(30),
                std::future::poll_fn(|cx| {
                    use std::{pin::Pin, task::Poll};
                    let stamp = match hangang_runtime::time::ElapsedStamp::now() {
                        Ok(stamp) => stamp,
                        Err(_) => return Poll::Ready(Err(io_error())),
                    };
                    let mut byte = [0];
                    let mut buf = tokio::io::ReadBuf::new(&mut byte);
                    match Pin::new(&mut *tls).poll_read(cx, &mut buf) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) if buf.filled().len() == 1 => Poll::Ready(Ok((
                            byte[0],
                            Budget::from_stamp(stamp, Duration::from_secs(1)),
                        ))),
                        _ => Poll::Ready(Err(io_error())),
                    }
                }),
            )
            .await
            .map_err(|_| io_error())??;
            if !budget.current() {
                return Err(io_error());
            }
            let Ok(_permit) = self.requests.clone().try_acquire_owned() else {
                return Err(io_error());
            };
            tls.get_mut().0.change(Mode::Budget(budget.clone()))?;
            let close = tokio::time::timeout(
                Duration::from_secs(1),
                self.operation(tls, first, budget, n == 4095),
            )
            .await
            .map_err(|_| io_error())??;
            if close {
                return Ok(());
            }
        }
        Ok(())
    }
    async fn operation<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        tls: &mut tokio_rustls::server::TlsStream<Guarded<S>>,
        first: u8,
        budget: Arc<Budget>,
        last: bool,
    ) -> std::io::Result<bool> {
        let header = wire::read_header(tls, first).await?;
        let frame = match wire::parse_header(&header, &self.config.authority, &self.config.token) {
            Ok(frame) => frame,
            Err(status) => {
                self.respond(tls, status, b"", true, None, &budget).await?;
                return Ok(true);
            }
        };
        let mut body = zeroize::Zeroizing::new(vec![0; frame.length]);
        tls.read_exact(&mut body).await?;
        if !budget.current() {
            return Err(io_error());
        }
        // Drain TLS protocol output before any allowing owner is installed.
        tls.flush().await?;
        if tls.get_ref().1.wants_write() {
            return Err(io_error());
        }
        let decoded = sar_wire::decode(&body);
        let close = frame.close || last;
        let capture = match &decoded {
            Ok(sar_wire::Decoded::Supported {
                principal,
                attributes,
            }) => owner::authorize(
                &self.authority,
                &self.config.cluster,
                principal,
                attributes,
                budget.clone(),
            ),
            _ => None,
        };
        let (status, response) = match decoded {
            Err(_) => (400, b"".as_slice()),
            Ok(_) => (
                200,
                if capture.is_some() {
                    sar_wire::ALLOW
                } else {
                    sar_wire::DENY
                },
            ),
        };
        self.respond(
            tls,
            status,
            response,
            close || status != 200,
            capture,
            &budget,
        )
        .await?;
        Ok(close || status != 200)
    }
    async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        tls: &mut tokio_rustls::server::TlsStream<Guarded<S>>,
        status: u16,
        body: &[u8],
        close: bool,
        capture: Option<Capture>,
        budget: &Arc<Budget>,
    ) -> std::io::Result<()> {
        let header = wire::response_header(status, body.len(), close);
        // All allocation/formatting complete BEFORE final allowing current check.
        tls.get_mut().0.change(match capture {
            Some(c) => Mode::Allow(c),
            None => Mode::Budget(budget.clone()),
        })?;
        tls.write_all(header.as_bytes()).await?;
        tls.write_all(body).await?;
        #[cfg(test)]
        self.accepted_responses.fetch_add(1, Ordering::Relaxed);
        tls.flush().await?;
        if tls.get_ref().1.is_handshaking() || tls.get_ref().1.wants_write() {
            return Err(io_error());
        }
        // No await/read/callback between final current and next state in requests().
        tls.get_mut().0.current()
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests;
