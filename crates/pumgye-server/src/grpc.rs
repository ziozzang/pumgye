//! Additional decision transport; all policy evaluation stays in Authority.
use crate::Authority;
use anyhow::{Result, ensure};
use pumgye_grpc::v1::{
    DecisionReply, DecisionRequest,
    authorization_server::{Authorization, AuthorizationServer},
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_stream::{StreamExt, wrappers::TcpListenerStream};
use tonic::{
    Request, Response, Status,
    transport::{
        Certificate, Identity, Server, ServerTlsConfig,
        server::{Connected, TcpConnectInfo},
    },
};

pub fn configuration(cert: &Path, key: &Path, ca: &Path) -> Result<ServerTlsConfig> {
    fn bounded(path: &Path) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "gRPC TLS material exceeds bound"
        );
        Ok(bytes)
    }
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(bounded(cert)?, bounded(key)?))
        .client_ca_root(Certificate::from_pem(bounded(ca)?))
        .client_auth_optional(false)
        .timeout(Duration::from_secs(3)))
}
struct Connection {
    socket: TcpStream,
    _permit: OwnedSemaphorePermit,
}
impl Connected for Connection {
    type ConnectInfo = TcpConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.socket.connect_info()
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().socket).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
    }
}
struct Service(Arc<Authority>);
#[tonic::async_trait]
impl Authorization for Service {
    async fn decide(
        &self,
        request: Request<DecisionRequest>,
    ) -> Result<Response<DecisionReply>, Status> {
        let mut values = request.metadata().get_all("authorization").iter();
        let value = values
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if values.next().is_some()
            || !value.is_some_and(|value| {
                crate::credential_matches(value.as_bytes(), self.0.decision.as_bytes())
            })
        {
            return Err(Status::unauthenticated("decision credential required"));
        }
        let _permit = self
            .0
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("decision capacity"))?;
        let input = request.into_inner();
        let ip = match input.ip.as_slice() {
            bytes if bytes.len() == 4 => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()))
            }
            bytes if bytes.len() == 16 => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
            }
            _ => return Err(Status::invalid_argument("invalid address size")),
        };
        let guard = match input.guard {
            1 => pumgye_core::GuardEvidence::EnforcedAllow,
            2 => pumgye_core::GuardEvidence::Deny,
            3 => pumgye_core::GuardEvidence::Observe,
            4 => pumgye_core::GuardEvidence::Unavailable,
            _ => return Err(Status::invalid_argument("guard evidence required")),
        };
        if input.aal > 3
            || [
                &input.service_id,
                &input.subject,
                &input.permission,
                &input.information_class,
            ]
            .iter()
            .any(|value| {
                value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
            })
        {
            return Err(Status::invalid_argument(
                "invalid decision identifiers or assurance",
            ));
        }
        let query = pumgye_protocol::Query {
            request_id: input.request_id,
            minimum_revision: input.minimum_revision,
            ip,
            aal: input.aal as u8,
            guard,
            service_id: &input.service_id,
            subject: &input.subject,
            permission: &input.permission,
            information_class: &input.information_class,
        };
        let result = self.0.evaluate(&query);
        let verdict = match result.decision {
            Some(pumgye_core::Decision::Allow) => 1,
            Some(_) => 2,
            None => 3,
        };
        Ok(Response::new(DecisionReply {
            request_id: result.request_id,
            revision: result.revision,
            verdict,
            native_reason: u32::from(result.encode()[1]),
            cache_ttl_ms: 0,
        }))
    }
}
pub async fn serve(
    listener: TcpListener,
    tls: ServerTlsConfig,
    authority: Arc<Authority>,
) -> Result<()> {
    let connections = Arc::new(Semaphore::new(2048));
    let incoming = TcpListenerStream::new(listener).filter_map(move |entry| match entry {
        Ok(socket) => {
            let permit = connections.clone().try_acquire_owned().ok()?;
            if let Err(error) = socket.set_nodelay(true) {
                return Some(Err(error));
            }
            Some(Ok(Connection {
                socket,
                _permit: permit,
            }))
        }
        Err(error) => Some(Err(error)),
    });
    Server::builder()
        .tls_config(tls)?
        .concurrency_limit_per_connection(64)
        .max_concurrent_streams(Some(64))
        .http2_max_header_list_size(Some(8192))
        .timeout(Duration::from_millis(1000))
        .add_service(
            AuthorizationServer::new(Service(authority))
                .max_decoding_message_size(2048)
                .max_encoding_message_size(1024),
        )
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(token: &str) -> Request<DecisionRequest> {
        let mut request = Request::new(DecisionRequest {
            request_id: 7,
            minimum_revision: 0,
            ip: vec![192, 0, 2, 8],
            aal: 1,
            guard: 1,
            service_id: "orders".into(),
            subject: "fixture".into(),
            permission: "read".into(),
            information_class: "public".into(),
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }
    #[tokio::test]
    async fn credentials_defaults_capacity_and_source_fence() {
        let root = tempfile::tempdir().unwrap();
        let mut a = crate::tests::authority(root.path());
        let service = Service(a.clone());
        assert_eq!(
            service
                .decide(request("fixture-admin-credential"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        let reply = service
            .decide(request("fixture-decision-credential"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.verdict, 2); // Unknown service, never a default allow.
        assert_eq!(reply.native_reason, 1);
        assert_eq!(reply.cache_ttl_ms, 0);
        let mut invalid = request("fixture-decision-credential");
        invalid.get_mut().guard = 0;
        assert_eq!(
            service.decide(invalid).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let mut invalid = request("fixture-decision-credential");
        invalid.get_mut().ip = vec![1, 2, 3];
        assert_eq!(
            service.decide(invalid).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let mut duplicate = request("fixture-decision-credential");
        duplicate.metadata_mut().append(
            "authorization",
            "Bearer fixture-decision-credential".parse().unwrap(),
        );
        assert_eq!(
            service.decide(duplicate).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        let held = a.requests.clone().acquire_many_owned(4096).await.unwrap();
        assert_eq!(
            service
                .decide(request("fixture-decision-credential"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        drop(held);
        a.healthy.store(false, std::sync::atomic::Ordering::Release);
        let reply = service
            .decide(request("fixture-decision-credential"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.verdict, 3);
        assert_eq!(reply.native_reason, 255);
        drop(service);
        a.healthy.store(true, std::sync::atomic::Ordering::Release);
        Arc::get_mut(&mut a).unwrap().kubernetes_owned = true;
        a.source_ready
            .store(true, std::sync::atomic::Ordering::Release);
        let document = a.view.load().document.clone();
        a.view.store(Arc::new(crate::View {
            compiled: document.policy.compile().unwrap(),
            document,
            source_expires: Some(std::time::Instant::now()),
        }));
        let reply = Service(a)
            .decide(request("fixture-decision-credential"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.verdict, 3);
        assert_eq!(reply.native_reason, 255);
    }
}
