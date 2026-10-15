//! Additional decision transport; all policy evaluation stays in Authority.
use crate::Authority;
use anyhow::Result;
pub use hangang_runtime::configuration;
use pumgye_grpc::v1::{
    DecisionReply, DecisionRequest,
    authorization_server::{Authorization, AuthorizationServer},
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::net::TcpListener;
use tonic::{Request, Response, Status, transport::ServerTlsConfig};

struct Service(Arc<Authority>);
impl Service {
    fn admission(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        let mut values = metadata.get_all("authorization").iter();
        let value = values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if values.next().is_some()
            || !value.is_some_and(|v| {
                crate::credential_matches(v.as_bytes(), self.0.decision.as_bytes())
            })
        {
            return Err(Status::unauthenticated("decision credential required"));
        }
        self.0
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("decision capacity"))
    }
}
#[tonic::async_trait]
impl
    pumgye_grpc::v1::authenticated_resource_authorization_server::AuthenticatedResourceAuthorization
    for Service
{
    async fn decide(
        &self,
        request: Request<pumgye_grpc::v1::AuthenticatedResourceRequest>,
    ) -> Result<Response<pumgye_grpc::v1::AuthenticatedResourceReply>, Status> {
        let _permit = self.admission(request.metadata())?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        if input.receipt.len() != hopae_grpc::receipt::LENGTH || input.request_sha256.len() != 32 {
            return Err(Status::invalid_argument("invalid receipt bounds"));
        }
        let ip = match input.ip.as_slice() {
            bytes if bytes.len() == 4 => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()))
            }
            bytes if bytes.len() == 16 => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
            }
            _ => return Err(Status::invalid_argument("invalid address size")),
        };
        let context = crate::authenticated_resource::ReceiptContext::from_wire(
            input
                .context
                .ok_or_else(|| Status::invalid_argument("receipt context required"))?,
        )
        .map_err(|_| Status::invalid_argument("invalid service context"))?;
        let query = crate::authenticated_resource::Query {
            route: input
                .route
                .map(|route| crate::authenticated_resource::RouteReference {
                    reference: route.reference,
                    destination_sha256: route.destination_sha256,
                }),
            request_id: input.request_id,
            minimum_revision: input.minimum_revision,
            ip,
            resource: input.resource,
            action: input.action,
            context,
            receipt: input.receipt,
            request_sha256: input.request_sha256,
        };
        let caller = || {
            let mut values = metadata.get_all("authorization").iter();
            let token = values
                .next()
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "));
            values.next().is_none()
                && token.is_some_and(|token| {
                    crate::credential_matches(token.as_bytes(), self.0.decision.as_bytes())
                })
        };
        let result = crate::authenticated_resource::evaluate(&self.0, query, &caller)
            .await
            .map_err(|status| match status {
                axum::http::StatusCode::BAD_REQUEST => {
                    Status::invalid_argument("invalid authenticated request")
                }
                axum::http::StatusCode::UNAUTHORIZED => {
                    Status::unauthenticated("decision credential required")
                }
                axum::http::StatusCode::FORBIDDEN => {
                    Status::permission_denied("authentication refused")
                }
                _ => Status::unavailable("native authority unavailable"),
            })?;
        Ok(Response::new(pumgye_grpc::v1::AuthenticatedResourceReply {
            route_observed: result.route_observed,
            request_id: input.request_id,
            revision: result.revision,
            network_revision: result.network_revision,
            verdict: if result.allow { 1 } else { 2 },
            cache_ttl_ms: 0,
        }))
    }
}
#[tonic::async_trait]
impl pumgye_grpc::v1::resource_authorization_server::ResourceAuthorization for Service {
    async fn decide(
        &self,
        request: Request<pumgye_grpc::v1::ResourceDecisionRequest>,
    ) -> Result<Response<pumgye_grpc::v1::ResourceDecisionReply>, Status> {
        let _permit = self.admission(request.metadata())?;
        let input = request.into_inner();
        let ip = match input.ip.as_slice() {
            bytes if bytes.len() == 4 => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()))
            }
            bytes if bytes.len() == 16 => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
            }
            _ => return Err(Status::invalid_argument("verified address required")),
        };
        let guard = match input.guard {
            1 => pumgye_core::GuardEvidence::EnforcedAllow,
            2 => pumgye_core::GuardEvidence::Deny,
            3 => pumgye_core::GuardEvidence::Observe,
            4 => pumgye_core::GuardEvidence::Unavailable,
            _ => return Err(Status::invalid_argument("guard evidence required")),
        };
        let aal =
            u8::try_from(input.aal).map_err(|_| Status::invalid_argument("invalid assurance"))?;
        let query = crate::ResourceEvaluation {
            service_id: &input.service_id,
            resource: &input.resource,
            action: &input.action,
            subject: &input.subject,
            ip,
            aal,
            guard,
            minimum_revision: input.minimum_revision,
        };
        if !query.valid() {
            return Err(Status::invalid_argument("invalid resource scope"));
        }
        let result = self.0.resource_decision(&query);
        let (revision, verdict, reason) = match result {
            Some((
                revision,
                pumgye_core::ResourceDecision::Decided(pumgye_core::Decision::Allow),
            )) => (revision, 1, "Allow".into()),
            Some((
                revision,
                pumgye_core::ResourceDecision::Decided(pumgye_core::Decision::GuardUnavailable),
            )) => (revision, 3, "GuardUnavailable".into()),
            Some((revision, pumgye_core::ResourceDecision::Decided(decision))) => {
                (revision, 2, format!("{decision:?}"))
            }
            Some((revision, other)) => (revision, 2, format!("{other:?}")),
            None => (
                self.0.view.load().document.revision,
                3,
                "Unavailable".into(),
            ),
        };
        Ok(Response::new(pumgye_grpc::v1::ResourceDecisionReply {
            request_id: input.request_id,
            revision,
            verdict,
            reason,
            cache_ttl_ms: 0,
        }))
    }
}
#[tonic::async_trait]
impl Authorization for Service {
    async fn decide(
        &self,
        request: Request<DecisionRequest>,
    ) -> Result<Response<DecisionReply>, Status> {
        let _permit = self.admission(request.metadata())?;
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
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let incoming = hangang_runtime::incoming(listener);
    hangang_runtime::server(tls)?
        .add_service(
            AuthorizationServer::new(Service(authority.clone()))
                .max_decoding_message_size(2048)
                .max_encoding_message_size(1024),
        )
        .add_service(
            pumgye_grpc::v1::resource_authorization_server::ResourceAuthorizationServer::new(
                Service(authority.clone()),
            )
            .max_decoding_message_size(2048)
            .max_encoding_message_size(1024),
        )
        .add_service(pumgye_grpc::v1::authenticated_resource_authorization_server::AuthenticatedResourceAuthorizationServer::new(Service(authority.clone())).max_decoding_message_size(4096).max_encoding_message_size(128))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn authenticated_admission_precedes_context_and_missing_resources_fail_closed() {
        use pumgye_grpc::v1::authenticated_resource_authorization_server::AuthenticatedResourceAuthorization;
        let root = tempfile::tempdir().unwrap();
        let owner = crate::tests::authority(root.path());
        let service = Service(owner.clone());
        let message = pumgye_grpc::v1::AuthenticatedResourceRequest {
            route: None,
            request_id: 1,
            minimum_revision: 1,
            ip: vec![192, 0, 2, 1],
            resource: "db:orders".into(),
            action: "select".into(),
            context: None,
            receipt: vec![0; 146],
            request_sha256: vec![3; 32],
        };
        let call = |token: &str, message| {
            let mut request = Request::new(message);
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            request
        };
        assert_eq!(
            AuthenticatedResourceAuthorization::decide(
                &service,
                call(&owner.admin, message.clone())
            )
            .await
            .err()
            .unwrap()
            .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            AuthenticatedResourceAuthorization::decide(
                &service,
                call(&owner.decision, message.clone())
            )
            .await
            .err()
            .unwrap()
            .code(),
            tonic::Code::InvalidArgument
        );
        let mut valid = message;
        valid.context = Some(hopae_grpc::v1::AuthenticationReceiptContext {
            issuer_ref: "hopae".into(),
            key_epoch: 1,
            identity_authority_epoch: "owned:service:1:app:1".into(),
            identity: Some(hopae_grpc::v1::ReceiptIdentity {
                subject_ref: "s_0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                kind: 2,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            }),
            service: "orders".into(),
            audience: "orders-api".into(),
            request_sha256: vec![3; 32],
        });
        assert_eq!(
            AuthenticatedResourceAuthorization::decide(&service, call(&owner.decision, valid))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::Unavailable
        );
    }
    #[tokio::test]
    async fn actual_resource_mtls_channel_tracks_catalog_changes_and_refuses_missing_certificate() {
        use pumgye_grpc::v1::{
            ResourceDecisionRequest, resource_authorization_client::ResourceAuthorizationClient,
        };
        use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
        let root = tempfile::tempdir().unwrap();
        let openssl = |args: &[&str]| {
            assert!(
                std::process::Command::new("openssl")
                    .args(args)
                    .current_dir(root.path())
                    .output()
                    .unwrap()
                    .status
                    .success()
            )
        };
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
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
        for (name, usage) in [("server", "serverAuth"), ("client", "clientAuth")] {
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let cert = format!("{name}.pem");
            let ext = format!("{name}.ext");
            openssl(&[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=owned",
                "-keyout",
                &key,
                "-out",
                &csr,
            ]);
            std::fs::write(root.path().join(&ext),format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:pumgye.example.test\n")).unwrap();
            openssl(&[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                &ext,
                "-out",
                &cert,
            ]);
        }
        let owner = crate::tests::authority(root.path());
        let document: crate::Document =
            serde_json::from_str(include_str!("../../../examples/resource-catalog.json")).unwrap();
        owner.view.store(Arc::new(crate::View {
            compiled: document.policy.compile().unwrap(),
            document: crate::Document {
                revision: 1,
                ..document
            },
            source_expires: None,
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = configuration(
            &root.path().join("server.pem"),
            &root.path().join("server.key"),
            &root.path().join("ca.pem"),
        )
        .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(serve(listener, tls, owner.clone(), async {
            let _ = stopped.await;
        }));
        let endpoint = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(2));
        let ca = Certificate::from_pem(std::fs::read(root.path().join("ca.pem")).unwrap());
        let tls = ClientTlsConfig::new()
            .domain_name("pumgye.example.test")
            .ca_certificate(ca.clone())
            .identity(Identity::from_pem(
                std::fs::read(root.path().join("client.pem")).unwrap(),
                std::fs::read(root.path().join("client.key")).unwrap(),
            ));
        let channel = endpoint
            .clone()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut authenticated = pumgye_grpc::v1::authenticated_resource_authorization_client::AuthenticatedResourceAuthorizationClient::new(channel.clone());
        let authenticated_request = |token: &str| {
            let mut request = Request::new(pumgye_grpc::v1::AuthenticatedResourceRequest {
                route: None,
                request_id: 43,
                minimum_revision: 1,
                ip: vec![192, 0, 2, 9],
                resource: "db:orders".into(),
                action: "select".into(),
                context: None,
                receipt: vec![0; 146],
                request_sha256: vec![3; 32],
            });
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            request
        };
        assert_eq!(
            authenticated
                .decide(authenticated_request(&owner.admin))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            authenticated
                .decide(authenticated_request(&owner.decision))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::InvalidArgument
        );
        let mut client = ResourceAuthorizationClient::new(channel);
        let request = |token: &str| {
            let mut request = Request::new(ResourceDecisionRequest {
                service_id: "orders".into(),
                request_id: 42,
                minimum_revision: 1,
                ip: vec![192, 0, 2, 9],
                aal: 2,
                guard: 1,
                resource: "db:orders".into(),
                action: "select".into(),
                subject: "fixture".into(),
            });
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            request
        };
        assert_eq!(
            client
                .decide(request(&owner.admin))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::Unauthenticated
        );
        let reply = client
            .decide(request(&owner.decision))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.verdict, 1);
        assert_eq!(reply.request_id, 42);
        assert_eq!(reply.cache_ttl_ms, 0);
        let mut document = owner.view.load().document.clone();
        document.revision = 2;
        document
            .policy
            .resources
            .get_mut("db:orders")
            .unwrap()
            .minimum_aal = 3;
        owner.view.store(Arc::new(crate::View {
            compiled: document.policy.compile().unwrap(),
            document,
            source_expires: None,
        }));
        let reply = client
            .decide(request(&owner.decision))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.revision, 2);
        assert_eq!(reply.verdict, 2);
        assert_eq!(reply.reason, "AssuranceDenied");
        let mut stronger = request(&owner.decision);
        stronger.get_mut().aal = 3;
        assert_eq!(
            client.decide(stronger).await.unwrap().into_inner().verdict,
            1
        );
        let tls = ClientTlsConfig::new()
            .domain_name("pumgye.example.test")
            .ca_certificate(ca);
        if let Ok(channel) = endpoint.tls_config(tls).unwrap().connect().await {
            assert!(
                ResourceAuthorizationClient::new(channel)
                    .decide(request(&owner.decision))
                    .await
                    .is_err()
            );
        }
        stop.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn resource_rpc_owns_class_and_shares_role_capacity_and_revision_fences() {
        use pumgye_grpc::v1::{
            ResourceDecisionRequest, resource_authorization_server::ResourceAuthorization,
        };
        let root = tempfile::tempdir().unwrap();
        let owner = crate::tests::authority(root.path());
        let document: crate::Document =
            serde_json::from_str(include_str!("../../../examples/resource-catalog.json")).unwrap();
        owner.view.store(Arc::new(crate::View {
            compiled: document.policy.compile().unwrap(),
            document: crate::Document {
                revision: 1,
                ..document
            },
            source_expires: None,
        }));
        let service = Service(owner.clone());
        let request = |token: &str| {
            let mut r = Request::new(ResourceDecisionRequest {
                service_id: "orders".into(),
                request_id: 42,
                minimum_revision: 1,
                ip: vec![192, 0, 2, 9],
                aal: 2,
                guard: 1,
                resource: "db:orders".into(),
                action: "select".into(),
                subject: "fixture".into(),
            });
            r.metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            r
        };
        assert_eq!(
            ResourceAuthorization::decide(&service, request(&owner.admin))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::Unauthenticated
        );
        let reply = ResourceAuthorization::decide(&service, request(&owner.decision))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.request_id, 42);
        assert_eq!(reply.verdict, 1);
        assert_eq!(reply.revision, 1);
        assert_eq!(reply.cache_ttl_ms, 0);
        let mut cross_service = request(&owner.decision);
        cross_service.get_mut().service_id = "billing".into();
        let reply = ResourceAuthorization::decide(&service, cross_service)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.verdict, 2);
        assert_eq!(reply.reason, "UnknownService");
        let mut weak = request(&owner.decision);
        weak.get_mut().aal = 1;
        let reply = ResourceAuthorization::decide(&service, weak)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.verdict, 2);
        assert_eq!(reply.reason, "AssuranceDenied");
        let mut missing = request(&owner.decision);
        missing.get_mut().ip.clear();
        assert_eq!(
            ResourceAuthorization::decide(&service, missing)
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::InvalidArgument
        );
        let mut stale = request(&owner.decision);
        stale.get_mut().minimum_revision = 2;
        assert_eq!(
            ResourceAuthorization::decide(&service, stale)
                .await
                .unwrap()
                .into_inner()
                .verdict,
            3
        );
        let mut observe = request(&owner.decision);
        observe.get_mut().guard = 3;
        assert_eq!(
            ResourceAuthorization::decide(&service, observe)
                .await
                .unwrap()
                .into_inner()
                .verdict,
            3
        );
        let held = owner
            .requests
            .clone()
            .acquire_many_owned(4096)
            .await
            .unwrap();
        assert_eq!(
            ResourceAuthorization::decide(&service, request(&owner.decision))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::ResourceExhausted
        );
        drop(held);
    }

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
