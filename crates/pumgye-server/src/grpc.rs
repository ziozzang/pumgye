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

#[derive(Clone)]
struct Service(Arc<Authority>);
impl Service {
    fn caller(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
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
        Ok(())
    }
    fn admission(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        self.caller(metadata)?;
        self.0
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("decision capacity"))
    }
}
fn authenticate_transport<S>(
    service: S,
    authority: Arc<Authority>,
) -> tonic::service::interceptor::InterceptedService<S, impl tonic::service::Interceptor + Clone> {
    let caller = Service(authority);
    tonic::service::interceptor::InterceptedService::new(service, move |request: Request<()>| {
        caller.caller(request.metadata())?;
        Ok(request)
    })
}
impl Service {
    async fn authenticated(
        &self,
        request: Request<pumgye_grpc::v1::AuthenticatedResourceRequest>,
        issue: bool,
    ) -> Result<crate::authenticated_resource::Outcome, Status> {
        let permit = self.admission(request.metadata())?;
        self.authenticated_admitted(request, issue, permit).await
    }
    async fn authenticated_admitted(
        &self,
        request: Request<pumgye_grpc::v1::AuthenticatedResourceRequest>,
        issue: bool,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<crate::authenticated_resource::Outcome, Status> {
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
        let result = crate::authenticated_resource::evaluate_mode(&self.0, query, &caller, issue)
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
        Ok(result)
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
        let result = self.authenticated(request, false).await?;
        Ok(Response::new(pumgye_grpc::v1::AuthenticatedResourceReply {
            route_observed: result.route_observed,
            request_id: result.request_id,
            revision: result.revision,
            network_revision: result.network_revision,
            verdict: if result.allow { 1 } else { 2 },
            cache_ttl_ms: 0,
        }))
    }
}
#[tonic::async_trait]
impl pumgye_grpc::v1::projection_permits_server::ProjectionPermits for Service {
    async fn validate(
        &self,
        request: Request<pumgye_grpc::v1::PermitValidationRequest>,
    ) -> Result<Response<pumgye_grpc::v1::PermitValidationReply>, Status> {
        let admission = self.admission(request.metadata())?;
        let metadata = request.metadata().clone();
        let input = request.into_inner();
        if !(1..=9_007_199_254_740_991).contains(&input.request_id) {
            return Err(Status::invalid_argument("invalid validation correlation"));
        }
        let native = input
            .request
            .ok_or_else(|| Status::invalid_argument("native request required"))?;
        let wire = input
            .permit
            .ok_or_else(|| Status::invalid_argument("permit required"))?;
        if self.0.route_live.is_none() || self.0.projection_live.is_none() || native.route.is_none()
        {
            return Err(Status::unavailable("native permit owners required"));
        }
        let signer = self
            .0
            .permit_signer
            .as_ref()
            .ok_or_else(|| Status::unavailable("native signer unavailable"))?;
        let view = self.0.view.load_full();
        let checked = pumgye_server::permit_wire::verify(
            signer,
            &self.0.authority_epoch,
            &native,
            &wire,
            crate::authenticated_resource::now(),
        )
        .map_err(|_| Status::permission_denied("permit refused"))?;
        let mut native = Request::new(native);
        *native.metadata_mut() = metadata;
        let outcome = self
            .authenticated_admitted(native, false, admission)
            .await?;
        let owners = outcome
            .owners
            .ok_or_else(|| Status::unavailable("native owners unavailable"))?;
        let now = crate::authenticated_resource::now();
        if !outcome.allow
            || checked.revisions()
                != (
                    outcome.revision,
                    outcome.network_revision,
                    owners.route_revision,
                    owners.plan_revision,
                )
        {
            return Err(Status::permission_denied("permit owner state retired"));
        }
        if !checked.valid_at(now)
            || now >= owners.expires_ms
            || !self.0.healthy.load(std::sync::atomic::Ordering::Acquire)
            || !Arc::ptr_eq(&view, &self.0.view.load_full())
            || (self.0.kubernetes_owned
                && (!self
                    .0
                    .source_ready
                    .load(std::sync::atomic::Ordering::Acquire)
                    || view
                        .source_expires
                        .is_none_or(|expires| std::time::Instant::now() >= expires)))
        {
            return Err(Status::unavailable("permit validation expired or retired"));
        }
        Ok(Response::new(pumgye_grpc::v1::PermitValidationReply {
            request_id: input.request_id,
            expires_ms: checked.expires_ms().min(owners.expires_ms),
            cache_ttl_ms: 0,
        }))
    }

    async fn issue(
        &self,
        request: Request<pumgye_grpc::v1::AuthenticatedResourceRequest>,
    ) -> Result<Response<pumgye_grpc::v1::ProjectionPermitReply>, Status> {
        let result = self.authenticated(request, true).await?;
        result
            .permit
            .map(Response::new)
            .ok_or_else(|| Status::unavailable("native permit unavailable"))
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
        .add_service(authenticate_transport(
            AuthorizationServer::new(Service(authority.clone()))
                .max_decoding_message_size(2048)
                .max_encoding_message_size(1024),
            authority.clone(),
        ))
        .add_service(authenticate_transport(
            pumgye_grpc::v1::resource_authorization_server::ResourceAuthorizationServer::new(
                Service(authority.clone()),
            )
            .max_decoding_message_size(2048)
            .max_encoding_message_size(1024),
            authority.clone(),
        ))
        .add_service(authenticate_transport(pumgye_grpc::v1::authenticated_resource_authorization_server::AuthenticatedResourceAuthorizationServer::new(Service(authority.clone())).max_decoding_message_size(4096).max_encoding_message_size(128), authority.clone()))
        .add_service(authenticate_transport(pumgye_grpc::v1::projection_permits_server::ProjectionPermitsServer::new(Service(authority.clone())).max_decoding_message_size(8192).max_encoding_message_size(2048), authority))
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
        use pumgye_grpc::v1::projection_permits_server::ProjectionPermits;
        assert_eq!(
            ProjectionPermits::issue(&service, call(&owner.admin, message.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            ProjectionPermits::issue(&service, call(&owner.decision, message.clone()))
                .await
                .unwrap_err()
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
            AuthenticatedResourceAuthorization::decide(
                &service,
                call(&owner.decision, valid.clone())
            )
            .await
            .err()
            .unwrap()
            .code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            ProjectionPermits::issue(&service, call(&owner.decision, valid))
                .await
                .unwrap_err()
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
        let mut permits = pumgye_grpc::v1::projection_permits_client::ProjectionPermitsClient::new(
            channel.clone(),
        );
        let validation = |token: &str| {
            let mut request = Request::new(pumgye_grpc::v1::PermitValidationRequest {
                request_id: 92,
                request: None,
                permit: None,
            });
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            request
        };
        assert_eq!(
            permits
                .validate(validation(&owner.admin))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            permits
                .validate(validation(&owner.decision))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            permits
                .issue(authenticated_request(&owner.admin))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            permits
                .issue(authenticated_request(&owner.decision))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let mut missing = authenticated_request(&owner.decision);
        missing.get_mut().context = Some(hopae_grpc::v1::AuthenticationReceiptContext {
            issuer_ref: "hopae".into(),
            key_epoch: 1,
            identity_authority_epoch: "owned-epoch".into(),
            identity: Some(hopae_grpc::v1::ReceiptIdentity {
                subject_ref: "s_owned".into(),
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
            permits.issue(missing).await.unwrap_err().code(),
            tonic::Code::Unavailable
        );
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

    use axum::{
        body::{Body, Bytes},
        http,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    struct PredecodeStream {
        polls: Arc<AtomicUsize>,
        forbid_poll: bool,
        chunks: std::collections::VecDeque<Bytes>,
    }
    impl tonic::codegen::tokio_stream::Stream for PredecodeStream {
        type Item = Result<Bytes, std::io::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.forbid_poll,
                "unauthenticated protobuf body was polled"
            );
            std::task::Poll::Ready(self.chunks.pop_front().map(Ok))
        }
    }
    fn predecode_body(chunks: Vec<Bytes>, forbid_poll: bool) -> (Body, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        (
            Body::from_stream(PredecodeStream {
                polls: polls.clone(),
                forbid_poll,
                chunks: chunks.into(),
            }),
            polls,
        )
    }
    fn predecode_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }
    fn predecode_request(path: &str, credentials: &[&str], body: Body) -> http::Request<Body> {
        let mut request = http::Request::builder()
            .method("POST")
            .version(http::Version::HTTP_2)
            .uri(path)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(body)
            .unwrap();
        for credential in credentials {
            request
                .headers_mut()
                .append("authorization", credential.parse().unwrap());
        }
        request
    }
    async fn predecode_response<B>(response: http::Response<B>) -> (u16, Vec<u8>)
    where
        B: tonic::codegen::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut status = response
            .headers()
            .get("grpc-status")
            .map(|v| v.to_str().unwrap().parse::<u16>().unwrap());
        let mut body = response.into_body();
        let mut data = Vec::new();
        while let Some(frame) =
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
        {
            match frame.unwrap().into_data() {
                Ok(bytes) => data.extend_from_slice(&bytes),
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers()
                        && let Some(value) = trailers.get("grpc-status")
                    {
                        status = Some(value.to_str().unwrap().parse::<u16>().unwrap());
                    }
                }
            }
        }
        (status.expect("gRPC status"), data)
    }

    fn predecode_service(
        owner: Arc<Authority>,
        kind: usize,
    ) -> tower::util::BoxCloneService<
        http::Request<Body>,
        http::Response<Body>,
        std::convert::Infallible,
    > {
        macro_rules! wrap {
            ($server:expr) => {
                tower::util::BoxCloneService::new(
                    tower::ServiceExt::<http::Request<Body>>::map_response(
                        authenticate_transport($server, owner.clone()),
                        |response| response.map(Body::new),
                    ),
                )
            };
        }
        match kind {
                0 => wrap!(AuthorizationServer::new(Service(owner.clone())).max_decoding_message_size(2048).max_encoding_message_size(1024)),
                1 => wrap!(pumgye_grpc::v1::resource_authorization_server::ResourceAuthorizationServer::new(Service(owner.clone())).max_decoding_message_size(2048).max_encoding_message_size(1024)),
                2 => wrap!(pumgye_grpc::v1::authenticated_resource_authorization_server::AuthenticatedResourceAuthorizationServer::new(Service(owner.clone())).max_decoding_message_size(4096).max_encoding_message_size(128)),
                3 => wrap!(pumgye_grpc::v1::projection_permits_server::ProjectionPermitsServer::new(Service(owner.clone())).max_decoding_message_size(8192).max_encoding_message_size(2048)),
                _ => panic!("unknown test service"),
            }
    }
    const PREDECODE_METHODS: &[(usize, &str, usize)] = &[
        (0, "/hangang.pumgye.v1.Authorization/Decide", 2048),
        (1, "/hangang.pumgye.v1.ResourceAuthorization/Decide", 2048),
        (
            2,
            "/hangang.pumgye.v1.AuthenticatedResourceAuthorization/Decide",
            4096,
        ),
        (3, "/hangang.pumgye.v1.ProjectionPermits/Issue", 8192),
        (3, "/hangang.pumgye.v1.ProjectionPermits/Validate", 8192),
    ];
    #[tokio::test]
    async fn predecode_auth_rejects_missing_wrong_role_and_duplicate_headers_before_body() {
        let root = tempfile::tempdir().unwrap();
        let owner = crate::tests::authority(root.path());
        for &(kind, path, _) in PREDECODE_METHODS {
            for credentials in [
                vec![],
                vec!["Bearer incorrect"],
                vec!["Bearer fixture-admin-credential"],
                vec!["Bearer fixture-decision-credential", "Bearer incorrect"],
                vec!["Bearer incorrect", "Bearer fixture-decision-credential"],
                vec![
                    "Bearer fixture-decision-credential",
                    "Bearer fixture-decision-credential",
                ],
            ] {
                let (body, polls) = predecode_body(vec![Bytes::from_static(&[255; 5])], true);
                let response = predecode_service(owner.clone(), kind)
                    .oneshot(predecode_request(path, &credentials, body))
                    .await
                    .unwrap();
                let (status, data) = predecode_response(response).await;
                assert_eq!(status, tonic::Code::Unauthenticated as u16, "{path}");
                assert!(data.is_empty());
                assert_eq!(polls.load(Ordering::SeqCst), 0);
                assert_eq!(owner.queries.load(Ordering::SeqCst), 0);
                assert_eq!(owner.requests.available_permits(), 4096);
            }
        }
    }
    #[tokio::test]
    async fn predecode_auth_preserves_decoding_and_real_decision_execution() {
        let root = tempfile::tempdir().unwrap();
        let owner = crate::tests::authority(root.path());
        // Canonical DecisionRequest protobuf: id=7, ip=192.0.2.8, aal=1,
        // enforced allow evidence, orders/fixture/read/public, minimum=0.
        let payload = b"\x08\x07\x1a\x04\xc0\x00\x02\x08\x20\x01\x28\x01\x32\x06orders\x3a\x07fixture\x42\x04read\x4a\x06public";
        let frame = predecode_frame(payload);
        let (body, polls) = predecode_body(
            vec![
                Bytes::copy_from_slice(&frame[..2]),
                Bytes::copy_from_slice(&frame[2..5]),
                Bytes::copy_from_slice(&frame[5..]),
            ],
            false,
        );
        let response = predecode_service(owner.clone(), 0)
            .oneshot(predecode_request(
                PREDECODE_METHODS[0].1,
                &["Bearer fixture-decision-credential"],
                body,
            ))
            .await
            .unwrap();
        let (status, data) = predecode_response(response).await;
        assert_eq!(status, tonic::Code::Ok as u16);
        // The fixture's revision-one catalog denies the unknown service:
        // request_id=7, revision=1, verdict=2, native_reason=1, cache_ttl=0.
        assert_eq!(data, predecode_frame(b"\x08\x07\x10\x01\x18\x02\x20\x01"));
        assert_eq!(owner.queries.load(Ordering::SeqCst), 1);
        assert!(polls.load(Ordering::SeqCst) >= 3);
        assert_eq!(owner.requests.available_permits(), 4096);
    }
    #[tokio::test]
    async fn predecode_auth_preserves_each_generated_service_message_cap() {
        let root = tempfile::tempdir().unwrap();
        let owner = crate::tests::authority(root.path());
        for &(kind, path, limit) in PREDECODE_METHODS {
            let mut prefix = vec![0];
            prefix.extend_from_slice(&u32::try_from(limit + 1).unwrap().to_be_bytes());
            let (body, polls) = predecode_body(vec![Bytes::from(prefix)], false);
            let response = predecode_service(owner.clone(), kind)
                .oneshot(predecode_request(
                    path,
                    &["Bearer fixture-decision-credential"],
                    body,
                ))
                .await
                .unwrap();
            let (status, data) = predecode_response(response).await;
            assert_eq!(status, tonic::Code::OutOfRange as u16, "{path}");
            assert!(data.is_empty());
            assert!(polls.load(Ordering::SeqCst) > 0);
            assert_eq!(owner.queries.load(Ordering::SeqCst), 0);
            assert_eq!(owner.requests.available_permits(), 4096);
        }
    }
}
