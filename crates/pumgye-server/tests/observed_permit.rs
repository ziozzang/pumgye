#![cfg(feature = "observed-authentication")]
use base64::{Engine, engine::general_purpose::STANDARD};
use hopae_grpc::{
    PrincipalKind,
    observed_client::{EndpointConfig, Limits},
    receipt, receipt_binding,
    receipt_time::ClockRates,
    service_epoch, v1,
};
use pumgye_server::{
    authentication_config::{Document, Entry, Trust},
    authentication_observed::{AuthenticationOwnerGeneration, Configuration, OwnerSlot},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};
use tonic::{Request, Response, Status};
const CALLER: &str = "pumgye-native-test-caller-at-least-thirty-two-bytes";
fn context(subject: char, revision: u64) -> v1::AuthenticationReceiptContext {
    v1::AuthenticationReceiptContext {
        issuer_ref: "issuer".into(),
        key_epoch: 1,
        identity_authority_epoch: service_epoch::encode_clock(
            "owner",
            revision,
            9,
            "11111111111111111111111111111111",
        )
        .unwrap(),
        identity: Some(v1::ReceiptIdentity {
            subject_ref: format!("s_{}", subject.to_string().repeat(48)),
            kind: 2,
            aal: 0,
            revision,
            credential_generation: revision,
        }),
        service: "orders".into(),
        audience: "api".into(),
        request_sha256: vec![5; 32],
    }
}
fn binding(c: &v1::AuthenticationReceiptContext) -> [u8; 32] {
    let i = c.identity.as_ref().unwrap();
    receipt_binding::digest(
        &receipt_binding::Context {
            issuer_ref: &c.issuer_ref,
            key_epoch: c.key_epoch,
            identity_authority_epoch: &c.identity_authority_epoch,
            identity: receipt_binding::Identity {
                subject_ref: &i.subject_ref,
                kind: PrincipalKind::Service,
                aal: 0,
                revision: i.revision,
                credential_generation: i.credential_generation,
            },
            service: &c.service,
            audience: &c.audience,
            request_sha256: c.request_sha256.as_slice().try_into().unwrap(),
        },
        None,
    )
    .unwrap()
}
fn signed(c: &v1::AuthenticationReceiptContext) -> Vec<u8> {
    receipt::sign(
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        &receipt::Claims {
            purpose: receipt::Purpose::Authentication,
            issued_ms: 1_000_000,
            expires_ms: 1_001_000,
            binding: binding(c),
            nonce: [3; 32],
        },
    )
    .unwrap()
    .to_vec()
}
struct Peer {
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicU64>,
    strict_calls: Arc<AtomicU64>,
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}
#[tonic::async_trait]
impl v1::authentication_receipts_server::AuthenticationReceipts for Peer {
    async fn issue_service(
        &self,
        _: Request<v1::ServiceReceiptRequest>,
    ) -> Result<Response<v1::ServiceReceiptReply>, Status> {
        self.strict_calls.fetch_add(1, Ordering::AcqRel);
        Err(Status::permission_denied("strict path must remain unused"))
    }
    async fn validate_service(
        &self,
        _: Request<v1::ServiceReceiptValidationRequest>,
    ) -> Result<Response<v1::ServiceReceiptValidationReply>, Status> {
        self.strict_calls.fetch_add(1, Ordering::AcqRel);
        Err(Status::permission_denied("strict path must remain unused"))
    }
    async fn issue_service_observed(
        &self,
        _: Request<v1::ServiceReceiptRequest>,
    ) -> Result<Response<v1::ServiceReceiptObservedReply>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn observe_service_time(
        &self,
        request: Request<v1::ServiceReceiptValidationRequest>,
    ) -> Result<Response<v1::ServiceReceiptTimeReply>, Status> {
        use sha2::{Digest, Sha256};
        assert_eq!(
            request
                .metadata()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("Bearer {CALLER}")
        );
        self.calls.fetch_add(1, Ordering::AcqRel);
        let q = request.into_inner();
        let c = q.context.unwrap();
        let i = c.identity.as_ref().unwrap();
        receipt::verify_signature(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
            &q.receipt,
            receipt::Purpose::Authentication,
            &binding(&c),
        )
        .unwrap();
        let mode = self.mode.load(Ordering::Acquire);
        if mode == 1 {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        if mode == 2 {
            return Err(Status::unimplemented("observed peer unavailable"));
        }
        Ok(Response::new(v1::ServiceReceiptTimeReply {
            request_id: q.request_id,
            owner_now_ms: 1_000_100,
            remaining_ms: if mode == 3 { 40 } else { 700 },
            receipt_sha256: Sha256::digest(q.receipt).to_vec(),
            clock_domain: service_epoch::decode_clock(&c.identity_authority_epoch)
                .unwrap()
                .clock_domain
                .into(),
            profile_revision: i.revision,
            application_generation: 9,
            key_registry_revision: 1,
            cache_ttl_ms: 0,
        }))
    }
}

#[derive(Clone)]
struct NativePeer {
    mode: Arc<AtomicU8>,
    route_calls: Arc<AtomicU64>,
}
#[tonic::async_trait]
impl guard_grpc::v1::network_server::Network for NativePeer {
    async fn check(
        &self,
        q: Request<guard_grpc::v1::NetworkRequest>,
    ) -> Result<Response<guard_grpc::v1::NetworkReply>, Status> {
        let q = q.into_inner();
        Ok(Response::new(guard_grpc::v1::NetworkReply {
            request_id: q.request_id,
            revision: 3,
            verdict: if self.mode.load(Ordering::Acquire) == 1 {
                2
            } else {
                1
            },
            mode: 2,
            ttl_ms: 1000,
        }))
    }
}
#[tonic::async_trait]
impl hangang_route_grpc::v1::route_ownership_server::RouteOwnership for NativePeer {
    async fn observe(
        &self,
        q: Request<hangang_route_grpc::v1::RouteRequest>,
    ) -> Result<Response<hangang_route_grpc::v1::RouteReply>, Status> {
        let q = q.into_inner();
        let n = self.route_calls.fetch_add(1, Ordering::AcqRel) + 1;
        // A third query is the post-sign boundary.
        let changed = self.mode.load(Ordering::Acquire) == 2 && n.is_multiple_of(3);
        Ok(Response::new(hangang_route_grpc::v1::RouteReply {
            request_id: q.request_id,
            route_id: "orders".into(),
            configuration_revision: if changed { 5 } else { 4 },
            service: "orders".into(),
            audience: "api".into(),
            resource: "db:orders".into(),
            action: "select".into(),
            client_ip: vec![192, 0, 2, 9],
            request_sha256: q.request_sha256,
            destination_sha256: q.destination_sha256,
            remaining_ms: 1000,
        }))
    }
}
#[tonic::async_trait]
impl v1::projection_plans_server::ProjectionPlans for NativePeer {
    async fn observe(
        &self,
        q: Request<v1::ProjectionPlanRequest>,
    ) -> Result<Response<v1::ProjectionPlanReply>, Status> {
        let q = q.into_inner();
        Ok(Response::new(v1::ProjectionPlanReply {
            request_id: q.request_id,
            revision: 5,
            service: q.service,
            audience: q.audience,
            resource: "db:orders".into(),
            action: "select".into(),
            minimum_aal: 0,
            cache_ttl_ms: 0,
        }))
    }
}
struct PolicyPublication {
    compiled: pumgye_core::CompiledPolicy,
    revision: u64,
}
struct PolicyOwner(Arc<arc_swap::ArcSwap<PolicyPublication>>);
struct PolicySnapshot {
    owner: Arc<arc_swap::ArcSwap<PolicyPublication>>,
    view: Arc<PolicyPublication>,
}
impl pumgye_server::observed_permit::NativePolicySource for PolicyOwner {
    fn capture(
        &self,
    ) -> Result<Arc<dyn pumgye_server::observed_permit::NativePolicySnapshot>, Status> {
        Ok(Arc::new(PolicySnapshot {
            owner: self.0.clone(),
            view: self.0.load_full(),
        }))
    }
}
impl pumgye_server::observed_permit::NativePolicySnapshot for PolicySnapshot {
    fn compiled(&self) -> &pumgye_core::CompiledPolicy {
        &self.view.compiled
    }
    fn revision(&self) -> u64 {
        self.view.revision
    }
    fn current(&self) -> bool {
        Arc::ptr_eq(&self.view, &self.owner.load_full())
    }
    fn remaining(&self) -> Result<Duration, Status> {
        Ok(Duration::from_millis(1000))
    }
}
fn policy() -> Arc<PolicyPublication> {
    let subject = context('a', 7).identity.unwrap().subject_ref;
    let mut value = serde_json::json!({"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"require_guard":true,"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":0}},"users":{},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"}}}});
    value["services"]["orders"]["users"][subject] = serde_json::json!(["reader"]);
    Arc::new(PolicyPublication {
        compiled: serde_json::from_value::<pumgye_core::Policy>(value)
            .unwrap()
            .compile()
            .unwrap(),
        revision: 2,
    })
}
#[tokio::test]
async fn actual_native_owners_issue_observe_and_postsign_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let openssl = |args: &[&str]| {
        assert!(
            std::process::Command::new("openssl")
                .args(args)
                .current_dir(dir.path())
                .output()
                .unwrap()
                .status
                .success()
        );
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
        "/CN=test-ca",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    ]);
    for (name, usage) in [("server", "serverAuth"), ("client", "clientAuth")] {
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=test",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
        ]);
        std::fs::write(dir.path().join(format!("{name}.ext")), format!("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:hopae.test\n")).unwrap();
        openssl(&[
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
    let read = |name: &str| std::fs::read(dir.path().join(name)).unwrap();
    let ca = read("ca.pem");
    let cert = read("client.pem");
    let key = read("client.key");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("https://{}", listener.local_addr().unwrap());
    let mode = Arc::new(AtomicU8::new(0));
    let calls = Arc::new(AtomicU64::new(0));
    let strict_calls = Arc::new(AtomicU64::new(0));
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            read("server.pem"),
            read("server.key"),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(&ca));
    let native_mode = Arc::new(AtomicU8::new(0));
    let route_calls = Arc::new(AtomicU64::new(0));
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(
                v1::authentication_receipts_server::AuthenticationReceiptsServer::new(Peer {
                    mode: mode.clone(),
                    calls: calls.clone(),
                    strict_calls: strict_calls.clone(),
                    entered: entered.clone(),
                    release: release.clone(),
                }),
            )
            .add_service(guard_grpc::v1::network_server::NetworkServer::new(
                NativePeer {
                    mode: native_mode.clone(),
                    route_calls: route_calls.clone(),
                },
            ))
            .add_service(
                hangang_route_grpc::v1::route_ownership_server::RouteOwnershipServer::new(
                    NativePeer {
                        mode: native_mode.clone(),
                        route_calls: route_calls.clone(),
                    },
                ),
            )
            .add_service(v1::projection_plans_server::ProjectionPlansServer::new(
                NativePeer {
                    mode: native_mode.clone(),
                    route_calls: route_calls.clone(),
                },
            ))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );

    let trust = Arc::new(
        Trust::compile(Document {
            entries: vec![Entry {
                issuer_ref: "issuer".into(),
                key_epoch: 1,
                identity_epoch: "owner".into(),
                service: "orders".into(),
                audience: "api".into(),
                minimum_revision: 7,
                public_key: STANDARD.encode(
                    ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
            }],
        })
        .unwrap(),
    );
    let auth = AuthenticationOwnerGeneration::new(
        trust,
        Configuration {
            issuer_ref: "issuer",
            minimum_application_generation: 1,
            minimum_key_registry_revision: 1,
            endpoint: EndpointConfig {
                address: &address,
                server_name: "hopae.test",
                ca: &ca,
                certificate: &cert,
                private_key: &key,
                caller_key: CALLER,
            },
        },
        Arc::new(hangang_runtime::time::ReceiverClock::new([7; 16]).unwrap()),
        ClockRates::new(50, 50).unwrap(),
        Limits {
            concurrent: 4,
            timeout: Duration::from_millis(500),
        },
    )
    .unwrap();
    let slot = Arc::new(OwnerSlot::default());
    slot.replace(Some(auth)).unwrap();
    let network = pumgye_server::network_live::Client::connect(
        &address,
        "hopae.test",
        &ca,
        &cert,
        &key,
        CALLER,
    )
    .await
    .unwrap();
    let route = pumgye_server::route_live::Client::prepare(
        &address,
        "hopae.test",
        &ca,
        &cert,
        &key,
        CALLER,
    )
    .unwrap();
    let plan =
        pumgye_server::plan_live::Client::prepare(&address, "hopae.test", &ca, &cert, &key, CALLER)
            .unwrap();
    let signer = pumgye_server::permit::Signer::new(
        "pumgye".into(),
        1,
        ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
    )
    .unwrap();
    let publication = Arc::new(PolicyOwner(Arc::new(arc_swap::ArcSwap::from(policy()))));
    let owner = pumgye_server::observed_permit::Service::from_native(
        pumgye_server::observed_permit::Owners {
            authentication: slot,
            network: Arc::new(network),
            route: Arc::new(route),
            plan: Arc::new(plan),
        },
        Arc::new(signer),
        publication.clone(),
        "policy",
        ClockRates::new(50, 75).unwrap(),
    )
    .unwrap();
    let c = context('a', 7);
    let q = pumgye_grpc::v1::AuthenticatedResourceRequest {
        request_id: 19,
        minimum_revision: 2,
        ip: vec![192, 0, 2, 9],
        resource: "db:orders".into(),
        action: "select".into(),
        receipt: signed(&c),
        context: Some(c),
        request_sha256: vec![5; 32],
        route: Some(pumgye_grpc::v1::NativeRouteReference {
            reference: vec![1; 32],
            destination_sha256: vec![2; 32],
        }),
    };
    // Generated protocol over actual mTLS, including enforcement authentication.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let permit_address = format!("https://{}", listener.local_addr().unwrap());
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            read("server.pem"),
            read("server.key"),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(&ca));
    let grpc =
        pumgye_server::observed_permit::GrpcService::new(owner.clone(), CALLER.into()).unwrap();
    let permit_server = tokio::spawn(tonic::transport::Server::builder().tls_config(tls).unwrap()
        .add_service(pumgye_grpc::v1::observed_projection_permits_server::ObservedProjectionPermitsServer::new(grpc).max_decoding_message_size(8192).max_encoding_message_size(3072))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)));
    let channel = tonic::transport::Endpoint::from_shared(permit_address)
        .unwrap()
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name("hopae.test")
                .ca_certificate(tonic::transport::Certificate::from_pem(&ca))
                .identity(tonic::transport::Identity::from_pem(&cert, &key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc =
        pumgye_grpc::v1::observed_projection_permits_client::ObservedProjectionPermitsClient::new(
            channel,
        );
    assert_eq!(
        grpc.issue(Request::new(q.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    let mut rpc = Request::new(q.clone());
    rpc.metadata_mut()
        .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
    let rpc_issued = grpc.issue(rpc).await.unwrap().into_inner();
    assert_eq!(rpc_issued.observation.as_ref().unwrap().request_id, 19);
    let mut rpc = Request::new(pumgye_grpc::v1::PermitValidationRequest {
        request_id: 81,
        request: Some(q.clone()),
        permit: rpc_issued.permit,
    });
    rpc.metadata_mut()
        .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
    assert_eq!(grpc.observe(rpc).await.unwrap().into_inner().request_id, 81);
    calls.store(0, Ordering::Release);
    route_calls.store(0, Ordering::Release);
    let issued = owner.issue(q.clone(), &|| true).await.unwrap();
    assert_eq!(calls.load(Ordering::Acquire), 3);
    assert_eq!(route_calls.load(Ordering::Acquire), 3);
    assert_eq!(strict_calls.load(Ordering::Acquire), 0);
    let wire = issued.permit.unwrap();
    let report = issued.observation.unwrap();
    assert_eq!(
        wire.binding.as_ref().unwrap().authority_epoch,
        owner.clock_domain()
    );
    assert_eq!(report.clock_domain, owner.clock_domain());
    assert!(report.clock_domain.starts_with("pobs1:"));
    assert!(report.owner_now_ms < 1_000_000); // independent auth clock, never fake UTC
    assert!(report.remaining_ms > 0 && report.remaining_ms <= report.proof_remaining_ms);
    assert!(report.proof_remaining_ms <= 700);
    let claims = receipt::verify_signature(
        &ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key(),
        &wire.receipt,
        receipt::Purpose::Permit,
        &{
            let c = wire.context.as_ref().unwrap();
            let i = c.identity.as_ref().unwrap();
            let p = wire.binding.as_ref().unwrap();
            receipt_binding::digest(
                &receipt_binding::Context {
                    issuer_ref: &c.issuer_ref,
                    key_epoch: c.key_epoch,
                    identity_authority_epoch: &c.identity_authority_epoch,
                    identity: receipt_binding::Identity {
                        subject_ref: &i.subject_ref,
                        kind: PrincipalKind::Service,
                        aal: 0,
                        revision: i.revision,
                        credential_generation: i.credential_generation,
                    },
                    service: &c.service,
                    audience: &c.audience,
                    request_sha256: [5; 32],
                },
                Some(&receipt_binding::Permit {
                    authentication_receipt_sha256: p
                        .authentication_receipt_sha256
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    decision_ref: &p.decision_ref,
                    resource: &p.resource,
                    action: &p.action,
                    authority_epoch: &p.authority_epoch,
                    catalog_revision: p.catalog_revision,
                    policy_revision: p.policy_revision,
                    network_revision: p.network_revision,
                    route_revision: p.route_revision,
                    plan_revision: p.plan_revision,
                }),
            )
            .unwrap()
        },
    )
    .unwrap();
    assert!(claims.claims().issued_ms < 1_000_000);
    let validated = owner
        .observe(
            pumgye_grpc::v1::PermitValidationRequest {
                request_id: 55,
                request: Some(q.clone()),
                permit: Some(wire.clone()),
            },
            &|| true,
        )
        .await
        .unwrap();
    assert_eq!(validated.request_id, 55);
    assert!(validated.proof_remaining_ms <= report.proof_remaining_ms);
    let mut changed = wire.clone();
    changed.binding.as_mut().unwrap().authority_epoch =
        "pobs1:22222222222222222222222222222222:policy".into();
    assert!(
        owner
            .observe(
                pumgye_grpc::v1::PermitValidationRequest {
                    request_id: 56,
                    request: Some(q.clone()),
                    permit: Some(changed)
                },
                &|| true
            )
            .await
            .is_err()
    );
    assert!(owner.issue(q.clone(), &|| false).await.is_err());
    native_mode.store(1, Ordering::Release);
    assert!(owner.issue(q.clone(), &|| true).await.is_err());
    native_mode.store(2, Ordering::Release);
    route_calls.store(0, Ordering::Release);
    assert!(owner.issue(q.clone(), &|| true).await.is_err());
    assert_eq!(route_calls.load(Ordering::Acquire), 3);
    native_mode.store(0, Ordering::Release);
    // Policy publication can be synchronously replaced in a callback; no lock is
    // held across it, and the exact captured generation must refuse immediately.
    let callbacks = AtomicU64::new(0);
    owner
        .issue(q.clone(), &|| {
            callbacks.fetch_add(1, Ordering::AcqRel);
            true
        })
        .await
        .unwrap();
    let total = callbacks.load(Ordering::Acquire);
    for boundary in [1, total / 2, total - 1, total] {
        callbacks.store(0, Ordering::Release);
        assert!(
            owner
                .issue(q.clone(), &|| {
                    if callbacks.fetch_add(1, Ordering::AcqRel) + 1 == boundary {
                        publication.0.store(policy());
                    }
                    true
                })
                .await
                .is_err(),
            "callback boundary {boundary}/{total}"
        );
    }
    callbacks.store(0, Ordering::Release);
    assert!(
        owner
            .issue(q.clone(), &|| {
                if callbacks.fetch_add(1, Ordering::AcqRel) + 1 == total {
                    std::thread::sleep(Duration::from_millis(750));
                }
                true
            })
            .await
            .is_err()
    );
    owner.retire();
    assert!(owner.issue(q, &|| true).await.is_err());
    permit_server.abort();
    server.abort();
}
