#![cfg(all(feature = "observed-authentication", target_os = "linux"))]
// STRUCTURAL native Pum Service/core execution + real TLS/public opaque SDK.
// Hop peer signs fixture metadata; NOT actual Engine/TOTP or full H3 qualification.
// The compiled Pum fixture exercises its actual Authority bridge and mounted Human RPC.
// Real Hop native authentication is covered only by the separately invoked external runtime gate.
use base64::{Engine, engine::general_purpose::STANDARD};
use hopae_grpc::{
    PrincipalKind, human_epoch,
    human_observed_client::{EndpointConfig, Limits},
    receipt, receipt_binding,
    receipt_time::ClockRates,
    v1,
};
use pumgye_server::{
    authentication_config::{Document, Entry, Trust},
    authentication_human_observed::{AuthenticationOwnerGeneration, Configuration, OwnerSlot},
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
        identity_authority_epoch: human_epoch::encode(
            "owner",
            revision,
            9,
            "11111111111111111111111111111111",
        )
        .unwrap(),
        identity: Some(v1::ReceiptIdentity {
            subject_ref: format!("human1:{}", subject.to_string().repeat(64)),
            kind: 1,
            aal: 1,
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
                kind: PrincipalKind::Human,
                aal: i.aal as u8,
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
impl v1::human_authentication_receipts_server::HumanAuthenticationReceipts for Peer {
    async fn issue_observed(
        &self,
        _: Request<v1::HumanReceiptRequest>,
    ) -> Result<Response<v1::HumanReceiptObservedReply>, Status> {
        self.strict_calls.fetch_add(1, Ordering::AcqRel);
        Err(Status::unimplemented("issue not used by Pum observer"))
    }
    async fn observe_time(
        &self,
        request: Request<v1::HumanReceiptObservationRequest>,
    ) -> Result<Response<v1::HumanReceiptTimeReply>, Status> {
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
        Ok(Response::new(v1::HumanReceiptTimeReply {
            request_id: q.request_id,
            owner_now_ms: 1_000_100,
            remaining_ms: if mode == 3 { 40 } else { 700 },
            receipt_sha256: Sha256::digest(q.receipt).to_vec(),
            clock_domain: human_epoch::decode(&c.identity_authority_epoch)
                .unwrap()
                .clock_domain
                .into(),
            source_revision: human_epoch::decode(&c.identity_authority_epoch)
                .unwrap()
                .source_scope_revision,
            application_generation: 9,
            key_registry_revision: 1,
            scope_sha256: hopae_grpc::human_observed_client::HumanScope {
                service: c.service.clone(),
                audience: c.audience.clone(),
                app_id: "app".into(),
                route_id: "orders".into(),
                route_revision: 4,
                destination_sha256: [2; 32],
                header_policy_revision: 13,
                header_names: vec![],
                reserved_names: vec!["x-owned-secret".into()],
            }
            .fingerprint()
            .unwrap()
            .to_vec(),
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
    policy_variant(0)
}
fn policy_variant(mode: u8) -> Arc<PolicyPublication> {
    let subject = context('a', 7).identity.unwrap().subject_ref;
    let mut value = serde_json::json!({"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"require_guard":true,"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":0}},"users":{},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"}}}});
    value["services"]["orders"]["human_users"][subject] = serde_json::json!(["reader"]);
    // Same subject exists in both classes. Human must never borrow legacy rights.
    let subject = context('a', 7).identity.unwrap().subject_ref;
    value["services"]["orders"]["roles"]["blocked"] =
        serde_json::json!({"permissions":[],"information_classes":["internal"],"minimum_aal":0});
    value["services"]["orders"]["users"][&subject] = serde_json::json!(["blocked"]);
    match mode {
        1 => {
            value["services"]["orders"]["human_users"] = serde_json::json!({});
            value["services"]["orders"]["users"][&subject] = serde_json::json!(["reader"]);
        }
        2 => value["services"]["orders"]["roles"]["reader"]["minimum_aal"] = serde_json::json!(2),
        3 => {
            value["services"]["orders"]["roles"]["reader"]["information_classes"] =
                serde_json::json!([])
        }
        4 => {
            value["services"]["orders"]["networks"][0]["cidr"] =
                serde_json::json!("198.51.100.0/24")
        }
        _ => {}
    }
    Arc::new(PolicyPublication {
        compiled: serde_json::from_value::<pumgye_core::Policy>(value)
            .unwrap()
            .compile()
            .unwrap(),
        revision: 2,
    })
}
#[tokio::test]
async fn human_native_policy_with_authenticated_peer_fixtures_and_postsign_retirement() {
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
                v1::human_authentication_receipts_server::HumanAuthenticationReceiptsServer::new(
                    Peer {
                        mode: mode.clone(),
                        calls: calls.clone(),
                        strict_calls: strict_calls.clone(),
                        entered: entered.clone(),
                        release: release.clone(),
                    },
                ),
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
            minimum_source_revision: 7,
            scopes: vec![hopae_grpc::human_observed_client::HumanScope {
                service: "orders".into(),
                audience: "api".into(),
                app_id: "app".into(),
                route_id: "orders".into(),
                route_revision: 4,
                destination_sha256: [2; 32],
                header_policy_revision: 13,
                header_names: vec![],
                reserved_names: vec!["x-owned-secret".into()],
            }],
            minimum_application_generation: 1,
            minimum_key_registry_revision: 1,
            endpoint: EndpointConfig {
                address: &address,
                server_name: "hopae.test",
                ca: &ca,
                certificate: &cert,
                private_key: &key,
                caller_key: CALLER,
            }
            .into(),
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
    let owner = pumgye_server::human_observed_permit::Service::from_native(
        pumgye_server::human_observed_permit::Owners {
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
    compiled_pum_binary_fixture(dir.path(), &address, &ca, &cert, &key, &q, &calls).await;
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
                        kind: PrincipalKind::Human,
                        aal: i.aal as u8,
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
    // Typed collision, deletion, assurance, information class and network conjunction
    // all run through the same compiled native policy and actual owner RPCs.
    let prior = owner
        .issue(q.clone(), &|| true)
        .await
        .unwrap()
        .permit
        .unwrap();
    publication.0.store(policy_variant(1));
    assert_eq!(
        owner
            .observe(
                pumgye_grpc::v1::PermitValidationRequest {
                    request_id: 92,
                    request: Some(q.clone()),
                    permit: Some(prior),
                },
                &|| true
            )
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    for variant in 1..=4 {
        publication.0.store(policy_variant(variant));
        assert_eq!(
            owner.issue(q.clone(), &|| true).await.unwrap_err().code(),
            tonic::Code::PermissionDenied,
            "policy variant {variant}"
        );
    }
    publication.0.store(policy_variant(2));
    let mut two = q.clone();
    two.context.as_mut().unwrap().identity.as_mut().unwrap().aal = 2;
    two.receipt = signed(two.context.as_ref().unwrap());
    let qualified_fixture = owner.issue(two, &|| true).await.unwrap();
    assert_eq!(
        qualified_fixture
            .permit
            .unwrap()
            .context
            .unwrap()
            .identity
            .unwrap()
            .aal,
        2
    );
    publication.0.store(policy());
    for (kind, aal) in [(2, 0), (3, 0), (1, 0), (1, 3)] {
        let mut wrong = q.clone();
        let identity = wrong.context.as_mut().unwrap().identity.as_mut().unwrap();
        identity.kind = kind;
        identity.aal = aal;
        assert!(owner.issue(wrong, &|| true).await.is_err());
    }
    for (resource, action) in [("db:absent", "select"), ("db:orders", "drop")] {
        let mut wrong = q.clone();
        wrong.resource = resource.into();
        wrong.action = action.into();
        assert!(owner.issue(wrong, &|| true).await.is_err());
    }
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
    server.abort();
}

// Actual compiled Pum binary / Authority / SQLite CAS. Hop/native evidence peers
// remain fixtures: this does not qualify real Human login/TOTP or full H3.
async fn compiled_pum_binary_fixture(
    dir: &std::path::Path,
    address: &str,
    ca: &[u8],
    cert: &[u8],
    key: &[u8],
    q: &pumgye_grpc::v1::AuthenticatedResourceRequest,
    source_calls: &Arc<AtomicU64>,
) {
    use pumgye_grpc::v1::human_observed_projection_permits_client::HumanObservedProjectionPermitsClient;
    let admin = "owned-pum-human-admin-secret-at-least-32";
    let reserve = || {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        address
    };
    let grpc_address = reserve();
    let admin_address = reserve();
    let write = |name: &str, value: serde_json::Value| {
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    };
    let subject = q
        .context
        .as_ref()
        .unwrap()
        .identity
        .as_ref()
        .unwrap()
        .subject_ref
        .clone();
    let policy = serde_json::json!({"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"require_guard":true,"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":1},"blocked":{"permissions":[],"information_classes":["internal"]}},"users":{subject.clone():["blocked"]},"human_users":{subject.clone():["reader"]},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"}}}});
    let bootstrap = write(
        "binary-policy.json",
        serde_json::json!({"revision":1,"policy":policy}),
    );
    let trust = write(
        "binary-trust.json",
        serde_json::json!({"entries":[{"issuer_ref":"issuer","key_epoch":1,"identity_epoch":"owner","service":"orders","audience":"api","minimum_revision":7,"public_key":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes())}]}),
    );
    let signer = write(
        "binary-permit.json",
        serde_json::json!({"issuer_ref":"pumgye","key_epoch":1,"public_key":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[8;32]).verifying_key().as_bytes()),"seed_env":"OWNED_PERMIT_SEED"}),
    );
    let transport = serde_json::json!({"address":address,"server_name":"hopae.test","ca":dir.join("ca.pem"),"certificate":dir.join("client.pem"),"key":dir.join("client.key"),"token_env":"OWNED_PEER_CALLER"});
    let peers = write("binary-peers.json", transport.clone());
    let mut human_transport = transport;
    human_transport["issuer_ref"] = "issuer".into();
    human_transport["observed_clock_rates"] =
        serde_json::json!({"source_ppm":50,"receiver_ppm":75});
    let human = write(
        "binary-human.json",
        serde_json::json!({"transport":human_transport,"minimum_source_revision":7,"minimum_application_generation":1,"minimum_key_registry_revision":1,"scopes":[{"service":"orders","audience":"api","app_id":"app","route_id":"orders","route_revision":4,"destination_sha256":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"header_policy_revision":13,"header_names":[],"reserved_names":["x-owned-secret"]}]}),
    );
    let database = dir.join("binary-authority.sqlite3");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_pumgye"));
    command
        .arg("--listen")
        .arg(admin_address.to_string())
        .arg("--grpc-listen")
        .arg(grpc_address.to_string())
        .arg("--database")
        .arg(&database)
        .arg("--policy")
        .arg(&bootstrap)
        .arg("--tls-cert")
        .arg(dir.join("server.pem"))
        .arg("--tls-key")
        .arg(dir.join("server.key"))
        .arg("--client-ca")
        .arg(dir.join("ca.pem"))
        .arg("--human-observed-permits")
        .arg("--human-authentication-live")
        .arg(&human)
        .arg("--authentication-trust")
        .arg(&trust)
        .arg("--permit-key")
        .arg(&signer)
        .arg("--network-live")
        .arg(&peers)
        .arg("--route-live")
        .arg(&peers)
        .arg("--projection-live")
        .arg(&peers)
        .env("PUMGYE_ADMIN_TOKEN", admin)
        .env("PUMGYE_DECISION_TOKEN", CALLER)
        .env("OWNED_PEER_CALLER", CALLER)
        .env("OWNED_PERMIT_SEED", STANDARD.encode([8; 32]))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(
            std::fs::File::create(dir.join("binary.stderr")).unwrap(),
        ))
        .kill_on_drop(true);
    let mut child = command.spawn().unwrap();
    // Startup readiness only; never retry authorization or expand proof budgets.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "Pum fixture exited before readiness"
            );
            if tokio::net::TcpStream::connect(grpc_address).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let channel = tonic::transport::Endpoint::from_shared(format!("https://{grpc_address}"))
        .unwrap()
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name("hopae.test")
                .ca_certificate(tonic::transport::Certificate::from_pem(ca))
                .identity(tonic::transport::Identity::from_pem(cert, key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = HumanObservedProjectionPermitsClient::new(channel.clone());
    let mut query = q.clone();
    query.minimum_revision = 1;
    fn request<T>(input: T) -> Request<T> {
        let mut r = Request::new(input);
        r.metadata_mut()
            .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
        r
    }

    assert_eq!(
        grpc.issue(Request::new(query.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    let preliminary_message = pumgye_grpc::v1::ResourceDecisionRequest {
        request_id: 91,
        minimum_revision: 1,
        ip: query.ip.clone(),
        aal: 1,
        guard: 1,
        resource: query.resource.clone(),
        action: query.action.clone(),
        subject: subject.clone(),
        service_id: "orders".into(),
    };
    let mut preliminary =
        pumgye_grpc::v1::human_resource_authorization_client::HumanResourceAuthorizationClient::new(
            channel.clone(),
        );
    let before = source_calls.load(Ordering::Acquire);
    assert_eq!(
        preliminary
            .decide(Request::new(preliminary_message.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    let reply = preliminary
        .decide(request(preliminary_message.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (reply.verdict, reply.cache_ttl_ms, reply.revision),
        (1, 0, 1)
    );
    assert_eq!(source_calls.load(Ordering::Acquire), before); // Preliminary is NOT authentication.
    for aal in [0, 3, u32::MAX] {
        let mut bad = preliminary_message.clone();
        bad.aal = aal;
        assert_eq!(
            preliminary.decide(request(bad)).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
    for subject in ["s_wrong".to_owned(), format!("human1:{}", "b".repeat(64))] {
        let mut bad = preliminary_message.clone();
        bad.subject = subject;
        assert_eq!(
            preliminary
                .decide(request(bad))
                .await
                .unwrap()
                .into_inner()
                .verdict,
            2
        );
    }
    {
        // The peer clock remains fresh; no Source RPC may follow delayed decode.
        use axum::body::HttpBody;
        use prost::Message;
        use tokio_stream::StreamExt;
        use tower::ServiceExt;
        // Actual configured Human mounts, including its original-admission
        // interceptor, refuse hostile frames without any Source observation.
        for (path, limit) in [
            (
                "/hangang.pumgye.v1.HumanResourceAuthorization/Decide",
                2048usize,
            ),
            (
                "/hangang.pumgye.v1.HumanObservedProjectionPermits/Issue",
                8192,
            ),
            (
                "/hangang.pumgye.v1.HumanObservedProjectionPermits/Observe",
                8192,
            ),
        ] {
            for hostile in 0..3 {
                let mut frame = vec![0];
                frame.extend_from_slice(
                    &u32::try_from(if hostile == 1 { limit + 1 } else { 0 })
                        .unwrap()
                        .to_be_bytes(),
                );
                if hostile == 2 {
                    frame.extend_from_slice(&[0; 5]);
                }
                let mut raw = tonic::codegen::http::Request::builder()
                    .method("POST")
                    .version(tonic::codegen::http::Version::HTTP_2)
                    .uri(path)
                    .header("content-type", "application/grpc")
                    .header("te", "trailers")
                    .header("authorization", format!("Bearer {CALLER}"));
                if hostile == 0 {
                    raw = raw.header("authorization", format!("Bearer {CALLER}"));
                }
                let before = source_calls.load(Ordering::Acquire);
                let response = channel
                    .clone()
                    .oneshot(
                        raw.body(tonic::body::Body::new(axum::body::Body::from(frame)))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let mut status = response
                    .headers()
                    .get("grpc-status")
                    .map(|v| v.to_str().unwrap().to_owned());
                let mut body = response.into_body();
                while let Some(frame) =
                    std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
                {
                    if let Some(trailers) = frame.unwrap().trailers_ref()
                        && let Some(value) = trailers.get("grpc-status")
                    {
                        status = Some(value.to_str().unwrap().to_owned());
                    }
                }
                assert_eq!(
                    status.as_deref(),
                    Some(match hostile {
                        0 => "16",
                        1 => "11",
                        _ => "3",
                    }),
                    "{path} case {hostile}"
                );
                assert_eq!(source_calls.load(Ordering::Acquire), before);
            }
        }
        let payload = query.encode_to_vec();
        let mut frame = vec![0];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let before = source_calls.load(Ordering::Acquire);
        let chunks = vec![
            axum::body::Bytes::copy_from_slice(&frame[..3]),
            axum::body::Bytes::copy_from_slice(&frame[3..]),
        ];
        let body = axum::body::Body::from_stream(
            tokio_stream::iter(chunks.into_iter().enumerate()).then(|(index, chunk)| async move {
                if index == 1 {
                    tokio::time::sleep(Duration::from_millis(1100)).await;
                }
                Ok::<_, std::io::Error>(chunk)
            }),
        );
        let raw = tonic::codegen::http::Request::builder()
            .method("POST")
            .version(tonic::codegen::http::Version::HTTP_2)
            .uri("/hangang.pumgye.v1.HumanObservedProjectionPermits/Issue")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("authorization", format!("Bearer {CALLER}"))
            .body(tonic::body::Body::new(body))
            .unwrap();
        let response = channel.clone().oneshot(raw).await.unwrap();
        let timeout_message = response
            .headers()
            .get("grpc-message")
            .map(|v| v.to_str().unwrap().to_owned());
        let mut status = response
            .headers()
            .get("grpc-status")
            .map(|v| v.to_str().unwrap().to_owned());
        let mut body = response.into_body();
        while let Some(frame) =
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
        {
            if let Some(trailers) = frame.unwrap().trailers_ref()
                && let Some(value) = trailers.get("grpc-status")
            {
                status = Some(value.to_str().unwrap().to_owned());
            }
        }
        // The existing runtime server's 1000ms transport timeout closes first.
        assert_eq!(status.as_deref(), Some("1"));
        assert_eq!(timeout_message.as_deref(), Some("Timeout%20expired"));
        assert_eq!(source_calls.load(Ordering::Acquire), before);
    }
    let issued = grpc
        .issue(request(query.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        issued
            .permit
            .as_ref()
            .unwrap()
            .binding
            .as_ref()
            .unwrap()
            .policy_revision,
        1
    );
    assert_eq!(
        issued
            .permit
            .as_ref()
            .unwrap()
            .context
            .as_ref()
            .unwrap()
            .identity
            .as_ref()
            .unwrap()
            .kind,
        1
    );
    let mut pem = cert.to_vec();
    pem.extend_from_slice(key);
    let admin_client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(ca).unwrap())
        .identity(reqwest::Identity::from_pem(&pem).unwrap())
        .resolve("hopae.test", admin_address)
        .build()
        .unwrap();
    let url = format!("https://hopae.test:{}/v1/policy", admin_address.port());
    let original: serde_json::Value = admin_client
        .get(&url)
        .bearer_auth(admin)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(original["revision"], 1);
    let mut withdrawn = original.clone();
    withdrawn["policy"]["services"]["orders"]["human_users"] = serde_json::json!({});
    withdrawn["policy"]["services"]["orders"]["users"][&subject] = serde_json::json!(["reader"]);
    let published: serde_json::Value = admin_client
        .put(&url)
        .bearer_auth(admin)
        .header("if-match", "\"1\"")
        .json(&withdrawn)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(published["revision"], 2);
    assert_eq!(
        preliminary
            .decide(request(preliminary_message.clone()))
            .await
            .unwrap()
            .into_inner()
            .verdict,
        2
    );
    assert_eq!(
        admin_client
            .put(&url)
            .bearer_auth(admin)
            .header("if-match", "\"1\"")
            .json(&withdrawn)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT
    );

    assert_eq!(
        grpc.issue(request(query.clone())).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let old = pumgye_grpc::v1::PermitValidationRequest {
        request_id: 88,
        request: Some(query.clone()),
        permit: issued.permit.clone(),
    };
    assert!(grpc.observe(request(old.clone())).await.is_err());
    let mut restored = original;
    restored["revision"] = 2.into();
    let published: serde_json::Value = admin_client
        .put(&url)
        .bearer_auth(admin)
        .header("if-match", "\"2\"")
        .json(&restored)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(published["revision"], 3);
    assert_eq!(
        grpc.issue(request(query.clone()))
            .await
            .unwrap()
            .into_inner()
            .permit
            .unwrap()
            .binding
            .unwrap()
            .policy_revision,
        3
    );
    child.kill().await.unwrap();
    // Same DB restart restores the Human map, but cannot validate old P-domain permits.
    let mut child = command.spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.try_wait().unwrap().is_none());
            if tokio::net::TcpStream::connect(grpc_address).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let channel = tonic::transport::Endpoint::from_shared(format!("https://{grpc_address}"))
        .unwrap()
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name("hopae.test")
                .ca_certificate(tonic::transport::Certificate::from_pem(ca))
                .identity(tonic::transport::Identity::from_pem(cert, key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = HumanObservedProjectionPermitsClient::new(channel);
    assert!(grpc.observe(request(old)).await.is_err());
    assert_eq!(
        grpc.issue(request(query))
            .await
            .unwrap()
            .into_inner()
            .permit
            .unwrap()
            .binding
            .unwrap()
            .policy_revision,
        3
    );
    child.kill().await.unwrap();
    // A persisted Human grant map alone never activates a Human RPC.
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_pumgye"))
        .arg("--listen")
        .arg(admin_address.to_string())
        .arg("--grpc-listen")
        .arg(grpc_address.to_string())
        .arg("--database")
        .arg(&database)
        .arg("--tls-cert")
        .arg(dir.join("server.pem"))
        .arg("--tls-key")
        .arg(dir.join("server.key"))
        .arg("--client-ca")
        .arg(dir.join("ca.pem"))
        .env("PUMGYE_ADMIN_TOKEN", admin)
        .env("PUMGYE_DECISION_TOKEN", CALLER)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(
            std::fs::File::create(dir.join("binary-default.stderr")).unwrap(),
        ))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.try_wait().unwrap().is_none());
            if tokio::net::TcpStream::connect(grpc_address).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let channel = tonic::transport::Endpoint::from_shared(format!("https://{grpc_address}"))
        .unwrap()
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name("hopae.test")
                .ca_certificate(tonic::transport::Certificate::from_pem(ca))
                .identity(tonic::transport::Identity::from_pem(cert, key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = HumanObservedProjectionPermitsClient::new(channel.clone());
    assert_eq!(
        grpc.issue(request(q.clone())).await.unwrap_err().code(),
        tonic::Code::Unimplemented
    );
    let mut preliminary =
        pumgye_grpc::v1::human_resource_authorization_client::HumanResourceAuthorizationClient::new(
            channel,
        );
    assert_eq!(
        preliminary
            .decide(request(preliminary_message))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );
    child.kill().await.unwrap();
}

#[path = "fixtures/human_native_runtime.rs"]
mod human_native_runtime;
