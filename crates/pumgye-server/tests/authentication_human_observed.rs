#![cfg(all(feature = "observed-authentication", target_os = "linux"))]
// STRUCTURAL authenticated-peer fixture: real TLS + public opaque Human SDK.
// Peer signs test metadata; it is NOT native Engine/session/TOTP or H3 end-to-end qualification.
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
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
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
            7,
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
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}
#[tonic::async_trait]
impl v1::human_authentication_receipts_server::HumanAuthenticationReceipts for Peer {
    async fn issue_observed(
        &self,
        _: Request<v1::HumanReceiptRequest>,
    ) -> Result<Response<v1::HumanReceiptObservedReply>, Status> {
        Err(Status::unimplemented("observer fixture only"))
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
                route_id: if mode == 4 { "wrong-route" } else { "route" }.into(),
                route_revision: 11,
                destination_sha256: [0x12; 32],
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
#[tokio::test]
async fn human_observed_wrapper_digest_identity_and_lifecycle() {
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
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            read("server.pem"),
            read("server.key"),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(&ca));
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(
                v1::human_authentication_receipts_server::HumanAuthenticationReceiptsServer::new(
                    Peer {
                        mode: mode.clone(),
                        calls: calls.clone(),
                        entered: entered.clone(),
                        release: release.clone(),
                    },
                ),
            )
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let trust = Arc::new(
        Trust::compile(Document {
            entries: [("api", 7), ("reporting", 9)]
                .into_iter()
                .map(|(audience, minimum_revision)| Entry {
                    issuer_ref: "issuer".into(),
                    key_epoch: 1,
                    identity_epoch: "owner".into(),
                    service: "orders".into(),
                    audience: audience.into(),
                    minimum_revision,
                    public_key: STANDARD.encode(
                        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                })
                .collect(),
        })
        .unwrap(),
    );
    let make = || {
        AuthenticationOwnerGeneration::new(
            trust.clone(),
            Configuration {
                issuer_ref: "issuer",
                minimum_source_revision: 7,
                scopes: ["api", "reporting"]
                    .into_iter()
                    .map(|audience| hopae_grpc::human_observed_client::HumanScope {
                        service: "orders".into(),
                        audience: audience.into(),
                        app_id: "app".into(),
                        route_id: "route".into(),
                        route_revision: 11,
                        destination_sha256: [0x12; 32],
                        header_policy_revision: 13,
                        header_names: vec![],
                        reserved_names: vec!["x-owned-secret".into()],
                    })
                    .collect(),
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
        .unwrap()
    };
    let slot = OwnerSlot::default();
    let owner = make();
    slot.replace(Some(owner.clone())).unwrap();
    let live = || true;
    let caller = AtomicBool::new(true);
    let view = AtomicBool::new(true);
    let caller_ok = || caller.load(Ordering::Acquire);
    let view_ok = || view.load(Ordering::Acquire);
    // No method/path/body exist in this adapter; authenticated final digest binds it.
    let c = context('a', 1);
    let raw = signed(&c);
    let checked = slot
        .observe(
            owner.clone(),
            c.clone(),
            [5; 32],
            &raw,
            &caller_ok,
            &view_ok,
        )
        .await
        .unwrap();
    assert_eq!(checked.subject(), format!("human1:{}", "a".repeat(64)));
    assert_eq!(checked.revision(), 1);
    let first = slot.check(&checked, &live, &live).unwrap();
    let checked = slot.refresh(checked, &live, &live).await.unwrap();
    assert!(slot.check(&checked, &live, &live).unwrap() <= first);
    // A valid signature/global source revision cannot substitute another
    // route's actual source fingerprint, even with the same service/audience.
    mode.store(4, Ordering::Release);
    assert!(
        slot.observe(owner.clone(), c.clone(), [5; 32], &raw, &live, &live)
            .await
            .is_err()
    );
    mode.store(0, Ordering::Release);
    let c2 = context('b', 2);
    let raw2 = signed(&c2);
    assert_eq!(
        slot.observe(owner.clone(), c2.clone(), [5; 32], &raw2, &live, &live)
            .await
            .unwrap()
            .revision(),
        2
    );
    let before = calls.load(Ordering::Acquire);
    assert!(
        slot.observe(owner.clone(), c.clone(), [6; 32], &raw, &live, &live)
            .await
            .is_err()
    );
    for field in [
        "issuer",
        "key",
        "base",
        "scope",
        "floor",
        "scope-floor",
        "subject",
    ] {
        let mut changed = c.clone();
        match field {
            "issuer" => changed.issuer_ref = "other".into(),
            "key" => changed.key_epoch = 2,
            "base" => {
                changed.identity_authority_epoch =
                    human_epoch::encode("other", 7, 9, "11111111111111111111111111111111").unwrap()
            }
            "scope" => changed.audience = "other".into(),
            "floor" => {
                changed.identity_authority_epoch =
                    human_epoch::encode("owner", 6, 9, "11111111111111111111111111111111").unwrap()
            }
            "scope-floor" => {
                changed.identity_authority_epoch =
                    human_epoch::encode("owner", 8, 9, "11111111111111111111111111111111").unwrap();
                changed.audience = "reporting".into();
            }
            "subject" => changed.identity.as_mut().unwrap().subject_ref = "worker".into(),
            _ => unreachable!(),
        };
        let bytes = signed(&changed);
        assert!(
            slot.observe(owner.clone(), changed, [5; 32], &bytes, &live, &live)
                .await
                .is_err(),
            "{field}"
        );
    }
    let mut tampered = raw.clone();
    tampered[10] ^= 1;
    assert!(
        slot.observe(owner.clone(), c.clone(), [5; 32], &tampered, &live, &live)
            .await
            .is_err()
    );
    caller.store(false, Ordering::Release);
    assert!(
        slot.observe(owner.clone(), c.clone(), [5; 32], &raw, &caller_ok, &live)
            .await
            .is_err()
    );
    caller.store(true, Ordering::Release);
    assert_eq!(calls.load(Ordering::Acquire), before);
    mode.store(2, Ordering::Release);
    assert!(
        slot.observe(owner.clone(), c.clone(), [5; 32], &raw, &live, &live)
            .await
            .is_err()
    );
    mode.store(3, Ordering::Release);
    let expires = slot
        .observe(owner.clone(), c.clone(), [5; 32], &raw, &live, &live)
        .await
        .unwrap();
    // The last external callback can outlive admission; time must be sampled
    // after it, with no callback between that sample and the final native seal.
    let blocking_view = || {
        std::thread::sleep(Duration::from_millis(60));
        true
    };
    assert!(slot.check(&expires, &live, &blocking_view).is_err());
    assert!(slot.check(&expires, &live, &live).is_err());
    assert!(slot.refresh(expires, &live, &live).await.is_err());
    mode.store(1, Ordering::Release);
    let pending = slot.observe(
        owner.clone(),
        c.clone(),
        [5; 32],
        &raw,
        &caller_ok,
        &view_ok,
    );
    let revoke = async {
        entered.acquire().await.unwrap().forget();
        caller.store(false, Ordering::Release);
        release.add_permits(1);
    };
    let (result, _) = tokio::join!(pending, revoke);
    assert!(result.is_err());
    caller.store(true, Ordering::Release);
    let pending = slot.observe(
        owner.clone(),
        c.clone(),
        [5; 32],
        &raw,
        &caller_ok,
        &view_ok,
    );
    let revoke = async {
        entered.acquire().await.unwrap().forget();
        view.store(false, Ordering::Release);
        release.add_permits(1);
    };
    let (result, _) = tokio::join!(pending, revoke);
    assert!(result.is_err());
    view.store(true, Ordering::Release);
    // Refresh has the same independent caller/view fences across its await.
    for revoke_caller in [true, false] {
        mode.store(0, Ordering::Release);
        let fresh = slot
            .observe(owner.clone(), c.clone(), [5; 32], &raw, &live, &live)
            .await
            .unwrap();
        mode.store(1, Ordering::Release);
        let pending = slot.refresh(fresh, &caller_ok, &view_ok);
        let revoke = async {
            entered.acquire().await.unwrap().forget();
            if revoke_caller {
                caller.store(false, Ordering::Release);
            } else {
                view.store(false, Ordering::Release);
            }
            release.add_permits(1);
        };
        let (result, _) = tokio::join!(pending, revoke);
        assert!(result.is_err());
        caller.store(true, Ordering::Release);
        view.store(true, Ordering::Release);
    }
    let pending = slot.observe(owner.clone(), c.clone(), [5; 32], &raw, &live, &live);
    let replace = async {
        entered.acquire().await.unwrap().forget();
        slot.replace(Some(make())).unwrap();
        release.add_permits(1);
    };
    let (result, _) = tokio::join!(pending, replace);
    assert!(result.is_err());
    assert!(slot.check(&checked, &live, &live).is_err());
    let healthy = slot.capture().unwrap();
    assert!(slot.replace(Some(owner)).is_err());
    assert!(Arc::ptr_eq(&healthy, &slot.capture().unwrap()));
    slot.replace(Some(healthy.clone())).unwrap();
    assert!(Arc::ptr_eq(&healthy, &slot.capture().unwrap()));
    let owner = make();
    slot.replace(Some(owner.clone())).unwrap();
    mode.store(0, Ordering::Release);
    let fresh = slot
        .observe(owner, c, [5; 32], &raw, &live, &live)
        .await
        .unwrap();
    mode.store(1, Ordering::Release);
    let pending = slot.refresh(fresh, &live, &live);
    let replace = async {
        entered.acquire().await.unwrap().forget();
        slot.replace(Some(make())).unwrap();
        release.add_permits(1);
    };
    let (result, _) = tokio::join!(pending, replace);
    assert!(result.is_err());
    // A callback can synchronously replace its own slot. No native lock may
    // cross that callback, and retirement cannot be undone by republishing.
    mode.store(0, Ordering::Release);
    let owner = slot.capture().unwrap();
    let fresh = slot
        .observe(owner.clone(), context('a', 1), [5; 32], &raw, &live, &live)
        .await
        .unwrap();
    let reentrant_view = || {
        slot.replace(None).unwrap();
        true
    };
    assert!(slot.check(&fresh, &live, &reentrant_view).is_err());
    assert!(slot.replace(Some(owner)).is_err());
    server.abort();
}
