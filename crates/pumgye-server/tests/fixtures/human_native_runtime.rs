//! Explicit real external Hop-native → public SDK → actual Pum binary gate.
//! Sum/route/plan are fixed owning protocol fixtures; this is not H4/Root qualification.
use super::*;
use hopae_grpc::human_observed_client as sdk;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

struct Runtime {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    ready: serde_json::Value,
}
impl Drop for Runtime {
    fn drop(&mut self) {
        // The helper's SIGTERM handler cleans up only its owned Hop/LDAP children.
        if self.child.try_wait().ok().flatten().is_none()
            && let Some(pid) = self.child.id()
        {
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while self.child.try_wait().ok().flatten().is_none()
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
impl Runtime {
    async fn command(&mut self, op: &str, aal: u8) -> serde_json::Value {
        let command = serde_json::to_vec(&serde_json::json!({"op":op,"aal":aal})).unwrap();
        self.input.write_all(&command).await.unwrap();
        self.input.write_all(b"\n").await.unwrap();
        self.input.flush().await.unwrap();
        let line = tokio::time::timeout(Duration::from_secs(60), self.output.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("native fixture missing safe reply");
        let reply: serde_json::Value =
            serde_json::from_str(&line).expect("invalid safe fixture reply");
        assert_eq!(
            reply["ok"], true,
            "native fixture operation failed (private evidence retained)"
        );
        reply
    }
}
fn text<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v[key].as_str().expect("native fixture field missing")
}
fn fixed_scope(v: &serde_json::Value) -> sdk::HumanScope {
    let v = &v["scope"];
    sdk::HumanScope {
        service: text(v, "service").into(),
        audience: text(v, "audience").into(),
        app_id: text(v, "app_id").into(),
        route_id: text(v, "route_id").into(),
        route_revision: v["route_revision"].as_u64().unwrap(),
        destination_sha256: serde_json::from_value(v["destination_sha256"].clone()).unwrap(),
        header_policy_revision: v["header_policy_revision"].as_u64().unwrap(),
        header_names: serde_json::from_value(v["header_names"].clone()).unwrap(),
        reserved_names: serde_json::from_value(v["reserved_names"].clone()).unwrap(),
    }
}
fn headers(cookie: &str) -> Vec<v1::Header> {
    [
        ("x-hopae-contract", "1".to_owned()),
        ("x-original-url", "https://app.example.test/data".into()),
        ("x-forwarded-proto", "https".into()),
        ("x-forwarded-host", "app.example.test".into()),
        ("x-forwarded-for", "192.0.2.10".into()),
        ("x-original-method", "GET".into()),
        ("x-hangang-canonical-path", "/data".into()),
        ("x-hangang-route-id", "owned-route".into()),
        ("cookie", format!("__Host-hopae={cookie}")),
    ]
    .into_iter()
    .map(|(name, value)| v1::Header {
        name: name.into(),
        value: value.into_bytes(),
    })
    .collect()
}
fn request<T>(value: T) -> Request<T> {
    let mut r = Request::new(value);
    r.metadata_mut()
        .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
    r
}

#[derive(Clone)]
struct Peers {
    minimum_aal: Arc<AtomicU8>,
}
#[tonic::async_trait]
impl guard_grpc::v1::network_server::Network for Peers {
    async fn check(
        &self,
        q: Request<guard_grpc::v1::NetworkRequest>,
    ) -> Result<Response<guard_grpc::v1::NetworkReply>, Status> {
        Ok(Response::new(guard_grpc::v1::NetworkReply {
            request_id: q.into_inner().request_id,
            revision: 3,
            verdict: 1,
            mode: 2,
            ttl_ms: 1000,
        }))
    }
}
#[tonic::async_trait]
impl hangang_route_grpc::v1::route_ownership_server::RouteOwnership for Peers {
    async fn observe(
        &self,
        q: Request<hangang_route_grpc::v1::RouteRequest>,
    ) -> Result<Response<hangang_route_grpc::v1::RouteReply>, Status> {
        let q = q.into_inner();
        Ok(Response::new(hangang_route_grpc::v1::RouteReply {
            request_id: q.request_id,
            route_id: "owned-route".into(),
            configuration_revision: 11,
            service: "orders".into(),
            audience: "orders-api".into(),
            resource: "db:orders".into(),
            action: "select".into(),
            client_ip: vec![192, 0, 2, 10],
            request_sha256: q.request_sha256,
            destination_sha256: q.destination_sha256,
            remaining_ms: 1000,
        }))
    }
}
#[tonic::async_trait]
impl v1::projection_plans_server::ProjectionPlans for Peers {
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
            minimum_aal: u32::from(self.minimum_aal.load(Ordering::Acquire)),
            cache_ttl_ms: 0,
        }))
    }
}

#[tokio::test]
#[ignore = "requires explicit exact public Hop binary and private native portal fixture; run separately"]
async fn actual_native_hop_sdk_to_pum_authority_human_permit() {
    let helper =
        std::env::var("OWNED_HUMAN_RUNTIME_FIXTURE").expect("explicit native fixture required");
    let binary = std::env::var("OWNED_HOPAE_BINARY").expect("exact qualified Hop binary required");
    let provider = std::env::var("OWNED_HUMAN_PROVIDER").unwrap_or_else(|_| "oidc".into());
    assert!(matches!(provider.as_str(), "oidc" | "ldap"));
    let dir = tempfile::Builder::new()
        .prefix("pumgye-human-native-evidence-")
        .tempdir()
        .unwrap()
        .keep();
    let ready_path = dir.as_path().join("ready.json");
    let mut child = tokio::process::Command::new("python3")
        .arg(helper)
        .arg("--binary")
        .arg(binary)
        .arg("--directory")
        .arg(dir.as_path().join("native"))
        .arg("--provider")
        .arg(provider)
        .args(
            std::env::var("OWNED_HUMAN_LDAP_STARTTLS")
                .is_ok_and(|s| s == "1")
                .then_some("--ldap-starttls"),
        )
        .arg("--ready")
        .arg(&ready_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::from(
            std::fs::File::create(dir.as_path().join("native.stderr")).unwrap(),
        ))
        .kill_on_drop(false)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "native helper failed before readiness"
            );
            if ready_path.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("native helper startup budget exceeded");
    let ready: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ready_path).unwrap()).unwrap();
    let mut runtime = Runtime {
        input: child.stdin.take().unwrap(),
        output: BufReader::new(child.stdout.take().unwrap()).lines(),
        child,
        ready,
    };
    let scope = fixed_scope(&runtime.ready);
    let ca = std::fs::read(text(&runtime.ready, "ca")).unwrap();
    let cert = std::fs::read(text(&runtime.ready, "certificate")).unwrap();
    let key = std::fs::read(text(&runtime.ready, "key")).unwrap();
    let caller = std::fs::read_to_string(text(&runtime.ready, "caller_file")).unwrap();
    let public = hex_key(text(&runtime.ready, "public_key"));
    let client = sdk::Client::new_human(
        sdk::EndpointConfig {
            address: text(&runtime.ready, "endpoint"),
            server_name: text(&runtime.ready, "server_name"),
            ca: &ca,
            certificate: &cert,
            private_key: &key,
            caller_key: &caller,
        },
        sdk::HumanTrustPolicy {
            issuer_ref: text(&runtime.ready, "issuer_ref").into(),
            key_epoch: 1,
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap(),
            identity_authority: text(&runtime.ready, "identity_authority").into(),
            scopes: vec![scope.clone()],
            minimum_source_revision: 7,
            minimum_application_generation: 1,
            minimum_key_registry_revision: 1,
        },
        Arc::new(hangang_runtime::time::ReceiverClock::new([0x61; 16]).unwrap()),
        ClockRates::new(500, 500).unwrap(),
        sdk::Limits {
            concurrent: 4,
            timeout: Duration::from_millis(500),
        },
    )
    .unwrap();
    let login = runtime.command("login", 1).await;
    let cookie = std::fs::read_to_string(text(&login, "cookie_file")).unwrap();
    let observed = issue(&client, &scope, &cookie).await;
    let subject = observed
        .context()
        .identity
        .as_ref()
        .unwrap()
        .subject_ref
        .clone();
    assert!(subject.starts_with("human1:"));
    assert_eq!(observed.context().identity.as_ref().unwrap().aal, 1);
    assert!(client.check(&observed, observed.request()).is_ok());
    let independently_observed = client
        .observe(
            client
                .prepare_observation(
                    observed.context().clone(),
                    observed.receipt(),
                    observed
                        .context()
                        .request_sha256
                        .as_slice()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        client
            .check(&independently_observed, independently_observed.request())
            .is_ok()
    );
    let original = client.check(&observed, observed.request()).unwrap();
    let refreshed = client.refresh(observed).await.unwrap();
    assert!(client.check(&refreshed, refreshed.request()).unwrap() <= original);
    actual_pum(&mut runtime, &client, &scope, &subject, dir.as_path()).await;
    runtime.command("shutdown", 0).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), runtime.child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
fn hex_key(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
async fn issue(client: &sdk::Client, scope: &sdk::HumanScope, cookie: &str) -> sdk::Observation {
    client
        .issue(
            client
                .prepare(
                    scope,
                    &hopae_grpc::request_binding_v2::Request {
                        service: &scope.service,
                        audience: &scope.audience,
                        route_id: &scope.route_id,
                        route_revision: scope.route_revision,
                        destination_sha256: &scope.destination_sha256,
                        method: "GET",
                        target: "/data",
                        body: b"body",
                        bound_headers: &[],
                    },
                    headers(cookie),
                )
                .unwrap(),
        )
        .await
        .expect("actual native source refused")
}

async fn actual_pum(
    runtime: &mut Runtime,
    client: &sdk::Client,
    scope: &sdk::HumanScope,
    subject: &str,
    dir: &std::path::Path,
) {
    use pumgye_grpc::v1::human_observed_projection_permits_client::HumanObservedProjectionPermitsClient;
    let ca = std::fs::read(text(&runtime.ready, "ca")).unwrap();
    let cert = std::fs::read(text(&runtime.ready, "certificate")).unwrap();
    let key = std::fs::read(text(&runtime.ready, "key")).unwrap();
    let minimum = Arc::new(AtomicU8::new(1));
    let peer = Peers {
        minimum_aal: minimum.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peers_address = format!("https://{}", listener.local_addr().unwrap());
    let peer_task = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(
                tonic::transport::ServerTlsConfig::new()
                    .identity(tonic::transport::Identity::from_pem(&cert, &key))
                    .client_ca_root(tonic::transport::Certificate::from_pem(&ca)),
            )
            .unwrap()
            .add_service(guard_grpc::v1::network_server::NetworkServer::new(
                peer.clone(),
            ))
            .add_service(
                hangang_route_grpc::v1::route_ownership_server::RouteOwnershipServer::new(
                    peer.clone(),
                ),
            )
            .add_service(v1::projection_plans_server::ProjectionPlansServer::new(
                peer,
            ))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let write = |name: &str, value: serde_json::Value| {
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    };
    let policy = serde_json::json!({"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"require_guard":true,"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":1}},"users":{},"human_users":{subject:["reader"]},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"}}}});
    let policy_file = write(
        "policy.json",
        serde_json::json!({"revision":1,"policy":policy}),
    );
    let trust = write(
        "trust.json",
        serde_json::json!({"entries":[{"issuer_ref":runtime.ready["issuer_ref"],"key_epoch":1,"identity_epoch":runtime.ready["identity_authority"],"service":scope.service,"audience":scope.audience,"minimum_revision":7,"public_key":STANDARD.encode(hex_key(text(&runtime.ready,"public_key")))}]}),
    );
    let human = write(
        "human.json",
        serde_json::json!({"transport":{"issuer_ref":runtime.ready["issuer_ref"],"address":runtime.ready["endpoint"],"server_name":runtime.ready["server_name"],"ca":runtime.ready["ca"],"certificate":runtime.ready["certificate"],"key":runtime.ready["key"],"token_env":"OWNED_NATIVE_HOP_CALLER","observed_clock_rates":{"source_ppm":500,"receiver_ppm":500}},"minimum_source_revision":7,"minimum_application_generation":1,"minimum_key_registry_revision":1,"scopes":[runtime.ready["scope"]]}),
    );
    let peers = write(
        "peers.json",
        serde_json::json!({"address":peers_address,"server_name":"localhost","ca":runtime.ready["ca"],"certificate":runtime.ready["certificate"],"key":runtime.ready["key"],"token_env":"OWNED_NATIVE_PEER_CALLER"}),
    );
    let signer = write(
        "signer.json",
        serde_json::json!({"issuer_ref":"pumgye","key_epoch":1,"public_key":STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[8;32]).verifying_key().as_bytes()),"seed_env":"OWNED_NATIVE_PERMIT_SEED"}),
    );
    let reserve = || {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let grpc_address = reserve();
    let admin_address = reserve();
    let admin = "owned-native-human-policy-admin-at-least32";
    let caller = std::fs::read_to_string(text(&runtime.ready, "caller_file")).unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_pumgye"))
        .arg("--listen")
        .arg(admin_address.to_string())
        .arg("--grpc-listen")
        .arg(grpc_address.to_string())
        .arg("--database")
        .arg(dir.join("authority.sqlite3"))
        .arg("--policy")
        .arg(policy_file)
        .arg("--tls-cert")
        .arg(text(&runtime.ready, "certificate"))
        .arg("--tls-key")
        .arg(text(&runtime.ready, "key"))
        .arg("--client-ca")
        .arg(text(&runtime.ready, "ca"))
        .arg("--human-observed-permits")
        .arg("--human-authentication-live")
        .arg(human)
        .arg("--authentication-trust")
        .arg(trust)
        .arg("--permit-key")
        .arg(signer)
        .arg("--network-live")
        .arg(&peers)
        .arg("--route-live")
        .arg(&peers)
        .arg("--projection-live")
        .arg(&peers)
        .env("PUMGYE_ADMIN_TOKEN", admin)
        .env("PUMGYE_DECISION_TOKEN", CALLER)
        .env("OWNED_NATIVE_HOP_CALLER", &caller)
        .env("OWNED_NATIVE_PEER_CALLER", CALLER)
        .env("OWNED_NATIVE_PERMIT_SEED", STANDARD.encode([8; 32]))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(
            std::fs::File::create(dir.join("pum.stderr")).unwrap(),
        ))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "native Pum failed before readiness"
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
                .domain_name("localhost")
                .ca_certificate(tonic::transport::Certificate::from_pem(&ca))
                .identity(tonic::transport::Identity::from_pem(&cert, &key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = HumanObservedProjectionPermitsClient::new(channel);
    let login = runtime.command("login", 1).await;
    let cookie1 = std::fs::read_to_string(text(&login, "cookie_file")).unwrap();
    let one = issue(client, scope, &cookie1).await;
    assert_eq!(
        one.context().identity.as_ref().unwrap().subject_ref,
        subject
    );
    let query1 = query(&one);
    let issued = grpc
        .issue(request(query1.clone()))
        .await
        .expect("actual AAL1 native permit refused")
        .into_inner();
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
            .aal,
        1
    );
    assert_eq!(issued.observation.as_ref().unwrap().cache_ttl_ms, 0);
    minimum.store(2, Ordering::Release);
    let one = issue(client, scope, &cookie1).await;
    // Existing plan-live treats an unmet authenticated AAL floor as an
    // unavailable prerequisite, before typed policy evaluation.
    assert_eq!(
        grpc.issue(request(query(&one))).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    let login = runtime.command("login", 2).await;
    let cookie2 = std::fs::read_to_string(text(&login, "cookie_file")).unwrap();
    let two = issue(client, scope, &cookie2).await;
    assert_eq!(
        two.context().identity.as_ref().unwrap().subject_ref,
        subject
    );
    assert_eq!(two.context().identity.as_ref().unwrap().aal, 2);
    let query2 = query(&two);
    let issued = grpc
        .issue(request(query2.clone()))
        .await
        .expect("actual native TOTP permit refused")
        .into_inner();
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
            .aal,
        2
    );
    let validation = pumgye_grpc::v1::PermitValidationRequest {
        request_id: 22,
        request: Some(query2),
        permit: issued.permit,
    };
    assert!(grpc.observe(request(validation.clone())).await.is_ok());
    minimum.store(3, Ordering::Release);
    let two = issue(client, scope, &cookie2).await;
    assert_eq!(
        grpc.issue(request(query(&two))).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    minimum.store(2, Ordering::Release);
    let mut pem = cert.clone();
    pem.extend_from_slice(&key);
    let admin_client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .identity(reqwest::Identity::from_pem(&pem).unwrap())
        .resolve("localhost", admin_address)
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/v1/policy", admin_address.port());
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
    let mut changed = original.clone();
    changed["policy"]["services"]["orders"]["human_users"] = serde_json::json!({});
    changed["policy"]["services"]["orders"]["users"][subject] = serde_json::json!(["reader"]);
    let changed: serde_json::Value = admin_client
        .put(&url)
        .bearer_auth(admin)
        .header("if-match", r#""1""#)
        .json(&changed)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(changed["revision"], 2);
    let two = issue(client, scope, &cookie2).await;
    assert_eq!(
        grpc.issue(request(query(&two))).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert!(grpc.observe(request(validation)).await.is_err());
    let mut restored = original;
    restored["revision"] = 2.into();
    let restored: serde_json::Value = admin_client
        .put(&url)
        .bearer_auth(admin)
        .header("if-match", r#""2""#)
        .json(&restored)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(restored["revision"], 3);
    let two = issue(client, scope, &cookie2).await;
    let query_before_revoke = query(&two);
    assert!(
        grpc.issue(request(query_before_revoke.clone()))
            .await
            .is_ok()
    );
    runtime.command("revoke", 2).await;
    assert!(
        client.check(&two, two.request()).is_ok(),
        "native logout exceeded the original proof budget; revocation was not isolated"
    );
    let denied = grpc.issue(request(query_before_revoke)).await.unwrap_err();
    assert_eq!(denied.code(), tonic::Code::Unavailable);
    assert_eq!(denied.message(), "observed native owner unavailable"); // Independent Hop ObserveTime refuses after native logout.
    assert!(client.refresh(two).await.is_err());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    peer_task.abort();
}
fn query(observation: &sdk::Observation) -> pumgye_grpc::v1::AuthenticatedResourceRequest {
    pumgye_grpc::v1::AuthenticatedResourceRequest {
        request_id: 19,
        minimum_revision: 1,
        ip: vec![192, 0, 2, 10],
        resource: "db:orders".into(),
        action: "select".into(),
        receipt: observation.receipt().to_vec(),
        context: Some(observation.context().clone()),
        request_sha256: observation.context().request_sha256.clone(),
        route: Some(pumgye_grpc::v1::NativeRouteReference {
            reference: vec![1; 32],
            destination_sha256: vec![0x12; 32],
        }),
    }
}
