//! Owned interactive process fixture; credentials never appear in output.
use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hopae_grpc::{receipt_binding, request_binding, v1};
use pumgye_server::{
    authentication::{Configuration as TrustConfiguration, ServiceTrust},
    authentication_live::Client,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
#[derive(Deserialize)]
struct Tls {
    server_name: String,
    ca: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
}
#[derive(Deserialize)]
struct Settings {
    transport: String,
    address: String,
    tls: Tls,
}
fn default_epoch() -> String {
    "epoch1".into()
}
fn default_ip() -> String {
    "203.0.113.9".into()
}
#[derive(Deserialize)]
struct Config {
    permit_network: Option<PathBuf>,
    pumgye_endpoint: Option<String>,
    pumgye_grpc_address: Option<String>,
    #[serde(default = "default_epoch")]
    identity_epoch: String,
    #[serde(default = "default_ip")]
    qualification_ip: String,
    settings: Settings,
    issuer_ref: String,
    key_epoch: u64,
    public_key: String,
    service: String,
    audience: String,
    method: String,
    target: String,
    body: String,
    headers: Vec<(String, String)>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn context(reply: &v1::ServiceReceiptReply) -> Result<receipt_binding::Context<'_>> {
    let c = reply
        .context
        .as_ref()
        .ok_or_else(|| anyhow!("context absent"))?;
    let i = c
        .identity
        .as_ref()
        .ok_or_else(|| anyhow!("identity absent"))?;
    ensure!(i.kind == 2 && i.aal == 0, "unexpected identity");
    Ok(receipt_binding::Context {
        issuer_ref: &c.issuer_ref,
        key_epoch: c.key_epoch,
        identity_authority_epoch: &c.identity_authority_epoch,
        identity: receipt_binding::Identity {
            subject_ref: &i.subject_ref,
            kind: hopae_grpc::PrincipalKind::Service,
            aal: 0,
            revision: i.revision,
            credential_generation: i.credential_generation,
        },
        service: &c.service,
        audience: &c.audience,
        request_sha256: c.request_sha256.as_slice().try_into()?,
    })
}
async fn endpoint(
    config: &Config,
    checked: &pumgye_server::authentication::CheckedService<'_>,
    receipt: &[u8],
    rpc: &mut Option<pumgye_grpc::v1::authenticated_resource_authorization_client::AuthenticatedResourceAuthorizationClient<tonic::transport::Channel>>,
) -> Result<bool> {
    if let Some(client) = rpc {
        let c = checked.context();
        let ip: std::net::IpAddr = config.qualification_ip.parse()?;
        let packed = match ip {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let mut request = tonic::Request::new(pumgye_grpc::v1::AuthenticatedResourceRequest {
            route: None,
            request_id: 1,
            minimum_revision: 1,
            ip: packed,
            resource: "db:orders".into(),
            action: "select".into(),
            context: Some(v1::AuthenticationReceiptContext {
                issuer_ref: c.issuer_ref.into(),
                key_epoch: c.key_epoch,
                identity_authority_epoch: c.identity_authority_epoch.into(),
                identity: Some(v1::ReceiptIdentity {
                    subject_ref: c.identity.subject_ref.into(),
                    kind: 2,
                    aal: 0,
                    revision: c.identity.revision,
                    credential_generation: c.identity.credential_generation,
                }),
                service: c.service.into(),
                audience: c.audience.into(),
                request_sha256: c.request_sha256.to_vec(),
            }),
            receipt: receipt.to_vec(),
            request_sha256: c.request_sha256.to_vec(),
        });
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", std::env::var("PUMGYE_DECISION_TOKEN")?).parse()?,
        );
        request.set_timeout(std::time::Duration::from_secs(1));
        let reply = match client.decide(request).await {
            Ok(reply) => reply.into_inner(),
            Err(_) => return Ok(false),
        };
        ensure!(
            reply.request_id == 1
                && reply.revision >= 1
                && reply.network_revision >= 1
                && reply.cache_ttl_ms == 0
                && matches!(reply.verdict, 1 | 2),
            "invalid native gRPC reply"
        );
        return Ok(reply.verdict == 1);
    }
    let endpoint = config
        .pumgye_endpoint
        .as_ref()
        .ok_or_else(|| anyhow!("endpoint absent"))?;
    ensure!(
        (endpoint.starts_with("http://127.0.0.1:") || endpoint.starts_with("https://127.0.0.1:")),
        "owned endpoint required"
    );
    let c = checked.context();
    let body = serde_json::json!({"request_id":1,"minimum_revision":1,"resource":"db:orders","action":"select","ip":config.qualification_ip,"context":{"issuer_ref":c.issuer_ref,"key_epoch":c.key_epoch,"identity_authority_epoch":c.identity_authority_epoch,"identity":{"subject_ref":c.identity.subject_ref,"kind":2,"aal":0,"revision":c.identity.revision,"credential_generation":c.identity.credential_generation},"service":c.service,"audience":c.audience,"request_sha256":c.request_sha256},"receipt":receipt,"request_sha256":c.request_sha256});
    let mut http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(2));
    if endpoint.starts_with("https://") {
        let ca = std::fs::read(&config.settings.tls.ca)?;
        let mut identity = std::fs::read(&config.settings.tls.certificate)?;
        identity.extend(std::fs::read(&config.settings.tls.key)?);
        http = http
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .identity(reqwest::Identity::from_pem(&identity)?);
    }
    let response = http
        .build()?
        .post(endpoint)
        .bearer_auth(std::env::var("PUMGYE_DECISION_TOKEN")?)
        .json(&body)
        .send()
        .await?;
    if !response.status().is_success() {
        return Ok(false);
    }
    let result: serde_json::Value = response.json().await?;
    ensure!(
        result["request_id"] == 1 && result["ttl_ms"] == 0,
        "invalid native reply"
    );
    Ok(result["allow"] == true)
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow!("configuration required"))?,
    )?)?;
    let permit_network = match &config.permit_network {
        Some(path) => Some(
            pumgye_server::network_live_config::load(path, &|name| std::env::var(name).ok()).await,
        ),
        None => None,
    };
    let setup = async {
        ensure!(config.settings.transport == "grpc", "grpc required");
        let ca = std::fs::read(&config.settings.tls.ca)?;
        let cert = std::fs::read(&config.settings.tls.certificate)?;
        let key = std::fs::read(&config.settings.tls.key)?;
        let token = std::env::var("OWNED_RECEIPT_CALLER")?;
        let address = format!("https://{}", config.settings.address);
        let live = Client::connect(
            &address,
            &config.settings.tls.server_name,
            &ca,
            &cert,
            &key,
            &token,
        )
        .await
        .map_err(|_| anyhow!("live connection refused"))?;
        let tls = ClientTlsConfig::new()
            .domain_name(&config.settings.tls.server_name)
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, key));
        let channel = Endpoint::from_shared(address)?
            .tls_config(tls)?
            .connect()
            .await?;
        let issuer = v1::authentication_receipts_client::AuthenticationReceiptsClient::new(channel);
        let public_key: [u8; 32] = STANDARD
            .decode(&config.public_key)?
            .try_into()
            .map_err(|_| anyhow!("public pin invalid"))?;
        let trust = ServiceTrust::new(TrustConfiguration {
            issuer: config.issuer_ref.clone(),
            key_epoch: config.key_epoch,
            identity_epoch: config.identity_epoch.clone(),
            service: config.service.clone(),
            audience: config.audience.clone(),
            minimum_revision: 1,
            public_key,
        })
        .map_err(|_| anyhow!("trust refused"))?;
        let body: [u8; 32] = Sha256::digest(config.body.as_bytes()).into();
        let digest = request_binding::digest(&request_binding::Request {
            service: &config.service,
            audience: &config.audience,
            method: &config.method,
            target: &config.target,
            body_sha256: &body,
        })
        .map_err(|_| anyhow!("binding refused"))?;
        let rpc = if let Some(address) = &config.pumgye_grpc_address {
            ensure!(address.starts_with("https://localhost:") || address.starts_with("https://127.0.0.1:"), "owned gRPC address required");
            let tls = ClientTlsConfig::new().domain_name(&config.settings.tls.server_name).ca_certificate(Certificate::from_pem(std::fs::read(&config.settings.tls.ca)?)).identity(Identity::from_pem(std::fs::read(&config.settings.tls.certificate)?,std::fs::read(&config.settings.tls.key)?));
            let channel = Endpoint::from_shared(address.clone())?.timeout(std::time::Duration::from_secs(1)).connect_timeout(std::time::Duration::from_secs(1)).tls_config(tls)?.connect().await?;
            Some(pumgye_grpc::v1::authenticated_resource_authorization_client::AuthenticatedResourceAuthorizationClient::new(channel).max_encoding_message_size(4096).max_decoding_message_size(128))
        } else { None };
        Ok::<_, anyhow::Error>((live, issuer, trust, digest, token, rpc))
    }
    .await;
    let mut setup = setup.ok();
    let mut prior: Option<v1::ServiceReceiptReply> = None;
    for command in std::io::stdin().lock().lines() {
        let command = command?;
        ensure!(
            matches!(
                command.as_str(),
                "allow" | "deny" | "deny-network" | "outage"
            ),
            "unknown command"
        );
        if command == "outage" {
            let (live, _, trust, digest, _, rpc) = setup
                .as_mut()
                .ok_or_else(|| anyhow!("outage resources unavailable"))?;
            let old = prior
                .as_ref()
                .ok_or_else(|| anyhow!("outage proof absent"))?;
            let c = context(old)?;
            let checked = trust
                .verify(&c, &old.receipt, digest, now())
                .map_err(|_| anyhow!("outage proof expired before query"))?;
            ensure!(
                live.validate(&checked, &old.receipt, &now).await.is_err(),
                "outage validation accepted"
            );
            if config.pumgye_endpoint.is_some() || config.pumgye_grpc_address.is_some() {
                ensure!(
                    !endpoint(&config, &checked, &old.receipt, rpc).await?,
                    "endpoint accepted authority outage"
                );
            }
            println!("{}", serde_json::json!({"allowed":false}));
            std::io::stdout().flush()?;
            continue;
        }
        let result = async {
            let (live, issuer, trust, digest, token, rpc) =
                setup.as_mut().ok_or_else(|| anyhow!("resources refused"))?;
            if command == "deny"
                && let Some(old) = &prior
            {
                let c = context(old)?;
                let checked = trust.verify(&c, &old.receipt, digest, now()).expect(
                    "cached proof must remain cryptographically valid during revocation test",
                );
                assert!(
                    live.validate(&checked, &old.receipt, &now).await.is_err(),
                    "retired proof accepted"
                );
                if config.pumgye_endpoint.is_some() || config.pumgye_grpc_address.is_some() { assert!(!endpoint(&config, &checked, &old.receipt, rpc).await?, "endpoint accepted retired proof"); }
            }
            let mut headers: Vec<_> = config
                .headers
                .iter()
                .map(|(name, value)| v1::Header {
                    name: name.clone(),
                    value: value.as_bytes().to_vec(),
                })
                .collect();
            headers.push(v1::Header {
                name: "authorization".into(),
                value: format!("Bearer {}", std::env::var("OWNED_RECEIPT_CREDENTIAL")?)
                    .into_bytes(),
            });
            let mut request = tonic::Request::new(v1::ServiceReceiptRequest {
                verification: Some(v1::VerifyRequest {
                    request_id: 1,
                    headers,
                }),
                service: config.service.clone(),
                audience: config.audience.clone(),
                request_sha256: digest.to_vec(),
            });
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse()?);
            let reply = issuer.issue_service(request).await?.into_inner();
            let c = context(&reply)?;
            let checked = trust
                .verify(&c, &reply.receipt, digest, now())
                .map_err(|_| anyhow!("local verification refused"))?;
            let observation = live
                .validate(&checked, &reply.receipt, &now)
                .await
                .map_err(|_| anyhow!("live verification refused"))?;
            ensure!(
                observation.valid_for(&checked, now()),
                "observation expired"
            );
            let mut policy = serde_json::json!({"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"require_guard":false,"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":0}},"users":{},"networks":[{"cidr":format!("{}/{}",config.qualification_ip,if config.qualification_ip.contains(':') {128} else {32}),"roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"},"minimum_aal":0}}});
            policy["services"]["orders"]["users"][checked.subject()] = serde_json::json!(["reader"]);
            let compiled = std::sync::Arc::new(serde_json::from_value::<pumgye_core::Policy>(policy)?.compile()?);
            let owner = arc_swap::ArcSwap::from(compiled.clone());
            let resource_request = pumgye_server::authorization::ResourceRequest { resource: "db:orders", action: "select", ip: config.qualification_ip.parse()?, guard: pumgye_core::GuardEvidence::Unavailable, network_expires_ms: checked.expires_ms() };
            let native_class = pumgye_server::authorization::authorize_live_resource_then(&compiled, &resource_request, &checked, &observation, now, || std::sync::Arc::ptr_eq(&owner.load_full(), &compiled), |resource| resource.information_class.clone()).map_err(|_| anyhow!("native resource refused"))?;
            ensure!(native_class == "internal", "owner classification changed");
            if config.pumgye_endpoint.is_some() || config.pumgye_grpc_address.is_some() { ensure!(endpoint(&config, &checked, &reply.receipt, rpc).await?, "native endpoint refused Allow"); }
            if let Some(network) = &permit_network {
                let network = network.as_ref().map_err(|_| anyhow!("permit network resources refused"))?;
                let ip = config.qualification_ip.parse()?;
                let network = network.check(ip, 1, &now).await.map_err(|_| anyhow!("permit network observation refused"))?;
                let evidence = pumgye_server::authorization::LiveEvidence { authentication: &observation, network: &network };
                let target = pumgye_server::authorization::NativeResourceRequest { resource: "db:orders", action: "select", ip };
                let mut seed = zeroize::Zeroizing::new([0; 32]);
                getrandom::fill(seed.as_mut()).map_err(|_| anyhow!("permit entropy unavailable"))?;
                let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                let public = key.verifying_key();
                let signer = pumgye_server::permit::Signer::new("owned-pumgye".into(), 1, key).map_err(|_| anyhow!("permit signer refused"))?;
                // These are local synthetic fixture owners, not remote route or
                // projection discovery and not downstream replay admission.
                let deadline = now().checked_add(1000).ok_or_else(|| anyhow!("permit clock overflow"))?;
                let state = pumgye_server::permit::State { decision_ref: "owned-decision", authority_epoch: "owned-policy", policy_revision: 1, network_revision: network.revision(), route_revision: 1, plan_revision: 1, policy_expires_ms: deadline, route_expires_ms: deadline, plan_expires_ms: deadline };
                let signed = signer.issue_combined(&compiled, &target, &checked, &evidence, &state, now, || std::sync::Arc::ptr_eq(&owner.load_full(), &compiled)).map_err(|_| anyhow!("combined permit refused"))?;
                let binding = receipt_binding::digest(signed.context(), Some(signed.permit())).map_err(|_| anyhow!("permit binding refused"))?;
                hopae_grpc::receipt::verify(&public, signed.bytes(), hopae_grpc::receipt::Purpose::Permit, &binding, now()).map_err(|_| anyhow!("permit signature refused"))?;
                ensure!(signed.expires_ms() <= network.expires_ms() && signed.expires_ms() <= checked.expires_ms(), "permit exceeded evidence deadline");
            }
            let revision = checked.revision();
            prior = Some(reply);
            Ok::<_, anyhow::Error>(revision)
        }
        .await;
        match (command.as_str(), result) {
            ("allow", Ok(revision)) => println!(
                "{}",
                serde_json::json!({"allowed":true,"revision":revision,"permit_candidate":config.permit_network.is_some()})
            ),
            ("deny" | "deny-network", Err(_)) => {
                println!("{}", serde_json::json!({"allowed":false}))
            }
            _ => return Err(anyhow!("result differed from expected outcome")),
        }
        std::io::stdout().flush()?;
    }
    Ok(())
}
