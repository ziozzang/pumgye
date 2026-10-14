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
#[derive(Deserialize)]
struct Config {
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
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow!("configuration required"))?,
    )?)?;
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
            identity_epoch: "epoch1".into(),
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
        Ok::<_, anyhow::Error>((live, issuer, trust, digest, token))
    }
    .await;
    let mut setup = setup.ok();
    let mut prior: Option<v1::ServiceReceiptReply> = None;
    for command in std::io::stdin().lock().lines() {
        let command = command?;
        ensure!(
            matches!(command.as_str(), "allow" | "deny" | "outage"),
            "unknown command"
        );
        if command == "outage" {
            let (live, _, trust, digest, _) = setup
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
            println!("{}", serde_json::json!({"allowed":false}));
            std::io::stdout().flush()?;
            continue;
        }
        let result = async {
            let (live, issuer, trust, digest, token) =
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
            let revision = checked.revision();
            prior = Some(reply);
            Ok::<_, anyhow::Error>(revision)
        }
        .await;
        match (command.as_str(), result) {
            ("allow", Ok(revision)) => println!(
                "{}",
                serde_json::json!({"allowed":true,"revision":revision})
            ),
            ("deny", Err(_)) => println!("{}", serde_json::json!({"allowed":false})),
            _ => return Err(anyhow!("result differed from expected outcome")),
        }
        std::io::stdout().flush()?;
    }
    Ok(())
}
