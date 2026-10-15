//! Reference-only native mTLS validation resource loading.
use crate::{
    authentication::CheckedService,
    authentication_live::{Client, Observation, Refused},
};
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub issuer_ref: String,
    pub address: String,
    pub server_name: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub token_env: String,
    /// Required only when activating the separate observed permit owner.
    #[serde(default)]
    pub observed_clock_rates: Option<ObservedClockRates>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedClockRates {
    pub source_ppm: u32,
    pub receiver_ppm: u32,
}
#[cfg(feature = "observed-authentication")]
pub struct ConfiguredObserved {
    pub owner: std::sync::Arc<crate::authentication_observed::AuthenticationOwnerGeneration>,
    pub rates: hopae_grpc::receipt_time::ClockRates,
}
pub struct Configured {
    issuer: String,
    client: Client,
}
impl Configured {
    pub async fn validate(
        &self,
        checked: &CheckedService<'_>,
        receipt: &[u8],
        clock: &(dyn Fn() -> u64 + Sync),
    ) -> Result<Observation, Refused> {
        if checked.context().issuer_ref != self.issuer {
            return Err(Refused);
        }
        self.client.validate(checked, receipt, clock).await
    }
}
fn read(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, Refused> {
    let file = std::fs::File::open(path).map_err(|_| Refused)?;
    if !file.metadata().map_err(|_| Refused)?.is_file() {
        return Err(Refused);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refused)?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(Refused);
    }
    Ok(bytes)
}
pub async fn load(
    path: &Path,
    trust: &crate::authentication_config::Trust,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Result<Configured, Refused> {
    let bytes = read(path, 16 * 1024)?;
    let config: Configuration = serde_json::from_slice(&bytes).map_err(|_| Refused)?;
    if !trust.has_issuer(&config.issuer_ref)
        || config.token_env.is_empty()
        || config.token_env.len() > 128
        || !config
            .token_env
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(Refused);
    }
    let token = Zeroizing::new(resolve(&config.token_env).ok_or(Refused)?);
    let ca = read(&config.ca, 128 * 1024)?;
    let certificate = read(&config.certificate, 128 * 1024)?;
    let key = read(&config.key, 128 * 1024)?;
    let client = Client::connect(
        &config.address,
        &config.server_name,
        &ca,
        &certificate,
        &key,
        &token,
    )
    .await?;
    Ok(Configured {
        issuer: config.issuer_ref,
        client,
    })
}

/// Additive observed native owner, using the same fixed endpoint resources.
/// Strict Configured/ValidateService behavior remains unchanged.
#[cfg(feature = "observed-authentication")]
pub fn load_observed(
    path: &Path,
    trust: std::sync::Arc<crate::authentication_config::Trust>,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Result<ConfiguredObserved, crate::authentication::Refused> {
    use crate::{
        authentication::Refused,
        authentication_observed::{
            AuthenticationOwnerGeneration, Configuration as ObservedConfiguration,
        },
    };
    let bytes = read(path, 16 * 1024).map_err(|_| Refused)?;
    let config: Configuration = serde_json::from_slice(&bytes).map_err(|_| Refused)?;
    let bounds = config.observed_clock_rates.as_ref().ok_or(Refused)?;
    let rates = || {
        hopae_grpc::receipt_time::ClockRates::new(bounds.source_ppm, bounds.receiver_ppm)
            .map_err(|_| Refused)
    };
    let native_rates = rates()?;
    if !trust.has_issuer(&config.issuer_ref)
        || config.token_env.is_empty()
        || config.token_env.len() > 128
        || !config
            .token_env
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(Refused);
    }
    let token = Zeroizing::new(resolve(&config.token_env).ok_or(Refused)?);
    let ca = read(&config.ca, 128 * 1024).map_err(|_| Refused)?;
    let cert = read(&config.certificate, 128 * 1024).map_err(|_| Refused)?;
    let key = read(&config.key, 128 * 1024).map_err(|_| Refused)?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| Refused)?;
    let owner = AuthenticationOwnerGeneration::new(
        trust,
        ObservedConfiguration {
            issuer_ref: &config.issuer_ref,
            endpoint: hopae_grpc::observed_client::EndpointConfig {
                address: &config.address,
                server_name: &config.server_name,
                ca: &ca,
                certificate: &cert,
                private_key: &key,
                caller_key: &token,
            },
            minimum_application_generation: 1,
            minimum_key_registry_revision: 1,
        },
        std::sync::Arc::new(hangang_runtime::time::ReceiverClock::new(nonce).map_err(|_| Refused)?),
        rates()?,
        hopae_grpc::observed_client::Limits {
            concurrent: 128,
            timeout: std::time::Duration::from_secs(1),
        },
    )?;
    Ok(ConfiguredObserved {
        owner,
        rates: native_rates,
    })
}

#[cfg(all(test, feature = "observed-authentication"))]
mod observed_tests {
    use super::*;
    use base64::Engine;
    #[test]
    fn observed_activation_requires_explicit_valid_rates_before_secret_resolution() {
        let trust = std::sync::Arc::new(
            crate::authentication_config::Trust::compile(crate::authentication_config::Document {
                entries: vec![crate::authentication_config::Entry {
                    issuer_ref: "hopae".into(),
                    key_epoch: 1,
                    identity_epoch: "owner".into(),
                    service: "orders".into(),
                    audience: "api".into(),
                    minimum_revision: 1,
                    public_key: base64::engine::general_purpose::STANDARD.encode(
                        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                }],
            })
            .unwrap(),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.json");
        let mut value = serde_json::json!({"issuer_ref":"hopae","address":"https://hopae.test:443","server_name":"hopae.test","ca":"ca.pem","certificate":"client.pem","key":"client.key","token_env":"CALLER"});
        let parsed: Configuration = serde_json::from_value(value.clone()).unwrap();
        assert!(parsed.observed_clock_rates.is_none()); // strict remains compatible
        for rates in [
            None,
            Some(serde_json::json!({"source_ppm":1000000,"receiver_ppm":50})),
            Some(serde_json::json!({"source_ppm":50,"receiver_ppm":1000000})),
        ] {
            if let Some(rates) = rates {
                value["observed_clock_rates"] = rates;
            }
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(
                load_observed(&path, trust.clone(), &|_| panic!(
                    "invalid/missing rates must fail before resolving secrets"
                ))
                .is_err()
            );
        }
        value["observed_clock_rates"] = serde_json::json!({"source_ppm":500,"receiver_ppm":700});
        let parsed: Configuration = serde_json::from_value(value).unwrap();
        let rates = parsed.observed_clock_rates.unwrap();
        assert_eq!((rates.source_ppm, rates.receiver_ppm), (500, 700));
    }
}
