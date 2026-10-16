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
    let tls = crate::authority_transport::file_tls(
        "authentication_live client",
        &config.ca,
        &config.certificate,
        &config.key,
    )
    .map_err(|_| Refused)?;
    let client = Client::connect_tls(&config.address, &config.server_name, tls, &token).await?;
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

/// Separate Workload client publication; Service activation is unchanged.
#[cfg(feature = "observed-authentication")]
pub struct ConfiguredWorkloadObserved {
    pub owner:
        std::sync::Arc<crate::authentication_workload_observed::AuthenticationOwnerGeneration>,
    pub rates: hopae_grpc::receipt_time::ClockRates,
}
/// Additive observed native owner, using the same fixed endpoint resources.
/// Strict Configured/ValidateService behavior remains unchanged.
#[cfg(feature = "observed-authentication")]
pub fn load_workload_observed(
    path: &Path,
    trust: std::sync::Arc<crate::authentication_config::Trust>,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Result<ConfiguredWorkloadObserved, crate::authentication::Refused> {
    use crate::{
        authentication::Refused,
        authentication_workload_observed::{
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
    Ok(ConfiguredWorkloadObserved {
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

/// Separate Human-only configuration. No raw caller identity/endpoint in queries.
#[cfg(feature = "observed-authentication")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanConfiguration {
    pub transport: Configuration,
    pub minimum_source_revision: u64,
    pub minimum_application_generation: u64,
    pub minimum_key_registry_revision: u64,
    pub scopes: Vec<HumanScopeConfiguration>,
}
#[cfg(feature = "observed-authentication")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanScopeConfiguration {
    pub service: String,
    pub audience: String,
    pub app_id: String,
    pub route_id: String,
    pub route_revision: u64,
    pub destination_sha256: [u8; 32],
    pub header_policy_revision: u64,
    pub header_names: Vec<String>,
    pub reserved_names: Vec<String>,
}
#[cfg(feature = "observed-authentication")]
pub struct ConfiguredHumanObserved {
    pub owner: std::sync::Arc<crate::authentication_human_observed::AuthenticationOwnerGeneration>,
    pub rates: hopae_grpc::receipt_time::ClockRates,
}
#[cfg(feature = "observed-authentication")]
pub fn load_human_observed(
    path: &Path,
    trust: std::sync::Arc<crate::authentication_config::Trust>,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Result<ConfiguredHumanObserved, crate::authentication::Refused> {
    use crate::authentication::Refused;
    let bytes = read(path, 64 * 1024).map_err(|_| Refused)?;
    let human: HumanConfiguration = serde_json::from_slice(&bytes).map_err(|_| Refused)?;
    if ![
        human.minimum_source_revision,
        human.minimum_application_generation,
        human.minimum_key_registry_revision,
    ]
    .iter()
    .all(|n| (1..=9_007_199_254_740_991).contains(n))
        || human.scopes.is_empty()
        || human.scopes.len() > 128
    {
        return Err(Refused);
    }
    let c = human.transport;
    let bounds = c.observed_clock_rates.as_ref().ok_or(Refused)?;
    let rates = || {
        hopae_grpc::receipt_time::ClockRates::new(bounds.source_ppm, bounds.receiver_ppm)
            .map_err(|_| Refused)
    };
    if !trust.has_issuer(&c.issuer_ref)
        || c.token_env.is_empty()
        || c.token_env.len() > 128
        || !c
            .token_env
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(Refused);
    }
    let token = Zeroizing::new(resolve(&c.token_env).ok_or(Refused)?);
    let ca = read(&c.ca, 128 * 1024).map_err(|_| Refused)?;
    let cert = read(&c.certificate, 128 * 1024).map_err(|_| Refused)?;
    let key = read(&c.key, 128 * 1024).map_err(|_| Refused)?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| Refused)?;
    let scopes = human
        .scopes
        .into_iter()
        .map(|s| hopae_grpc::human_observed_client::HumanScope {
            service: s.service,
            audience: s.audience,
            app_id: s.app_id,
            route_id: s.route_id,
            route_revision: s.route_revision,
            destination_sha256: s.destination_sha256,
            header_policy_revision: s.header_policy_revision,
            header_names: s.header_names,
            reserved_names: s.reserved_names,
        })
        .collect();
    let owner = crate::authentication_human_observed::AuthenticationOwnerGeneration::new(
        trust,
        crate::authentication_human_observed::Configuration {
            issuer_ref: &c.issuer_ref,
            endpoint: hopae_grpc::human_observed_client::EndpointConfig {
                address: &c.address,
                server_name: &c.server_name,
                ca: &ca,
                certificate: &cert,
                private_key: &key,
                caller_key: &token,
            },
            scopes,
            minimum_source_revision: human.minimum_source_revision,
            minimum_application_generation: human.minimum_application_generation,
            minimum_key_registry_revision: human.minimum_key_registry_revision,
        },
        std::sync::Arc::new(hangang_runtime::time::ReceiverClock::new(nonce).map_err(|_| Refused)?),
        rates()?,
        hopae_grpc::human_observed_client::Limits {
            concurrent: 128,
            timeout: std::time::Duration::from_secs(1),
        },
    )?;
    Ok(ConfiguredHumanObserved {
        owner,
        rates: rates()?,
    })
}

#[cfg(all(test, feature = "observed-authentication"))]
mod human_config_tests {
    use super::*;
    use base64::Engine;
    #[test]
    fn human_config_refuses_missing_rates_unknown_fields_and_bad_floors_before_secret_resolution() {
        let trust = std::sync::Arc::new(
            crate::authentication_config::Trust::compile(crate::authentication_config::Document {
                entries: vec![crate::authentication_config::Entry {
                    issuer_ref: "hopae".into(),
                    key_epoch: 1,
                    identity_epoch: "owned".into(),
                    service: "orders".into(),
                    audience: "api".into(),
                    minimum_revision: 1,
                    public_key: base64::engine::general_purpose::STANDARD.encode(
                        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                            .verifying_key()
                            .as_bytes(),
                    ),
                }],
            })
            .unwrap(),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("human.json");
        let base = serde_json::json!({"transport":{"issuer_ref":"hopae","address":"https://hopae.test:443","server_name":"hopae.test","ca":"missing.pem","certificate":"missing.pem","key":"missing.key","token_env":"CALLER"},"minimum_source_revision":1,"minimum_application_generation":1,"minimum_key_registry_revision":1,"scopes":[{"service":"orders","audience":"api","app_id":"app","route_id":"route","route_revision":1,"destination_sha256":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"header_policy_revision":1,"header_names":[],"reserved_names":[]}]});
        for mode in 0..4 {
            let mut value = base.clone();
            match mode {
                0 => {}
                1 => value["unexpected"] = true.into(),
                2 => value["minimum_source_revision"] = 0.into(),
                _ => value["scopes"] = serde_json::json!([]),
            };
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let calls = std::cell::Cell::new(0);
            assert!(
                load_human_observed(&path, trust.clone(), &|_| {
                    calls.set(calls.get() + 1);
                    Some("secret-never-read".into())
                })
                .is_err()
            );
            assert_eq!(calls.get(), 0);
        }
    }
}
