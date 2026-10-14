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
        clock: &dyn Fn() -> u64,
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
