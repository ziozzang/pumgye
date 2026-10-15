//! Reference-only native route/plan authority loading.
use crate::route_live::{Client, Refused};
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub address: String,
    pub server_name: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub token_env: String,
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
pub fn load(path: &Path, resolve: &dyn Fn(&str) -> Option<String>) -> Result<Client, Refused> {
    load_with(path, resolve, Client::prepare)
}
pub fn load_plan(
    path: &Path,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Result<crate::plan_live::Client, Refused> {
    load_with(
        path,
        resolve,
        |address, name, ca, certificate, key, token| {
            crate::plan_live::Client::prepare(address, name, ca, certificate, key, token)
                .map_err(|_| Refused)
        },
    )
}
fn load_with<T>(
    path: &Path,
    resolve: &dyn Fn(&str) -> Option<String>,
    prepare: impl FnOnce(&str, &str, &[u8], &[u8], &[u8], &str) -> Result<T, Refused>,
) -> Result<T, Refused> {
    let config: Configuration =
        serde_json::from_slice(&read(path, 16 * 1024)?).map_err(|_| Refused)?;
    if config.token_env.is_empty()
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
    prepare(
        &config.address,
        &config.server_name,
        &ca,
        &certificate,
        &key,
        &token,
    )
}
