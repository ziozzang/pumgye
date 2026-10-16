use super::*;
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    listen: SocketAddr,
    cluster: String,
    authority: String,
    certificate: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
    client_sha256: Vec<String>,
    caller_token_env: String,
}
// Deliberately no Debug/Serialize: caller credentials never enter diagnostics.
pub(crate) struct Configuration {
    pub(super) listen: SocketAddr,
    pub(super) cluster: String,
    pub(super) authority: String,
    pub(super) tls: Arc<pumgye_server::tls_reload::Reloading<rustls::ServerConfig>>,
    pub(super) fingerprints: Vec<[u8; 32]>,
    pub(super) token: Zeroizing<String>,
}
pub(crate) fn load(
    path: &Path,
    resolve: &dyn Fn(&str) -> Option<String>,
    forbidden: &[&str],
) -> Result<Configuration> {
    let mut bytes = Zeroizing::new(Vec::new());
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "SAR configuration must be a file"
    );
    file.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "SAR configuration bound");
    let w: Wire =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid SAR configuration"))?;
    ensure!(
        w.version == 1
            && !w.cluster.is_empty()
            && w.cluster.len() <= 64
            && w.cluster
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid SAR cluster/version"
    );
    ensure!(
        !w.authority.is_empty()
            && w.authority.len() <= 256
            && w.authority.is_ascii()
            && w.authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:-[]".contains(&b)),
        "invalid SAR HTTP authority"
    );
    let authority_url = reqwest::Url::parse(&format!("https://{}", w.authority))
        .map_err(|_| anyhow::anyhow!("invalid SAR HTTP authority"))?;
    ensure!(
        authority_url.host_str().is_some()
            && authority_url.path() == "/"
            && authority_url.query().is_none()
            && authority_url.fragment().is_none(),
        "invalid SAR HTTP authority"
    );
    ensure!(
        !w.client_sha256.is_empty() && w.client_sha256.len() <= 16,
        "SAR caller fingerprint bound"
    );
    let mut fingerprints = vec![];
    for value in w.client_sha256 {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid SAR fingerprint"
        );
        let mut digest = [0; 32];
        for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            digest[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
        }
        ensure!(!fingerprints.contains(&digest), "duplicate SAR fingerprint");
        fingerprints.push(digest);
    }
    ensure!(
        !w.caller_token_env.is_empty()
            && w.caller_token_env.len() <= 128
            && w.caller_token_env
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "invalid SAR credential reference"
    );
    let token = Zeroizing::new(
        resolve(&w.caller_token_env)
            .ok_or_else(|| anyhow::anyhow!("SAR caller credential unavailable"))?,
    );
    ensure!(
        (32..=4096).contains(&token.len())
            && token.bytes().all(|b| b.is_ascii_graphic())
            && forbidden
                .iter()
                .all(|v| !crate::credential_matches(v.as_bytes(), token.as_bytes())),
        "distinct bounded SAR caller credential required"
    );
    let (c, k, a) = (w.certificate.clone(), w.key.clone(), w.client_ca.clone());
    let tls = pumgye_server::tls_reload::Reloading::new(
        "sar listener",
        vec![c.clone(), k.clone(), a.clone()],
        Some(c.clone()),
        move || {
            let mut config =
                Arc::unwrap_or_clone(crate::transport::tls_config(&c, &k, &a, &[b"http/1.1"])?);
            config.send_tls13_tickets = 0;
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.max_early_data_size = 0;
            Ok(config)
        },
    )?;
    // Default rustls ticketer is disabled; no custom resumable ticket provider.
    let _ = Budget::new(Duration::from_secs(1))?;
    Ok(Configuration {
        listen: w.listen,
        cluster: w.cluster,
        authority: w.authority,
        tls,
        fingerprints,
        token,
    })
}
