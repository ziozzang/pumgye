//! Shared transport construction for native authority clients. TLS material is
//! a reloading rustls client configuration: a rotated certificate, key or CA is
//! used for the next connection without restarting (see `tls_reload`).
use crate::tls_reload::{self, Reloading};
use rustls::ClientConfig;
use std::{sync::Arc, time::Duration};
use tonic::{
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
};
#[derive(Debug)]
pub(crate) struct Refused;
type Credential = MetadataValue<tonic::metadata::Ascii>;
fn endpoint(
    address: &str,
    server_name: &str,
    tls: Arc<Reloading<ClientConfig>>,
    token: &str,
) -> Result<(Endpoint, tls_reload::Connector, Credential), Refused> {
    if !address.starts_with("https://")
        || address.len() > 256
        || server_name.is_empty()
        || server_name.len() > 253
        || !server_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        || !(32..=4096).contains(&token.len())
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(Refused);
    }
    let mut credential: Credential = format!("Bearer {token}").parse().map_err(|_| Refused)?;
    credential.set_sensitive(true);
    let connector = tls_reload::Connector::new(tls, server_name).map_err(|_| Refused)?;
    // TLS is performed by the reloading connector, so tonic's own TLS layer is
    // bypassed: it refuses `https` URIs without a tonic TLS config. Dial the
    // `http` form of the address and keep `https` as the request origin.
    let origin: tonic::codegen::http::Uri = address.parse().map_err(|_| Refused)?;
    let endpoint = Endpoint::from_shared(format!("http://{}", &address["https://".len()..]))
        .map_err(|_| Refused)?
        .origin(origin)
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(1))
        .tcp_nodelay(true);
    Ok((endpoint, connector, credential))
}
/// Static PEM material (embedded fixtures); production loaders use files.
pub(crate) fn static_tls(
    ca: &[u8],
    certificate: &[u8],
    key: &[u8],
) -> Result<Arc<Reloading<ClientConfig>>, Refused> {
    if [ca, certificate, key]
        .iter()
        .any(|value| value.is_empty() || value.len() > 128 * 1024)
    {
        return Err(Refused);
    }
    tls_reload::client_static(ca, certificate, key, &[b"h2"]).map_err(|_| Refused)
}
/// Reloading material from files.
pub(crate) fn file_tls(
    name: &str,
    ca: &std::path::Path,
    certificate: &std::path::Path,
    key: &std::path::Path,
) -> Result<Arc<Reloading<ClientConfig>>, Refused> {
    tls_reload::client(name, ca, certificate, key, &[b"h2"]).map_err(|_| Refused)
}
pub(crate) fn lazy(
    address: &str,
    server_name: &str,
    tls: Arc<Reloading<ClientConfig>>,
    token: &str,
) -> Result<(Channel, Credential), Refused> {
    let (endpoint, connector, credential) = endpoint(address, server_name, tls, token)?;
    Ok((endpoint.connect_with_connector_lazy(connector), credential))
}
pub(crate) async fn connect(
    address: &str,
    server_name: &str,
    tls: Arc<Reloading<ClientConfig>>,
    token: &str,
) -> Result<(Channel, Credential), Refused> {
    let (endpoint, connector, credential) = endpoint(address, server_name, tls, token)?;
    let channel = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.connect_with_connector(connector),
    )
    .await
    .map_err(|_| Refused)?
    .map_err(|_| Refused)?;
    Ok((channel, credential))
}
