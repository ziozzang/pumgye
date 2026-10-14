//! Shared static transport construction for native authority clients.
use std::time::Duration;
use tonic::{
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};
#[derive(Debug)]
pub(crate) struct Refused;
pub(crate) async fn connect(
    address: &str,
    server_name: &str,
    ca: &[u8],
    certificate: &[u8],
    key: &[u8],
    token: &str,
) -> Result<(Channel, MetadataValue<tonic::metadata::Ascii>), Refused> {
    if !address.starts_with("https://")
        || address.len() > 256
        || server_name.is_empty()
        || server_name.len() > 253
        || !server_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        || [ca, certificate, key]
            .iter()
            .any(|value| value.is_empty() || value.len() > 128 * 1024)
        || !(32..=4096).contains(&token.len())
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(crate::authority_transport::Refused);
    }
    let credential = format!("Bearer {token}")
        .parse()
        .map_err(|_| crate::authority_transport::Refused)?;
    let tls = ClientTlsConfig::new()
        .domain_name(server_name)
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(certificate, key));
    let endpoint = Endpoint::from_shared(address.to_owned())
        .map_err(|_| crate::authority_transport::Refused)?
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(1))
        .tcp_nodelay(true)
        .tls_config(tls)
        .map_err(|_| crate::authority_transport::Refused)?;
    let channel = tokio::time::timeout(Duration::from_secs(1), endpoint.connect())
        .await
        .map_err(|_| crate::authority_transport::Refused)?
        .map_err(|_| crate::authority_transport::Refused)?;
    Ok((channel, credential))
}
