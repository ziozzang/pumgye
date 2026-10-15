//! Configured persistent mTLS route owner observations, never permission leases.
use hangang_route_grpc::v1::{
    RouteReply, RouteRequest, route_ownership_client::RouteOwnershipClient,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tonic::{metadata::MetadataValue, transport::Channel};
const MAXIMUM: u64 = 9_007_199_254_740_991;
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Expected<'a> {
    pub reference: &'a [u8; 32],
    pub request_sha256: &'a [u8; 32],
    pub destination_sha256: &'a [u8; 32],
    pub service: &'a str,
    pub audience: &'a str,
    pub resource: &'a str,
    pub action: &'a str,
    pub ip: IpAddr,
}
pub struct Client {
    client: RouteOwnershipClient<Channel>,
    credential: MetadataValue<tonic::metadata::Ascii>,
    admission: Semaphore,
    sequence: AtomicU64,
    owner: Arc<()>,
}
/// No public constructor/Clone/Debug/serde. Native scope and transport owner are
/// retained; local expiry alone cannot prove remote state is still current.
pub struct Observation<'a> {
    expected: Expected<'a>,
    owner: Arc<()>,
    route_id: String,
    revision: u64,
    before_ms: u64,
    expires_ms: u64,
    begun: Instant,
}
impl Observation<'_> {
    pub fn configuration_revision(&self) -> u64 {
        self.revision
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub fn valid_at(&self, now_ms: u64) -> bool {
        now_ms >= self.before_ms
            && now_ms.max(
                self.before_ms
                    .saturating_add(self.begun.elapsed().as_millis().min(u64::MAX as u128) as u64),
            ) < self.expires_ms
    }
    pub fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
            && self.expected == other.expected
            && self.route_id == other.route_id
            && self.revision == other.revision
    }
    pub fn belongs_to(&self, client: &Client) -> bool {
        Arc::ptr_eq(&self.owner, &client.owner)
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}
impl Client {
    /// Construction is lazy to avoid a gateway/authority startup cycle. TLS
    /// resources are validated now; no observation exists before an actual RPC.
    pub fn prepare(
        address: &str,
        server_name: &str,
        ca: &[u8],
        certificate: &[u8],
        key: &[u8],
        token: &str,
    ) -> Result<Self, Refused> {
        let uri: tonic::codegen::http::Uri = address.parse().map_err(|_| Refused)?;
        if token.len() > 256
            || uri.scheme_str() != Some("https")
            || uri
                .authority()
                .is_none_or(|authority| authority.as_str().contains('@'))
            || uri
                .path_and_query()
                .is_some_and(|path| path.as_str() != "/")
            || uri.port_u16() == Some(0)
        {
            return Err(Refused);
        }
        let (channel, credential) =
            crate::authority_transport::lazy(address, server_name, ca, certificate, key, token)
                .map_err(|_| Refused)?;
        Ok(Self {
            client: RouteOwnershipClient::new(channel)
                .max_encoding_message_size(512)
                .max_decoding_message_size(1024),
            credential,
            admission: Semaphore::new(128),
            sequence: AtomicU64::new(1),
            owner: Arc::new(()),
        })
    }
    pub async fn observe<'a>(
        &self,
        expected: Expected<'a>,
        clock: &(dyn Fn() -> u64 + Sync),
    ) -> Result<Observation<'a>, Refused> {
        if ![
            expected.service,
            expected.audience,
            expected.resource,
            expected.action,
        ]
        .into_iter()
        .all(identifier)
        {
            return Err(Refused);
        }
        let _admission = self.admission.try_acquire().map_err(|_| Refused)?;
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < MAXIMUM).then_some(value + 1)
            })
            .map_err(|_| Refused)?;
        let before_ms = clock();
        let begun = Instant::now();
        let mut request = tonic::Request::new(RouteRequest {
            request_id,
            reference: expected.reference.to_vec(),
            request_sha256: expected.request_sha256.to_vec(),
            destination_sha256: expected.destination_sha256.to_vec(),
        });
        request
            .metadata_mut()
            .insert("authorization", self.credential.clone());
        request.set_timeout(Duration::from_secs(1));
        let reply =
            tokio::time::timeout(Duration::from_secs(1), self.client.clone().observe(request))
                .await
                .map_err(|_| Refused)?
                .map_err(|_| Refused)?
                .into_inner();
        self.accept(expected, request_id, before_ms, clock(), begun, reply)
    }
    fn accept<'a>(
        &self,
        expected: Expected<'a>,
        request_id: u64,
        before_ms: u64,
        after_ms: u64,
        begun: Instant,
        reply: RouteReply,
    ) -> Result<Observation<'a>, Refused> {
        let ip = match reply.client_ip.as_slice() {
            value if value.len() == 4 => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(value).map_err(|_| Refused)?,
            )),
            value if value.len() == 16 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(value).map_err(|_| Refused)?,
            )),
            _ => return Err(Refused),
        };
        if reply.request_id != request_id
            || reply.configuration_revision > MAXIMUM
            || !identifier(&reply.route_id)
            || reply.service != expected.service
            || reply.audience != expected.audience
            || reply.resource != expected.resource
            || reply.action != expected.action
            || ip != expected.ip
            || reply.request_sha256.as_slice() != expected.request_sha256
            || reply.destination_sha256.as_slice() != expected.destination_sha256
            || !(1..=1000).contains(&reply.remaining_ms)
            || after_ms < before_ms
        {
            return Err(Refused);
        }
        let observed = Observation {
            expected,
            owner: self.owner.clone(),
            route_id: reply.route_id,
            revision: reply.configuration_revision,
            before_ms,
            expires_ms: before_ms
                .checked_add(u64::from(reply.remaining_ms))
                .ok_or(Refused)?,
            begun,
        };
        if !observed.valid_at(after_ms) {
            return Err(Refused);
        }
        Ok(observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client() -> Client {
        Client {
            client: RouteOwnershipClient::new(
                Channel::from_static("https://owned.example.test").connect_lazy(),
            ),
            credential: "Bearer owned-fixture".parse().unwrap(),
            admission: Semaphore::new(1),
            sequence: AtomicU64::new(1),
            owner: Arc::new(()),
        }
    }
    fn expected() -> Expected<'static> {
        Expected {
            reference: &[1; 32],
            request_sha256: &[2; 32],
            destination_sha256: &[3; 32],
            service: "orders",
            audience: "orders-api",
            resource: "db:orders",
            action: "select",
            ip: "192.0.2.9".parse().unwrap(),
        }
    }
    fn reply() -> RouteReply {
        RouteReply {
            request_id: 7,
            configuration_revision: 0,
            route_id: "orders".into(),
            service: "orders".into(),
            audience: "orders-api".into(),
            resource: "db:orders".into(),
            action: "select".into(),
            client_ip: vec![192, 0, 2, 9],
            request_sha256: vec![2; 32],
            destination_sha256: vec![3; 32],
            remaining_ms: 500,
        }
    }
    #[tokio::test]
    async fn native_scope_exchange_time_and_client_identity_remain_bound() {
        let client = client();
        let other = super::tests::client();
        let first = client
            .accept(expected(), 7, 1000, 1001, Instant::now(), reply())
            .unwrap();
        assert_eq!(first.configuration_revision(), 0);
        assert_eq!(first.expires_ms(), 1500);
        assert!(first.valid_at(1002));
        assert!(!first.valid_at(999));
        assert!(!first.valid_at(1500));
        assert!(first.belongs_to(&client));
        assert!(!first.belongs_to(&other));
        let second = client
            .accept(expected(), 7, 1000, 1001, Instant::now(), reply())
            .unwrap();
        assert!(first.same_owner(&second));
        let foreign = other
            .accept(expected(), 7, 1000, 1001, Instant::now(), reply())
            .unwrap();
        assert!(!first.same_owner(&foreign));
        let mut changed = reply();
        changed.configuration_revision = 1;
        let changed = client
            .accept(expected(), 7, 1000, 1001, Instant::now(), changed)
            .unwrap();
        assert!(!first.same_owner(&changed));
        assert!(
            client
                .accept(expected(), 7, 1000, 999, Instant::now(), reply())
                .is_err()
        );
        assert!(
            client
                .accept(expected(), 7, 1000, 1500, Instant::now(), reply())
                .is_err()
        );
        assert!(
            client
                .accept(
                    expected(),
                    7,
                    1000,
                    1001,
                    Instant::now() - Duration::from_secs(1),
                    reply()
                )
                .is_err()
        );
        assert!(
            client
                .accept(
                    expected(),
                    7,
                    u64::MAX - 1,
                    u64::MAX - 1,
                    Instant::now(),
                    reply()
                )
                .is_err()
        );
    }
    #[tokio::test]
    async fn every_scope_hash_address_and_lifetime_mismatch_refuses() {
        let client = client();
        for field in 0..14 {
            let mut input = reply();
            match field {
                0 => input.request_id = 8,
                1 => input.configuration_revision = MAXIMUM + 1,
                2 => input.route_id.clear(),
                3 => input.route_id = "x".repeat(129),
                4 => input.service = "billing".into(),
                5 => input.audience = "billing-api".into(),
                6 => input.resource = "db:billing".into(),
                7 => input.action = "drop".into(),
                8 => input.client_ip = vec![192, 0, 2, 10],
                9 => input.client_ip = vec![1; 5],
                10 => input.request_sha256[0] ^= 1,
                11 => input.destination_sha256[0] ^= 1,
                12 => input.remaining_ms = 0,
                _ => input.remaining_ms = 1001,
            }
            assert!(
                client
                    .accept(expected(), 7, 1000, 1001, Instant::now(), input)
                    .is_err(),
                "unsafe reply field {field}"
            );
        }
        let mut ipv6 = expected();
        ipv6.ip = "2001:db8::9".parse().unwrap();
        let mut input = reply();
        input.client_ip = match ipv6.ip {
            IpAddr::V6(ip) => ip.octets().to_vec(),
            _ => unreachable!(),
        };
        assert!(
            client
                .accept(ipv6, 7, 1000, 1001, Instant::now(), input)
                .is_ok()
        );
    }
    #[tokio::test]
    async fn validation_admission_and_counter_exhaustion_refuse_before_network() {
        let client = client();
        let mut input = expected();
        input.resource = "";
        assert!(client.observe(input, &|| 1000).await.is_err());
        let held = client.admission.acquire().await.unwrap();
        assert!(client.observe(expected(), &|| 1000).await.is_err());
        drop(held);
        client.sequence.store(MAXIMUM, Ordering::Relaxed);
        assert!(client.observe(expected(), &|| 1000).await.is_err());
        for address in [
            "http://127.0.0.1:1",
            "https://user@127.0.0.1:1",
            "https://127.0.0.1:1/path",
            "https://127.0.0.1:1/?query=1",
            "https://127.0.0.1:0",
        ] {
            assert!(
                Client::prepare(
                    address,
                    "owned.example.test",
                    b"ca",
                    b"cert",
                    b"key",
                    &"x".repeat(32)
                )
                .is_err()
            );
        }
    }
}
