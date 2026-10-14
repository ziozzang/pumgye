//! Persistent mTLS Sumunjang observations. Enforce Allow only; not a signed lease.
use guard_grpc::v1::{NetworkReply, NetworkRequest, network_client::NetworkClient};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tonic::{metadata::MetadataValue, transport::Channel};
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
pub struct Client {
    client: NetworkClient<Channel>,
    credential: MetadataValue<tonic::metadata::Ascii>,
    requests: Semaphore,
    sequence: AtomicU64,
    floor: AtomicU64,
}
/// No public constructor, Clone, Debug or serde; invalidated by newer observations.
pub struct Observation<'a> {
    floor: &'a AtomicU64,
    ip: IpAddr,
    revision: u64,
    expires_ms: u64,
    before_ms: u64,
    begun: Instant,
}
impl Observation<'_> {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub fn valid_at(&self, ip: IpAddr, now_ms: u64) -> bool {
        ip == self.ip
            && now_ms >= self.before_ms
            && self.floor.load(Ordering::Acquire) == self.revision
            && now_ms.max(
                self.before_ms
                    .saturating_add(self.begun.elapsed().as_millis().min(u64::MAX as u128) as u64),
            ) < self.expires_ms
    }
}
impl Client {
    pub async fn connect(
        address: &str,
        server_name: &str,
        ca: &[u8],
        certificate: &[u8],
        key: &[u8],
        token: &str,
    ) -> Result<Self, Refused> {
        let (channel, credential) =
            crate::authority_transport::connect(address, server_name, ca, certificate, key, token)
                .await
                .map_err(|_| Refused)?;
        Ok(Self {
            client: NetworkClient::new(channel)
                .max_encoding_message_size(128)
                .max_decoding_message_size(64),
            credential,
            requests: Semaphore::new(128),
            sequence: AtomicU64::new(1),
            floor: AtomicU64::new(0),
        })
    }
    pub async fn check(
        &self,
        ip: IpAddr,
        minimum_revision: u64,
        clock: &dyn Fn() -> u64,
    ) -> Result<Observation<'_>, Refused> {
        let _permit = self.requests.try_acquire().map_err(|_| Refused)?;
        if minimum_revision > 9_007_199_254_740_991 {
            return Err(Refused);
        }
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < 9_007_199_254_740_991).then_some(value + 1)
            })
            .map_err(|_| Refused)?;
        let begun = Instant::now();
        let before_ms = clock();
        let floor = minimum_revision.max(self.floor.load(Ordering::Acquire));
        let packed = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let mut request = tonic::Request::new(NetworkRequest {
            request_id,
            ip: packed,
            minimum_revision: floor,
        });
        request
            .metadata_mut()
            .insert("authorization", self.credential.clone());
        request.set_timeout(Duration::from_secs(1));
        let reply =
            tokio::time::timeout(Duration::from_secs(1), self.client.clone().check(request))
                .await
                .map_err(|_| Refused)?
                .map_err(|_| Refused)?
                .into_inner();
        self.accept(ip, request_id, floor, before_ms, clock(), begun, reply)
    }
    #[allow(clippy::too_many_arguments)]
    fn accept(
        &self,
        ip: IpAddr,
        request_id: u64,
        minimum_revision: u64,
        before_ms: u64,
        after_ms: u64,
        begun: Instant,
        reply: NetworkReply,
    ) -> Result<Observation<'_>, Refused> {
        if reply.request_id != request_id
            || !(1..=9_007_199_254_740_991).contains(&reply.revision)
            || reply.revision < minimum_revision
            || !(1..=3).contains(&reply.verdict)
            || !(0..=2).contains(&reply.mode)
            || reply.ttl_ms > 5000
            || after_ms < before_ms
        {
            return Err(Refused);
        }
        // A newer valid refusal must retire previously observed Allow as well.
        self.floor.fetch_max(reply.revision, Ordering::AcqRel);
        if reply.verdict != 1 || reply.mode != 2 || reply.ttl_ms == 0 {
            return Err(Refused);
        }
        let expires_ms = before_ms
            .checked_add(u64::from(reply.ttl_ms).min(1000))
            .ok_or(Refused)?;
        let observation = Observation {
            floor: &self.floor,
            ip,
            revision: reply.revision,
            expires_ms,
            before_ms,
            begun,
        };
        if !observation.valid_at(ip, after_ms) {
            return Err(Refused);
        }
        Ok(observation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client() -> Client {
        let channel = Channel::from_static("https://owned.example.test").connect_lazy();
        Client {
            client: NetworkClient::new(channel),
            credential: "Bearer fixture".parse().unwrap(),
            requests: Semaphore::new(1),
            sequence: AtomicU64::new(1),
            floor: AtomicU64::new(0),
        }
    }
    fn reply() -> NetworkReply {
        NetworkReply {
            request_id: 7,
            revision: 3,
            verdict: 1,
            mode: 2,
            ttl_ms: 5000,
        }
    }
    #[tokio::test]
    async fn enforced_allow_is_ip_bound_short_lived_and_retired_by_newer_denial() {
        let client = client();
        let ip = "192.0.2.1".parse().unwrap();
        let accepted = client
            .accept(ip, 7, 3, 1000, 1001, Instant::now(), reply())
            .unwrap();
        assert_eq!(accepted.expires_ms(), 2000);
        assert!(accepted.valid_at(ip, 1002));
        assert!(!accepted.valid_at("192.0.2.2".parse().unwrap(), 1002));
        assert!(!accepted.valid_at(ip, 999));
        assert!(!accepted.valid_at(ip, 2000));
        let mut denial = reply();
        denial.revision = 4;
        denial.verdict = 2;
        assert!(
            client
                .accept(ip, 7, 3, 1000, 1001, Instant::now(), denial)
                .is_err()
        );
        assert!(!accepted.valid_at(ip, 1002));
        assert!(
            client
                .accept(ip, 7, 3, 1000, 1001, Instant::now(), reply())
                .is_err()
        );
    }
    #[tokio::test]
    async fn malformed_observe_unavailable_or_delayed_replies_never_grant_evidence() {
        let ip = "192.0.2.1".parse().unwrap();
        for case in [
            "id",
            "revision",
            "observe",
            "deny",
            "unavailable",
            "mode",
            "zero-ttl",
            "oversize-ttl",
        ] {
            let client = client();
            let mut value = reply();
            match case {
                "id" => value.request_id = 8,
                "revision" => value.revision = 2,
                "observe" => value.mode = 1,
                "deny" => value.verdict = 2,
                "unavailable" => value.verdict = 3,
                "mode" => value.mode = 99,
                "zero-ttl" => value.ttl_ms = 0,
                "oversize-ttl" => value.ttl_ms = 5001,
                _ => unreachable!(),
            }
            assert!(
                client
                    .accept(ip, 7, 3, 1000, 1001, Instant::now(), value)
                    .is_err(),
                "{case}"
            );
        }
        let client = client();
        assert!(
            client
                .accept(ip, 7, 3, 1000, 999, Instant::now(), reply())
                .is_err()
        );
        assert!(
            client
                .accept(
                    ip,
                    7,
                    3,
                    1000,
                    1001,
                    Instant::now() - Duration::from_secs(2),
                    reply()
                )
                .is_err()
        );
    }
}
