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
impl<'a> Observation<'a> {
    #[cfg(test)]
    pub(crate) fn fixture(
        floor: &'a AtomicU64,
        ip: IpAddr,
        revision: u64,
        expires_ms: u64,
    ) -> Self {
        Self {
            floor,
            ip,
            revision,
            expires_ms,
            before_ms: 1000,
            begun: Instant::now(),
        }
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    #[cfg(feature = "observed-authentication")]
    pub(crate) fn observed_bound(
        &self,
        rates: &hopae_grpc::receipt_time::ClockRates,
        now: u64,
    ) -> Result<u64, tonic::Status> {
        crate::observed_permit::prerequisite_bound(self.before_ms, self.expires_ms, now, rates)
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
        let tls =
            crate::authority_transport::static_tls(ca, certificate, key).map_err(|_| Refused)?;
        Self::connect_tls(address, server_name, tls, token).await
    }
    /// As [`Self::connect`] with reloading TLS material (rotated files apply on reconnect).
    pub async fn connect_tls(
        address: &str,
        server_name: &str,
        tls: std::sync::Arc<crate::tls_reload::Reloading<rustls::ClientConfig>>,
        token: &str,
    ) -> Result<Self, Refused> {
        let (channel, credential) =
            crate::authority_transport::connect(address, server_name, tls, token)
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
        clock: &(dyn Fn() -> u64 + Sync),
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

#[cfg(test)]
mod combined_tests {
    use super::*;
    use crate::{
        authentication::{Configuration, ServiceTrust},
        authorization::{self, LiveEvidence, NativeResourceRequest},
    };
    use hopae_grpc::{PrincipalKind, receipt, receipt_binding};
    #[test]
    fn combined_native_allow_requires_both_observations_and_rechecks_network_after_work() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let subject = "s_0123456789abcdef0123456789abcdef0123456789abcdef";
        let context = receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: "owned:service:3:app:1",
            identity: receipt_binding::Identity {
                subject_ref: subject,
                kind: PrincipalKind::Service,
                aal: 0,
                revision: 3,
                credential_generation: 3,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
        };
        let bytes = receipt::sign(
            &key,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 1000,
                expires_ms: 1800,
                binding: receipt_binding::digest(&context, None).unwrap(),
                nonce: [7; 32],
            },
        )
        .unwrap();
        let trust = ServiceTrust::new(Configuration {
            issuer: "hopae".into(),
            key_epoch: 1,
            identity_epoch: "owned".into(),
            service: "orders".into(),
            audience: "orders-api".into(),
            minimum_revision: 3,
            public_key: key.verifying_key().to_bytes(),
        })
        .unwrap();
        let checked = trust.verify(&context, &bytes, &[3; 32], 1001).unwrap();
        let auth = crate::authentication_live::Observation::fixture(&checked, 1001);
        let floor = AtomicU64::new(3);
        let ip = "192.0.2.1".parse().unwrap();
        let network = Observation {
            floor: &floor,
            ip,
            revision: 3,
            expires_ms: 1800,
            before_ms: 1001,
            begun: Instant::now(),
        };
        let evidence = LiveEvidence {
            authentication: &auth,
            network: &network,
        };
        let mut document = serde_json::json!({"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"require_guard":true,"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":0}},"users":{},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"},"minimum_aal":0}}});
        document["services"]["orders"]["users"][subject] = serde_json::json!(["reader"]);
        let policy = serde_json::from_value::<pumgye_core::Policy>(document)
            .unwrap()
            .compile()
            .unwrap();
        let mut target = NativeResourceRequest {
            resource: "db:orders",
            action: "select",
            ip,
        };
        assert_eq!(
            authorization::authorize_combined_resource_then(
                &policy,
                &target,
                &checked,
                &evidence,
                || 1002,
                || true,
                |resource| resource.information_class.clone()
            )
            .unwrap(),
            "internal"
        );
        target.ip = "192.0.2.2".parse().unwrap();
        assert!(
            authorization::authorize_combined_resource_then(
                &policy,
                &target,
                &checked,
                &evidence,
                || 1002,
                || true,
                |_| panic!("wrong IP must never operate")
            )
            .is_err()
        );
        target.ip = ip;
        assert!(
            authorization::authorize_combined_resource_then(
                &policy,
                &target,
                &checked,
                &evidence,
                || 1002,
                || true,
                |_| {
                    floor.store(4, Ordering::Release);
                    "private candidate"
                }
            )
            .is_err()
        );
    }
}
