//! Native Hopae plan observations. No caller plan facts or secret material.
use hopae_grpc::v1::{
    ProjectionPlanReply, ProjectionPlanRequest, projection_plans_client::ProjectionPlansClient,
};
use std::{
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
    pub service: &'a str,
    pub audience: &'a str,
    pub resource: &'a str,
    pub action: &'a str,
    pub aal: u8,
    pub minimum_revision: u64,
}
pub struct Client {
    client: ProjectionPlansClient<Channel>,
    credential: MetadataValue<tonic::metadata::Ascii>,
    admission: Semaphore,
    sequence: AtomicU64,
    owner: Arc<()>,
}
/// Private construction; not a transferable permission or remote lease.
pub struct Observation<'a> {
    expected: Expected<'a>,
    owner: Arc<()>,
    revision: u64,
    minimum_aal: u8,
    before_ms: u64,
    expires_ms: u64,
    begun: Instant,
}
impl Observation<'_> {
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
            && self.revision == other.revision
            && self.minimum_aal == other.minimum_aal
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
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
impl Client {
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
            || uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
            || uri.port_u16() == Some(0)
        {
            return Err(Refused);
        }
        let tls =
            crate::authority_transport::static_tls(ca, certificate, key).map_err(|_| Refused)?;
        Self::prepare_tls(address, server_name, tls, token)
    }
    /// As [`Self::prepare`] with reloading TLS material (rotated files apply on reconnect).
    pub fn prepare_tls(
        address: &str,
        server_name: &str,
        tls: std::sync::Arc<crate::tls_reload::Reloading<rustls::ClientConfig>>,
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
            crate::authority_transport::lazy(address, server_name, tls, token)
                .map_err(|_| Refused)?;
        Ok(Self {
            client: ProjectionPlansClient::new(channel)
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
            || expected.minimum_revision > MAXIMUM
            || expected.aal > 3
        {
            return Err(Refused);
        }
        let _admission = self.admission.try_acquire().map_err(|_| Refused)?;
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (v < MAXIMUM).then_some(v + 1)
            })
            .map_err(|_| Refused)?;
        let before_ms = clock();
        let begun = Instant::now();
        let mut request = tonic::Request::new(ProjectionPlanRequest {
            request_id,
            service: expected.service.into(),
            audience: expected.audience.into(),
            minimum_revision: expected.minimum_revision,
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
        reply: ProjectionPlanReply,
    ) -> Result<Observation<'a>, Refused> {
        if reply.request_id != request_id
            || !(1..=MAXIMUM).contains(&reply.revision)
            || reply.revision < expected.minimum_revision
            || reply.service != expected.service
            || reply.audience != expected.audience
            || reply.resource != expected.resource
            || reply.action != expected.action
            || reply.minimum_aal > 3
            || reply.minimum_aal > u32::from(expected.aal)
            || reply.cache_ttl_ms != 0
            || after_ms < before_ms
        {
            return Err(Refused);
        }
        let observed = Observation {
            expected,
            owner: self.owner.clone(),
            revision: reply.revision,
            minimum_aal: reply.minimum_aal as u8,
            before_ms,
            expires_ms: before_ms.checked_add(1000).ok_or(Refused)?,
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
            client: ProjectionPlansClient::new(
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
            service: "orders",
            audience: "orders-api",
            resource: "orders",
            action: "read",
            aal: 2,
            minimum_revision: 1,
        }
    }
    fn reply() -> ProjectionPlanReply {
        ProjectionPlanReply {
            request_id: 7,
            revision: 1,
            service: "orders".into(),
            audience: "orders-api".into(),
            resource: "orders".into(),
            action: "read".into(),
            minimum_aal: 2,
            cache_ttl_ms: 0,
        }
    }
    #[tokio::test]
    async fn native_scope_deadline_owner_and_retirement_revision_are_bound() {
        let client = client();
        let other = self::client();
        let old = client
            .accept(expected(), 7, 1000, 1001, Instant::now(), reply())
            .unwrap();
        assert!(old.valid_at(1001));
        assert!(!old.valid_at(999));
        assert!(!old.valid_at(2000));
        assert!(old.belongs_to(&client));
        assert!(!old.belongs_to(&other));
        assert_eq!((old.revision(), old.expires_ms()), (1, 2000));
        let same = client
            .accept(expected(), 7, 1000, 1001, Instant::now(), reply())
            .unwrap();
        assert!(old.same_owner(&same));
        let mut replacement = reply();
        replacement.revision = 2;
        let replacement = client
            .accept(expected(), 7, 1000, 1001, Instant::now(), replacement)
            .unwrap();
        assert!(!old.same_owner(&replacement));
        let foreign = other
            .accept(expected(), 7, 1000, 1001, Instant::now(), reply())
            .unwrap();
        assert!(!old.same_owner(&foreign));
        assert!(
            client
                .accept(expected(), 7, 1000, 999, Instant::now(), reply())
                .is_err()
        );
        assert!(
            client
                .accept(expected(), 7, 1000, 2000, Instant::now(), reply())
                .is_err()
        );
        assert!(
            client
                .accept(
                    expected(),
                    7,
                    u64::MAX - 1,
                    u64::MAX,
                    Instant::now(),
                    reply()
                )
                .is_err()
        );
        assert!(
            client
                .accept(
                    expected(),
                    7,
                    1000,
                    1001,
                    Instant::now() - Duration::from_secs(2),
                    reply()
                )
                .is_err()
        );
    }
    #[tokio::test]
    async fn hostile_replies_and_local_capacity_fail_closed() {
        let client = client();
        for case in 0..10 {
            let mut value = reply();
            match case {
                0 => value.request_id = 8,
                1 => value.revision = 0,
                2 => value.revision = MAXIMUM + 1,
                3 => value.service = "other".into(),
                4 => value.audience = "other".into(),
                5 => value.resource = "other".into(),
                6 => value.action = "write".into(),
                7 => value.minimum_aal = 3,
                8 => value.minimum_aal = u32::MAX,
                _ => value.cache_ttl_ms = 1,
            }
            assert!(
                client
                    .accept(expected(), 7, 1000, 1001, Instant::now(), value)
                    .is_err(),
                "case {case}"
            );
        }
        let mut floor = expected();
        floor.minimum_revision = 2;
        assert!(
            client
                .accept(floor, 7, 1000, 1001, Instant::now(), reply())
                .is_err()
        );
        let _permit = client.admission.acquire().await.unwrap();
        assert!(client.observe(expected(), &|| 1000).await.is_err());
        drop(_permit);
        client.sequence.store(MAXIMUM, Ordering::Relaxed);
        assert!(client.observe(expected(), &|| 1000).await.is_err());
        let mut invalid = expected();
        invalid.service = "bad/name";
        assert!(client.observe(invalid, &|| 1000).await.is_err());
    }
}
