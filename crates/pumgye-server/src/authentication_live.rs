//! Native persistent mTLS validation client. Replies are observations, not leases.
use crate::authentication::CheckedService;
use hopae_grpc::v1::{self, authentication_receipts_client::AuthenticationReceiptsClient};
use sha2::{Digest, Sha256};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tonic::{metadata::MetadataValue, transport::Channel};
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
pub struct Client {
    client: AuthenticationReceiptsClient<Channel>,
    credential: MetadataValue<tonic::metadata::Ascii>,
    requests: Semaphore,
    sequence: AtomicU64,
}
/// Opaque point-in-time observation; downstream owners still require fencing.
pub struct Observation {
    receipt_sha256: [u8; 32],
    expires_ms: u64,
    observed_ms: u64,
    begun: Instant,
}
impl Observation {
    #[cfg(test)]
    pub(crate) fn fixture(checked: &CheckedService<'_>, now: u64) -> Self {
        Self {
            receipt_sha256: checked.receipt_sha256(),
            expires_ms: checked.expires_ms(),
            observed_ms: now,
            begun: Instant::now(),
        }
    }
    pub fn valid_for(&self, checked: &CheckedService<'_>, now_ms: u64) -> bool {
        self.receipt_sha256 == checked.receipt_sha256()
            && now_ms >= self.observed_ms
            && checked.valid_at(now_ms)
            && now_ms.max(
                self.observed_ms
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
            client: AuthenticationReceiptsClient::new(channel)
                .max_encoding_message_size(2048)
                .max_decoding_message_size(64),
            credential,
            requests: Semaphore::new(128),
            sequence: AtomicU64::new(1),
        })
    }
    pub async fn validate(
        &self,
        checked: &CheckedService<'_>,
        receipt: &[u8],
        clock: &(dyn Fn() -> u64 + Sync),
    ) -> Result<Observation, Refused> {
        let _permit = self.requests.try_acquire().map_err(|_| Refused)?;
        let begun = Instant::now();
        let before = clock();
        if !checked.valid_at(before)
            || receipt.len() != hopae_grpc::receipt::LENGTH
            || <[u8; 32]>::from(Sha256::digest(receipt)) != checked.receipt_sha256()
        {
            return Err(Refused);
        }
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < 9_007_199_254_740_991).then_some(value + 1)
            })
            .map_err(|_| Refused)?;
        let context = checked.context();
        let message = v1::ServiceReceiptValidationRequest {
            request_id,
            context: Some(v1::AuthenticationReceiptContext {
                issuer_ref: context.issuer_ref.into(),
                key_epoch: context.key_epoch,
                identity_authority_epoch: context.identity_authority_epoch.into(),
                identity: Some(v1::ReceiptIdentity {
                    subject_ref: context.identity.subject_ref.into(),
                    kind: 2,
                    aal: 0,
                    revision: context.identity.revision,
                    credential_generation: context.identity.credential_generation,
                }),
                service: context.service.into(),
                audience: context.audience.into(),
                request_sha256: context.request_sha256.to_vec(),
            }),
            receipt: receipt.to_vec(),
            request_sha256: context.request_sha256.to_vec(),
        };
        let mut request = tonic::Request::new(message);
        request
            .metadata_mut()
            .insert("authorization", self.credential.clone());
        request.set_timeout(Duration::from_millis(
            checked.expires_ms().saturating_sub(before).min(1000),
        ));
        let reply = tokio::time::timeout(
            Duration::from_millis(checked.expires_ms().saturating_sub(before).min(1000)),
            self.client.clone().validate_service(request),
        )
        .await
        .map_err(|_| Refused)?
        .map_err(|_| Refused)?
        .into_inner();
        let after = clock();
        let final_ms = after
            .max(before.saturating_add(begun.elapsed().as_millis().min(u64::MAX as u128) as u64));
        if after < before
            || !checked.valid_at(final_ms)
            || reply.request_id != request_id
            || reply.expires_ms != checked.expires_ms()
        {
            return Err(Refused);
        }
        Ok(Observation {
            receipt_sha256: checked.receipt_sha256(),
            expires_ms: checked.expires_ms(),
            observed_ms: final_ms,
            begun: Instant::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::{Configuration, ServiceTrust};
    use hopae_grpc::{PrincipalKind, receipt, receipt_binding};
    #[tokio::test]
    async fn unencrypted_or_missing_native_resources_refuse_before_connecting() {
        assert!(
            Client::connect(
                "http://127.0.0.1:1",
                "owned.example.test",
                b"ca",
                b"cert",
                b"key",
                &"a".repeat(32)
            )
            .await
            .is_err()
        );
        assert!(
            Client::connect(
                "https://127.0.0.1:1",
                "owned.example.test",
                b"ca",
                b"cert",
                b"",
                &"a".repeat(32)
            )
            .await
            .is_err()
        );
        assert!(
            Client::connect(
                "https://127.0.0.1:1",
                "bad name",
                b"ca",
                b"cert",
                b"key",
                &"a".repeat(32)
            )
            .await
            .is_err()
        );
    }
    #[test]
    fn observation_remains_bound_to_exact_verified_receipt_and_deadline() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
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
        let context = receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: "owned:service:3:app:1",
            identity: receipt_binding::Identity {
                subject_ref: "s_0123456789abcdef0123456789abcdef0123456789abcdef",
                kind: PrincipalKind::Service,
                aal: 0,
                revision: 3,
                credential_generation: 3,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
        };
        let sign = |nonce| {
            receipt::sign(
                &key,
                &receipt::Claims {
                    purpose: receipt::Purpose::Authentication,
                    issued_ms: 1000,
                    expires_ms: 1800,
                    binding: receipt_binding::digest(&context, None).unwrap(),
                    nonce: [nonce; 32],
                },
            )
            .unwrap()
        };
        let first = sign(7);
        let second = sign(8);
        let checked = trust.verify(&context, &first, &[3; 32], 1001).unwrap();
        let other = trust.verify(&context, &second, &[3; 32], 1001).unwrap();
        let observation = Observation {
            receipt_sha256: checked.receipt_sha256(),
            expires_ms: 1800,
            observed_ms: 1002,
            begun: Instant::now(),
        };
        assert!(observation.valid_for(&checked, 1003));
        assert!(!observation.valid_for(&other, 1003));
        let policy = serde_json::from_value::<pumgye_core::Policy>(
            serde_json::json!({"version":1,"information_classes":["public"],"services":{}}),
        )
        .unwrap()
        .compile()
        .unwrap();
        let request = crate::authorization::ResourceRequest {
            resource: "absent",
            action: "read",
            ip: "192.0.2.1".parse().unwrap(),
            guard: pumgye_core::GuardEvidence::Unavailable,
            network_expires_ms: 1800,
        };
        assert!(matches!(
            crate::authorization::authorize_live_resource_then(
                &policy,
                &request,
                &other,
                &observation,
                || 1003,
                || true,
                |_| panic!("mismatched receipt must never reach operation")
            ),
            Err(crate::authorization::Refused::Unavailable)
        ));
        assert!(matches!(
            crate::authorization::authorize_live_resource_then(
                &policy,
                &request,
                &checked,
                &observation,
                || 1003,
                || false,
                |_| panic!("retired native owners must never reach operation")
            ),
            Err(crate::authorization::Refused::Unavailable)
        ));
        let reads = std::cell::Cell::new(0);
        let rollback = || {
            let read = reads.get();
            reads.set(read + 1);
            if read == 0 { 1100 } else { 1099 }
        };
        assert!(matches!(
            crate::authorization::authorize_live_resource_then(
                &policy,
                &request,
                &checked,
                &observation,
                rollback,
                || true,
                |_| panic!("guard-time rollback must refuse")
            ),
            Err(crate::authorization::Refused::Unavailable)
        ));
        assert!(!observation.valid_for(&checked, 1001));
        assert!(!observation.valid_for(&checked, 1800));
        let delayed = Observation {
            receipt_sha256: checked.receipt_sha256(),
            expires_ms: 1800,
            observed_ms: 1002,
            begun: Instant::now() - Duration::from_secs(1),
        };
        assert!(!delayed.valid_for(&checked, 1003));
    }
}
