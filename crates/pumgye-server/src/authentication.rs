//! Server-selected Hopae trust and scope. No caller-selected key or class.
use ed25519_dalek::VerifyingKey;
use hopae_grpc::{PrincipalKind, receipt, receipt_binding};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
pub struct Refused;

pub struct ServiceTrust {
    issuer: String,
    key_epoch: u64,
    identity_epoch: String,
    service: String,
    audience: String,
    minimum_revision: u64,
    key: VerifyingKey,
}
pub struct Configuration {
    pub issuer: String,
    pub key_epoch: u64,
    pub identity_epoch: String,
    pub service: String,
    pub audience: String,
    pub minimum_revision: u64,
    pub public_key: [u8; 32],
}
/// No Clone/Debug/serde or public constructor. Still requires live owner checks
/// and a native resource Allow before permission signing or secret projection.
pub struct CheckedService<'a> {
    context: receipt_binding::Context<'a>,
    verified_ms: u64,
    expires_ms: u64,
    receipt_sha256: [u8; 32],
}
impl CheckedService<'_> {
    pub fn valid_at(&self, now_ms: u64) -> bool {
        now_ms >= self.verified_ms && now_ms < self.expires_ms
    }
    pub fn context(&self) -> &receipt_binding::Context<'_> {
        &self.context
    }
    pub fn subject(&self) -> &str {
        self.context.identity.subject_ref
    }
    pub fn revision(&self) -> u64 {
        self.context.identity.revision
    }
    pub fn aal(&self) -> u8 {
        0
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub fn receipt_sha256(&self) -> [u8; 32] {
        self.receipt_sha256
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn revision(value: u64) -> bool {
    (1..=9_007_199_254_740_991).contains(&value)
}
impl ServiceTrust {
    /// Configuration must come from the owning server, never from the request.
    pub fn new(config: Configuration) -> Result<Self, Refused> {
        if [
            &config.issuer,
            &config.identity_epoch,
            &config.service,
            &config.audience,
        ]
        .iter()
        .any(|v| !identifier(v))
            || config.identity_epoch.len() > 96
            || !revision(config.key_epoch)
            || !revision(config.minimum_revision)
        {
            return Err(Refused);
        }
        let key = VerifyingKey::from_bytes(&config.public_key).map_err(|_| Refused)?;
        if key.is_weak() {
            return Err(Refused);
        }
        Ok(Self {
            issuer: config.issuer,
            key_epoch: config.key_epoch,
            identity_epoch: config.identity_epoch,
            service: config.service,
            audience: config.audience,
            minimum_revision: config.minimum_revision,
            key,
        })
    }
    /// `request_sha256` must be the bound final request from the authenticated
    /// enforcement caller. Checked fields are extracted only after verification.
    pub fn verify<'a>(
        &self,
        context: &receipt_binding::Context<'a>,
        bytes: &[u8],
        request_sha256: &[u8; 32],
        now_ms: u64,
    ) -> Result<CheckedService<'a>, Refused> {
        let identity = &context.identity;
        let epoch_revision = context
            .identity_authority_epoch
            .strip_prefix(&self.identity_epoch)
            .and_then(|v| v.strip_prefix(":service:"));
        let epoch_matches = epoch_revision.is_some_and(|v| {
            !v.starts_with('0')
                && v.len() <= 16
                && v.bytes().all(|b| b.is_ascii_digit())
                && v.parse::<u64>().ok() == Some(identity.revision)
        });
        if context.issuer_ref != self.issuer
            || context.key_epoch != self.key_epoch
            || !epoch_matches
            || context.service != self.service
            || context.audience != self.audience
            || context.request_sha256 != *request_sha256
            || identity.kind != PrincipalKind::Service
            || identity.aal != 0
            || identity.revision < self.minimum_revision
            || identity.credential_generation != identity.revision
            || identity.subject_ref.len() != 50
            || !identity.subject_ref.starts_with("s_")
            || !identity.subject_ref.as_bytes()[2..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(Refused);
        }
        let binding = receipt_binding::digest(context, None).map_err(|_| Refused)?;
        let checked = receipt::verify(
            &self.key,
            bytes,
            receipt::Purpose::Authentication,
            &binding,
            now_ms,
        )
        .map_err(|_| Refused)?;
        Ok(CheckedService {
            verified_ms: now_ms,
            context: receipt_binding::Context {
                issuer_ref: context.issuer_ref,
                key_epoch: context.key_epoch,
                identity_authority_epoch: context.identity_authority_epoch,
                identity: receipt_binding::Identity {
                    subject_ref: identity.subject_ref,
                    kind: identity.kind,
                    aal: identity.aal,
                    revision: identity.revision,
                    credential_generation: identity.credential_generation,
                },
                service: context.service,
                audience: context.audience,
                request_sha256: context.request_sha256,
            },
            expires_ms: checked.claims().expires_ms,
            receipt_sha256: Sha256::digest(bytes).into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    fn context() -> receipt_binding::Context<'static> {
        receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: "epoch1:service:3",
            identity: receipt_binding::Identity {
                subject_ref: "s_0123456789abcdef0123456789abcdef0123456789abcdef",
                kind: PrincipalKind::Service,
                aal: 0,
                revision: 3,
                credential_generation: 3,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [5; 32],
        }
    }
    fn trust(key: &SigningKey) -> ServiceTrust {
        ServiceTrust::new(Configuration {
            issuer: "hopae".into(),
            key_epoch: 1,
            identity_epoch: "epoch1".into(),
            service: "orders".into(),
            audience: "orders-api".into(),
            minimum_revision: 3,
            public_key: key.verifying_key().to_bytes(),
        })
        .unwrap()
    }
    fn signed(
        key: &SigningKey,
        context: &receipt_binding::Context<'_>,
        purpose: receipt::Purpose,
    ) -> [u8; receipt::LENGTH] {
        receipt::sign(
            key,
            &receipt::Claims {
                purpose,
                issued_ms: 1000,
                expires_ms: 1800,
                binding: receipt_binding::digest(context, None).unwrap(),
                nonce: [7; 32],
            },
        )
        .unwrap()
    }
    #[test]
    fn verified_facts_are_extracted_only_from_pinned_signed_context() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust(&key);
        let mut input = context();
        let bytes = signed(&key, &input, receipt::Purpose::Authentication);
        let checked = trust.verify(&input, &bytes, &[5; 32], 1001).unwrap();
        assert_eq!(checked.subject(), input.identity.subject_ref);
        assert_eq!(checked.revision(), 3);
        assert_eq!(checked.aal(), 0);
        assert_eq!(checked.expires_ms(), 1800);
        assert_eq!(
            checked.receipt_sha256(),
            <[u8; 32]>::from(Sha256::digest(bytes))
        );
        input.key_epoch = 2;
        input.identity.revision = 4;
        input.service = "billing";
        assert_eq!(input.key_epoch, 2);
        assert_eq!(input.identity.revision, 4);
        assert_eq!(input.service, "billing");
        assert_eq!(checked.context().key_epoch, 1);
        assert_eq!(checked.revision(), 3);
        assert_eq!(checked.context().service, "orders");
    }
    #[test]
    fn even_valid_signatures_cannot_override_native_trust_scope_or_identity_kind() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = trust(&key);
        for case in [
            "issuer",
            "epoch",
            "identity-epoch",
            "epoch-revision",
            "epoch-format",
            "service",
            "audience",
            "request",
            "human",
            "subject",
            "generation",
            "floor",
        ] {
            let mut input = context();
            match case {
                "issuer" => input.issuer_ref = "other",
                "epoch" => input.key_epoch = 2,
                "identity-epoch" => input.identity_authority_epoch = "other:service:3",
                "epoch-revision" => input.identity_authority_epoch = "epoch1:service:2",
                "epoch-format" => input.identity_authority_epoch = "epoch1:service:03",
                "service" => input.service = "billing",
                "audience" => input.audience = "billing-api",
                "request" => input.request_sha256 = [6; 32],
                "human" => {
                    input.identity.kind = PrincipalKind::Human;
                    input.identity.aal = 1;
                }
                "subject" => input.identity.subject_ref = "raw-worker",
                "generation" => input.identity.credential_generation = 2,
                "floor" => {
                    input.identity.revision = 2;
                    input.identity.credential_generation = 2;
                    input.identity_authority_epoch = "epoch1:service:2";
                }
                _ => unreachable!(),
            }
            let bytes = signed(&key, &input, receipt::Purpose::Authentication);
            assert!(
                trust.verify(&input, &bytes, &[5; 32], 1001).is_err(),
                "{case}"
            );
        }
    }
    #[test]
    fn wrong_key_purpose_tamper_and_time_never_produce_checked_identity() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let verifier = trust(&key);
        let input = context();
        let bytes = signed(&key, &input, receipt::Purpose::Authentication);
        let other = SigningKey::from_bytes(&[10; 32]);
        assert!(
            trust(&other)
                .verify(&input, &bytes, &[5; 32], 1001)
                .is_err()
        );
        let permit = signed(&key, &input, receipt::Purpose::Permit);
        assert!(verifier.verify(&input, &permit, &[5; 32], 1001).is_err());
        for now in [999, 1800, 3000] {
            assert!(verifier.verify(&input, &bytes, &[5; 32], now).is_err());
        }
        for index in 0..bytes.len() {
            let mut tampered = bytes;
            tampered[index] ^= 1;
            assert!(verifier.verify(&input, &tampered, &[5; 32], 1001).is_err());
        }
    }
}
