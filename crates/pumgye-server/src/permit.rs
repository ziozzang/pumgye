//! Native signed permit candidates. Owner discovery/replay/transport are separate.
use crate::{
    authentication::CheckedService,
    authorization::{self, ResourceRequest},
};
use ed25519_dalek::SigningKey;
use hopae_grpc::{receipt, receipt_binding};
use pumgye_core::CompiledPolicy;
use std::cell::Cell;

pub struct Signer {
    issuer: String,
    key_epoch: u64,
    key: SigningKey,
}
pub struct State<'a> {
    pub decision_ref: &'a str,
    pub authority_epoch: &'a str,
    pub policy_revision: u64,
    pub network_revision: u64,
    pub route_revision: u64,
    pub plan_revision: u64,
    pub policy_expires_ms: u64,
    pub route_expires_ms: u64,
    pub plan_expires_ms: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Authorization(authorization::Refused),
    InvalidBinding,
    Unavailable,
}
/// No public constructor, Clone, Debug or serialization. Returned only after
/// native Allow and final owner/time fences. The receiver still consumes replay.
pub struct SignedPermit<'a> {
    context: receipt_binding::Context<'a>,
    permit: receipt_binding::Permit<'a>,
    bytes: [u8; receipt::LENGTH],
    issued_ms: u64,
    expires_ms: u64,
}
impl SignedPermit<'_> {
    pub fn context(&self) -> &receipt_binding::Context<'_> {
        &self.context
    }
    pub fn permit(&self) -> &receipt_binding::Permit<'_> {
        &self.permit
    }
    pub fn bytes(&self) -> &[u8; receipt::LENGTH] {
        &self.bytes
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
}
impl Signer {
    /// Public descriptor for the native durable retirement fence.
    pub fn receipt_key(&self) -> hopae_grpc::receipt_keys::Key {
        hopae_grpc::receipt_keys::Key {
            issuer_ref: self.issuer.clone(),
            purpose: receipt::Purpose::Permit,
            epoch: self.key_epoch,
            public_key: self.key.verifying_key().to_bytes(),
        }
    }
    /// Caller loads an independent native permit key from owning resources.
    pub fn new(issuer: String, key_epoch: u64, key: SigningKey) -> Result<Self, Refused> {
        if issuer.is_empty()
            || issuer.len() > 128
            || !issuer
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || !(1..=9_007_199_254_740_991).contains(&key_epoch)
        {
            return Err(Refused::InvalidBinding);
        }
        Ok(Self {
            issuer,
            key_epoch,
            key,
        })
    }
    // Private native observed service signing boundary; no public budget grant.
    #[cfg(feature = "observed-authentication")]
    pub(crate) fn sign_observed(
        &self,
        input: &pumgye_grpc::v1::AuthenticatedResourceRequest,
        binding: pumgye_grpc::v1::PermitBinding,
        issued_ms: u64,
        expires_ms: u64,
    ) -> Result<pumgye_grpc::v1::ProjectionPermitReply, Refused> {
        let mut context = input.context.clone().ok_or(Refused::InvalidBinding)?;
        context.issuer_ref = self.issuer.clone();
        context.key_epoch = self.key_epoch;
        let identity = context.identity.as_ref().ok_or(Refused::InvalidBinding)?;
        let canonical = receipt_binding::Context {
            issuer_ref: &context.issuer_ref,
            key_epoch: context.key_epoch,
            identity_authority_epoch: &context.identity_authority_epoch,
            identity: receipt_binding::Identity {
                subject_ref: &identity.subject_ref,
                kind: hopae_grpc::PrincipalKind::Service,
                aal: 0,
                revision: identity.revision,
                credential_generation: identity.credential_generation,
            },
            service: &context.service,
            audience: &context.audience,
            request_sha256: context
                .request_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused::InvalidBinding)?,
        };
        let permit = receipt_binding::Permit {
            authentication_receipt_sha256: binding
                .authentication_receipt_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused::InvalidBinding)?,
            decision_ref: &binding.decision_ref,
            resource: &binding.resource,
            action: &binding.action,
            authority_epoch: &binding.authority_epoch,
            catalog_revision: binding.catalog_revision,
            policy_revision: binding.policy_revision,
            network_revision: binding.network_revision,
            route_revision: binding.route_revision,
            plan_revision: binding.plan_revision,
        };
        let digest = receipt_binding::digest(&canonical, Some(&permit))
            .map_err(|_| Refused::InvalidBinding)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Refused::Unavailable)?;
        let bytes = receipt::sign(
            &self.key,
            &receipt::Claims {
                purpose: receipt::Purpose::Permit,
                issued_ms,
                expires_ms,
                binding: digest,
                nonce,
            },
        )
        .map_err(|_| Refused::InvalidBinding)?;
        Ok(pumgye_grpc::v1::ProjectionPermitReply {
            request_id: input.request_id,
            context: Some(context),
            binding: Some(binding),
            receipt: bytes.to_vec(),
            cache_ttl_ms: 0,
        })
    }
    /// Require actual Hopae and Sumunjang observations before signing. This
    /// bounds the candidate by observed network expiry and revision rather than
    /// trusting caller-provided Guard evidence. Observations are not leases:
    /// `current` must still fence the exact policy/key/route/projection owners,
    /// and the downstream receiver must independently consume replay.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_combined<'a>(
        &'a self,
        policy: &CompiledPolicy,
        target: &authorization::NativeResourceRequest<'a>,
        authentication: &'a CheckedService<'a>,
        evidence: &authorization::LiveEvidence<'_>,
        state: &State<'a>,
        clock: impl Fn() -> u64,
        current: impl Fn() -> bool,
    ) -> Result<SignedPermit<'a>, Refused> {
        if state.network_revision != evidence.network.revision() {
            return Err(Refused::InvalidBinding);
        }
        let last = Cell::new(0);
        let reversed = Cell::new(false);
        let observed = || {
            let now = clock();
            if now < last.get() {
                reversed.set(true);
            }
            last.set(now);
            now
        };
        let request = ResourceRequest {
            resource: target.resource,
            action: target.action,
            ip: target.ip,
            guard: pumgye_core::GuardEvidence::EnforcedAllow,
            network_expires_ms: evidence.network.expires_ms(),
        };
        self.issue(policy, &request, authentication, state, observed, || {
            let now = observed();
            !reversed.get()
                && evidence.authentication.valid_for(authentication, now)
                && evidence.network.valid_at(target.ip, now)
                && current()
                && {
                    let after = observed();
                    !reversed.get()
                        && evidence.authentication.valid_for(authentication, after)
                        && evidence.network.valid_at(target.ip, after)
                }
        })
    }
    /// All state/fences are native owner facts, never unchecked request fields.
    /// `current` checks the exact policy and identity/key/network/route/plan owners.
    pub fn issue<'a>(
        &'a self,
        policy: &CompiledPolicy,
        request: &ResourceRequest<'a>,
        authentication: &'a CheckedService<'a>,
        state: &State<'a>,
        clock: impl Fn() -> u64,
        current: impl Fn() -> bool,
    ) -> Result<SignedPermit<'a>, Refused> {
        let last = Cell::new(0);
        let reversed = Cell::new(false);
        let observed = || {
            let now = clock();
            if now < last.get() {
                reversed.set(true);
            }
            last.set(now);
            now
        };
        let candidate = authorization::authorize_resource_then(
            policy,
            request,
            authentication,
            observed,
            &current,
            |_| {
                let now = observed();
                let expires = authentication
                    .expires_ms()
                    .min(request.network_expires_ms)
                    .min(state.policy_expires_ms)
                    .min(state.route_expires_ms)
                    .min(state.plan_expires_ms)
                    .min(now.checked_add(1000).ok_or(Refused::Unavailable)?);
                if reversed.get() || !authentication.valid_at(now) || expires <= now {
                    return Err(Refused::Unavailable);
                }
                let auth = authentication.context();
                let context = receipt_binding::Context {
                    issuer_ref: &self.issuer,
                    key_epoch: self.key_epoch,
                    identity_authority_epoch: auth.identity_authority_epoch,
                    identity: receipt_binding::Identity {
                        subject_ref: auth.identity.subject_ref,
                        kind: auth.identity.kind,
                        aal: auth.identity.aal,
                        revision: auth.identity.revision,
                        credential_generation: auth.identity.credential_generation,
                    },
                    service: auth.service,
                    audience: auth.audience,
                    request_sha256: auth.request_sha256,
                };
                let permit = receipt_binding::Permit {
                    authentication_receipt_sha256: authentication.receipt_sha256(),
                    decision_ref: state.decision_ref,
                    resource: request.resource,
                    action: request.action,
                    authority_epoch: state.authority_epoch,
                    catalog_revision: state.policy_revision,
                    policy_revision: state.policy_revision,
                    network_revision: state.network_revision,
                    route_revision: state.route_revision,
                    plan_revision: state.plan_revision,
                };
                let binding = receipt_binding::digest(&context, Some(&permit))
                    .map_err(|_| Refused::InvalidBinding)?;
                let mut nonce = [0; 32];
                getrandom::fill(&mut nonce).map_err(|_| Refused::Unavailable)?;
                let bytes = receipt::sign(
                    &self.key,
                    &receipt::Claims {
                        purpose: receipt::Purpose::Permit,
                        issued_ms: now,
                        expires_ms: expires,
                        binding,
                        nonce,
                    },
                )
                .map_err(|_| Refused::InvalidBinding)?;
                Ok(SignedPermit {
                    context,
                    permit,
                    bytes,
                    issued_ms: now,
                    expires_ms: expires,
                })
            },
        )
        .map_err(Refused::Authorization)??;
        let now = observed();
        if reversed.get() || now < candidate.issued_ms || now >= candidate.expires_ms || !current()
        {
            return Err(Refused::Unavailable);
        }
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::{Configuration, ServiceTrust};
    use hopae_grpc::PrincipalKind;
    use pumgye_core::GuardEvidence;
    const SUBJECT: &str = "s_0123456789abcdef0123456789abcdef0123456789abcdef";
    fn context() -> receipt_binding::Context<'static> {
        receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: "epoch1:service:3:app:1",
            identity: receipt_binding::Identity {
                subject_ref: SUBJECT,
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
    fn authentication(context: &receipt_binding::Context<'static>) -> CheckedService<'static> {
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = ServiceTrust::new(Configuration {
            issuer: "hopae".into(),
            key_epoch: 1,
            identity_epoch: "epoch1".into(),
            service: "orders".into(),
            audience: "orders-api".into(),
            minimum_revision: 3,
            public_key: key.verifying_key().to_bytes(),
        })
        .unwrap();
        let bytes = receipt::sign(
            &key,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 1000,
                expires_ms: 1800,
                binding: receipt_binding::digest(context, None).unwrap(),
                nonce: [7; 32],
            },
        )
        .unwrap();
        trust.verify(context, &bytes, &[5; 32], 1001).unwrap()
    }
    fn policy() -> CompiledPolicy {
        let mut value = serde_json::json!({"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":0}},"users":{},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"}}}});
        value["services"]["orders"]["users"][SUBJECT] = serde_json::json!(["reader"]);
        serde_json::from_value::<pumgye_core::Policy>(value)
            .unwrap()
            .compile()
            .unwrap()
    }
    fn request() -> ResourceRequest<'static> {
        ResourceRequest {
            resource: "db:orders",
            action: "select",
            ip: "192.0.2.9".parse().unwrap(),
            guard: GuardEvidence::EnforcedAllow,
            network_expires_ms: 1600,
        }
    }
    fn state() -> State<'static> {
        State {
            decision_ref: "decision1",
            authority_epoch: "policy1",
            policy_revision: 4,
            network_revision: 5,
            route_revision: 6,
            plan_revision: 7,
            policy_expires_ms: 1700,
            route_expires_ms: 1500,
            plan_expires_ms: 1400,
        }
    }
    #[test]
    fn combined_signing_binds_actual_network_deadline_and_refuses_mismatched_evidence() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let auth = authentication(&context());
        let live = crate::authentication_live::Observation::fixture(&auth, 1001);
        let floor = AtomicU64::new(5);
        let ip = "192.0.2.9".parse().unwrap();
        let network = crate::network_live::Observation::fixture(&floor, ip, 5, 1200);
        let evidence = authorization::LiveEvidence {
            authentication: &live,
            network: &network,
        };
        let signer = Signer::new("pumgye".into(), 2, SigningKey::from_bytes(&[11; 32])).unwrap();
        let policy = policy();
        let mut state = state();
        let mut target = authorization::NativeResourceRequest {
            resource: "db:orders",
            action: "select",
            ip,
        };
        let signed = signer
            .issue_combined(&policy, &target, &auth, &evidence, &state, || 1002, || true)
            .unwrap();
        assert_eq!(signed.expires_ms(), 1200);
        assert_eq!(signed.permit().network_revision, 5);
        let binding = receipt_binding::digest(signed.context(), Some(signed.permit())).unwrap();
        receipt::verify(
            &signer.key.verifying_key(),
            signed.bytes(),
            receipt::Purpose::Permit,
            &binding,
            1003,
        )
        .unwrap();
        assert!(
            receipt::verify(
                &signer.key.verifying_key(),
                signed.bytes(),
                receipt::Purpose::Permit,
                &binding,
                1200
            )
            .is_err()
        );
        state.network_revision = 6;
        assert!(matches!(
            signer.issue_combined(
                &policy,
                &target,
                &auth,
                &evidence,
                &state,
                || 1002,
                || panic!("mismatched native revision")
            ),
            Err(Refused::InvalidBinding)
        ));
        state.network_revision = 5;
        target.ip = "192.0.2.10".parse().unwrap();
        assert!(
            signer
                .issue_combined(&policy, &target, &auth, &evidence, &state, || 1002, || true)
                .is_err()
        );
        target.ip = ip;
        target.action = "drop";
        assert!(matches!(
            signer.issue_combined(&policy, &target, &auth, &evidence, &state, || 1002, || true),
            Err(Refused::Authorization(authorization::Refused::Denied(_)))
        ));
        target.action = "select";
        assert!(
            signer
                .issue_combined(&policy, &target, &auth, &evidence, &state, || 1200, || true)
                .is_err()
        );
        floor.store(6, Ordering::Release);
        assert!(
            signer
                .issue_combined(&policy, &target, &auth, &evidence, &state, || 1002, || true)
                .is_err()
        );
    }
    #[test]
    fn combined_signing_rechecks_native_owners_during_signing_and_rejects_clock_reversal() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let auth = authentication(&context());
        let live = crate::authentication_live::Observation::fixture(&auth, 1001);
        let floor = AtomicU64::new(5);
        let ip = "192.0.2.9".parse().unwrap();
        let network = crate::network_live::Observation::fixture(&floor, ip, 5, 1600);
        let evidence = authorization::LiveEvidence {
            authentication: &live,
            network: &network,
        };
        let signer = Signer::new("pumgye".into(), 2, SigningKey::from_bytes(&[11; 32])).unwrap();
        let policy = policy();
        let state = state();
        let target = authorization::NativeResourceRequest {
            resource: "db:orders",
            action: "select",
            ip,
        };
        let checks = Cell::new(0);
        assert!(
            signer
                .issue_combined(
                    &policy,
                    &target,
                    &auth,
                    &evidence,
                    &state,
                    || 1002,
                    || {
                        checks.set(checks.get() + 1);
                        if checks.get() == 2 {
                            floor.store(6, Ordering::Release);
                        }
                        true
                    }
                )
                .is_err()
        );
        // Retirement during even the final owner callback must discard the
        // private signature, rather than expose a previously checked network.
        floor.store(5, Ordering::Release);
        checks.set(0);
        assert!(
            signer
                .issue_combined(
                    &policy,
                    &target,
                    &auth,
                    &evidence,
                    &state,
                    || 1002,
                    || {
                        checks.set(checks.get() + 1);
                        if checks.get() == 4 {
                            floor.store(6, Ordering::Release);
                        }
                        true
                    }
                )
                .is_err()
        );
        assert_eq!(checks.get(), 4);
        floor.store(5, Ordering::Release);
        let ticks = Cell::new(0);
        assert!(
            signer
                .issue_combined(
                    &policy,
                    &target,
                    &auth,
                    &evidence,
                    &state,
                    || {
                        ticks.set(ticks.get() + 1);
                        if ticks.get() == 3 { 1001 } else { 1002 }
                    },
                    || true
                )
                .is_err()
        );
        let expired_live = crate::authentication_live::Observation::fixture(&auth, 1003);
        let evidence = authorization::LiveEvidence {
            authentication: &expired_live,
            network: &network,
        };
        assert!(
            signer
                .issue_combined(&policy, &target, &auth, &evidence, &state, || 1002, || true)
                .is_err()
        );
        assert!(
            signer
                .issue_combined(
                    &policy,
                    &target,
                    &auth,
                    &evidence,
                    &state,
                    || 1004,
                    || false
                )
                .is_err()
        );
    }
    #[test]
    fn native_allow_signs_independent_permit_bound_to_authentication_and_all_revisions() {
        let auth = authentication(&context());
        let key = SigningKey::from_bytes(&[11; 32]);
        let public = key.verifying_key();
        let signer = Signer::new("pumgye".into(), 2, key).unwrap();
        let policy = policy();
        let request = request();
        let state = state();
        let signed = signer
            .issue(&policy, &request, &auth, &state, || 1002, || true)
            .unwrap();
        assert_eq!(signed.context().issuer_ref, "pumgye");
        assert_eq!(signed.context().key_epoch, 2);
        assert_eq!(
            signed.permit().authentication_receipt_sha256,
            auth.receipt_sha256()
        );
        assert_eq!(signed.permit().catalog_revision, 4);
        assert_eq!(signed.permit().policy_revision, 4);
        assert_eq!(signed.permit().network_revision, 5);
        assert_eq!(signed.permit().route_revision, 6);
        assert_eq!(signed.permit().plan_revision, 7);
        assert_eq!(signed.expires_ms(), 1400);
        let binding = receipt_binding::digest(signed.context(), Some(signed.permit())).unwrap();
        receipt::verify(
            &public,
            signed.bytes(),
            receipt::Purpose::Permit,
            &binding,
            1003,
        )
        .unwrap();
        assert!(
            receipt::verify(
                &public,
                signed.bytes(),
                receipt::Purpose::Authentication,
                &binding,
                1003
            )
            .is_err()
        );
        let other = SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert!(
            receipt::verify(
                &other,
                signed.bytes(),
                receipt::Purpose::Permit,
                &binding,
                1003
            )
            .is_err()
        );
        let mut changed = receipt_binding::Permit {
            authentication_receipt_sha256: auth.receipt_sha256(),
            decision_ref: "decision1",
            resource: "db:orders",
            action: "select",
            authority_epoch: "policy1",
            catalog_revision: 4,
            policy_revision: 4,
            network_revision: 5,
            route_revision: 6,
            plan_revision: 8,
        };
        let altered = receipt_binding::digest(signed.context(), Some(&changed)).unwrap();
        assert!(
            receipt::verify(
                &public,
                signed.bytes(),
                receipt::Purpose::Permit,
                &altered,
                1003
            )
            .is_err()
        );
        changed.plan_revision = 7;
        changed.authentication_receipt_sha256[0] ^= 1;
        let altered = receipt_binding::digest(signed.context(), Some(&changed)).unwrap();
        assert!(
            receipt::verify(
                &public,
                signed.bytes(),
                receipt::Purpose::Permit,
                &altered,
                1003
            )
            .is_err()
        );
        assert!(
            receipt::verify(
                &public,
                signed.bytes(),
                receipt::Purpose::Permit,
                &binding,
                1400
            )
            .is_err()
        );
        let second = signer
            .issue(&policy, &request, &auth, &state, || 1002, || true)
            .unwrap();
        assert_ne!(&signed.bytes()[50..82], &second.bytes()[50..82]);
    }
    #[test]
    fn deny_retirement_expiry_and_invalid_owner_state_do_not_return_permits() {
        let auth = authentication(&context());
        let signer = Signer::new("pumgye".into(), 2, SigningKey::from_bytes(&[11; 32])).unwrap();
        let policy = policy();
        let mut request = request();
        let mut state = state();
        request.action = "drop";
        assert!(matches!(
            signer.issue(&policy, &request, &auth, &state, || 1002, || true),
            Err(Refused::Authorization(authorization::Refused::Denied(_)))
        ));
        request.action = "select";
        assert!(
            signer
                .issue(&policy, &request, &auth, &state, || 1002, || false)
                .is_err()
        );
        state.policy_revision = 0;
        assert!(matches!(
            signer.issue(&policy, &request, &auth, &state, || 1002, || true),
            Err(Refused::InvalidBinding)
        ));
        state.policy_revision = 4;
        state.plan_expires_ms = 1002;
        assert!(
            signer
                .issue(&policy, &request, &auth, &state, || 1002, || true)
                .is_err()
        );
        state.plan_expires_ms = 1400;
        let checks = Cell::new(0);
        assert!(
            signer
                .issue(
                    &policy,
                    &request,
                    &auth,
                    &state,
                    || 1002,
                    || {
                        let count = checks.get() + 1;
                        checks.set(count);
                        count < 3
                    }
                )
                .is_err()
        );
        let ticks = Cell::new(0);
        assert!(
            signer
                .issue(
                    &policy,
                    &request,
                    &auth,
                    &state,
                    || {
                        let count = ticks.get() + 1;
                        ticks.set(count);
                        if count == 3 { 1001 } else { 1002 }
                    },
                    || true
                )
                .is_err()
        );
        ticks.set(0);
        assert!(
            signer
                .issue(
                    &policy,
                    &request,
                    &auth,
                    &state,
                    || {
                        let count = ticks.get() + 1;
                        ticks.set(count);
                        if count >= 4 { 1400 } else { 1002 }
                    },
                    || true
                )
                .is_err()
        );
    }
}
