//! Native checked identity -> resource Allow -> private candidate boundary.
use crate::authentication::CheckedService;
use pumgye_core::{CompiledPolicy, Decision, GuardEvidence, Resource, ResourceDecision};
use std::net::IpAddr;

/// Resource/action and verified network evidence come from native enforcement.
/// Identity, assurance, service and classification cannot be supplied here.
pub struct ResourceRequest<'a> {
    pub resource: &'a str,
    pub action: &'a str,
    pub ip: IpAddr,
    pub guard: GuardEvidence,
    pub network_expires_ms: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Unavailable,
    Denied(ResourceDecision),
}

/// `current` is a mandatory native owner fence, not a request claim. It must
/// recheck the exact policy snapshot and identity/key/network/route/plan owners.
/// The callback must keep candidate output private until success and have no
/// irreversible external effect. This function does not implement remote owner
/// discovery, permission signing or replay admission.
pub fn authorize_resource_then<T>(
    policy: &CompiledPolicy,
    request: &ResourceRequest<'_>,
    authentication: &CheckedService<'_>,
    clock: impl Fn() -> u64,
    current: impl Fn() -> bool,
    operation: impl FnOnce(&Resource) -> T,
) -> Result<T, Refused> {
    let before = clock();
    if !authentication.valid_at(before) || before >= request.network_expires_ms || !current() {
        return Err(Refused::Unavailable);
    }
    let decision = policy.evaluate_scoped_resource(
        authentication.context().service,
        request.resource,
        request.action,
        authentication.subject(),
        request.ip,
        authentication.aal(),
        request.guard,
    );
    if decision != ResourceDecision::Decided(Decision::Allow) {
        return Err(Refused::Denied(decision));
    }
    let ready = clock();
    if ready < before
        || !authentication.valid_at(ready)
        || ready >= request.network_expires_ms
        || !current()
    {
        return Err(Refused::Unavailable);
    }
    let metadata = policy
        .resource_metadata(request.resource)
        .ok_or(Refused::Unavailable)?;
    let output = operation(metadata);
    let after = clock();
    if after < ready
        || !authentication.valid_at(after)
        || after >= request.network_expires_ms
        || !current()
    {
        return Err(Refused::Unavailable);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::{Configuration, ServiceTrust};
    use ed25519_dalek::SigningKey;
    use hopae_grpc::{PrincipalKind, receipt, receipt_binding};
    use std::cell::Cell;
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
    fn checked(context: &receipt_binding::Context<'static>) -> CheckedService<'static> {
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
        let mut value = serde_json::json!({"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read"],"require_guard":true,"roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":0}},"users":{},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}},"resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"},"minimum_aal":0}}});
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
            network_expires_ms: 2000,
        }
    }
    #[test]
    fn checked_service_reaches_only_its_native_resource_allow() {
        let identity = checked(&context());
        let policy = policy();
        let mut request = request();
        let output = authorize_resource_then(
            &policy,
            &request,
            &identity,
            || 1002,
            || true,
            |metadata| {
                assert_eq!(metadata.service, "orders");
                assert_eq!(metadata.information_class, "internal");
                metadata.actions["select"].clone()
            },
        )
        .unwrap();
        assert_eq!(output, "read");
        request.guard = GuardEvidence::Unavailable;
        assert_eq!(
            authorize_resource_then(
                &policy,
                &request,
                &identity,
                || 1002,
                || true,
                |_| panic!("network refusal must not sign")
            )
            .unwrap_err(),
            Refused::Denied(ResourceDecision::Decided(Decision::GuardUnavailable))
        );
        request.guard = GuardEvidence::EnforcedAllow;
        request.action = "drop";
        assert_eq!(
            authorize_resource_then(
                &policy,
                &request,
                &identity,
                || 1002,
                || true,
                |_| panic!("unknown action must not sign")
            )
            .unwrap_err(),
            Refused::Denied(ResourceDecision::UnknownAction)
        );
    }
    #[test]
    fn identity_expiry_and_owner_retirement_discard_private_candidate() {
        let identity = checked(&context());
        let policy = policy();
        let mut request = request();
        for now in [1000, 1800] {
            assert_eq!(
                authorize_resource_then(
                    &policy,
                    &request,
                    &identity,
                    || now,
                    || true,
                    |_| panic!("expired or rolled-back identity cannot sign")
                )
                .unwrap_err(),
                Refused::Unavailable
            );
        }
        assert_eq!(
            authorize_resource_then(
                &policy,
                &request,
                &identity,
                || 1002,
                || false,
                |_| panic!("retired owner cannot sign")
            )
            .unwrap_err(),
            Refused::Unavailable
        );
        let clock = Cell::new(1002);
        let current = Cell::new(true);
        let result = authorize_resource_then(
            &policy,
            &request,
            &identity,
            || clock.get(),
            || current.get(),
            |_| {
                current.set(false);
                "private candidate"
            },
        );
        assert_eq!(result.unwrap_err(), Refused::Unavailable);
        current.set(true);
        let result = authorize_resource_then(
            &policy,
            &request,
            &identity,
            || clock.get(),
            || current.get(),
            |_| {
                clock.set(1800);
                "private candidate"
            },
        );
        assert_eq!(result.unwrap_err(), Refused::Unavailable);
        clock.set(1002);
        request.network_expires_ms = 1500;
        let network_expired = authorize_resource_then(
            &policy,
            &request,
            &identity,
            || clock.get(),
            || current.get(),
            |_| {
                clock.set(1500);
                "private candidate"
            },
        );
        assert_eq!(network_expired.unwrap_err(), Refused::Unavailable);
        clock.set(1002);
        let result = authorize_resource_then(
            &policy,
            &request,
            &identity,
            || clock.get(),
            || current.get(),
            |_| {
                clock.set(1001);
                "private candidate"
            },
        );
        assert_eq!(result.unwrap_err(), Refused::Unavailable);
    }
}
