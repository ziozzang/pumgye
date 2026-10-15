//! Signature/context checking only. Callers must still validate every native owner.
use crate::permit::Signer;
use hopae_grpc::{receipt, receipt_binding};
use pumgye_grpc::v1::{AuthenticatedResourceRequest, ProjectionPermitReply};
use sha2::{Digest, Sha256};
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
pub struct Checked {
    policy_revision: u64,
    network_revision: u64,
    route_revision: u64,
    plan_revision: u64,
    verified_ms: u64,
    expires_ms: u64,
    begun: std::time::Instant,
}
impl Checked {
    pub fn revisions(&self) -> (u64, u64, u64, u64) {
        (
            self.policy_revision,
            self.network_revision,
            self.route_revision,
            self.plan_revision,
        )
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.verified_ms
            && now.max(
                self.verified_ms
                    .saturating_add(self.begun.elapsed().as_millis().min(u64::MAX as u128) as u64),
            ) < self.expires_ms
    }
}
pub fn verify(
    signer: &Signer,
    authority_epoch: &str,
    input: &AuthenticatedResourceRequest,
    wire: &ProjectionPermitReply,
    now: u64,
) -> Result<Checked, Refused> {
    verify_inner(
        signer,
        authority_epoch,
        input,
        wire,
        now,
        true,
        hopae_grpc::PrincipalKind::Service,
    )
}
/// Only the native observed permit owner uses this with its own process ticks.
#[cfg(feature = "observed-authentication")]
pub(crate) fn verify_observed(
    signer: &Signer,
    authority_epoch: &str,
    input: &AuthenticatedResourceRequest,
    wire: &ProjectionPermitReply,
    now: u64,
) -> Result<Checked, Refused> {
    verify_inner(
        signer,
        authority_epoch,
        input,
        wire,
        now,
        false,
        hopae_grpc::PrincipalKind::Service,
    )
}
/// Workload observed owner only; source ticks never enter strict UTC validation.
#[cfg(feature = "observed-authentication")]
pub(crate) fn verify_observed_workload(
    signer: &Signer,
    authority_epoch: &str,
    input: &AuthenticatedResourceRequest,
    wire: &ProjectionPermitReply,
    now: u64,
) -> Result<Checked, Refused> {
    verify_inner(
        signer,
        authority_epoch,
        input,
        wire,
        now,
        false,
        hopae_grpc::PrincipalKind::Workload,
    )
}
#[cfg(feature = "observed-authentication")]
pub(crate) fn verify_observed_human(
    signer: &Signer,
    authority_epoch: &str,
    input: &AuthenticatedResourceRequest,
    wire: &ProjectionPermitReply,
    now: u64,
) -> Result<Checked, Refused> {
    verify_inner(
        signer,
        authority_epoch,
        input,
        wire,
        now,
        false,
        hopae_grpc::PrincipalKind::Human,
    )
}
#[allow(clippy::too_many_arguments)]
fn verify_inner(
    signer: &Signer,
    authority_epoch: &str,
    input: &AuthenticatedResourceRequest,
    wire: &ProjectionPermitReply,
    now: u64,
    strict_auth_expiry: bool,
    kind: hopae_grpc::PrincipalKind,
) -> Result<Checked, Refused> {
    let key = signer.receipt_key();
    let mut expected_context = input.context.clone().ok_or(Refused)?;
    expected_context.issuer_ref = key.issuer_ref.clone();
    expected_context.key_epoch = key.epoch;
    let context = wire.context.as_ref().ok_or(Refused)?;
    let identity = context.identity.as_ref().ok_or(Refused)?;
    let permit = wire.binding.as_ref().ok_or(Refused)?;
    if wire.request_id != input.request_id
        || !(1..=9_007_199_254_740_991).contains(&input.request_id)
        || wire.cache_ttl_ms != 0
        || input.receipt.len() != receipt::LENGTH
        || input.request_sha256.len() != 32
        || context != &expected_context
        || context.request_sha256 != input.request_sha256
        || identity.kind
            != match kind {
                hopae_grpc::PrincipalKind::Service => 2,
                hopae_grpc::PrincipalKind::Workload => 3,
                hopae_grpc::PrincipalKind::Human => 1,
                _ => return Err(Refused),
            }
        || if kind == hopae_grpc::PrincipalKind::Human {
            !matches!(identity.aal, 1 | 2)
        } else {
            identity.aal != 0
        }
        || permit.resource != input.resource
        || permit.action != input.action
        || permit.authority_epoch != authority_epoch
        || permit.catalog_revision != permit.policy_revision
        || permit.policy_revision < input.minimum_revision
        || permit.authentication_receipt_sha256.as_slice()
            != <[u8; 32]>::from(Sha256::digest(&input.receipt))
    {
        return Err(Refused);
    }
    if kind == hopae_grpc::PrincipalKind::Human
        && (pumgye_core::HumanSubject::parse(&identity.subject_ref).is_err()
            || hopae_grpc::human_epoch::decode(&context.identity_authority_epoch).is_err())
    {
        return Err(Refused);
    }
    let context = receipt_binding::Context {
        issuer_ref: &context.issuer_ref,
        key_epoch: context.key_epoch,
        identity_authority_epoch: &context.identity_authority_epoch,
        identity: receipt_binding::Identity {
            subject_ref: &identity.subject_ref,
            kind,
            aal: identity.aal.try_into().map_err(|_| Refused)?,
            revision: identity.revision,
            credential_generation: identity.credential_generation,
        },
        service: &context.service,
        audience: &context.audience,
        request_sha256: context
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Refused)?,
    };
    let binding = receipt_binding::Permit {
        authentication_receipt_sha256: permit
            .authentication_receipt_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Refused)?,
        decision_ref: &permit.decision_ref,
        resource: &permit.resource,
        action: &permit.action,
        authority_epoch: &permit.authority_epoch,
        catalog_revision: permit.catalog_revision,
        policy_revision: permit.policy_revision,
        network_revision: permit.network_revision,
        route_revision: permit.route_revision,
        plan_revision: permit.plan_revision,
    };
    let digest = receipt_binding::digest(&context, Some(&binding)).map_err(|_| Refused)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key.public_key).map_err(|_| Refused)?;
    let checked = receipt::verify(&key, &wire.receipt, receipt::Purpose::Permit, &digest, now)
        .map_err(|_| Refused)?;
    let expires_ms = checked.claims().expires_ms;
    // Authentication is independently verified by the following native evaluation.
    if strict_auth_expiry
        && expires_ms > u64::from_be_bytes(input.receipt[10..18].try_into().map_err(|_| Refused)?)
    {
        return Err(Refused);
    }
    Ok(Checked {
        policy_revision: binding.policy_revision,
        network_revision: binding.network_revision,
        route_revision: binding.route_revision,
        plan_revision: binding.plan_revision,
        verified_ms: now,
        expires_ms,
        begun: std::time::Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hopae_grpc::v1::{AuthenticationReceiptContext, ReceiptIdentity};
    use pumgye_grpc::v1::{NativeRouteReference, PermitBinding};
    fn fixture() -> (Signer, AuthenticatedResourceRequest, ProjectionPermitReply) {
        let auth_key = SigningKey::from_bytes(&[7; 32]);
        let key = SigningKey::from_bytes(&[8; 32]);
        let signer = Signer::new("pumgye".into(), 1, key.clone()).unwrap();
        let auth = receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: "owned-auth",
            identity: receipt_binding::Identity {
                subject_ref: "s_owned",
                kind: hopae_grpc::PrincipalKind::Service,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
        };
        let auth_bytes = receipt::sign(
            &auth_key,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 100,
                expires_ms: 900,
                binding: receipt_binding::digest(&auth, None).unwrap(),
                nonce: [1; 32],
            },
        )
        .unwrap();
        let auth_context = AuthenticationReceiptContext {
            issuer_ref: "hopae".into(),
            key_epoch: 1,
            identity_authority_epoch: "owned-auth".into(),
            identity: Some(ReceiptIdentity {
                subject_ref: "s_owned".into(),
                kind: 2,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            }),
            service: "orders".into(),
            audience: "orders-api".into(),
            request_sha256: vec![3; 32],
        };
        let binding = receipt_binding::Permit {
            authentication_receipt_sha256: Sha256::digest(auth_bytes).into(),
            decision_ref: "owned-decision",
            resource: "db:orders",
            action: "select",
            authority_epoch: "owned-process",
            catalog_revision: 2,
            policy_revision: 2,
            network_revision: 3,
            route_revision: 4,
            plan_revision: 5,
        };
        let permission_context = receipt_binding::Context {
            issuer_ref: "pumgye",
            ..auth
        };
        let permission = receipt::sign(
            &key,
            &receipt::Claims {
                purpose: receipt::Purpose::Permit,
                issued_ms: 102,
                expires_ms: 800,
                binding: receipt_binding::digest(&permission_context, Some(&binding)).unwrap(),
                nonce: [2; 32],
            },
        )
        .unwrap();
        let native = AuthenticatedResourceRequest {
            request_id: 7,
            minimum_revision: 2,
            ip: vec![192, 0, 2, 1],
            resource: "db:orders".into(),
            action: "select".into(),
            context: Some(auth_context.clone()),
            receipt: auth_bytes.to_vec(),
            request_sha256: vec![3; 32],
            route: Some(NativeRouteReference {
                reference: vec![4; 32],
                destination_sha256: vec![5; 32],
            }),
        };
        let wire = ProjectionPermitReply {
            request_id: 7,
            cache_ttl_ms: 0,
            context: Some(AuthenticationReceiptContext {
                issuer_ref: "pumgye".into(),
                ..auth_context
            }),
            receipt: permission.to_vec(),
            binding: Some(PermitBinding {
                authentication_receipt_sha256: binding.authentication_receipt_sha256.to_vec(),
                decision_ref: "owned-decision".into(),
                resource: "db:orders".into(),
                action: "select".into(),
                authority_epoch: "owned-process".into(),
                catalog_revision: 2,
                policy_revision: 2,
                network_revision: 3,
                route_revision: 4,
                plan_revision: 5,
            }),
        };
        (signer, native, wire)
    }
    #[test]
    fn native_signature_context_incarnation_and_deadline_are_bound() {
        let (signer, native, wire) = fixture();
        let checked = verify(&signer, "owned-process", &native, &wire, 103).unwrap();
        assert_eq!(checked.revisions(), (2, 3, 4, 5));
        assert_eq!(checked.expires_ms(), 800);
        assert!(checked.valid_at(104));
        assert!(!checked.valid_at(102));
        assert!(!checked.valid_at(800));
        assert!(verify(&signer, "new-process", &native, &wire, 103).is_err());
        assert!(verify(&signer, "owned-process", &native, &wire, 800).is_err());
        let other = Signer::new("pumgye".into(), 1, SigningKey::from_bytes(&[9; 32])).unwrap();
        assert!(verify(&other, "owned-process", &native, &wire, 103).is_err());
        for case in 0..10 {
            let mut bad = wire.clone();
            match case {
                0 => bad.request_id = 8,
                1 => bad.cache_ttl_ms = 1,
                2 => {
                    bad.context
                        .as_mut()
                        .unwrap()
                        .identity
                        .as_mut()
                        .unwrap()
                        .revision = 2
                }
                3 => bad.context.as_mut().unwrap().audience = "other".into(),
                4 => bad.binding.as_mut().unwrap().authentication_receipt_sha256[0] ^= 1,
                5 => bad.binding.as_mut().unwrap().resource = "other".into(),
                6 => bad.binding.as_mut().unwrap().catalog_revision = 1,
                7 => bad.binding.as_mut().unwrap().plan_revision = 0,
                8 => bad.receipt[1] = 1,
                _ => bad.receipt[100] ^= 1,
            }
            assert!(
                verify(&signer, "owned-process", &native, &bad, 103).is_err(),
                "case {case}"
            );
        }
    }
    #[cfg(feature = "observed-authentication")]
    #[test]
    fn typed_observed_signing_and_verification_never_cross_principal_classes() {
        let (signer, mut input, template) = fixture();
        let binding = template.binding.unwrap();
        for wire_kind in [1, 2, 3, 4, 0, u32::MAX] {
            input
                .context
                .as_mut()
                .unwrap()
                .identity
                .as_mut()
                .unwrap()
                .kind = wire_kind;
            let service = signer.sign_observed(&input, binding.clone(), 100, 700);
            let workload = signer.sign_observed_workload(&input, binding.clone(), 100, 700);
            assert_eq!(service.is_ok(), wire_kind == 2);
            assert_eq!(workload.is_ok(), wire_kind == 3);
            if let Ok(wire) = service {
                assert!(verify_observed(&signer, "owned-process", &input, &wire, 101).is_ok());
                assert!(
                    verify_observed_workload(&signer, "owned-process", &input, &wire, 101).is_err()
                );
            }
            if let Ok(wire) = workload {
                assert!(
                    verify_observed_workload(&signer, "owned-process", &input, &wire, 101).is_ok()
                );
                assert!(verify_observed(&signer, "owned-process", &input, &wire, 101).is_err());
                assert!(verify(&signer, "owned-process", &input, &wire, 101).is_err());
            }
        }
        input
            .context
            .as_mut()
            .unwrap()
            .identity
            .as_mut()
            .unwrap()
            .kind = 3;
        input
            .context
            .as_mut()
            .unwrap()
            .identity
            .as_mut()
            .unwrap()
            .aal = 1;
        assert!(
            signer
                .sign_observed_workload(&input, binding, 100, 700)
                .is_err()
        );
    }

    // Pure private wire/signature tests; not evidence of native Human authentication.
    #[cfg(feature = "observed-authentication")]
    #[test]
    fn human_typed_wire_keeps_assurance_and_rejects_crossclass_reinterpretation() {
        let (signer, mut input, previous) = fixture();
        let context = input.context.as_mut().unwrap();
        context.identity_authority_epoch =
            hopae_grpc::human_epoch::encode("owned", 7, 1, "123456789abcdef0123456789abcdef0")
                .unwrap();
        let identity = context.identity.as_mut().unwrap();
        identity.kind = 1;
        identity.aal = 2;
        identity.subject_ref = format!("human1:{}", "a".repeat(64));
        identity.revision = 3;
        identity.credential_generation = 9;
        let binding = previous.binding.unwrap();
        let wire = signer
            .sign_observed_human(&input, binding.clone(), 100, 800)
            .unwrap();
        assert!(
            verify_observed_human(&signer, &binding.authority_epoch, &input, &wire, 200).is_ok()
        );
        assert!(
            verify_observed_workload(&signer, &binding.authority_epoch, &input, &wire, 200)
                .is_err()
        );
        assert!(verify_observed(&signer, &binding.authority_epoch, &input, &wire, 200).is_err());
        for aal in [0, 3, u32::MAX] {
            let mut bad = input.clone();
            bad.context.as_mut().unwrap().identity.as_mut().unwrap().aal = aal;
            assert!(
                signer
                    .sign_observed_human(&bad, binding.clone(), 100, 800)
                    .is_err()
            );
            assert!(
                verify_observed_human(&signer, &binding.authority_epoch, &bad, &wire, 200).is_err()
            );
        }
        let mut bad = input.clone();
        bad.context
            .as_mut()
            .unwrap()
            .identity
            .as_mut()
            .unwrap()
            .subject_ref = "s_other".into();
        assert!(
            signer
                .sign_observed_human(&bad, binding.clone(), 100, 800)
                .is_err()
        );
        let mut bad = wire.clone();
        bad.binding.as_mut().unwrap().authentication_receipt_sha256[0] ^= 1;
        assert!(
            verify_observed_human(&signer, &binding.authority_epoch, &input, &bad, 200).is_err()
        );
    }
}
