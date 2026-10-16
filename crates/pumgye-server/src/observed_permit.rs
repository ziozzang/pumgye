//! Native observed permit source. All prerequisite RPC clocks use this source's
//! BOOTTIME domain. Authentication stays a separate SDK receiver observation.
use crate::{
    authentication_observed::OwnerSlot, network_live, permit::Signer, plan_live, route_live,
};
use hangang_runtime::time::ReceiverClock;
use pumgye_core::{CompiledPolicy, Decision, GuardEvidence, ResourceDecision};
use pumgye_grpc::v1::*;
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tonic::{Request, Response, Status};

const MAXIMUM: u64 = 9_007_199_254_740_991;
fn unavailable() -> Status {
    Status::unavailable("observed native owner unavailable")
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

// Arithmetic only, invoked by native private-construction observations. The
// caller's before/expiry ticks belong to this exact P BOOTTIME adapter. Rounded
// elapsed includes a full tick to cover independent fractional sample phases.
pub(crate) fn prerequisite_bound(
    before: u64,
    expires: u64,
    now: u64,
    rates: &hopae_grpc::receipt_time::ClockRates,
) -> Result<u64, Status> {
    let budget = u32::try_from(expires.checked_sub(before).ok_or_else(unavailable)?)
        .map_err(|_| unavailable())?;
    let elapsed = now
        .checked_sub(before)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(unavailable)?;
    rates
        .remaining_admission_until(
            budget,
            &hopae_grpc::receipt_time::Exchange {
                before_ms: before,
                after_ms: now,
                elapsed_ms: elapsed,
            },
        )
        .map_err(|_| unavailable())
}
/// Native database/Kubernetes snapshot retaining the exact compiled policy.
pub trait NativePolicySnapshot: Send + Sync {
    fn compiled(&self) -> &CompiledPolicy;
    fn revision(&self) -> u64;
    fn current(&self) -> bool;
    /// Suspend-inclusive readiness anchored by the native publication owner.
    fn remaining(&self) -> Result<std::time::Duration, Status>;
}
pub trait NativePolicySource: Send + Sync {
    fn capture(&self) -> Result<Arc<dyn NativePolicySnapshot>, Status>;
}
/// Fixed native transport topology, never request-selected endpoints or reports.
pub struct Owners {
    pub authentication: Arc<OwnerSlot>,
    pub network: Arc<network_live::Client>,
    pub route: Arc<route_live::Client>,
    pub plan: Arc<plan_live::Client>,
}
pub struct Service {
    owners: Owners,
    signer: Arc<Signer>,
    clock: Arc<ReceiverClock>,
    domain: String,
    policy: Arc<dyn NativePolicySource>,
    rates: hopae_grpc::receipt_time::ClockRates,
    active: AtomicBool,
    admission: tokio::sync::Semaphore,
}
impl Service {
    /// Capture the existing authority's exact publication, never a policy copy.
    /// Domain is pobs1:<32 lowercase hex CSPRNG process nonce>:<1..64 ASCII base>.
    pub fn from_native(
        owners: Owners,
        signer: Arc<Signer>,
        policy: Arc<dyn NativePolicySource>,
        base_authority: &str,
        rates: hopae_grpc::receipt_time::ClockRates,
    ) -> Result<Arc<Self>, Status> {
        if base_authority.len() > 64 || !valid_id(base_authority) {
            return Err(unavailable());
        }
        let mut generation = [0; 16];
        getrandom::fill(&mut generation).map_err(|_| unavailable())?;
        let nonce: String = generation.iter().map(|b| format!("{b:02x}")).collect();
        let clock = Arc::new(ReceiverClock::new(generation).map_err(|_| unavailable())?);
        Ok(Arc::new(Self {
            owners,
            signer,
            clock,
            domain: format!("pobs1:{nonce}:{base_authority}"),
            policy,
            rates,
            active: AtomicBool::new(true),
            admission: tokio::sync::Semaphore::new(64),
        }))
    }
    pub fn clock_domain(&self) -> &str {
        &self.domain
    }
    pub fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.clock.retire();
    }
    fn ticks(&self) -> Result<u64, Status> {
        if !self.active.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        match self.clock.sample_ticks() {
            Ok(t) => Ok(t),
            // A legacy Fn()->u64 adapter can return zero only AFTER irreversible
            // retirement; no later successful clock read may rescue an output.
            Err(_) => {
                self.retire();
                Err(unavailable())
            }
        }
    }
    fn current(&self, policy: &Arc<dyn NativePolicySnapshot>) -> bool {
        self.active.load(Ordering::Acquire) && policy.current()
    }
    fn fence(
        &self,
        policy: &Arc<dyn NativePolicySnapshot>,
        caller: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), Status> {
        if !self.current(policy) || !caller() || !self.current(policy) {
            return Err(unavailable());
        }
        self.ticks()?;
        Ok(())
    }
    /// This entrypoint requires an authenticated enforcement caller fence.
    /// A generated server adapter below supplies the fixed native credential.
    pub async fn issue(
        &self,
        input: AuthenticatedResourceRequest,
        caller: &(dyn Fn() -> bool + Sync),
    ) -> Result<ObservedProjectionPermitReply, Status> {
        let result = self.run(input, None, caller).await;
        crate::metrics::METRICS.observed_permit(
            crate::metrics::PermitKind::Service,
            result.as_ref().err().map(Status::code),
        );
        let (permit, observation) = result?;
        Ok(ObservedProjectionPermitReply {
            permit: Some(permit),
            observation: Some(observation),
        })
    }
    pub async fn observe(
        &self,
        input: PermitValidationRequest,
        caller: &(dyn Fn() -> bool + Sync),
    ) -> Result<ObservedPermitTimeReply, Status> {
        if !(1..=MAXIMUM).contains(&input.request_id) {
            return Err(Status::invalid_argument("request correlation"));
        }
        let (_, mut report) = self
            .run(
                input.request.ok_or_else(unavailable)?,
                Some(input.permit.ok_or_else(unavailable)?),
                caller,
            )
            .await?;
        report.request_id = input.request_id;
        Ok(report)
    }
    async fn run(
        &self,
        input: AuthenticatedResourceRequest,
        existing: Option<ProjectionPermitReply>,
        caller: &(dyn Fn() -> bool + Sync),
    ) -> Result<(ProjectionPermitReply, ObservedPermitTimeReply), Status> {
        let _admission = self
            .admission
            .try_acquire()
            .map_err(|_| Status::resource_exhausted("observed capacity"))?;
        let policy = self.policy.capture()?;
        self.fence(&policy, caller)?;
        let started = self.ticks()?;
        if !(1..=MAXIMUM).contains(&input.request_id)
            || input.minimum_revision > policy.revision()
            || !valid_id(&input.resource)
            || !valid_id(&input.action)
        {
            return Err(Status::invalid_argument("request binding"));
        }
        let ip = match input.ip.as_slice() {
            b if b.len() == 4 => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(b).map_err(|_| unavailable())?,
            )),
            b if b.len() == 16 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(b).map_err(|_| unavailable())?,
            )),
            _ => return Err(Status::invalid_argument("IP binding")),
        };
        let digest: [u8; 32] = input
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("request digest"))?;
        let context = input.context.as_ref().ok_or_else(unavailable)?;
        let route_ref = input.route.as_ref().ok_or_else(unavailable)?;
        let reference: [u8; 32] = route_ref
            .reference
            .as_slice()
            .try_into()
            .map_err(|_| unavailable())?;
        let destination: [u8; 32] = route_ref
            .destination_sha256
            .as_slice()
            .try_into()
            .map_err(|_| unavailable())?;
        let expected_route = route_live::Expected {
            reference: &reference,
            request_sha256: &digest,
            destination_sha256: &destination,
            service: &context.service,
            audience: &context.audience,
            resource: &input.resource,
            action: &input.action,
            ip,
        };
        let expected_plan = plan_live::Expected {
            service: &context.service,
            audience: &context.audience,
            resource: &input.resource,
            action: &input.action,
            aal: 0,
            minimum_revision: 1,
        };
        let old = existing
            .as_ref()
            .map(|wire| {
                crate::permit_wire::verify_observed(
                    &self.signer,
                    &self.domain,
                    &input,
                    wire,
                    self.ticks()?,
                )
                .map_err(|_| unavailable())
            })
            .transpose()?;
        let owner = self
            .owners
            .authentication
            .capture()
            .map_err(|_| unavailable())?;
        let view = || self.current(&policy);
        let mut auth = self
            .owners
            .authentication
            .observe(
                owner,
                context.clone(),
                digest,
                &input.receipt,
                caller,
                &view,
            )
            .await
            .map_err(|_| unavailable())?;
        // Zero is only an error sentinel. ticks() irreversibly retires this source
        // before returning it, and every output boundary checks that retirement.
        let clock = || self.ticks().unwrap_or(0);
        let route = self
            .owners
            .route
            .observe(expected_route, &clock)
            .await
            .map_err(|_| unavailable())?;
        let plan = self
            .owners
            .plan
            .observe(expected_plan, &clock)
            .await
            .map_err(|_| unavailable())?;
        let network = self
            .owners
            .network
            .check(ip, 1, &clock)
            .await
            .map_err(|_| unavailable())?;
        self.fence(&policy, caller)?;
        let sampled = self.ticks()?;
        let route_bound = route.observed_bound(&self.rates, sampled)?;
        let plan_bound = plan.observed_bound(&self.rates, sampled)?;
        let network_bound = network.observed_bound(&self.rates, sampled)?;
        let decision = policy.compiled().evaluate_scoped_resource(
            &context.service,
            &input.resource,
            &input.action,
            auth.subject(),
            ip,
            0,
            GuardEvidence::EnforcedAllow,
        );
        if decision != ResourceDecision::Decided(Decision::Allow) {
            return Err(Status::permission_denied("native policy refused"));
        }
        let final_route = self
            .owners
            .route
            .observe(expected_route, &clock)
            .await
            .map_err(|_| unavailable())?;
        let final_plan = self
            .owners
            .plan
            .observe(expected_plan, &clock)
            .await
            .map_err(|_| unavailable())?;
        if !route.same_owner(&final_route) || !plan.same_owner(&final_plan) {
            return Err(unavailable());
        }
        let sampled = self.ticks()?;
        let final_route_bound = final_route.observed_bound(&self.rates, sampled)?;
        let final_plan_bound = final_plan.observed_bound(&self.rates, sampled)?;
        auth = self
            .owners
            .authentication
            .refresh(auth, caller, &view)
            .await
            .map_err(|_| unavailable())?;
        self.fence(&policy, caller)?;
        // Anchor BEFORE SDK checks and their callbacks. No callback can move a
        // duration's origin forwards. All native expiries below share P's clock.
        let anchor = self.ticks()?;
        let policy_left = policy.remaining()?;
        let auth_left = self
            .owners
            .authentication
            .check(&auth, caller, &view)
            .map_err(|_| unavailable())?;
        let auth_ms =
            u64::try_from(auth_left.min(policy_left).as_millis()).map_err(|_| unavailable())?;
        let expires = anchor
            .checked_add(auth_ms)
            .ok_or_else(unavailable)?
            .min(started.checked_add(1000).ok_or_else(unavailable)?)
            .min(route_bound)
            .min(plan_bound)
            .min(network_bound)
            .min(final_route_bound)
            .min(final_plan_bound)
            .checked_sub(1)
            .ok_or_else(unavailable)?;
        let issued = self.ticks()?;
        if issued >= expires
            || !route.valid_at(issued)
            || !plan.valid_at(issued)
            || !network.valid_at(ip, issued)
        {
            return Err(unavailable());
        }
        let revisions = (
            policy.revision(),
            network.revision(),
            route.configuration_revision(),
            plan.revision(),
        );
        if old.as_ref().is_some_and(|o| o.revisions() != revisions) {
            return Err(unavailable());
        }
        let wire = match existing {
            Some(wire) => wire,
            None => {
                let mut nonce = [0; 16];
                getrandom::fill(&mut nonce).map_err(|_| unavailable())?;
                let decision_ref: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
                self.signer
                    .sign_observed(
                        &input,
                        PermitBinding {
                            authentication_receipt_sha256: Sha256::digest(&input.receipt).to_vec(),
                            decision_ref,
                            resource: input.resource.clone(),
                            action: input.action.clone(),
                            authority_epoch: self.domain.clone(),
                            catalog_revision: policy.revision(),
                            policy_revision: policy.revision(),
                            network_revision: network.revision(),
                            route_revision: route.configuration_revision(),
                            plan_revision: plan.revision(),
                        },
                        issued,
                        expires,
                    )
                    .map_err(|_| unavailable())?
            }
        };
        let proof = crate::permit_wire::verify_observed(
            &self.signer,
            &self.domain,
            &input,
            &wire,
            self.ticks()?,
        )
        .map_err(|_| unavailable())?;
        // Keep the signature private through fresh post-sign owner RPCs.
        let post_route = self
            .owners
            .route
            .observe(expected_route, &clock)
            .await
            .map_err(|_| unavailable())?;
        let post_plan = self
            .owners
            .plan
            .observe(expected_plan, &clock)
            .await
            .map_err(|_| unavailable())?;
        if !route.same_owner(&post_route) || !plan.same_owner(&post_plan) {
            return Err(unavailable());
        }
        let sampled = self.ticks()?;
        let post_route_bound = post_route.observed_bound(&self.rates, sampled)?;
        let post_plan_bound = post_plan.observed_bound(&self.rates, sampled)?;
        auth = self
            .owners
            .authentication
            .refresh(auth, caller, &view)
            .await
            .map_err(|_| unavailable())?;
        self.fence(&policy, caller)?;
        let output_anchor = self.ticks()?;
        let publication_left = policy.remaining()?;
        let left = self
            .owners
            .authentication
            .check(&auth, caller, &view)
            .map_err(|_| unavailable())?;
        let output_bound = output_anchor
            .checked_add(
                u64::try_from(left.min(publication_left).as_millis()).map_err(|_| unavailable())?,
            )
            .ok_or_else(unavailable)?
            .checked_sub(1)
            .ok_or_else(unavailable)?;
        // All callbacks precede final pure native seals and time samples.
        if !self.current(&policy) {
            return Err(unavailable());
        }
        let now = self.ticks()?;
        if now >= expires
            || now >= proof.expires_ms()
            || !network.valid_at(ip, now)
            || !route.valid_at(now)
            || !plan.valid_at(now)
            || !post_route.valid_at(now)
            || !post_plan.valid_at(now)
        {
            return Err(unavailable());
        }
        let bound = expires
            .min(proof.expires_ms())
            .min(output_bound)
            .min(post_route_bound)
            .min(post_plan_bound);
        let remaining = bound
            .checked_sub(now)
            .and_then(|n| n.checked_sub(1))
            .filter(|n| *n > 0)
            .ok_or_else(unavailable)?;
        let report = ObservedPermitTimeReply {
            request_id: input.request_id,
            receipt_sha256: Sha256::digest(&wire.receipt).to_vec(),
            clock_domain: self.domain.clone(),
            owner_now_ms: now,
            proof_remaining_ms: u32::try_from(proof.expires_ms() - now)
                .map_err(|_| unavailable())?,
            remaining_ms: u32::try_from(remaining).map_err(|_| unavailable())?,
            policy_revision: revisions.0,
            network_revision: revisions.1,
            route_revision: revisions.2,
            plan_revision: revisions.3,
            cache_ttl_ms: 0,
        };
        Ok((wire, report))
    }
}

/// Fixed native enforcement credential. Install only behind authenticated mTLS
/// with the transport's bounded ingress layer; no request-selected endpoint.
#[derive(Clone)]
pub struct GrpcService {
    owner: Arc<Service>,
    credential: Arc<str>,
}
impl GrpcService {
    pub fn new(owner: Arc<Service>, credential: String) -> Result<Self, Status> {
        if credential.len() < 32
            || credential.len() > 256
            || !credential.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(unavailable());
        }
        Ok(Self {
            owner,
            credential: credential.into(),
        })
    }
    fn authorized(&self, metadata: &tonic::metadata::MetadataMap) -> bool {
        let mut values = metadata.get_all("authorization").iter();
        let candidate = values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if values.next().is_some() {
            return false;
        }
        candidate.is_some_and(|v| {
            let a = v.as_bytes();
            let b = self.credential.as_bytes();
            let mut d = a.len() ^ b.len();
            for i in 0..a.len().max(b.len()) {
                d |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
            }
            d == 0
        })
    }
}
#[tonic::async_trait]
impl observed_projection_permits_server::ObservedProjectionPermits for GrpcService {
    async fn issue(
        &self,
        request: Request<AuthenticatedResourceRequest>,
    ) -> Result<Response<ObservedProjectionPermitReply>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(Status::unauthenticated("enforcement caller required"));
        }
        let (metadata, _, input) = request.into_parts();
        self.owner
            .issue(input, &|| self.authorized(&metadata))
            .await
            .map(Response::new)
    }
    async fn observe(
        &self,
        request: Request<PermitValidationRequest>,
    ) -> Result<Response<ObservedPermitTimeReply>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(Status::unauthenticated("enforcement caller required"));
        }
        let (metadata, _, input) = request.into_parts();
        self.owner
            .observe(input, &|| self.authorized(&metadata))
            .await
            .map(Response::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_prerequisite_rates_preserve_original_origin_and_refuse_near_expiry() {
        let rates = hopae_grpc::receipt_time::ClockRates::new(100_000, 200_000).unwrap();
        // Independent source/receiver rates contract the original 1000 ms TTL
        // to floor(999 * .8 / 1.1), anchored at the pre-RPC sample, never now.
        for before in [10, 1_000_000] {
            let bound = prerequisite_bound(before, before + 1000, before + 490, &rates).unwrap();
            assert_eq!(bound, before + 726);
            assert_eq!(
                prerequisite_bound(before, before + 1000, before + 724, &rates).unwrap(),
                bound
            );
            assert!(prerequisite_bound(before, before + 1000, before + 725, &rates).is_err());
            assert!(prerequisite_bound(before, before + 1000, before + 1000, &rates).is_err());
            assert!(prerequisite_bound(before, before + 1000, before - 1, &rates).is_err());
        }
    }
}
