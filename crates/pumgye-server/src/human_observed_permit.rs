//! Human-only native observed permit source. All prerequisite RPC clocks use this source's
//! BOOTTIME domain. Authentication stays a separate SDK receiver observation.
use crate::{
    authentication_human_observed::OwnerSlot, network_live, permit::Signer, plan_live, route_live,
};
use hangang_runtime::time::ReceiverClock;
use pumgye_core::{Decision, GuardEvidence, ResourceDecision};
use pumgye_grpc::v1::*;
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tonic::Status;

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

use crate::observed_permit::{NativePolicySnapshot, NativePolicySource};
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
/// Cloneable transport carrier; one original clock anchor, consumed exactly once.
#[derive(Clone)]
pub struct Ingress {
    stamp: Arc<std::sync::Mutex<Option<IngressStamp>>>,
}
struct IngressStamp {
    clock: std::sync::Weak<ReceiverClock>,
    started: u64,
    deadline: std::time::Instant,
    policy: Arc<dyn NativePolicySnapshot>,
    authentication: Arc<crate::authentication_human_observed::AuthenticationOwnerGeneration>,
}
impl Service {
    pub fn begin_ingress(&self) -> Result<Ingress, Status> {
        let started = self.ticks()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1000);
        let policy = self.policy.capture()?;
        let authentication = self
            .owners
            .authentication
            .capture()
            .map_err(|_| unavailable())?;
        if !self.current(&policy) {
            return Err(unavailable());
        }
        Ok(Ingress {
            stamp: Arc::new(std::sync::Mutex::new(Some(IngressStamp {
                clock: Arc::downgrade(&self.clock),
                started,
                deadline,
                policy,
                authentication,
            }))),
        })
    }
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
        let ingress = self.begin_ingress()?;
        self.issue_admitted(input, ingress, caller).await
    }
    pub async fn issue_admitted(
        &self,
        input: AuthenticatedResourceRequest,
        ingress: Ingress,
        caller: &(dyn Fn() -> bool + Sync),
    ) -> Result<ObservedProjectionPermitReply, Status> {
        let (permit, observation) = self.run(input, None, caller, ingress).await?;
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
        let ingress = self.begin_ingress()?;
        self.observe_admitted(input, ingress, caller).await
    }
    pub async fn observe_admitted(
        &self,
        input: PermitValidationRequest,
        ingress: Ingress,
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
                ingress,
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
        ingress: Ingress,
    ) -> Result<(ProjectionPermitReply, ObservedPermitTimeReply), Status> {
        let stamp = ingress
            .stamp
            .lock()
            .map_err(|_| unavailable())?
            .take()
            .ok_or_else(unavailable)?;
        if !std::sync::Weak::ptr_eq(&stamp.clock, &Arc::downgrade(&self.clock))
            || std::time::Instant::now() >= stamp.deadline
        {
            return Err(unavailable());
        }
        let started = stamp.started;
        if self
            .ticks()?
            .checked_sub(started)
            .is_none_or(|age| age >= 1000)
        {
            return Err(unavailable());
        }
        let _admission = self
            .admission
            .try_acquire()
            .map_err(|_| Status::resource_exhausted("observed capacity"))?;
        let original_caller = caller;
        let caller = &|| std::time::Instant::now() < stamp.deadline && original_caller();
        let policy = stamp.policy;
        self.fence(&policy, caller)?;
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
        let old = existing
            .as_ref()
            .map(|wire| {
                crate::permit_wire::verify_observed_human(
                    &self.signer,
                    &self.domain,
                    &input,
                    wire,
                    self.ticks()?,
                )
                .map_err(|_| unavailable())
            })
            .transpose()?;
        let owner = stamp.authentication;
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
        let expected_plan = plan_live::Expected {
            service: &context.service,
            audience: &context.audience,
            resource: &input.resource,
            action: &input.action,
            aal: auth.aal(),
            minimum_revision: 1,
        };
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
        if !auth.route_matches(
            route.route_id(),
            route.configuration_revision(),
            &destination,
        ) {
            return Err(unavailable());
        }
        // The receipt is verified: its sealed level (AAL3 only for opted-in
        // applications, Hopae ADR-0018) is evidence, not an adapter assertion.
        let sealed = pumgye_core::SealedAssurance::from_verified_receipt(auth.aal())
            .ok_or_else(unavailable)?;
        let decision = policy.compiled().evaluate_scoped_human_sealed_resource(
            &context.service,
            &input.resource,
            &input.action,
            auth.subject(),
            ip,
            sealed,
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
                    .sign_observed_human(
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
        let proof = crate::permit_wire::verify_observed_human(
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
