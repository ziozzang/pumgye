//! Observed authentication evidence foundation. No permission constructor or
//! endpoint activation. The enforcement caller supplies the authenticated final
//! digest; Pumgye does not claim to own unseen HTTP method/path/body bytes.
use crate::{authentication::Refused, authentication_config::Trust};
use arc_swap::ArcSwapOption;
use hangang_runtime::time::ReceiverClock;
use hopae_grpc::{
    human_observed_client::{self, Client, Observation},
    receipt_time::ClockRates,
    v1,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Native immutable configuration generation. One persistent client serves
/// dynamic signed subjects and process domains; it is never built from a query.
pub struct AuthenticationOwnerGeneration {
    trust: Arc<Trust>,
    client: Client,
    active: AtomicBool,
}
/// Native startup policy and fixed owner routing, never incoming request data.
pub struct Configuration<'a> {
    pub issuer_ref: &'a str,
    /// Fixed PEM (`EndpointConfig`) or reloadable TLS (`ReloadableEndpointConfig`).
    pub endpoint: human_observed_client::ClientEndpoint<'a>,
    pub scopes: Vec<human_observed_client::HumanScope>,
    pub minimum_source_revision: u64,
    pub minimum_application_generation: u64,
    pub minimum_key_registry_revision: u64,
}
impl AuthenticationOwnerGeneration {
    pub fn new(
        trust: Arc<Trust>,
        config: Configuration<'_>,
        clock: Arc<ReceiverClock>,
        rates: ClockRates,
        limits: human_observed_client::Limits,
    ) -> Result<Arc<Self>, Refused> {
        let policy = trust.human_observed_policy(
            config.issuer_ref,
            config.scopes,
            config.minimum_source_revision,
            config.minimum_application_generation,
            config.minimum_key_registry_revision,
        )?;
        let client = Client::new_human(config.endpoint, policy, clock, rates, limits)
            .map_err(|_| Refused)?;
        Ok(Arc::new(Self {
            trust,
            client,
            active: AtomicBool::new(true),
        }))
    }
    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.client.retire();
    }
}

/// Retirement and publication are serialized. Capture at ingress and retain the
/// exact Arc throughout asynchronous work. A replaced generation cannot return.
#[derive(Default)]
pub struct OwnerSlot {
    current: ArcSwapOption<AuthenticationOwnerGeneration>,
    replacement: Mutex<()>,
}
impl OwnerSlot {
    pub fn replace(&self, next: Option<Arc<AuthenticationOwnerGeneration>>) -> Result<(), Refused> {
        let _writer = self.replacement.lock().map_err(|_| Refused)?;
        // Validate under the writer lock before changing a healthy generation.
        if next
            .as_ref()
            .is_some_and(|n| !n.active.load(Ordering::Acquire))
        {
            return Err(Refused);
        }
        let current = self.current.load();
        if current
            .as_ref()
            .zip(next.as_ref())
            .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
        {
            return Ok(());
        }
        if let Some(old) = current.as_ref() {
            old.retire();
        }
        self.current.store(next);
        Ok(())
    }
    pub fn capture(&self) -> Result<Arc<AuthenticationOwnerGeneration>, Refused> {
        self.current.load_full().ok_or(Refused)
    }
    // Pure native seal check: no external code runs with this snapshot guard.
    fn current(&self, owner: &Arc<AuthenticationOwnerGeneration>) -> Result<(), Refused> {
        let current = self.current.load();
        if !current.as_ref().is_some_and(|c| Arc::ptr_eq(c, owner))
            || !owner.active.load(Ordering::Acquire)
        {
            return Err(Refused);
        }
        Ok(())
    }
    fn fence(
        &self,
        owner: &Arc<AuthenticationOwnerGeneration>,
        caller: &(dyn Fn() -> bool + Sync),
        view: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), Refused> {
        self.current(owner)?;
        // No snapshot guard or writer mutex crosses external callbacks.
        // Callbacks may replace native state or block. Recheck the pure seal
        // after they return, and sample admission time after all callbacks.
        if !caller() || !view() {
            return Err(Refused);
        }
        self.current(owner)
    }
    /// No strict verifier, fabricated UTC, or legacy RPC fallback. Both native
    /// caller and policy-view health/identity fences must be live on each side.
    pub async fn observe(
        &self,
        owner: Arc<AuthenticationOwnerGeneration>,
        context: v1::AuthenticationReceiptContext,
        authenticated_final_digest: [u8; 32],
        raw_receipt: &[u8],
        caller: &(dyn Fn() -> bool + Sync),
        view: &(dyn Fn() -> bool + Sync),
    ) -> Result<CheckedObservedHuman, Refused> {
        self.fence(&owner, caller, view)?;
        owner.trust.human_observed_scope(&context)?;
        let prepared = owner
            .client
            .prepare_observation(context, raw_receipt, authenticated_final_digest)
            .map_err(|_| Refused)?;
        let observation = owner.client.observe(prepared).await.map_err(|_| Refused)?;
        self.fence(&owner, caller, view)?;
        owner.trust.human_observed_scope(observation.context())?;
        let checked = CheckedObservedHuman { owner, observation };
        self.check(&checked, caller, view)?;
        Ok(checked)
    }
    /// Local BOOTTIME admission only; not a remote revocation lease.
    pub fn check(
        &self,
        checked: &CheckedObservedHuman,
        caller: &(dyn Fn() -> bool + Sync),
        view: &(dyn Fn() -> bool + Sync),
    ) -> Result<Duration, Refused> {
        self.fence(&checked.owner, caller, view)?;
        let remaining = checked
            .owner
            .client
            .check(&checked.observation, checked.observation.request())
            .map_err(|_| Refused)?;
        self.current(&checked.owner)?;
        Ok(remaining)
    }
    /// Consumes the old observation; SDK preserves its original shortest budget.
    pub async fn refresh(
        &self,
        checked: CheckedObservedHuman,
        caller: &(dyn Fn() -> bool + Sync),
        view: &(dyn Fn() -> bool + Sync),
    ) -> Result<CheckedObservedHuman, Refused> {
        self.check(&checked, caller, view)?;
        let CheckedObservedHuman { owner, observation } = checked;
        let observation = owner
            .client
            .refresh(observation)
            .await
            .map_err(|_| Refused)?;
        self.fence(&owner, caller, view)?;
        owner.trust.human_observed_scope(observation.context())?;
        let checked = CheckedObservedHuman { owner, observation };
        self.check(&checked, caller, view)?;
        Ok(checked)
    }
}
/// Verified native Human identity and fixed-owner time evidence, never a strict
/// CheckedService or a permission. No public constructor, Clone or serde.
pub struct CheckedObservedHuman {
    owner: Arc<AuthenticationOwnerGeneration>,
    observation: Observation,
}
impl CheckedObservedHuman {
    pub fn context(&self) -> &v1::AuthenticationReceiptContext {
        self.observation.context()
    }
    pub fn receipt(&self) -> &[u8] {
        self.observation.receipt()
    }
    pub fn subject(&self) -> &str {
        &self
            .context()
            .identity
            .as_ref()
            .expect("SDK verified identity")
            .subject_ref
    }
    pub fn aal(&self) -> u8 {
        self.context()
            .identity
            .as_ref()
            .expect("SDK verified Human")
            .aal as u8
    }
    pub fn revision(&self) -> u64 {
        self.context()
            .identity
            .as_ref()
            .expect("SDK verified identity")
            .revision
    }
}

impl CheckedObservedHuman {
    pub(crate) fn route_matches(&self, route: &str, revision: u64, destination: &[u8; 32]) -> bool {
        let scope = self.observation.scope();
        scope.service == self.context().service
            && scope.audience == self.context().audience
            && scope.route_id == route
            && scope.route_revision == revision
            && &scope.destination_sha256 == destination
    }
}
