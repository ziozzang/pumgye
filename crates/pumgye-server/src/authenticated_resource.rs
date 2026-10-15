//! Actual decision-role endpoint; identities and network evidence are native.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    subject_ref: String,
    kind: u8,
    aal: u8,
    revision: u64,
    credential_generation: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptContext {
    issuer_ref: String,
    key_epoch: u64,
    identity_authority_epoch: String,
    identity: Identity,
    service: String,
    audience: String,
    request_sha256: Vec<u8>,
}
impl ReceiptContext {
    pub(crate) fn from_wire(
        context: hopae_grpc::v1::AuthenticationReceiptContext,
    ) -> Result<Self, StatusCode> {
        let identity = context.identity.ok_or(StatusCode::BAD_REQUEST)?;
        if identity.kind != 2 || identity.aal != 0 {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(Self {
            issuer_ref: context.issuer_ref,
            key_epoch: context.key_epoch,
            identity_authority_epoch: context.identity_authority_epoch,
            identity: Identity {
                subject_ref: identity.subject_ref,
                kind: 2,
                aal: 0,
                revision: identity.revision,
                credential_generation: identity.credential_generation,
            },
            service: context.service,
            audience: context.audience,
            request_sha256: context.request_sha256,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteReference {
    pub(crate) reference: Vec<u8>,
    pub(crate) destination_sha256: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Query {
    #[serde(default)]
    pub(crate) route: Option<RouteReference>,
    pub(crate) request_id: u64,
    pub(crate) minimum_revision: u64,
    pub(crate) resource: String,
    pub(crate) action: String,
    pub(crate) ip: IpAddr,
    pub(crate) context: ReceiptContext,
    pub(crate) receipt: Vec<u8>,
    pub(crate) request_sha256: Vec<u8>,
}
#[derive(Serialize)]
pub(crate) struct OwnerState {
    pub(crate) route_revision: u64,
    pub(crate) plan_revision: u64,
    pub(crate) expires_ms: u64,
}
#[derive(Serialize)]
pub(crate) struct Outcome {
    #[serde(skip)]
    pub(crate) owners: Option<OwnerState>,
    #[serde(skip)]
    pub(crate) permit: Option<pumgye_grpc::v1::ProjectionPermitReply>,
    pub(crate) route_observed: bool,
    version: u8,
    pub(crate) request_id: u64,
    pub(crate) revision: u64,
    pub(crate) network_revision: u64,
    pub(crate) allow: bool,
    ttl_ms: u8,
}
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis().min(u64::MAX as u128) as u64)
}
async fn decide(
    State(a): State<Arc<Authority>>,
    headers: HeaderMap,
    Json(q): Json<Query>,
) -> Result<Json<Outcome>, StatusCode> {
    if !authorized(&headers, &a.decision) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    evaluate(&a, q, &|| authorized(&headers, &a.decision))
        .await
        .map(Json)
}
pub(crate) async fn evaluate(
    a: &Authority,
    q: Query,
    caller: &(dyn Fn() -> bool + Sync),
) -> Result<Outcome, StatusCode> {
    evaluate_mode(a, q, caller, false).await
}
pub(crate) async fn evaluate_mode(
    a: &Authority,
    q: Query,
    caller: &(dyn Fn() -> bool + Sync),
    issue: bool,
) -> Result<Outcome, StatusCode> {
    if !caller() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !(1..=9_007_199_254_740_991).contains(&q.request_id)
        || q.minimum_revision > 9_007_199_254_740_991
        || q.receipt.len() != hopae_grpc::receipt::LENGTH
        || q.context.identity.kind != 2
        || q.context.identity.aal != 0
        || [&q.resource, &q.action].iter().any(|v| {
            v.is_empty()
                || v.len() > 128
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        })
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if issue
        && (a.permit_signer.is_none()
            || a.route_live.is_none()
            || a.projection_live.is_none()
            || q.route.is_none())
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let trust = a
        .authentication_trust
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let live = a
        .authentication_live
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let network = a
        .network_live
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let context = hopae_grpc::receipt_binding::Context {
        issuer_ref: &q.context.issuer_ref,
        key_epoch: q.context.key_epoch,
        identity_authority_epoch: &q.context.identity_authority_epoch,
        identity: hopae_grpc::receipt_binding::Identity {
            subject_ref: &q.context.identity.subject_ref,
            kind: hopae_grpc::PrincipalKind::Service,
            aal: 0,
            revision: q.context.identity.revision,
            credential_generation: q.context.identity.credential_generation,
        },
        service: &q.context.service,
        audience: &q.context.audience,
        request_sha256: q
            .context
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| StatusCode::BAD_REQUEST)?,
    };
    let expected = q
        .request_sha256
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let checked = trust
        .verify(&context, &q.receipt, &expected, now())
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let route_expected = q
        .route
        .as_ref()
        .map(|route| -> Result<_, StatusCode> {
            Ok(pumgye_server::route_live::Expected {
                reference: route
                    .reference
                    .as_slice()
                    .try_into()
                    .map_err(|_| StatusCode::BAD_REQUEST)?,
                request_sha256: &expected,
                destination_sha256: route
                    .destination_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| StatusCode::BAD_REQUEST)?,
                service: context.service,
                audience: context.audience,
                resource: &q.resource,
                action: &q.action,
                ip: q.ip,
            })
        })
        .transpose()?;
    let route_observation = match (&a.route_live, route_expected) {
        (Some(client), Some(expected)) => Some(
            client
                .observe(expected, &now)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        ),
        (None, None) => None,
        _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };
    let plan_expected = pumgye_server::plan_live::Expected {
        service: context.service,
        audience: context.audience,
        resource: &q.resource,
        action: &q.action,
        aal: context.identity.aal,
        minimum_revision: 1,
    };
    let plan_observation = match a.projection_live.as_ref() {
        Some(client) => Some(
            client
                .observe(plan_expected, &now)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        ),
        None => None,
    };
    let view = a.view.load_full();
    let current = || {
        a.healthy.load(Ordering::Acquire)
            && Arc::ptr_eq(&view, &a.view.load_full())
            && a.source_remaining(&view).is_some()
    };
    if !current() || view.document.revision < q.minimum_revision {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let network = network
        .check(q.ip, 1, &now)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let observation = live
        .validate(&checked, &q.receipt, &now)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let target = pumgye_server::authorization::NativeResourceRequest {
        resource: &q.resource,
        action: &q.action,
        ip: q.ip,
    };
    let evidence = pumgye_server::authorization::LiveEvidence {
        authentication: &observation,
        network: &network,
    };
    let result = pumgye_server::authorization::authorize_combined_resource_then(
        &view.compiled,
        &target,
        &checked,
        &evidence,
        now,
        current,
        |_| (),
    );
    a.queries.fetch_add(1, Ordering::Relaxed);
    let allow = match result {
        Ok(()) => true,
        Err(pumgye_server::authorization::Refused::Denied(_)) => false,
        Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };
    let final_plan = match (&a.projection_live, &plan_observation) {
        (Some(client), Some(prior)) => {
            let final_plan = client
                .observe(plan_expected, &now)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if !prior.valid_at(now()) || !prior.same_owner(&final_plan) {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            Some(final_plan)
        }
        (None, None) => None,
        _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };
    // Requery the actual owner after native identity/network/policy evaluation.
    // A first observation is not a distributed lease or a substitute for this.
    if let Some(prior) = route_observation.as_ref() {
        let client = a
            .route_live
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let expected = route_expected.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let final_route = client
            .observe(expected, &now)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !prior.valid_at(now()) || !final_route.valid_at(now()) || !prior.same_owner(&final_route)
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    if plan_observation
        .as_ref()
        .is_some_and(|plan| !plan.valid_at(now()))
        || final_plan
            .as_ref()
            .is_some_and(|plan| !plan.valid_at(now()))
        || !current()
        || !observation.valid_for(&checked, now())
        || !network.valid_at(q.ip, now())
        || !caller()
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let permit = if issue {
        if !allow {
            return Err(StatusCode::FORBIDDEN);
        }
        let signer = a
            .permit_signer
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let route = route_observation
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let plan = final_plan.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let decision_ref =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce);
        let start = now();
        let policy_budget = if a.kubernetes_owned {
            a.source_remaining(&view)
                .map(|duration| duration.as_millis().min(1000) as u64)
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        } else {
            1000
        };
        let state = pumgye_server::permit::State {
            decision_ref: &decision_ref,
            authority_epoch: &a.authority_epoch,
            policy_revision: view.document.revision,
            network_revision: network.revision(),
            route_revision: route.configuration_revision(),
            plan_revision: plan.revision(),
            policy_expires_ms: start
                .checked_add(policy_budget)
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?,
            route_expires_ms: route.expires_ms(),
            plan_expires_ms: plan.expires_ms(),
        };
        let signed = signer
            .issue_combined(
                &view.compiled,
                &target,
                &checked,
                &evidence,
                &state,
                now,
                || {
                    current()
                        && caller()
                        && route.valid_at(now())
                        && plan.valid_at(now())
                        && plan_observation
                            .as_ref()
                            .is_some_and(|prior| prior.valid_at(now()))
                },
            )
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let context = signed.context();
        let binding = signed.permit();
        let reply = pumgye_grpc::v1::ProjectionPermitReply {
            request_id: q.request_id,
            cache_ttl_ms: 0,
            receipt: signed.bytes().to_vec(),
            context: Some(hopae_grpc::v1::AuthenticationReceiptContext {
                issuer_ref: context.issuer_ref.into(),
                key_epoch: context.key_epoch,
                identity_authority_epoch: context.identity_authority_epoch.into(),
                identity: Some(hopae_grpc::v1::ReceiptIdentity {
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
            binding: Some(pumgye_grpc::v1::PermitBinding {
                authentication_receipt_sha256: binding.authentication_receipt_sha256.to_vec(),
                decision_ref: binding.decision_ref.into(),
                resource: binding.resource.into(),
                action: binding.action.into(),
                authority_epoch: binding.authority_epoch.into(),
                catalog_revision: binding.catalog_revision,
                policy_revision: binding.policy_revision,
                network_revision: binding.network_revision,
                route_revision: binding.route_revision,
                plan_revision: binding.plan_revision,
            }),
        };
        // Keep the signed candidate private through fresh post-sign owner queries.
        let post_route = a
            .route_live
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            .observe(route_expected.ok_or(StatusCode::SERVICE_UNAVAILABLE)?, &now)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let post_plan = a
            .projection_live
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            .observe(plan_expected, &now)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !route.same_owner(&post_route)
            || !plan.same_owner(&post_plan)
            || !post_route.valid_at(now())
            || !post_plan.valid_at(now())
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        if now() >= signed.expires_ms()
            || !current()
            || !caller()
            || !observation.valid_for(&checked, now())
            || !network.valid_at(q.ip, now())
            || !route.valid_at(now())
            || !plan.valid_at(now())
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Some(reply)
    } else {
        None
    };
    let owners = route_observation
        .as_ref()
        .zip(final_plan.as_ref())
        .map(|(route, plan)| OwnerState {
            route_revision: route.configuration_revision(),
            plan_revision: plan.revision(),
            expires_ms: route
                .expires_ms()
                .min(plan.expires_ms())
                .min(network.expires_ms())
                .min(checked.expires_ms()),
        });
    if owners
        .as_ref()
        .is_some_and(|owners| now() >= owners.expires_ms)
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Outcome {
        owners,
        permit,
        route_observed: route_observation.is_some(),
        version: 1,
        request_id: q.request_id,
        revision: view.document.revision,
        network_revision: network.revision(),
        allow,
        ttl_ms: 0,
    })
}
pub fn route() -> axum::routing::MethodRouter<Arc<Authority>> {
    post(decide).layer(axum::extract::DefaultBodyLimit::max(4096))
}
