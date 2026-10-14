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
pub(crate) struct Query {
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
pub(crate) struct Outcome {
    version: u8,
    pub(crate) request_id: u64,
    pub(crate) revision: u64,
    pub(crate) network_revision: u64,
    pub(crate) allow: bool,
    ttl_ms: u8,
}
fn now() -> u64 {
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
    let view = a.view.load_full();
    let current = || {
        a.healthy.load(Ordering::Acquire)
            && Arc::ptr_eq(&view, &a.view.load_full())
            && (!a.kubernetes_owned
                || (a.source_ready.load(Ordering::Acquire)
                    && view
                        .source_expires
                        .is_some_and(|deadline| std::time::Instant::now() < deadline)))
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
    if !current()
        || !observation.valid_for(&checked, now())
        || !network.valid_at(q.ip, now())
        || !caller()
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Outcome {
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
