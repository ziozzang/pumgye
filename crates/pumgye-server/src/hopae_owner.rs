//! Hopae owner inputs for policy model v2 (ADR 0021): the signed membership
//! projection (`docs/GROUPS.md` verification contract) and the subject lifecycle
//! feed (`docs/SUBJECT_DIRECTORY.md`). Pure verification and state machines are
//! separate from the authenticated HTTPS transport so they can be tested exactly.
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Domain separation string of the projection signature.
pub const DOMAIN: &[u8] = b"hangang-zerotrust:hopae-membership-projection:v1\0";
pub const FORMAT: &str = "hopae.membership-projection.v1";
pub const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Pages walked per snapshot or feed pass (bounded work per refresh).
pub const MAX_PAGES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    UnknownKey,
    Signature,
    Binding,
    /// Cursor/watermark/store continuity broken: take a new snapshot.
    Continuity,
    /// Hopae answered 410 cursor_expired.
    CursorExpired,
    Transport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyId {
    issuer_ref: String,
    key_epoch: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    key: KeyId,
    payload: String,
    signature: String,
}
#[derive(Deserialize)]
struct Header {
    kind: String,
    issuer_ref: String,
    key_epoch: u64,
    audience: String,
    store: String,
    vocabulary_sha256: String,
    issued_at: i64,
    max_aal: u8,
}
/// A pinned projection key from Pumgye's own configuration.
#[derive(Clone, Debug)]
pub struct PinnedKey {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub key: VerifyingKey,
}
impl PinnedKey {
    /// Base64 (standard) Ed25519 public key; weak keys refused.
    pub fn parse(issuer_ref: &str, key_epoch: u64, public_key: &str) -> Option<Self> {
        let bytes: [u8; 32] = STANDARD.decode(public_key).ok()?.try_into().ok()?;
        let key = VerifyingKey::from_bytes(&bytes).ok()?;
        (!key.is_weak() && !issuer_ref.is_empty() && issuer_ref.len() <= 128).then(|| Self {
            issuer_ref: issuer_ref.to_owned(),
            key_epoch,
            key,
        })
    }
}
/// SHA-256 hex of the sorted, de-duplicated vocabulary joined by `\n`.
pub fn vocabulary_digest(groups: &[String]) -> String {
    let mut v: Vec<&str> = groups.iter().map(String::as_str).collect();
    v.sort_unstable();
    v.dedup();
    format!("{:x}", Sha256::digest(v.join("\n").as_bytes()))
}
/// A verified page: header facts plus the parsed payload.
#[derive(Debug)]
pub struct Page {
    pub store: String,
    pub issued_at_ms: i64,
    pub max_aal: u8,
    pub body: Value,
}
/// Verification contract steps 1–4: envelope, pinned key, strict signature over
/// `DOMAIN || payload`, then header binding (kind, key, audience, vocabulary,
/// freshness). The payload is parsed only after the signature verifies.
pub fn verify(
    envelope: &str,
    keys: &[PinnedKey],
    kind: &str,
    audience: &str,
    vocabulary_sha256: &str,
    now_ms: i64,
    max_age_ms: i64,
) -> Result<Page, Refusal> {
    if envelope.len() > MAX_PAYLOAD_BYTES * 2 {
        return Err(Refusal::Malformed);
    }
    let env: Envelope = serde_json::from_str(envelope).map_err(|_| Refusal::Malformed)?;
    if env.format != FORMAT {
        return Err(Refusal::Malformed);
    }
    let key = keys
        .iter()
        .find(|k| k.issuer_ref == env.key.issuer_ref && k.key_epoch == env.key.key_epoch)
        .ok_or(Refusal::UnknownKey)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(env.payload.as_bytes())
        .map_err(|_| Refusal::Malformed)?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Refusal::Malformed);
    }
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(env.signature.as_bytes())
        .map_err(|_| Refusal::Malformed)?
        .try_into()
        .map_err(|_| Refusal::Malformed)?;
    let mut message = Vec::with_capacity(DOMAIN.len() + bytes.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&bytes);
    key.key
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| Refusal::Signature)?;
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| Refusal::Malformed)?;
    let header: Header = serde_json::from_value(body.clone()).map_err(|_| Refusal::Malformed)?;
    if header.kind != kind
        || header.issuer_ref != env.key.issuer_ref
        || header.key_epoch != env.key.key_epoch
        || header.audience != audience
        || header.vocabulary_sha256 != vocabulary_sha256
        || header.issued_at > now_ms + 60_000
        || now_ms - header.issued_at > max_age_ms
        || header.max_aal > 3
    {
        return Err(Refusal::Binding);
    }
    Ok(Page {
        store: header.store,
        issued_at_ms: header.issued_at,
        max_aal: header.max_aal,
        body,
    })
}

#[derive(Deserialize)]
struct SnapshotEntry {
    principal: Option<String>,
    user_id: String,
    status: String,
    groups: Vec<String>,
}
#[derive(Deserialize)]
struct Change {
    #[allow(dead_code)]
    revision: i64,
    change: String,
    group_id: String,
    user_id: Option<String>,
    principal: Option<String>,
}

/// Verified membership projection state for one vocabulary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Projection {
    pub store: String,
    pub vocabulary: Vec<String>,
    pub digest: String,
    /// Feed position (`r<revision>`) after the last applied page.
    pub cursor: String,
    pub max_aal: u8,
    pub members: BTreeMap<String, BTreeSet<String>>,
    principals: BTreeMap<String, String>,
    pub issued_at_ms: i64,
}
fn canonical_groups(
    groups: &[String],
    vocabulary: &BTreeSet<&str>,
) -> Result<BTreeSet<String>, Refusal> {
    let mut out = BTreeSet::new();
    for g in groups {
        // Byte comparison of canonical lowercase GroupRefs; never case-folded.
        if !pumgye_core::v2::group_ref_valid(g) || !vocabulary.contains(g.as_str()) {
            return Err(Refusal::Binding);
        }
        out.insert(g.clone());
    }
    Ok(out)
}
fn human(principal: &Option<String>) -> Option<&String> {
    principal
        .as_ref()
        .filter(|p| pumgye_core::v2::principal_ref_valid(pumgye_core::v2::PrincipalKind::Human, p))
}
impl Projection {
    /// Apply a complete, verified snapshot (all pages, in order) for `vocabulary`.
    pub fn from_snapshot(
        vocabulary: &[String],
        pages: &[Page],
        requested_cursors: &[Option<String>],
    ) -> Result<Self, Refusal> {
        let vocab: BTreeSet<&str> = vocabulary.iter().map(String::as_str).collect();
        let first = pages.first().ok_or(Refusal::Malformed)?;
        let watermark = first.body["watermark"].as_i64().ok_or(Refusal::Malformed)?;
        let mut p = Projection {
            store: first.store.clone(),
            vocabulary: vocabulary.to_vec(),
            digest: vocabulary_digest(vocabulary),
            cursor: format!("r{watermark}"),
            max_aal: first.max_aal,
            issued_at_ms: first.issued_at_ms,
            ..Default::default()
        };
        for (i, page) in pages.iter().enumerate() {
            let cursor = page.body.get("cursor").cloned().unwrap_or(Value::Null);
            let expected = requested_cursors.get(i).cloned().flatten();
            if page.store != p.store
                || page.body["watermark"].as_i64() != Some(watermark)
                || cursor.as_str().map(str::to_owned) != expected
                || (cursor.is_null() != expected.is_none())
            {
                return Err(Refusal::Continuity);
            }
            let more = page.body["more"].as_bool().ok_or(Refusal::Malformed)?;
            if more != (i + 1 < pages.len()) {
                return Err(Refusal::Continuity);
            }
            let entries: Vec<SnapshotEntry> = serde_json::from_value(page.body["entries"].clone())
                .map_err(|_| Refusal::Malformed)?;
            for e in entries {
                let groups = canonical_groups(&e.groups, &vocab)?;
                // Entries with a null principal cannot be bound and are ignored.
                let Some(principal) = human(&e.principal) else {
                    continue;
                };
                p.principals.insert(e.user_id.clone(), principal.clone());
                if e.status == "active" && !groups.is_empty() {
                    p.members.insert(principal.clone(), groups);
                }
            }
            p.issued_at_ms = p.issued_at_ms.min(page.issued_at_ms);
            p.max_aal = p.max_aal.min(page.max_aal);
        }
        Ok(p)
    }
    /// Apply one verified changes page requested from `self.cursor`. Returns `more`.
    pub fn apply_changes(&mut self, page: &Page) -> Result<bool, Refusal> {
        if page.store != self.store {
            return Err(Refusal::Continuity);
        }
        let from = page.body["from"].as_i64().ok_or(Refusal::Malformed)?;
        let asked: i64 = self
            .cursor
            .strip_prefix('r')
            .and_then(|n| n.parse().ok())
            .ok_or(Refusal::Malformed)?;
        let next: i64 = page.body["next_cursor"]
            .as_str()
            .and_then(|c| c.strip_prefix('r'))
            .and_then(|n| n.parse().ok())
            .ok_or(Refusal::Malformed)?;
        if from != asked || next < asked {
            return Err(Refusal::Continuity);
        }
        let vocab: BTreeSet<String> = self.vocabulary.iter().cloned().collect();
        let vocab_ref: BTreeSet<&str> = vocab.iter().map(String::as_str).collect();
        let changes: Vec<Change> =
            serde_json::from_value(page.body["changes"].clone()).map_err(|_| Refusal::Malformed)?;
        for c in changes {
            let group = canonical_groups(std::slice::from_ref(&c.group_id), &vocab_ref)?
                .into_iter()
                .next()
                .ok_or(Refusal::Malformed)?;
            let principal = human(&c.principal).cloned().or_else(|| {
                c.user_id
                    .as_ref()
                    .and_then(|u| self.principals.get(u).cloned())
            });
            if let (Some(u), Some(p)) = (&c.user_id, &principal) {
                self.principals.insert(u.clone(), p.clone());
            }
            match (c.change.as_str(), principal) {
                ("member_added" | "member_restored", Some(p)) => {
                    self.members.entry(p).or_default().insert(group);
                }
                ("member_removed" | "member_suspended", Some(p)) => {
                    if let Some(set) = self.members.get_mut(&p) {
                        set.remove(&group);
                        if set.is_empty() {
                            self.members.remove(&p);
                        }
                    }
                }
                ("group_deleted", _) => {
                    self.members.retain(|_, set| {
                        set.remove(&group);
                        !set.is_empty()
                    });
                }
                ("group_created" | "group_updated", _) | (_, None) => {}
                _ => return Err(Refusal::Malformed),
            }
        }
        self.cursor = format!("r{next}");
        self.issued_at_ms = page.issued_at_ms;
        self.max_aal = page.max_aal;
        page.body["more"].as_bool().ok_or(Refusal::Malformed)
    }
}

/// Hopae subject lifecycle state (unsigned feed over the authenticated channel).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lifecycle {
    pub statuses: BTreeMap<String, String>,
    pub cursor: Option<String>,
    /// A complete reconcile snapshot has been applied.
    pub complete: bool,
}
impl Lifecycle {
    /// Apply snapshot items (`human_subject`, `status`) or feed changes (same fields).
    pub fn apply(&mut self, items: &Value) -> Result<(), Refusal> {
        for item in items.as_array().ok_or(Refusal::Malformed)? {
            let status = item["status"].as_str().ok_or(Refusal::Malformed)?;
            if !matches!(status, "active" | "disabled" | "deleted") {
                return Err(Refusal::Malformed);
            }
            // Consumers apply the reported status, so replays are harmless.
            if let Some(subject) = item["human_subject"].as_str() {
                if !pumgye_core::v2::principal_ref_valid(
                    pumgye_core::v2::PrincipalKind::Human,
                    subject,
                ) {
                    return Err(Refusal::Malformed);
                }
                self.statuses.insert(subject.to_owned(), status.to_owned());
            }
        }
        Ok(())
    }
    pub fn view(&self) -> pumgye_core::v2::Lifecycle {
        let mut l = pumgye_core::v2::Lifecycle::default();
        for (s, status) in &self.statuses {
            match status.as_str() {
                "deleted" => {
                    l.deleted.insert(s.clone());
                }
                "disabled" => {
                    l.disabled.insert(s.clone());
                }
                _ => {}
            }
        }
        l
    }
    /// Known to Hopae (any status) — used to refuse unresolvable new references.
    pub fn knows(&self, subject: &str) -> bool {
        self.statuses.contains_key(subject)
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionConfig {
    pub audience: String,
    pub keys: Vec<KeyConfig>,
    #[serde(default = "default_age")]
    pub max_age_secs: u64,
    #[serde(default = "default_staleness")]
    pub max_staleness_secs: u64,
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleConfig {
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_reconcile")]
    pub reconcile_interval_secs: u64,
}
fn default_age() -> u64 {
    300
}
fn default_staleness() -> u64 {
    900
}
fn default_poll() -> u64 {
    15
}
fn default_reconcile() -> u64 {
    3600
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Hopae admin listener base URL (`https://host:port`).
    pub address: String,
    pub ca: std::path::PathBuf,
    pub certificate: std::path::PathBuf,
    pub key: std::path::PathBuf,
    /// Optional environment variable holding a bearer credential for Hopae.
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default)]
    pub projection: Option<ProjectionConfig>,
    #[serde(default)]
    pub lifecycle: Option<LifecycleConfig>,
}
pub struct Client {
    http: reqwest::Client,
    base: reqwest::Url,
    token: Option<zeroize::Zeroizing<String>>,
    pub keys: Vec<PinnedKey>,
    pub projection: Option<ProjectionConfig>,
    pub lifecycle: Option<LifecycleConfig>,
}
fn bounded(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= 128 * 1024,
        "owner material bound"
    );
    Ok(bytes)
}
impl Client {
    pub fn load(
        path: &std::path::Path,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let config: Config = serde_json::from_slice(&bounded(path)?)?;
        let base = reqwest::Url::parse(&config.address)?;
        anyhow::ensure!(
            base.scheme() == "https" && base.path() == "/",
            "Hopae owner address must be an https origin"
        );
        let mut identity = bounded(&config.certificate)?;
        identity.extend_from_slice(&bounded(&config.key)?);
        let http = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&bounded(&config.ca)?)?)
            .identity(reqwest::Identity::from_pem(&identity)?)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let token = match &config.token_env {
            Some(name) => {
                Some(zeroize::Zeroizing::new(env(name).ok_or_else(|| {
                    anyhow::anyhow!("Hopae owner credential unavailable")
                })?))
            }
            None => None,
        };
        let mut keys = Vec::new();
        if let Some(p) = &config.projection {
            anyhow::ensure!(
                !p.keys.is_empty() && !p.audience.is_empty(),
                "projection keys and audience required"
            );
            anyhow::ensure!(
                (1..=86_400).contains(&p.max_age_secs)
                    && (1..=604_800).contains(&p.max_staleness_secs)
                    && (1..=3600).contains(&p.poll_interval_secs),
                "projection timing bounds"
            );
            for k in &p.keys {
                keys.push(
                    PinnedKey::parse(&k.issuer_ref, k.key_epoch, &k.public_key)
                        .ok_or_else(|| anyhow::anyhow!("invalid pinned projection key"))?,
                );
            }
        }
        Ok(Self {
            http,
            base,
            token,
            keys,
            projection: config.projection,
            lifecycle: config.lifecycle,
        })
    }
    async fn post(&self, path: &str, body: &Value) -> Result<String, Refusal> {
        let url = self.base.join(path).map_err(|_| Refusal::Transport)?;
        let mut request = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .header("x-hopae-admin-request", "1")
            .body(body.to_string());
        if let Some(t) = &self.token {
            request = request.bearer_auth(t.as_str());
        }
        let response = request.send().await.map_err(|_| Refusal::Transport)?;
        if response.status() == reqwest::StatusCode::GONE {
            return Err(Refusal::CursorExpired);
        }
        if !response.status().is_success() {
            return Err(Refusal::Transport);
        }
        let bytes = response.bytes().await.map_err(|_| Refusal::Transport)?;
        if bytes.len() > MAX_PAYLOAD_BYTES * 2 {
            return Err(Refusal::Malformed);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| Refusal::Malformed)
    }
    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
    }
    /// Full snapshot then feed to the head for `vocabulary`.
    pub async fn snapshot(&self, vocabulary: &[String]) -> Result<Projection, Refusal> {
        let config = self.projection.as_ref().ok_or(Refusal::Transport)?;
        let digest = vocabulary_digest(vocabulary);
        let mut pages = Vec::new();
        let mut cursors = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let text = self
                .post(
                    "/v1/groups/projection/snapshot",
                    &serde_json::json!({"groups": vocabulary, "limit": 500, "cursor": cursor}),
                )
                .await?;
            let page = verify(
                &text,
                &self.keys,
                "snapshot",
                &config.audience,
                &digest,
                Self::now_ms(),
                config.max_age_secs as i64 * 1000,
            )?;
            let next = page.body["next_cursor"].as_str().map(str::to_owned);
            let more = page.body["more"].as_bool().unwrap_or(false);
            cursors.push(cursor.clone());
            pages.push(page);
            if !more {
                let mut projection = Projection::from_snapshot(vocabulary, &pages, &cursors)?;
                self.follow(&mut projection).await?;
                return Ok(projection);
            }
            cursor = Some(next.ok_or(Refusal::Malformed)?);
        }
        Err(Refusal::Continuity)
    }
    /// Apply the change feed from the projection's cursor until `more` is false.
    pub async fn follow(&self, projection: &mut Projection) -> Result<(), Refusal> {
        let config = self.projection.as_ref().ok_or(Refusal::Transport)?;
        for _ in 0..MAX_PAGES {
            let text = self
                .post(
                    "/v1/groups/projection/changes",
                    &serde_json::json!({"groups": projection.vocabulary, "cursor": projection.cursor, "limit": 500}),
                )
                .await?;
            let page = verify(
                &text,
                &self.keys,
                "changes",
                &config.audience,
                &projection.digest,
                Self::now_ms(),
                config.max_age_secs as i64 * 1000,
            )?;
            if !projection.apply_changes(&page)? {
                return Ok(());
            }
        }
        Err(Refusal::Continuity)
    }
    /// Reconcile snapshot followed by the feed.
    pub async fn lifecycle_snapshot(&self) -> Result<Lifecycle, Refusal> {
        let mut state = Lifecycle::default();
        let mut cursor: Option<String> = None;
        let mut watermark = None;
        for _ in 0..MAX_PAGES {
            let text = self
                .post(
                    "/v1/subjects/lifecycle/snapshot",
                    &serde_json::json!({"cursor": cursor, "limit": 200}),
                )
                .await?;
            let page: Value = serde_json::from_str(&text).map_err(|_| Refusal::Malformed)?;
            if watermark.is_none() {
                watermark = Some(page["watermark"].as_str().map(str::to_owned));
            }
            state.apply(&page["items"])?;
            match page["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => {
                    state.cursor = watermark.flatten();
                    state.complete = true;
                    self.lifecycle_follow(&mut state).await?;
                    return Ok(state);
                }
            }
        }
        Err(Refusal::Continuity)
    }
    pub async fn lifecycle_follow(&self, state: &mut Lifecycle) -> Result<(), Refusal> {
        for _ in 0..MAX_PAGES {
            let text = self
                .post(
                    "/v1/subjects/lifecycle",
                    &serde_json::json!({"cursor": state.cursor, "limit": 100}),
                )
                .await?;
            let page: Value = serde_json::from_str(&text).map_err(|_| Refusal::Malformed)?;
            state.apply(&page["changes"])?;
            if let Some(next) = page["next_cursor"].as_str() {
                state.cursor = Some(next.to_owned());
            }
            if !page["more"].as_bool().unwrap_or(false) {
                return Ok(());
            }
        }
        Err(Refusal::Continuity)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    pub(crate) const G1: &str = "grp1:00000000000000000000000000";
    pub(crate) const G2: &str = "grp1:11111111111111111111111111";
    pub(crate) const H1: &str =
        "human1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub(crate) const H2: &str =
        "human1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    pub(crate) fn signing() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }
    pub(crate) fn pinned() -> Vec<PinnedKey> {
        vec![
            PinnedKey::parse(
                "hopae-groups",
                3,
                &STANDARD.encode(signing().verifying_key().to_bytes()),
            )
            .unwrap(),
        ]
    }
    pub(crate) fn seal(key: &SigningKey, issuer: &str, epoch: u64, payload: &Value) -> String {
        let bytes = serde_json::to_vec(payload).unwrap();
        let mut m = DOMAIN.to_vec();
        m.extend_from_slice(&bytes);
        json!({"format": FORMAT, "key": {"issuer_ref": issuer, "key_epoch": epoch},
               "payload": URL_SAFE_NO_PAD.encode(&bytes), "signature": URL_SAFE_NO_PAD.encode(key.sign(&m).to_bytes())})
        .to_string()
    }
    pub(crate) fn header(kind: &str, vocab: &[String], at: i64) -> Value {
        json!({"kind": kind, "issuer_ref": "hopae-groups", "key_epoch": 3, "audience": "pumgye", "store": "realm-1",
               "vocabulary_sha256": vocabulary_digest(vocab), "issued_at": at, "max_aal": 2})
    }
    fn vocab() -> Vec<String> {
        vec![G1.into(), G2.into()]
    }
    fn page(kind: &str, extra: Value, at: i64) -> Page {
        let mut body = header(kind, &vocab(), at);
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        verify(
            &seal(&signing(), "hopae-groups", 3, &body),
            &pinned(),
            kind,
            "pumgye",
            &vocabulary_digest(&vocab()),
            at,
            60_000,
        )
        .unwrap()
    }

    #[test]
    fn verification_contract_refusals() {
        let v = vocab();
        let digest = vocabulary_digest(&v);
        let body = header("snapshot", &v, 1_000);
        let good = seal(&signing(), "hopae-groups", 3, &body);
        assert!(
            verify(
                &good,
                &pinned(),
                "snapshot",
                "pumgye",
                &digest,
                2_000,
                60_000
            )
            .is_ok()
        );
        // digest is order and duplicate insensitive
        assert_eq!(
            digest,
            vocabulary_digest(&[G2.into(), G1.into(), G1.into()])
        );
        let refuse = |text: &str, kind: &str, aud: &str, now: i64| {
            verify(text, &pinned(), kind, aud, &digest, now, 60_000).unwrap_err()
        };
        assert_eq!(refuse(&good, "changes", "pumgye", 2_000), Refusal::Binding);
        assert_eq!(refuse(&good, "snapshot", "other", 2_000), Refusal::Binding);
        assert_eq!(
            refuse(&good, "snapshot", "pumgye", 1_000 + 60_001),
            Refusal::Binding,
            "stale"
        );
        assert_eq!(
            refuse(&good, "snapshot", "pumgye", 1_000 - 60_001),
            Refusal::Binding,
            "future"
        );
        // Unknown key epoch / issuer, forged key, tampered payload, wrong domain.
        assert_eq!(
            refuse(
                &seal(&signing(), "hopae-groups", 4, &body),
                "snapshot",
                "pumgye",
                2_000
            ),
            Refusal::UnknownKey
        );
        assert_eq!(
            refuse(
                &seal(&SigningKey::from_bytes(&[7; 32]), "hopae-groups", 3, &body),
                "snapshot",
                "pumgye",
                2_000
            ),
            Refusal::Signature
        );
        let mut env: Value = serde_json::from_str(&good).unwrap();
        let mut tampered = body.clone();
        tampered["audience"] = json!("pumgye ");
        env["payload"] = json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).unwrap()));
        assert_eq!(
            refuse(&env.to_string(), "snapshot", "pumgye", 2_000),
            Refusal::Signature
        );
        let bytes = serde_json::to_vec(&body).unwrap();
        let wrong_domain = json!({"format": FORMAT, "key": {"issuer_ref":"hopae-groups","key_epoch":3},
            "payload": URL_SAFE_NO_PAD.encode(&bytes), "signature": URL_SAFE_NO_PAD.encode(signing().sign(&bytes).to_bytes())});
        assert_eq!(
            refuse(&wrong_domain.to_string(), "snapshot", "pumgye", 2_000),
            Refusal::Signature
        );
        let mut extra: Value = serde_json::from_str(&good).unwrap();
        extra["groups"] = json!([G1]);
        assert_eq!(
            refuse(&extra.to_string(), "snapshot", "pumgye", 2_000),
            Refusal::Malformed
        );
        // A different vocabulary binding is refused.
        let other = seal(
            &signing(),
            "hopae-groups",
            3,
            &header("snapshot", &[G1.into()], 1_000),
        );
        assert_eq!(
            refuse(&other, "snapshot", "pumgye", 2_000),
            Refusal::Binding
        );
    }

    #[test]
    fn snapshot_pages_and_feed_apply_as_set_operations() {
        let v = vocab();
        let p1 = page(
            "snapshot",
            json!({"watermark": 40, "cursor": null, "more": true, "next_cursor": "p1.40.u1",
            "entries": [{"principal": H1, "user_id": "u1", "status": "active", "groups": [G1]},
                        {"principal": null, "user_id": "u9", "status": "active", "groups": [G1]}]}),
            1_000,
        );
        let p2 = page(
            "snapshot",
            json!({"watermark": 40, "cursor": "p1.40.u1", "more": false, "next_cursor": null,
            "entries": [{"principal": H2, "user_id": "u2", "status": "disabled", "groups": [G2]}]}),
            1_000,
        );
        let mut p =
            Projection::from_snapshot(&v, &[p1, p2], &[None, Some("p1.40.u1".into())]).unwrap();
        assert_eq!(p.cursor, "r40");
        assert_eq!(
            p.members.len(),
            1,
            "null principal and disabled entries are not bound"
        );
        let changes = page(
            "changes",
            json!({"from": 40, "head": 44, "next_cursor": "r44", "more": false, "changes": [
            {"revision": 41, "at": 1, "change": "member_added", "group_id": G2, "user_id": "u1", "principal": H1},
            {"revision": 42, "at": 1, "change": "member_added", "group_id": G2, "user_id": "u2", "principal": H2},
            {"revision": 43, "at": 1, "change": "member_removed", "group_id": G1, "user_id": "u1", "principal": null},
            {"revision": 44, "at": 1, "change": "member_added", "group_id": G2, "user_id": "u2", "principal": H2}]}),
            1_000,
        );
        assert!(!p.apply_changes(&changes).unwrap());
        assert_eq!(p.members[H1], [G2.to_owned()].into());
        assert_eq!(p.members[H2], [G2.to_owned()].into());
        assert_eq!(p.cursor, "r44");
        // Replaying the same page is harmless only from the matching cursor.
        assert_eq!(p.apply_changes(&changes).unwrap_err(), Refusal::Continuity);
        let deleted = page(
            "changes",
            json!({"from": 44, "head": 45, "next_cursor": "r45", "more": false, "changes": [
            {"revision": 45, "at": 1, "change": "group_deleted", "group_id": G2, "user_id": null, "principal": null}]}),
            1_000,
        );
        p.apply_changes(&deleted).unwrap();
        assert!(p.members.is_empty());
        // Continuity: a page from another store, a wrong echo cursor, a foreign group.
        let mut other = page(
            "changes",
            json!({"from": 45, "head": 45, "next_cursor": "r45", "more": false, "changes": []}),
            1_000,
        );
        other.store = "realm-2".into();
        assert_eq!(p.apply_changes(&other).unwrap_err(), Refusal::Continuity);
        let p1 = page(
            "snapshot",
            json!({"watermark": 40, "cursor": "p1.40.zz", "more": false, "next_cursor": null, "entries": []}),
            1_000,
        );
        assert_eq!(
            Projection::from_snapshot(&v, &[p1], &[None]).unwrap_err(),
            Refusal::Continuity
        );
        let upper = page(
            "snapshot",
            json!({"watermark": 1, "cursor": null, "more": false, "next_cursor": null,
            "entries": [{"principal": H1, "user_id": "u1", "status": "active", "groups": ["grp1:AAAAAAAAAAAAAAAAAAAAAAAAAA"]}]}),
            1_000,
        );
        assert_eq!(
            Projection::from_snapshot(&v, &[upper], &[None]).unwrap_err(),
            Refusal::Binding
        );
    }

    #[test]
    fn lifecycle_applies_reported_status() {
        let mut l = Lifecycle::default();
        l.apply(&json!([{"user_id":"u1","human_subject":H1,"status":"active"},{"user_id":"u2","human_subject":H2,"status":"deleted"},{"user_id":"u3","human_subject":null,"status":"active"}])).unwrap();
        l.apply(
            &json!([{"user_id":"u1","human_subject":H1,"status":"disabled","change":"disabled"}]),
        )
        .unwrap();
        let v = l.view();
        assert!(v.deleted.contains(H2) && v.disabled.contains(H1));
        assert!(
            l.knows(H1)
                && !l.knows(
                    "human1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                )
        );
        assert!(
            l.apply(&json!([{"human_subject":H1,"status":"merged"}]))
                .is_err()
        );
    }
}
