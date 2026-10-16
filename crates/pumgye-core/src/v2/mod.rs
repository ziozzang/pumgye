//! Policy model version 2 (Hangang ADR 0021): principals and groups owned by
//! Hopae, global role templates, per-service permission vocabularies, allow and
//! explicit-deny bindings with lifecycle metadata, Catalog clearance labels and
//! Sumunjang network zones. The compiled snapshot is bitset based; evaluation is
//! allocation-free and generic over a [`TracerV2`] sink exactly like version 1.
pub mod convert;
pub mod diff;
pub mod explain;
pub mod time;

use crate::{AuthorizationContext, GuardEvidence, ResourceDecision};
use anyhow::{Context, Result, ensure};
use guard_core::prefix::PrefixTrie;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};
pub use time::Timestamp;

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------

/// Registered compile warning codes (also message keys).
pub const WARNING_CODES: &[&str] = &[
    "pumgye.warning.unsatisfiable_assurance",
    "pumgye.warning.legacy_workload_subject",
];
/// Registered publication admission refusals (beyond compilation).
pub const ADMISSION_CODES: &[&str] = &[
    "pumgye.validation.reason_required",
    "pumgye.validation.subject_deleted",
    "pumgye.validation.subject_unresolved",
    "pumgye.validation.subject_retired",
];
/// Registered converter review / unmigrated codes (also message keys).
pub const MIGRATION_CODES: &[&str] = &[
    "pumgye.migration.class_not_downward_closed",
    "pumgye.migration.class_compartments",
    "pumgye.migration.legacy_workload",
    "pumgye.migration.class_union",
    "pumgye.migration.empty_role",
    "pumgye.migration.kubernetes_mapping_retained",
    "pumgye.migration.unresolved_subject_kind",
];
/// Product limits validated at compile time (ADR 0021 P0 bounds).
pub mod limits {
    pub const SERVICES: usize = 4096;
    pub const TEMPLATES: usize = 1024;
    pub const BINDINGS: usize = 1_048_576;
    pub const PRINCIPALS: usize = 1_048_576;
    /// Relevant groups per snapshot (one `GroupMask`, one projection shard).
    pub const GROUPS: usize = 256;
    /// Zones per snapshot (one `ZoneMask`).
    pub const ZONES: usize = 64;
    pub const PREFIXES: usize = 65_536;
    pub const PERMISSIONS: usize = 256;
    pub const LEVELS: usize = 16;
    pub const COMPARTMENTS: usize = 64;
    pub const SUBJECTS_PER_BINDING: usize = 64;
    pub const INHERITS: usize = 8;
    /// Compiled grants per principal (or group) per service.
    pub const GRANTS_PER_SUBJECT_SERVICE: usize = 64;
    pub const CEILING_TEMPLATES: usize = 8;
    pub const RESOURCES: usize = 65_536;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyV2 {
    /// Always 2.
    pub version: u32,
    /// Read-only import of the Catalog-owned label vocabulary and resource labels.
    pub catalog: Catalog,
    /// Read-only import of Sumunjang-owned network zones (or local CIDR fallback).
    #[serde(default, skip_serializing_if = "Zones::is_empty")]
    pub zones: Zones,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub templates: BTreeMap<String, RoleTemplate>,
    pub services: BTreeMap<String, ServicePolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Catalog bundle revision this import was taken from.
    #[serde(default)]
    pub revision: u64,
    /// Classification levels in ascending order (1..16).
    pub levels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compartments: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, CatalogResource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogResource {
    pub service: String,
    pub level: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compartments: Vec<String>,
    #[serde(default)]
    pub minimum_aal: u8,
    /// action → service permission
    pub actions: BTreeMap<String, String>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneSource {
    /// Imported from the Sumunjang `NetworkZone` snapshot export (ADR 0021 P0 contract).
    Sumunjang,
    /// Local CIDR fallback (for example converter-generated `legacy.*` zones)
    /// until Sumunjang exports zones.
    #[default]
    Local,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zones {
    #[serde(default)]
    pub source: ZoneSource,
    /// Sumunjang zone snapshot revision (0 for local).
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub zones: BTreeMap<String, Zone>,
}
impl Zones {
    fn is_empty(&self) -> bool {
        self.zones.is_empty() && self.revision == 0 && self.source == ZoneSource::Local
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub prefixes: Vec<IpNet>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Clearance {
    pub level: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compartments: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTemplate {
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherits: Vec<String>,
    /// `null`: the template grants no clearance (nothing labelled is reachable).
    pub clearance_ceiling: Option<Clearance>,
    #[serde(default)]
    pub minimum_aal: u8,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CeilingMax {
    One(String),
    Many(Vec<String>),
}
impl CeilingMax {
    pub fn templates(&self) -> Vec<&str> {
        match self {
            CeilingMax::One(t) if t == "guest" => vec![],
            CeilingMax::One(t) => vec![t.as_str()],
            CeilingMax::Many(v) => v
                .iter()
                .map(String::as_str)
                .filter(|t| *t != "guest")
                .collect(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ceiling {
    pub zone: String,
    /// Template(s) bounding rights from this zone; `"guest"` bounds to nothing.
    pub max: CeilingMax,
}
fn yes() -> bool {
    true
}
fn is_true(v: &bool) -> bool {
    *v
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicy {
    pub permissions: Vec<String>,
    /// template permission → service permission (identity by default).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub permission_map: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_ceiling: Vec<Ceiling>,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub require_guard: bool,
    #[serde(default)]
    pub authorization_context: AuthorizationContext,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    Service,
    Workload,
}
impl PrincipalKind {
    pub const ALL: [PrincipalKind; 3] = [
        PrincipalKind::Human,
        PrincipalKind::Service,
        PrincipalKind::Workload,
    ];
    fn index(self) -> usize {
        self as usize
    }
    pub fn name(self) -> &'static str {
        match self {
            PrincipalKind::Human => "human",
            PrincipalKind::Service => "service",
            PrincipalKind::Workload => "workload",
        }
    }
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Kind-specific canonical reference check (Hopae-owned, opaque, never reused).
pub fn principal_ref_valid(kind: PrincipalKind, reference: &str) -> bool {
    match kind {
        PrincipalKind::Human => reference
            .strip_prefix("human1:")
            .is_some_and(|d| lower_hex(d, 64)),
        PrincipalKind::Service => reference
            .strip_prefix("s_")
            .is_some_and(|d| lower_hex(d, 48)),
        PrincipalKind::Workload => {
            reference
                .strip_prefix("wk2:")
                .is_some_and(|d| lower_hex(d, 64))
                || legacy_workload(reference)
                || spiffe_workload(reference)
        }
    }
}
/// Kubernetes ServiceAccount SPIFFE ID `spiffe://<trust-domain>/ns/<namespace>/sa/<name>`
/// (Hopae `docs/KUBERNETES_WORKLOAD.md`): names the ServiceAccount, not one UID
/// incarnation, so bindings by SPIFFE ID survive re-creation by design.
pub fn spiffe_workload(reference: &str) -> bool {
    let Some(rest) = reference.strip_prefix("spiffe://") else {
        return false;
    };
    let mut parts = rest.split('/');
    let (Some(td), Some("ns"), Some(ns), Some("sa"), Some(sa), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    let dns_label = |v: &str, max: usize| {
        !v.is_empty()
            && v.len() <= max
            && v.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            && !v.starts_with(['-', '.'])
            && !v.ends_with(['-', '.'])
    };
    reference.len() <= 512
        && !td.is_empty()
        && td.len() <= 255
        && td
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && dns_label(ns, 63)
        && dns_label(sa, 253)
}
/// Legacy Pod-bound workload subjects (`s_` form) kept by the converter; deprecated.
pub fn legacy_workload(reference: &str) -> bool {
    reference
        .strip_prefix("s_")
        .is_some_and(|d| lower_hex(d, 48))
}
/// Canonical GroupRef: `grp1:` + 26 lowercase Crockford base32 characters.
/// Compared byte for byte; other spellings are refused, never case-folded.
pub fn group_ref_valid(reference: &str) -> bool {
    reference.strip_prefix("grp1:").is_some_and(|d| {
        d.len() == 26
            && d.bytes()
                .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b))
    })
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum SubjectRef {
    Principal {
        kind: PrincipalKind,
        #[serde(rename = "ref")]
        reference: String,
    },
    Group {
        group: String,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllKeyword {
    All,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnyKeyword {
    Any,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Names<K> {
    Keyword(K),
    List(Vec<String>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub services: Names<AllKeyword>,
}
fn any_zone() -> Names<AnyKeyword> {
    Names::Keyword(AnyKeyword::Any)
}
fn is_any(v: &Names<AnyKeyword>) -> bool {
    matches!(v, Names::Keyword(_))
}
fn is_zero(v: &u8) -> bool {
    *v == 0
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conditions {
    #[serde(default = "any_zone", skip_serializing_if = "is_any")]
    pub zones: Names<AnyKeyword>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub minimum_aal: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}
impl Default for Conditions {
    fn default() -> Self {
        Self {
            zones: any_zone(),
            minimum_aal: 0,
            not_before: None,
            expires_at: None,
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Authenticated publishing actor; stamped by the server, never trusted from a body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<String>,
    /// `native`, `kubernetes:<uid>`, `jit:<id>` or `migrated:v1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    /// Policy revision that introduced or last changed the binding (server stamped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub id: String,
    pub effect: Effect,
    pub subjects: Vec<SubjectRef>,
    /// Allow: the granted template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Deny: service permissions or `"all"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Names<AllKeyword>>,
    pub scope: Scope,
    #[serde(default)]
    pub conditions: Conditions,
    #[serde(default)]
    pub metadata: Metadata,
}

// ---------------------------------------------------------------------------
// Compiled snapshot
// ---------------------------------------------------------------------------

/// FNV-1a for small, policy-defined vocabularies (services, permissions,
/// labels, actions). Request strings only look these tables up; they cannot
/// insert, and each table is bounded (≤ 4,096 services, ≤ 256 entries
/// otherwise), so probe length stays bounded. Principal and resource tables
/// keep the default SipHash.
#[derive(Default)]
pub struct Fnv(u64);
impl std::hash::Hasher for Fnv {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut h = if self.0 == 0 {
            0xcbf2_9ce4_8422_2325
        } else {
            self.0
        };
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        self.0 = h;
    }
}
pub(crate) type VocabMap<V> = HashMap<String, V, std::hash::BuildHasherDefault<Fnv>>;
/// Permission bitset over a service vocabulary of up to 256 permissions.
pub type PermMask = [u64; 4];
#[inline(always)]
fn has(mask: &PermMask, bit: u16) -> bool {
    mask[(bit >> 6) as usize] & (1u64 << (bit & 63)) != 0
}
fn set(mask: &mut PermMask, bit: u16) {
    mask[(bit >> 6) as usize] |= 1u64 << (bit & 63);
}
/// Group bitset over the snapshot's relevant group vocabulary (≤ 256).
pub type GroupMask = [u64; 4];
pub const ANY_ZONE: u64 = u64::MAX;
pub const NO_EXPIRY: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Grant {
    pub(crate) deny: bool,
    pub(crate) perms: PermMask,
    pub(crate) zones: u64,
    /// `u8::MAX`: no clearance.
    pub(crate) level: u8,
    pub(crate) compartments: u64,
    pub(crate) min_aal: u8,
    pub(crate) not_before: u64,
    pub(crate) expires_at: u64,
    pub(crate) binding: u32,
}
impl Grant {
    #[inline(always)]
    fn live(&self, now: u64) -> bool {
        self.not_before <= now && now < self.expires_at
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SliceEntry {
    pub(crate) start: u32,
    pub(crate) service: u16,
    pub(crate) len: u16,
}
/// Compact summary of a principal's only grant on its first service, kept in
/// the principal table entry so the common case needs no further memory loads.
/// Used only for unconditional allows (no validity window, any zone).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FastGrant {
    pub(crate) compartments: u64,
    /// Index into `CompiledV2::masks`; `u32::MAX`: not applicable.
    pub(crate) perms: u32,
    pub(crate) level: u8,
    pub(crate) min_aal: u8,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Slot {
    pub(crate) start: u32,
    pub(crate) len: u32,
    /// The first service slice inline: most subjects are bound on one service,
    /// so the hot path avoids the dependent slice-table load.
    pub(crate) first: SliceEntry,
    pub(crate) fast: FastGrant,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CeilingEntry {
    pub(crate) perms: PermMask,
    pub(crate) level: u8,
    pub(crate) compartments: u64,
    pub(crate) min_aal: u8,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CeilingSet {
    pub(crate) entries: [CeilingEntry; limits::CEILING_TEMPLATES],
    pub(crate) len: u8,
    /// Index into `ServicePolicy.network_ceiling`.
    pub(crate) rule: u32,
}
pub(crate) struct CompiledServiceV2 {
    pub(crate) index: u16,
    pub(crate) permissions: VocabMap<u16>,
    /// Ceiling sets per rule; the trie and host table hold compact indexes.
    pub(crate) ceiling_sets: Vec<CeilingSet>,
    pub(crate) ceilings: PrefixTrie<u32>,
    pub(crate) hosts: HashMap<IpAddr, u32>,
    pub(crate) require_guard: bool,
    pub(crate) context: AuthorizationContext,
}
pub(crate) struct CompiledResourceV2 {
    pub(crate) service: String,
    pub(crate) level: u8,
    pub(crate) compartments: u64,
    pub(crate) min_aal: u8,
    pub(crate) actions: VocabMap<u16>,
}
/// Compile-time findings that do not refuse the document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub code: &'static str,
    pub path: String,
}
pub struct CompiledV2 {
    pub(crate) services: VocabMap<CompiledServiceV2>,
    /// Request label names (`information_class` on the permission path): a level
    /// name resolves to (level, ∅); a compartment name to (lowest level, {c}).
    pub(crate) labels: VocabMap<(u8, u64)>,
    pub(crate) resources: HashMap<String, CompiledResourceV2>,
    pub(crate) zones: PrefixTrie<u64>,
    pub(crate) zone_hosts: HashMap<IpAddr, u64>,
    /// Deduplicated permission masks referenced by `FastGrant`.
    pub(crate) masks: Vec<PermMask>,
    pub(crate) principals: [HashMap<String, Slot>; 3],
    pub(crate) groups: Vec<Slot>,
    pub(crate) group_refs: Vec<String>,
    pub(crate) slices: Vec<SliceEntry>,
    pub(crate) grants: Vec<Grant>,
    pub warnings: Vec<Warning>,
    /// Bindings excluded because every subject is a deleted Hopae principal.
    pub orphaned: Vec<String>,
    /// Bindings whose principal subjects are disabled in Hopae (no rights change).
    pub subject_disabled: Vec<String>,
    /// Earliest future validity boundary (not_before/expires_at) after compile time.
    pub next_boundary: Option<u64>,
}
/// Hopae subject lifecycle input to compilation (orphan reconciliation).
#[derive(Clone, Debug, Default)]
pub struct Lifecycle {
    pub deleted: BTreeSet<String>,
    pub disabled: BTreeSet<String>,
}
/// Compilation context supplied by the authority.
#[derive(Clone, Debug)]
pub struct CompileOptions<'a> {
    pub lifecycle: Option<&'a Lifecycle>,
    /// Highest AAL Hopae advertises (projection `max_aal`); requirements above it warn.
    pub max_issued_aal: u8,
    pub now: u64,
}
impl Default for CompileOptions<'_> {
    fn default() -> Self {
        Self {
            lifecycle: None,
            max_issued_aal: 3,
            now: 0,
        }
    }
}

fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn binding_id(s: &str) -> bool {
    s.strip_prefix("bnd_").is_some_and(|r| {
        !r.is_empty()
            && r.len() <= 64
            && r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    })
}
fn text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
#[derive(Debug)]
struct At(String);
impl std::fmt::Display for At {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "at {}", self.0)
    }
}
fn at(path: impl Into<String>) -> At {
    At(path.into())
}
fn vocabulary(values: &[String], max: usize, _what: &str) -> Result<VocabMap<u16>> {
    ensure!(values.len() <= max, "vocabulary too large");
    let mut out = VocabMap::default();
    for (i, v) in values.iter().enumerate() {
        ensure!(
            name(v) && out.insert(v.clone(), i as u16).is_none(),
            "invalid or duplicate vocabulary"
        );
    }
    Ok(out)
}
fn compartment_mask(values: &[String], vocab: &VocabMap<u16>) -> Result<u64> {
    let mut m = 0u64;
    for v in values {
        let bit = vocab
            .get(v)
            .ok_or_else(|| anyhow::anyhow!("unknown compartment"))?;
        ensure!(m & (1 << bit) == 0, "duplicate compartment");
        m |= 1 << bit;
    }
    Ok(m)
}
/// A template resolved for one service: effective permissions (own ∪ inherited,
/// mapped through `permission_map`), its own clearance ceiling and the maximum
/// minimum AAL along its inheritance chain.
#[derive(Clone, Copy)]
struct Resolved {
    perms: PermMask,
    level: u8,
    compartments: u64,
    min_aal: u8,
}
struct TemplateClosure {
    permissions: BTreeSet<String>,
    level: Option<u8>,
    compartments: u64,
    min_aal: u8,
}
fn closure(
    id: &str,
    templates: &BTreeMap<String, RoleTemplate>,
    levels: &VocabMap<u8>,
    compartments: &VocabMap<u16>,
    visiting: &mut BTreeSet<String>,
    done: &mut HashMap<String, std::rc::Rc<TemplateClosure>>,
) -> Result<std::rc::Rc<TemplateClosure>> {
    closure_inner(id, templates, levels, compartments, visiting, done)
        .with_context(|| at(format!("templates.{id}")))
}
fn closure_inner(
    id: &str,
    templates: &BTreeMap<String, RoleTemplate>,
    levels: &VocabMap<u8>,
    compartments: &VocabMap<u16>,
    visiting: &mut BTreeSet<String>,
    done: &mut HashMap<String, std::rc::Rc<TemplateClosure>>,
) -> Result<std::rc::Rc<TemplateClosure>> {
    if let Some(c) = done.get(id) {
        return Ok(c.clone());
    }
    ensure!(visiting.insert(id.to_owned()), "template inheritance cycle");
    let t = templates
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("unknown template"))?;
    ensure!(
        t.inherits.len() <= limits::INHERITS && t.minimum_aal <= 3,
        "invalid inheritance or assurance"
    );
    ensure!(
        (!t.permissions.is_empty() || !t.inherits.is_empty())
            && t.permissions.len() <= limits::PERMISSIONS,
        "template permission count"
    );
    let mut permissions = BTreeSet::new();
    for p in &t.permissions {
        ensure!(
            name(p) && permissions.insert(p.clone()),
            "invalid or duplicate template permission"
        );
    }
    let (level, cmask) = match &t.clearance_ceiling {
        Some(c) => (
            Some(
                *levels
                    .get(&c.level)
                    .ok_or_else(|| anyhow::anyhow!("unknown clearance level"))?,
            ),
            compartment_mask(&c.compartments, compartments)?,
        ),
        None => (None, 0),
    };
    let mut min_aal = t.minimum_aal;
    let mut parents = BTreeSet::new();
    for parent in &t.inherits {
        ensure!(parents.insert(parent), "duplicate parent");
        let c = closure(parent, templates, levels, compartments, visiting, done)?;
        permissions.extend(c.permissions.iter().cloned());
        min_aal = min_aal.max(c.min_aal);
    }
    visiting.remove(id);
    let c = std::rc::Rc::new(TemplateClosure {
        permissions,
        level,
        compartments: cmask,
        min_aal,
    });
    done.insert(id.to_owned(), c.clone());
    Ok(c)
}
fn resolve_for(c: &TemplateClosure, service: &ServicePolicy, perms: &VocabMap<u16>) -> Resolved {
    let mut mask = [0u64; 4];
    for p in &c.permissions {
        let mapped = service.permission_map.get(p).unwrap_or(p);
        if let Some(bit) = perms.get(mapped) {
            set(&mut mask, *bit);
        }
    }
    Resolved {
        perms: mask,
        level: c.level.unwrap_or(u8::MAX),
        compartments: c.compartments,
        min_aal: c.min_aal,
    }
}

impl PolicyV2 {
    pub fn compile(&self) -> Result<CompiledV2> {
        self.compile_with(&CompileOptions::default())
    }
    /// Compile, reporting the most specific document path and a registered code.
    pub fn compile_located(
        &self,
        options: &CompileOptions<'_>,
    ) -> std::result::Result<CompiledV2, crate::PolicyViolation> {
        self.compile_with(options)
            .map_err(|e| crate::PolicyViolation::from_error(&e))
    }
    pub fn compile_with(&self, options: &CompileOptions<'_>) -> Result<CompiledV2> {
        ensure!(self.version == 2, "invalid version");
        ensure!(self.services.len() <= limits::SERVICES, "service capacity");
        ensure!(
            self.templates.len() <= limits::TEMPLATES,
            "template capacity"
        );
        ensure!(self.bindings.len() <= limits::BINDINGS, "binding capacity");
        let mut warnings = Vec::new();
        // Catalog vocabulary
        let levels: VocabMap<u8> = (|| {
            ensure!(!self.catalog.levels.is_empty(), "catalog levels required");
            Ok(vocabulary(&self.catalog.levels, limits::LEVELS, "level")?
                .into_iter()
                .map(|(k, v)| (k, v as u8))
                .collect())
        })()
        .with_context(|| at("catalog.levels"))?;
        let compartments = vocabulary(
            &self.catalog.compartments,
            limits::COMPARTMENTS,
            "compartment",
        )
        .with_context(|| at("catalog.compartments"))?;
        let mut labels: VocabMap<(u8, u64)> =
            levels.iter().map(|(k, v)| (k.clone(), (*v, 0))).collect();
        for (c, bit) in &compartments {
            if labels.insert(c.clone(), (0, 1u64 << bit)).is_some() {
                return Err(anyhow::anyhow!(
                    "label names must be unique across levels and compartments"
                )
                .context(at("catalog.compartments")));
            }
        }
        // Zones
        ensure!(self.zones.zones.len() <= limits::ZONES, "zone capacity");
        let mut zone_index = HashMap::new();
        let mut zones = PrefixTrie::<u64>::default();
        let mut zone_hosts: HashMap<IpAddr, u64> = HashMap::new();
        let mut zone_prefixes: BTreeMap<&String, Vec<IpNet>> = BTreeMap::new();
        let mut prefix_count = 0usize;
        for (i, (id, zone)) in self.zones.zones.iter().enumerate() {
            (|| {
                ensure!(name(id), "invalid zone name");
                ensure!(!zone.prefixes.is_empty(), "zone needs prefixes");
                prefix_count += zone.prefixes.len();
                ensure!(prefix_count <= limits::PREFIXES, "prefix capacity");
                let mut seen = BTreeSet::new();
                for p in &zone.prefixes {
                    ensure!(p.trunc() == *p, "network has host bits");
                    ensure!(seen.insert(*p), "duplicate network");
                    let exact = matches!(p, IpNet::V4(n) if n.prefix_len() == 32)
                        || matches!(p, IpNet::V6(n) if n.prefix_len() == 128);
                    if exact {
                        *zone_hosts.entry(p.addr().to_canonical()).or_insert(0) |= 1u64 << i;
                    } else {
                        let previous = zones.remove(*p).unwrap_or(0);
                        zones.insert(*p, previous | (1u64 << i));
                    }
                }
                Ok(())
            })()
            .with_context(|| at(format!("zones.zones.{id}")))?;
            zone_index.insert(id.clone(), i as u8);
            zone_prefixes.insert(id, zone.prefixes.clone());
        }
        // Templates (closure is service independent)
        let mut closures = HashMap::new();
        for id in self.templates.keys() {
            (|| {
                ensure!(name(id) && id != "guest", "invalid template name");
                closure(
                    id,
                    &self.templates,
                    &levels,
                    &compartments,
                    &mut BTreeSet::new(),
                    &mut closures,
                )?;
                Ok(())
            })()
            .with_context(|| at(format!("templates.{id}")))?;
            let t = &self.templates[id];
            if closures[id].min_aal > options.max_issued_aal {
                warnings.push(Warning {
                    code: "pumgye.warning.unsatisfiable_assurance",
                    path: format!("templates.{id}.minimum_aal"),
                });
            }
            let _ = t;
        }
        // Services
        let mut services = VocabMap::default();
        let mut service_names = Vec::new();
        for (i, (id, service)) in self.services.iter().enumerate() {
            let compiled = (|| {
                ensure!(name(id), "invalid service name");
                ensure!(
                    service.authorization_context == AuthorizationContext::NetworkAndGuard,
                    "version 2 supports the network_and_guard context only"
                );
                ensure!(
                    !service.permissions.is_empty(),
                    "service permissions required"
                );
                let permissions =
                    vocabulary(&service.permissions, limits::PERMISSIONS, "permission")
                        .with_context(|| at(format!("services.{id}.permissions")))?;
                for (from, to) in &service.permission_map {
                    ensure!(
                        name(from) && permissions.contains_key(to),
                        "unknown mapped permission"
                    );
                }
                let mut ceilings = PrefixTrie::default();
                let mut hosts = HashMap::new();
                let mut ceiling_sets = Vec::with_capacity(service.network_ceiling.len());
                for (rule, ceiling) in service.network_ceiling.iter().enumerate() {
                    (|| {
                        let prefixes = zone_prefixes
                            .get(&ceiling.zone)
                            .ok_or_else(|| anyhow::anyhow!("unknown zone"))?;
                        let templates = ceiling.max.templates();
                        ensure!(
                            templates.len() <= limits::CEILING_TEMPLATES,
                            "too many ceiling templates"
                        );
                        let mut set = CeilingSet {
                            rule: rule as u32,
                            ..Default::default()
                        };
                        let mut seen = BTreeSet::new();
                        for t in templates {
                            ensure!(seen.insert(t), "duplicate ceiling template");
                            let c = closures
                                .get(t)
                                .ok_or_else(|| anyhow::anyhow!("unknown template"))?;
                            let r = resolve_for(c, service, &permissions);
                            set.entries[set.len as usize] = CeilingEntry {
                                perms: r.perms,
                                level: r.level,
                                compartments: r.compartments,
                                min_aal: r.min_aal,
                            };
                            set.len += 1;
                        }
                        // Ceiling-wide assurance: the maximum over its templates (v1 parity).
                        let aal = set.entries[..set.len as usize]
                            .iter()
                            .map(|e| e.min_aal)
                            .max()
                            .unwrap_or(0);
                        for e in &mut set.entries[..set.len as usize] {
                            e.min_aal = aal;
                        }
                        let index = ceiling_sets.len() as u32;
                        ceiling_sets.push(set);
                        for p in prefixes {
                            let exact = matches!(p, IpNet::V4(n) if n.prefix_len() == 32)
                                || matches!(p, IpNet::V6(n) if n.prefix_len() == 128);
                            let previous = if exact {
                                hosts.insert(p.addr().to_canonical(), index)
                            } else {
                                ceilings.insert(*p, index)
                            };
                            ensure!(previous.is_none(), "ambiguous ceiling prefix");
                        }
                        Ok(())
                    })()
                    .with_context(|| at(format!("services.{id}.network_ceiling[{rule}]")))?;
                }
                Ok(CompiledServiceV2 {
                    index: i as u16,
                    ceiling_sets,
                    permissions,
                    ceilings,
                    hosts,
                    require_guard: service.require_guard,
                    context: service.authorization_context,
                })
            })()
            .with_context(|| at(format!("services.{id}")))?;
            services.insert(id.clone(), compiled);
            service_names.push(id.clone());
        }
        // Catalog resources
        ensure!(
            self.catalog.resources.len() <= limits::RESOURCES,
            "resource catalog capacity"
        );
        let mut resources = HashMap::new();
        for (id, r) in &self.catalog.resources {
            let compiled = (|| {
                ensure!(
                    name(id)
                        && r.minimum_aal <= 3
                        && !r.actions.is_empty()
                        && r.actions.len() <= 64,
                    "invalid resource metadata"
                );
                let service = services
                    .get(&r.service)
                    .ok_or_else(|| anyhow::anyhow!("unknown resource service"))?;
                let level = *levels
                    .get(&r.level)
                    .ok_or_else(|| anyhow::anyhow!("unknown resource class"))?;
                let cmask = compartment_mask(&r.compartments, &compartments)?;
                let mut actions = VocabMap::default();
                for (action, permission) in &r.actions {
                    ensure!(name(action), "invalid resource action");
                    actions.insert(
                        action.clone(),
                        *service
                            .permissions
                            .get(permission)
                            .ok_or_else(|| anyhow::anyhow!("unknown resource permission"))?,
                    );
                }
                if r.minimum_aal > options.max_issued_aal {
                    warnings.push(Warning {
                        code: "pumgye.warning.unsatisfiable_assurance",
                        path: format!("catalog.resources.{id}.minimum_aal"),
                    });
                }
                Ok(CompiledResourceV2 {
                    service: r.service.clone(),
                    level,
                    compartments: cmask,
                    min_aal: r.minimum_aal,
                    actions,
                })
            })()
            .with_context(|| at(format!("catalog.resources.{id}")))?;
            resources.insert(id.clone(), compiled);
        }
        // Bindings → grants per (subject, service)
        let mut ids = BTreeSet::new();
        let mut group_set = BTreeSet::new();
        let mut per_subject: BTreeMap<(u8, String), BTreeMap<u16, Vec<Grant>>> = BTreeMap::new();
        let mut orphaned = Vec::new();
        let mut subject_disabled = Vec::new();
        let mut next_boundary: Option<u64> = None;
        let mut boundary = |t: u64| {
            if t > options.now && t != NO_EXPIRY {
                next_boundary = Some(next_boundary.map_or(t, |b: u64| b.min(t)));
            }
        };
        for (index, b) in self.bindings.iter().enumerate() {
            let path = format!("bindings[{index}]");
            (|| {
                ensure!(
                    binding_id(&b.id) && ids.insert(b.id.clone()),
                    "invalid or duplicate binding id"
                );
                ensure!(
                    !b.subjects.is_empty() && b.subjects.len() <= limits::SUBJECTS_PER_BINDING,
                    "binding subject count"
                );
                ensure!(
                    b.conditions.minimum_aal <= 3,
                    "invalid inheritance or assurance"
                );
                let not_before = b.conditions.not_before.map_or(0, |t| t.0);
                let expires_at = b.conditions.expires_at.map_or(NO_EXPIRY, |t| t.0);
                ensure!(not_before < expires_at, "empty validity window");
                for (_field, value, max) in [
                    ("reason", &b.metadata.reason, 512),
                    ("granted_by", &b.metadata.granted_by, 256),
                    ("approval_ref", &b.metadata.approval_ref, 256),
                    ("source", &b.metadata.source, 128),
                ] {
                    ensure!(
                        value.as_deref().is_none_or(|v| text(v, max)),
                        "invalid binding metadata"
                    );
                }
                let zones_mask = match &b.conditions.zones {
                    Names::Keyword(_) => ANY_ZONE,
                    Names::List(list) => {
                        ensure!(!list.is_empty(), "empty zone condition");
                        let mut m = 0u64;
                        for z in list {
                            m |= 1u64
                                << zone_index
                                    .get(z)
                                    .ok_or_else(|| anyhow::anyhow!("unknown zone"))?;
                        }
                        m
                    }
                };
                let scope: Vec<&String> = match &b.scope.services {
                    Names::Keyword(_) => self.services.keys().collect(),
                    Names::List(list) => {
                        ensure!(!list.is_empty(), "empty service scope");
                        let mut seen = BTreeSet::new();
                        for s in list {
                            ensure!(
                                self.services.contains_key(s) && seen.insert(s),
                                "unknown or duplicate scoped service"
                            );
                        }
                        list.iter().collect()
                    }
                };
                let template = match (b.effect, &b.role, &b.permissions) {
                    (Effect::Allow, Some(role), None) => Some(
                        closures
                            .get(role)
                            .ok_or_else(|| anyhow::anyhow!("unknown template"))?
                            .clone(),
                    ),
                    (Effect::Deny, None, Some(_)) => None,
                    _ => anyhow::bail!("allow needs role only; deny needs permissions only"),
                };
                // Subjects, with lifecycle reconciliation.
                let mut live_subjects = Vec::new();
                let mut seen = BTreeSet::new();
                let mut disabled = false;
                for s in &b.subjects {
                    ensure!(seen.insert(s.clone()), "duplicate binding subject");
                    match s {
                        SubjectRef::Principal { kind, reference } => {
                            ensure!(
                                principal_ref_valid(*kind, reference),
                                "invalid principal reference"
                            );
                            if *kind == PrincipalKind::Workload && legacy_workload(reference) {
                                warnings.push(Warning {
                                    code: "pumgye.warning.legacy_workload_subject",
                                    path: path.clone(),
                                });
                            }
                            if let Some(l) = options.lifecycle {
                                if l.deleted.contains(reference) {
                                    continue;
                                }
                                disabled |= l.disabled.contains(reference);
                            }
                            live_subjects.push((kind.index() as u8, reference.clone()));
                        }
                        SubjectRef::Group { group } => {
                            ensure!(group_ref_valid(group), "invalid group reference");
                            group_set.insert(group.clone());
                            live_subjects.push((u8::MAX, group.clone()));
                        }
                    }
                }
                if live_subjects.is_empty() {
                    orphaned.push(b.id.clone());
                    return Ok(());
                }
                if disabled {
                    subject_disabled.push(b.id.clone());
                }
                if b.conditions.minimum_aal > options.max_issued_aal {
                    warnings.push(Warning {
                        code: "pumgye.warning.unsatisfiable_assurance",
                        path: format!("{path}.conditions.minimum_aal"),
                    });
                }
                boundary(not_before);
                boundary(expires_at);
                for service_id in scope {
                    let service = &self.services[service_id];
                    let compiled = &services[service_id];
                    let grant = match &template {
                        Some(c) => {
                            let r = resolve_for(c, service, &compiled.permissions);
                            Grant {
                                deny: false,
                                perms: r.perms,
                                zones: zones_mask,
                                level: r.level,
                                compartments: r.compartments,
                                min_aal: r.min_aal.max(b.conditions.minimum_aal),
                                not_before,
                                expires_at,
                                binding: index as u32,
                            }
                        }
                        None => {
                            let mut perms = [0u64; 4];
                            match b.permissions.as_ref().unwrap() {
                                Names::Keyword(_) => {
                                    for bit in compiled.permissions.values() {
                                        set(&mut perms, *bit);
                                    }
                                }
                                Names::List(list) => {
                                    ensure!(!list.is_empty(), "empty deny permissions");
                                    for p in list {
                                        let p = service.permission_map.get(p).unwrap_or(p);
                                        // A deny naming a permission absent from a scoped service is ignored there.
                                        if let Some(bit) = compiled.permissions.get(p) {
                                            set(&mut perms, *bit);
                                        }
                                    }
                                }
                            }
                            Grant {
                                deny: true,
                                perms,
                                zones: zones_mask,
                                level: 0,
                                compartments: 0,
                                min_aal: 0,
                                not_before,
                                expires_at,
                                binding: index as u32,
                            }
                        }
                    };
                    for subject in &live_subjects {
                        let list = per_subject
                            .entry(subject.clone())
                            .or_default()
                            .entry(compiled.index)
                            .or_default();
                        ensure!(
                            list.len() < limits::GRANTS_PER_SUBJECT_SERVICE,
                            "too many bindings for one subject on one service"
                        );
                        list.push(grant);
                    }
                }
                Ok(())
            })()
            .with_context(|| at(path.clone()))?;
        }
        ensure!(group_set.len() <= limits::GROUPS, "relevant group capacity");
        let group_refs: Vec<String> = group_set.into_iter().collect();
        let group_index: HashMap<&str, usize> = group_refs
            .iter()
            .enumerate()
            .map(|(i, g)| (g.as_str(), i))
            .collect();
        let mut slices = Vec::new();
        let mut grants = Vec::new();
        let mut masks: Vec<PermMask> = Vec::new();
        let mut mask_index: HashMap<PermMask, u32> = HashMap::new();
        let mut principals: [HashMap<String, Slot>; 3] = Default::default();
        let mut groups = vec![Slot::default(); group_refs.len()];
        for ((kind, reference), by_service) in per_subject {
            let mut slot = Slot {
                start: slices.len() as u32,
                len: by_service.len() as u32,
                first: SliceEntry::default(),
                fast: FastGrant {
                    perms: u32::MAX,
                    ..Default::default()
                },
            };
            for (n, (service, list)) in by_service.into_iter().enumerate() {
                let entry = SliceEntry {
                    service,
                    start: grants.len() as u32,
                    len: list.len() as u16,
                };
                if n == 0 {
                    slot.first = entry;
                    let g = list[0];
                    if list.len() == 1
                        && !g.deny
                        && g.zones == ANY_ZONE
                        && g.not_before == 0
                        && g.expires_at == NO_EXPIRY
                    {
                        let index = *mask_index.entry(g.perms).or_insert_with(|| {
                            masks.push(g.perms);
                            masks.len() as u32 - 1
                        });
                        slot.fast = FastGrant {
                            compartments: g.compartments,
                            perms: index,
                            level: g.level,
                            min_aal: g.min_aal,
                        };
                    }
                }
                slices.push(entry);
                grants.extend(list);
            }
            if kind == u8::MAX {
                groups[group_index[reference.as_str()]] = slot;
            } else {
                principals[kind as usize].insert(reference, slot);
            }
        }
        ensure!(
            principals.iter().map(HashMap::len).sum::<usize>() <= limits::PRINCIPALS,
            "principal capacity"
        );
        Ok(CompiledV2 {
            services,
            labels,
            resources,
            zones,
            zone_hosts,
            masks,
            principals,
            groups,
            group_refs,
            slices,
            grants,
            warnings,
            orphaned,
            subject_disabled,
            next_boundary,
        })
    }
}

// ---------------------------------------------------------------------------
// Membership projection index (input from Hopae, verified by the server)
// ---------------------------------------------------------------------------

/// Principal → relevant group bits for one compiled snapshot's vocabulary.
#[derive(Clone, Debug, Default)]
pub struct MembershipIndex {
    members: HashMap<String, GroupMask>,
    /// Workload wire subject (`s_`) → slots bound to its `wk2:` principal and
    /// its SPIFFE ID (from Hopae lifecycle `workload_observed`).
    workloads: HashMap<String, [Option<Slot>; 2]>,
    /// Alias names for explain/status (cold).
    workload_names: HashMap<String, (String, Option<String>)>,
}
impl MembershipIndex {
    /// Build from `principal → GroupRefs`; GroupRefs outside the vocabulary are ignored.
    pub fn build<'a>(
        compiled: &CompiledV2,
        memberships: impl IntoIterator<Item = (&'a str, &'a BTreeSet<String>)>,
    ) -> Self {
        let index: HashMap<&str, usize> = compiled
            .group_refs
            .iter()
            .enumerate()
            .map(|(i, g)| (g.as_str(), i))
            .collect();
        let mut members = HashMap::new();
        for (principal, groups) in memberships {
            let mut mask = [0u64; 4];
            for g in groups {
                if let Some(i) = index.get(g.as_str()) {
                    mask[i / 64] |= 1u64 << (i % 64);
                }
            }
            if mask.iter().any(|w| *w != 0) {
                members.insert(principal.to_owned(), mask);
            }
        }
        Self {
            members,
            workloads: HashMap::new(),
            workload_names: HashMap::new(),
        }
    }
    /// Add active workload aliases `(subject_ref s_, principal wk2:, spiffe_id)`.
    pub fn with_workloads<'a>(
        mut self,
        compiled: &CompiledV2,
        workloads: impl IntoIterator<Item = (&'a str, &'a str, Option<&'a str>)>,
    ) -> Self {
        let table = &compiled.principals[PrincipalKind::Workload.index()];
        for (subject, principal, spiffe) in workloads {
            if !legacy_workload(subject) || !principal_ref_valid(PrincipalKind::Workload, principal)
            {
                continue;
            }
            self.workload_names.insert(
                subject.to_owned(),
                (principal.to_owned(), spiffe.map(str::to_owned)),
            );
            let slots = [
                table.get(principal).copied(),
                spiffe
                    .filter(|s| spiffe_workload(s))
                    .and_then(|s| table.get(s).copied()),
            ];
            if slots.iter().any(Option::is_some) {
                self.workloads.insert(subject.to_owned(), slots);
            }
        }
        self
    }
    /// The `wk2:` principal and SPIFFE ID Hopae reported for a wire subject.
    pub fn workload_alias(&self, subject: &str) -> Option<&(String, Option<String>)> {
        self.workload_names.get(subject)
    }
    pub fn workload_aliases(&self) -> usize {
        self.workload_names.len()
    }
    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}
impl CompiledV2 {
    /// Relevant group vocabulary (sorted, de-duplicated) sent to Hopae.
    pub fn group_vocabulary(&self) -> &[String] {
        &self.group_refs
    }
    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Version 2 outcome: version 1 variants plus `ExplicitDenied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DecisionV2 {
    Allow,
    UnknownService,
    Guest,
    NetworkGuest,
    PermissionDenied,
    ClassDenied,
    AssuranceDenied,
    GuardDenied,
    GuardUnavailable,
    ExplicitDenied,
    UnknownResource,
    UnknownAction,
}
impl DecisionV2 {
    pub const ALL: [DecisionV2; 12] = [
        DecisionV2::Allow,
        DecisionV2::UnknownService,
        DecisionV2::Guest,
        DecisionV2::NetworkGuest,
        DecisionV2::PermissionDenied,
        DecisionV2::ClassDenied,
        DecisionV2::AssuranceDenied,
        DecisionV2::GuardDenied,
        DecisionV2::GuardUnavailable,
        DecisionV2::ExplicitDenied,
        DecisionV2::UnknownResource,
        DecisionV2::UnknownAction,
    ];
    /// Nearest version 1 code for unchanged wire peers (`ExplicitDenied` → `PermissionDenied`).
    pub fn to_v1(self) -> ResourceDecision {
        use crate::Decision as D;
        ResourceDecision::Decided(match self {
            DecisionV2::Allow => D::Allow,
            DecisionV2::UnknownService => D::UnknownService,
            DecisionV2::Guest => D::Guest,
            DecisionV2::NetworkGuest => D::NetworkGuest,
            DecisionV2::PermissionDenied | DecisionV2::ExplicitDenied => D::PermissionDenied,
            DecisionV2::ClassDenied => D::ClassDenied,
            DecisionV2::AssuranceDenied => D::AssuranceDenied,
            DecisionV2::GuardDenied => D::GuardDenied,
            DecisionV2::GuardUnavailable => D::GuardUnavailable,
            DecisionV2::UnknownResource => return ResourceDecision::UnknownResource,
            DecisionV2::UnknownAction => return ResourceDecision::UnknownAction,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            DecisionV2::Allow => "Allow",
            DecisionV2::UnknownService => "UnknownService",
            DecisionV2::Guest => "Guest",
            DecisionV2::NetworkGuest => "NetworkGuest",
            DecisionV2::PermissionDenied => "PermissionDenied",
            DecisionV2::ClassDenied => "ClassDenied",
            DecisionV2::AssuranceDenied => "AssuranceDenied",
            DecisionV2::GuardDenied => "GuardDenied",
            DecisionV2::GuardUnavailable => "GuardUnavailable",
            DecisionV2::ExplicitDenied => "ExplicitDenied",
            DecisionV2::UnknownResource => "UnknownResource",
            DecisionV2::UnknownAction => "UnknownAction",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum TargetV2<'a> {
    /// `/v1/decision`/PPG1 shape: the class names a Catalog level (advisory label).
    Permission { permission: &'a str, level: &'a str },
    /// Catalog resource: the label comes from the Catalog, never from the caller.
    Resource { resource: &'a str, action: &'a str },
}
#[derive(Clone, Copy, Debug)]
pub struct RequestV2<'a> {
    pub service: &'a str,
    pub kind: PrincipalKind,
    pub subject: &'a str,
    pub target: TargetV2<'a>,
    pub ip: IpAddr,
    pub aal: u8,
    pub guard: GuardEvidence,
    /// Authority wall time (Unix seconds) for validity windows.
    pub now: u64,
}

/// Facts emitted in evaluation order; see [`crate::Tracer`] for the v1 analogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceV2Event {
    Service {
        found: bool,
    },
    Context {
        context: AuthorizationContext,
    },
    Guard {
        evidence: GuardEvidence,
        require_guard: bool,
    },
    Catalog {
        resource_found: Option<bool>,
        scope_ok: bool,
        permission: Option<u16>,
        level: Option<u8>,
        compartments: u64,
        resource_min_aal: u8,
    },
    Principal {
        aliases: bool,
        valid: bool,
        direct: bool,
        groups: GroupMask,
    },
    ZoneSet {
        zones: u64,
    },
    Deny {
        binding: u32,
    },
    AllowSet {
        candidates: u32,
        live: u32,
        zoned: u32,
    },
    Ceiling {
        rule: Option<u32>,
        exact_host: bool,
    },
    Permission {
        granted: bool,
    },
    Clearance {
        granted: bool,
    },
    Assurance {
        presented: u8,
        required: u8,
    },
}
pub trait TracerV2 {
    /// False for the production sink: trace-only work is skipped entirely.
    const ENABLED: bool = true;
    fn event(&mut self, event: TraceV2Event);
    /// Each allow grant that survived validity and zone filtering (explain provenance).
    fn grant(&mut self, _binding: u32, _contributes: bool) {}
}
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTraceV2;
impl TracerV2 for NoTraceV2 {
    const ENABLED: bool = false;
    #[inline(always)]
    fn event(&mut self, _event: TraceV2Event) {}
    #[inline(always)]
    fn grant(&mut self, _binding: u32, _contributes: bool) {}
}
const _: () = assert!(std::mem::size_of::<NoTraceV2>() == 0);

impl CompiledV2 {
    #[inline(always)]
    fn subject_grants<'a>(&'a self, slot: &'a Slot, service: u16) -> &'a [Grant] {
        if slot.len > 0 && slot.first.service == service {
            let f = slot.first;
            return &self.grants[f.start as usize..f.start as usize + f.len as usize];
        }
        let slices = &self.slices[slot.start as usize..(slot.start + slot.len) as usize];
        for s in slices {
            if s.service == service {
                return &self.grants[s.start as usize..s.start as usize + s.len as usize];
            }
        }
        &[]
    }
    /// Visit every grant of the principal and its groups for one service.
    #[inline(always)]
    fn for_each_grant(
        &self,
        direct: Option<&Slot>,
        aliases: Option<&[Option<Slot>; 2]>,
        groups: &GroupMask,
        service: u16,
        mut f: impl FnMut(&Grant) -> bool,
    ) {
        if let Some(slot) = direct {
            for g in self.subject_grants(slot, service) {
                if !f(g) {
                    return;
                }
            }
        }
        for slot in aliases.into_iter().flatten().flatten() {
            for g in self.subject_grants(slot, service) {
                if !f(g) {
                    return;
                }
            }
        }
        for (w, word) in groups.iter().enumerate() {
            let mut bits = *word;
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let index = w * 64 + b;
                if let Some(slot) = self.groups.get(index) {
                    for g in self.subject_grants(slot, service) {
                        if !f(g) {
                            return;
                        }
                    }
                }
            }
        }
    }
    /// Allocation-free production evaluation.
    #[inline]
    pub fn evaluate(&self, membership: &MembershipIndex, request: &RequestV2<'_>) -> DecisionV2 {
        self.evaluate_traced(membership, request, &mut NoTraceV2)
    }
    /// The one version 2 evaluation function (ADR 0021 order 2–12; fences are
    /// the caller's). Explain instantiates it with a recording tracer.
    #[inline]
    pub fn evaluate_traced<T: TracerV2>(
        &self,
        membership: &MembershipIndex,
        r: &RequestV2<'_>,
        trace: &mut T,
    ) -> DecisionV2 {
        // 2. Context
        let service = self.services.get(r.service);
        trace.event(TraceV2Event::Service {
            found: service.is_some(),
        });
        let Some(service) = service else {
            return DecisionV2::UnknownService;
        };
        trace.event(TraceV2Event::Context {
            context: service.context,
        });
        if service.context != AuthorizationContext::NetworkAndGuard {
            return DecisionV2::PermissionDenied;
        }
        // 3. Sumunjang denial dominates.
        trace.event(TraceV2Event::Guard {
            evidence: r.guard,
            require_guard: service.require_guard,
        });
        if r.guard == GuardEvidence::Deny {
            return DecisionV2::GuardDenied;
        }
        if service.require_guard && r.guard != GuardEvidence::EnforcedAllow {
            return DecisionV2::GuardUnavailable;
        }
        // 4. Catalog
        let (permission, level, compartments, resource_min) = match r.target {
            TargetV2::Permission { permission, level } => {
                let p = service.permissions.get(permission).copied();
                let l = self.labels.get(level).copied();
                trace.event(TraceV2Event::Catalog {
                    resource_found: None,
                    scope_ok: true,
                    permission: p,
                    level: l.map(|l| l.0),
                    compartments: l.map_or(0, |l| l.1),
                    resource_min_aal: 0,
                });
                let Some(p) = p else {
                    return DecisionV2::PermissionDenied;
                };
                let Some((l, c)) = l else {
                    return DecisionV2::ClassDenied;
                };
                (p, l, c, 0)
            }
            TargetV2::Resource { resource, action } => {
                let res = self.resources.get(resource);
                let scope_ok = res.is_some_and(|x| x.service == r.service);
                let p = res
                    .filter(|_| scope_ok)
                    .and_then(|x| x.actions.get(action).copied());
                trace.event(TraceV2Event::Catalog {
                    resource_found: Some(res.is_some()),
                    scope_ok,
                    permission: p,
                    level: res.map(|x| x.level),
                    compartments: res.map_or(0, |x| x.compartments),
                    resource_min_aal: res.map_or(0, |x| x.min_aal),
                });
                let Some(res) = res else {
                    return DecisionV2::UnknownResource;
                };
                if !scope_ok {
                    return DecisionV2::UnknownService;
                }
                let Some(p) = p else {
                    return DecisionV2::UnknownAction;
                };
                (p, res.level, res.compartments, res.min_aal)
            }
        };
        // 5. Principal: kind-keyed lookup (only refs valid for the kind were
        // compiled); groups only from the verified projection, Humans only.
        let valid = if T::ENABLED {
            principal_ref_valid(r.kind, r.subject)
        } else {
            true
        };
        let direct = self.principals[r.kind.index()].get(r.subject);
        let groups = if r.kind == PrincipalKind::Human {
            membership
                .members
                .get(r.subject)
                .copied()
                .unwrap_or_default()
        } else {
            [0; 4]
        };
        // Workload wire subjects (`s_`) also carry the grants of their `wk2:`
        // principal and SPIFFE ID, as reported by Hopae's lifecycle feed.
        let aliases = if r.kind == PrincipalKind::Workload {
            membership.workloads.get(r.subject)
        } else {
            None
        };
        trace.event(TraceV2Event::Principal {
            valid,
            direct: direct.is_some(),
            groups,
            aliases: aliases.is_some(),
        });
        if direct.is_none() && aliases.is_none() && groups.iter().all(|w| *w == 0) {
            return DecisionV2::Guest;
        }
        // Production fast path (straight-line): a principal without groups whose only
        // grant on this service is an unconditional allow. Explain always takes the
        // general path below; corpus parity tests compare both.
        if !T::ENABLED
            && let Some(slot) = direct
            && slot.len == 1
            && slot.first.service == service.index
            && slot.first.len == 1
            && slot.fast.perms != u32::MAX
            && groups == [0; 4]
            && aliases.is_none()
        {
            return self.decide_fast(
                service,
                slot.fast,
                r,
                permission,
                level,
                compartments,
                resource_min,
            );
        }
        self.decide_general(
            service,
            direct,
            aliases,
            groups,
            r,
            permission,
            level,
            compartments,
            resource_min,
            trace,
        )
    }
    /// Stages 8–11 for an unconditional single allow (stages 6–7 are trivially
    /// satisfied: no deny, live, any zone).
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn decide_fast(
        &self,
        service: &CompiledServiceV2,
        g: FastGrant,
        r: &RequestV2<'_>,
        permission: u16,
        level: u8,
        compartments: u64,
        resource_min: u8,
    ) -> DecisionV2 {
        let index = match service.hosts.get(&r.ip.to_canonical()) {
            Some(i) => *i,
            None => match service.ceilings.longest(r.ip) {
                Some(i) => *i,
                None => return DecisionV2::NetworkGuest,
            },
        };
        let set = &service.ceiling_sets[index as usize];
        if !has(&self.masks[g.perms as usize], permission) {
            return DecisionV2::PermissionDenied;
        }
        let grant_fits =
            g.level != u8::MAX && level <= g.level && compartments & !g.compartments == 0;
        let (mut permitted, mut required) = (false, u8::MAX);
        for e in &set.entries[..set.len as usize] {
            let p = has(&e.perms, permission);
            permitted |= p;
            let fits = p
                && grant_fits
                && e.level != u8::MAX
                && level <= e.level
                && compartments & !e.compartments == 0;
            if fits {
                required = required.min(g.min_aal.max(e.min_aal).max(resource_min));
            }
        }
        if !permitted {
            return DecisionV2::PermissionDenied;
        }
        if required == u8::MAX {
            return DecisionV2::ClassDenied;
        }
        if r.aal > 3 || r.aal < required {
            return DecisionV2::AssuranceDenied;
        }
        DecisionV2::Allow
    }
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn decide_general<T: TracerV2>(
        &self,
        service: &CompiledServiceV2,
        direct: Option<&Slot>,
        aliases: Option<&[Option<Slot>; 2]>,
        groups: GroupMask,
        r: &RequestV2<'_>,
        permission: u16,
        level: u8,
        compartments: u64,
        resource_min: u8,
        trace: &mut T,
    ) -> DecisionV2 {
        // Zone membership is computed only when a grant carries a zone condition.
        let zones = std::cell::Cell::new(if T::ENABLED {
            Some(self.zone_mask(r.ip))
        } else {
            None
        });
        if let Some(z) = zones.get() {
            trace.event(TraceV2Event::ZoneSet { zones: z });
        }
        let zone_ok = |g: &Grant| {
            g.zones == ANY_ZONE
                || g.zones
                    & zones.get().unwrap_or_else(|| {
                        let z = self.zone_mask(r.ip);
                        zones.set(Some(z));
                        z
                    })
                    != 0
        };
        // 8 (looked up early, applied in ADR order below). Most specific; exact hosts first.
        let ceiling = service
            .hosts
            .get(&r.ip.to_canonical())
            .map(|c| (&service.ceiling_sets[*c as usize], true))
            .or_else(|| {
                service
                    .ceilings
                    .longest(r.ip)
                    .map(|c| (&service.ceiling_sets[*c as usize], false))
            });
        let entries: &[CeilingEntry] = ceiling.map_or(&[], |(c, _)| &c.entries[..c.len as usize]);
        // One pass: 6 explicit deny, 7 allow set, 9–11 per (template, ceiling) pair.
        let mut denied = None;
        let (mut candidates, mut live, mut zoned) = (0u32, 0u32, 0u32);
        let (mut permitted, mut cleared) = (false, false);
        let mut required = u8::MAX;
        {
            self.for_each_grant(direct, aliases, &groups, service.index, |g| {
                let is_live = g.live(r.now);
                if g.deny {
                    if is_live && has(&g.perms, permission) && zone_ok(g) {
                        denied = Some(g.binding);
                        return false;
                    }
                    return true;
                }
                candidates += 1;
                if !is_live {
                    return true;
                }
                live += 1;
                if !zone_ok(g) {
                    return true;
                }
                zoned += 1;
                if !has(&g.perms, permission) {
                    return true;
                }
                let mut contributes = false;
                for e in entries {
                    if !has(&e.perms, permission) {
                        continue;
                    }
                    permitted = true;
                    let fits = |l: u8, c: u64| l != u8::MAX && level <= l && compartments & !c == 0;
                    if fits(g.level, g.compartments) && fits(e.level, e.compartments) {
                        cleared = true;
                        contributes = true;
                        required = required.min(g.min_aal.max(e.min_aal).max(resource_min));
                    }
                }
                trace.grant(g.binding, contributes);
                true
            });
        }
        if let Some(binding) = denied {
            trace.event(TraceV2Event::Deny { binding });
            return DecisionV2::ExplicitDenied;
        }
        trace.event(TraceV2Event::AllowSet {
            candidates,
            live,
            zoned,
        });
        if live == 0 {
            return DecisionV2::Guest;
        }
        if zoned == 0 {
            return DecisionV2::NetworkGuest;
        }
        trace.event(TraceV2Event::Ceiling {
            rule: ceiling.map(|c| c.0.rule),
            exact_host: ceiling.is_some_and(|c| c.1),
        });
        if ceiling.is_none() {
            return DecisionV2::NetworkGuest;
        }
        trace.event(TraceV2Event::Permission { granted: permitted });
        if !permitted {
            return DecisionV2::PermissionDenied;
        }
        trace.event(TraceV2Event::Clearance { granted: cleared });
        if !cleared {
            return DecisionV2::ClassDenied;
        }
        trace.event(TraceV2Event::Assurance {
            presented: r.aal,
            required,
        });
        if r.aal > 3 || r.aal < required {
            return DecisionV2::AssuranceDenied;
        }
        DecisionV2::Allow
    }
    /// Zones containing the address: exact host entries plus the prefix trie.
    #[inline]
    fn zone_mask(&self, ip: IpAddr) -> u64 {
        let mut zones = self
            .zone_hosts
            .get(&ip.to_canonical())
            .copied()
            .unwrap_or(0);
        self.zones.visit_matches(ip, |m| zones |= *m);
        zones
    }
}
