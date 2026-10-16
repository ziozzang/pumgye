//! Evaluation trace sink shared by enforcement and administrative explain.
//!
//! Every public evaluation entrypoint is a thin wrapper that instantiates the one
//! evaluation function with [`NoTrace`]. `NoTrace` is zero-sized and its sink is an
//! empty `#[inline(always)]` method, so the production monomorphization contains no
//! trace code, no branches on a "tracing enabled" flag and no allocation. Explain
//! instantiates the *same* function with [`VecTrace`], a bounded event buffer.
use crate::{AuthorizationContext, GuardEvidence};
use std::net::IpAddr;

/// Receives facts in evaluation order. Implementations must not influence the
/// decision; the evaluator never reads anything back from a tracer.
pub trait Tracer<'a> {
    fn event(&mut self, event: TraceEvent<'a>);
}

/// Production sink: compiles away entirely.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTrace;
impl<'a> Tracer<'a> for NoTrace {
    #[inline(always)]
    fn event(&mut self, _event: TraceEvent<'a>) {}
}
const _: () = assert!(std::mem::size_of::<NoTrace>() == 0);

/// Maximum events a single evaluation can emit; evaluation paths emit at most 14.
pub const MAX_TRACE_EVENTS: usize = 32;

/// Bounded explain sink. It allocates once, never grows past
/// [`MAX_TRACE_EVENTS`] and marks `truncated` instead of growing.
#[derive(Debug)]
pub struct VecTrace<'a> {
    events: Vec<TraceEvent<'a>>,
    truncated: bool,
}
impl Default for VecTrace<'_> {
    fn default() -> Self {
        Self {
            events: Vec::with_capacity(MAX_TRACE_EVENTS),
            truncated: false,
        }
    }
}
impl<'a> VecTrace<'a> {
    pub fn events(&self) -> &[TraceEvent<'a>] {
        &self.events
    }
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}
impl<'a> Tracer<'a> for VecTrace<'a> {
    fn event(&mut self, event: TraceEvent<'a>) {
        if self.events.len() < MAX_TRACE_EVENTS {
            self.events.push(event);
        } else {
            self.truncated = true;
        }
    }
}

/// Compiled rights as bitsets over the service permission and global class vocabularies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RightsView {
    pub permissions: u64,
    pub classes: u64,
    pub minimum_aal: u8,
}

/// The single subject map an entrypoint consults; maps never fall back to each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectMap {
    Users,
    WorkloadUsers,
    HumanUsers,
}

/// Which compiled network entry won the longest-prefix match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkMatch {
    /// Index into the source `Service.networks` list.
    pub rule: u32,
    /// Exact host (/32 or /128) entries are consulted before the prefix trie.
    pub exact_host: bool,
    pub rights: RightsView,
}

/// One evaluation fact. Events borrow from the policy and the request only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceEvent<'a> {
    /// Service lookup by identifier (permission/class entrypoint).
    Service { service: &'a str, found: bool },
    /// Catalog resource lookup; `owner` is the owning service when found.
    Resource {
        resource: &'a str,
        owner: Option<&'a str>,
    },
    /// The requested service scope compared with the resource owner.
    Scope { requested: &'a str, owner: &'a str },
    /// The service authorization context compared with the entrypoint's context.
    Context {
        context: AuthorizationContext,
        required: AuthorizationContext,
    },
    /// Human principal format validation (Human entrypoint only).
    PrincipalFormat { valid: bool },
    /// Human verified-assurance range validation (Human entrypoint only).
    PrincipalAssurance { aal: u8 },
    /// Catalog action resolution to a service permission bit.
    Action {
        action: &'a str,
        permission: Option<u64>,
    },
    /// Sumunjang evidence handling.
    Guard {
        evidence: GuardEvidence,
        require_guard: bool,
    },
    /// Subject assignment lookup in exactly one map.
    Subject {
        map: SubjectMap,
        subject: &'a str,
        rights: Option<RightsView>,
    },
    /// Network rule selection for the client address.
    Network {
        ip: IpAddr,
        matched: Option<NetworkMatch>,
    },
    /// Effective rights after intersecting subject and network rights.
    Entitlements {
        subject: RightsView,
        network: Option<RightsView>,
        effective: RightsView,
    },
    /// Requested permission bit (`None`: unknown name) against effective permissions.
    Permission {
        requested: Option<u64>,
        granted: u64,
    },
    /// Requested class bit (`None`: unknown name) against effective classes.
    Class {
        requested: Option<u64>,
        granted: u64,
    },
    /// Presented assurance against the role and resource minimums.
    Assurance {
        presented: u8,
        role_minimum: u8,
        resource_minimum: u8,
    },
}
