//! Native resources for the owning Pumgye server. Authentication verification
//! alone grants no permissions and does not establish live identity freshness.
pub mod authentication;
pub mod authentication_config;
pub mod authorization;
/// Hopae membership projection and subject lifecycle owners (policy model v2).
pub mod hopae_owner;
pub mod permit;
pub mod permit_config;

pub mod authentication_live;

pub mod authentication_live_config;

mod authority_transport;
pub mod network_live;

pub mod network_live_config;

pub mod route_live;

pub mod route_live_config;

/// Authenticated native Hopae projection-plan owner client.
pub mod plan_live;

/// Canonical permission proof checking before live owner validation.
pub mod permit_wire;

/// Opt-in native observed authentication evidence; separate from strict APIs.
#[cfg(feature = "observed-authentication")]
pub mod authentication_observed;

/// Opt-in native observed permit owner and generated RPC adapter.
#[cfg(feature = "observed-authentication")]
pub mod observed_permit;

#[cfg(feature = "observed-authentication")]
pub mod authentication_workload_observed;
#[cfg(feature = "observed-authentication")]
pub mod workload_observed_permit;

#[cfg(feature = "observed-authentication")]
pub mod authentication_human_observed;
#[cfg(feature = "observed-authentication")]
pub mod human_observed_permit;
