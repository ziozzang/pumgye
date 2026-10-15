# Native observed permits

Build `pumgye` with `--features observed-authentication` and explicitly enable
`--observed-permits`. This adds `ObservedProjectionPermits/Issue` and `/Observe`
on the existing mTLS gRPC listener. The decision credential authenticates the
native enforcement caller. The flag requires `--grpc-listen`, `--permit-key`,
`--authentication-trust` (through `--authentication-live`),
`--authentication-live`, `--network-live`, `--route-live`, and `--projection-live`.
The authentication-live JSON accepts an optional `observed_clock_rates` object
with explicit `source_ppm` and `receiver_ppm` integers in `0..1_000_000` (exclusive
upper bound). It is REQUIRED for observed activation; there is no default or
silent equal-rate assumption. `source_ppm` must cover every fixed remote
auth/network/route/plan owner and `receiver_ppm` the local BOOTTIME clock. Example:
`"observed_clock_rates":{"source_ppm":50,"receiver_ppm":75}`. The strict loader
accepts the optional object without enabling observed behavior. Resource files
remain reference-only for secrets. The separate
strict RPCs and HTTP decisions keep their existing semantics. An unconfigured
observed owner refuses; it never falls back to strict validation.

`--observed-authority` selects a stable native authority base (default `pumgye`,
1–64 ASCII bytes from `A-Za-z0-9_.:-`). Startup creates an independent CSPRNG
128-bit process nonce and Linux BOOTTIME clock. The canonical signed permit
`binding.authority_epoch` and observation `clock_domain` are both
`pobs1:<32 lowercase hexadecimal nonce>:<base>`. Parse exactly the first two
colons; the remaining base may contain colons. The entire encoding is at most
103 bytes. No leading/trailing whitespace, alternate hexadecimal encoding, or
normalization is permitted. A restarted owner issues a different domain and
refuses previous-domain permits, even when its durable signing key is unchanged.
The signed authentication identity epoch remains Hopae lineage; it is not the
permit clock. Operators must route each request to its actual fixed owner;
load-balanced owner discovery and domain migration are unsupported.

The production service captures the existing authority's exact `Arc<View>` and
compiled policy from the same database/Kubernetes publication. It retains native
health, caller, and publication-identity fences. It does not compile another
policy copy. Kubernetes collection uses the authority's BOOTTIME ticks, and seals
the original collector `valid_until_ms` into a private `LocalDeadline` before the
publication transaction. Collection, compilation, durable commit, asynchronous
RPCs, callbacks, signing, and suspend all consume that original budget. Missing,
expired, or retired source evidence refuses observed authorization regardless of
the legacy `Instant` deadline.

Issuance requires actual `CheckedObservedService` evidence from the persistent
fixed Hopae SDK client, enforced Sumunjang Allow, native route ownership, a native
projection plan, and policy Allow. The existing network/route/plan clients sample
Pumgye BOOTTIME on both sides of every actual authenticated RPC. Their returned
TTL/remaining durations are anchored before the RPC, bounded to 1000 ms, and never
combined with source UTC expiries. Hopae observations are consumed by refresh;
refresh retains the original shortest authentication bound. Route and plan owners
are queried initially, before signing, and after signing; the exact scopes and
revisions must agree. The original bounds survive each requery. Native policy and
authentication durations are sampled only after a previously captured local
anchor, including after callbacks. The final permit lifetime intersects all
these local bounds and the operation's original 1000 ms cap, then rounds down
with a one-millisecond margin. Native relative TTLs first use the explicitly configured asymmetric oscillator
bounds and SDK interval arithmetic, preserving the original pre-RPC origin and
rounding down. The extra margin covers final source tick quantization. Clock read
failure irreversibly retires the source. No UTC sample is substituted.

`Issue` returns the ordinary signed `ProjectionPermitReply` inside a separate
`ObservedProjectionPermitReply` and an authenticated time report. `Observe`
accepts `PermitValidationRequest`, verifies the exact request/proof/domain and
re-evaluates all native owners and policy. It returns no replacement proof.
The report includes fresh request correlation, SHA-256 of the exact signed
receipt, process domain, own progressing `owner_now_ms`, and current
policy/network/route/plan revisions matching the signed binding. `cache_ttl_ms`
is always zero. `proof_remaining_ms` is the full signed lifetime remaining at
that sample, an upper bound for receiver replay retention; it is not admission.
`remaining_ms` is a separately shortened lower admission budget, limited by all
current prerequisites and the proof. Receivers must authenticate the endpoint,
verify the signature/binding, and convert both budgets with their own
before/after BOOTTIME exchange and explicit clock-rate bounds. They must preserve
previous shorter admission and longer retention on refresh. Neither numeric
field is itself a transferable permission or lease. No cross-domain raw-expiry
minimum is valid.

The generated endpoint uses bounded ingress (8192-byte request, 3072-byte reply,
shared predecode admission), decision-role authentication, and a separate bounded
native work semaphore. Native snapshot guards and writer locks do not cross
callbacks or asynchronous RPCs. Private signatures remain private through fresh
post-sign owner queries and final caller/publication/authentication/network/time
fences. Remote changes after the last query remain point-in-time limitations;
replay consumption and final credential output remain the downstream owners'
responsibility.

Verification includes actual generated mTLS auth/network/route/plan and observed
permit RPC fixtures, independent authentication/Pumgye clock offsets, digest and
caller refusal, changed post-sign route generation, publication replacement,
BOOTTIME Kubernetes readiness expiry, and unchanged strict tests. These tests do
not qualify a deployed end-to-end projector or dispatch chain.
