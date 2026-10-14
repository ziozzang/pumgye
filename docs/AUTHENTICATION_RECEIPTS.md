# Authentication receipt verification (unreleased)

[한국어](AUTHENTICATION_RECEIPTS.ko.md)

The owning server library `pumgye_server::authentication` consumes the pinned,
provider-independent Hopae receipt contract. It introduces no provider, session,
HTTP or database dependency in `pumgye-core`.

`ServiceTrust` is constructed from server-owned issuer/key epoch/public key,
identity authority epoch base, service/audience and minimum profile revision.
Request metadata cannot select another trusted key or classification. Verification
requires the canonical Service/AAL0 subject, matching profile/credential generation,
canonical service epoch, final request digest and a valid Authentication-purpose
signature/time window. Only after those checks does `CheckedService` retain the
verified context, exact receipt hash and expiry. It has no public constructor,
Clone, Debug or serialization; later changes to the supplied numeric context do
not rewrite its verified facts.

Tests cover valid extraction, independently signed but wrong scope/kind/generation,
identity/profile epoch mismatch, revision floors, wrong key/purpose, every-byte
tampering and time boundaries. Verification uses immutable resources and performs
no request-time SQL or provider calls.

This is a cryptographic server-library boundary, not an active permit endpoint.
Static revision floors do not establish live Hopae/key freshness. The signer must
combine current identity/key/epoch fences, verified network evidence, the native
resource Allow and final request/plan binding, then recheck those owners before
releasing its private candidate. Replay consumption remains required at projection.
Server trust configuration loading/publication, durable retirement floors and RPC
integration remain open. Existing service/resource transports are unchanged.

## Checked identity resource boundary (unreleased)

`authorization::authorize_resource_then` evaluates only the service, canonical
subject and AAL held by `CheckedService`. Its native resource request has no
identity, service, assurance or class override. The compiled catalog selects
classification/action rights. Mandatory owner-fence and clock callbacks guard
admission, candidate production and final return. Authentication verification time
is a rollback floor; authentication/network expiry and backward time refuse the
candidate. The operation receives owner metadata and must keep output private.

Tests combine a real signed authentication receipt with native resource Allow and
refuse network/unknown-action denial, initial retirement/expiry, retirement during
candidate production, authentication/network expiry and clock rollback after work.
This public server-library adapter remains unwired to an RPC. The current-owner
callback must be supplied by real identity/key/network/policy/route/plan owners;
this helper supplies no remote freshness discovery or signed permit by itself.

## Native permit candidate signer (unreleased)

`permit::Signer` uses a separate Pumgye signing identity and Permit purpose. It runs
inside checked-authentication resource authorization, then rechecks native owners
and every sampled clock before returning `SignedPermit`. The candidate binds the
exact authentication receipt hash, verified identity/service/audience/request,
decision/resource/action, authority epoch and policy/catalog/network/route/plan
revisions. Catalog and policy share one atomic document revision. No caller class
or assurance is accepted. Nonces come from the OS CSPRNG.

Expiry is the earliest authentication, network, policy, route, plan or one-second
limit. Independent receiver verification qualifies purpose/key separation, exact
chain/revision binding, expiry and distinct nonces. Denial, initial/final owner
retirement, invalid revisions, expired plans and clock rollback discard candidates.
All 44 workspace tests and strict Clippy pass.

The signer is a server-library capability, not a configured permission endpoint.
Native owner state and the mandatory freshness callback must originate in actual
owners. Signing key loading/rotation, owner discovery/coherence, RPC wiring,
receiver replay consumption and credential projection remain required. No operating
permit issuer is activated by this source change.

## Native permit signing resources (unreleased)

`--permit-key <file>` optionally loads reference-only JSON with `issuer_ref`,
`key_epoch`, `public_key` (base64 Ed25519 public bytes) and `seed_env` (environment
reference). Unknown fields, including inline `seed`, are refused. Files are bounded
to 16 KiB. Public identity/epoch/reference syntax is checked before resolving
secret material. The 32-byte seed must match the declared non-weak public key;
encoded seed and decode/file buffers are zeroized. Missing or invalid resources
fail before database creation or listener binding. Administrator status exposes
only `permit_key_configured`.

Use a separate deployment permit identity from release artifact and Hopae
authentication identities. Restart is the current loading boundary; dynamic
publication remains open. The durable startup fence is described below. Loading a key does not
activate a permit RPC or satisfy live owner/network/plan checks. The option conflicts
with inspection/observation-only modes. Existing deployments without the option
retain their ordinary decision behavior.

## Server-owned authentication trust loading (unreleased)

`--authentication-trust <file>` loads a bounded 64 KiB document with 1..128
`entries`. Each entry declares `issuer_ref`, `key_epoch`, `identity_epoch`,
`service`, `audience`, `minimum_revision` and a base64 `public_key`. Unknown fields
and secret fields are refused. Native validation checks references, epochs,
revision floors and strong public material. Duplicate issuer/service/audience
bindings, inconsistent key/epoch/identity bases for one issuer and public-material
reuse across issuers are rejected. Different audiences for the same declared
issuer/service can share its single active identity.

Compiled trust uses borrowed issuer/service/audience hash lookups without allocating
request-time composite keys. The request cannot choose a public key or introduce
an undeclared scope. Invalid trust fails before DB creation or listener binding;
administrator status reports only `authentication_trust_entries`. The option
conflicts with inspection/observation-only modes. Loading is restart-bound and
does not implement live Hopae revalidation, dynamic trust publication or permit
RPC activation. Key retirement is fenced by the durable startup transition below.

## Durable startup key history (unreleased)

Before opening listeners, the server compiles the combined authentication and
permit public descriptors and commits their immutable registry plus SHA-256 audit
in its private SQLite database. The combined set permits up to 64 active keys,
128 authority/purpose floors and 256 historical public keys; the 128 trust-scope
limit remains separate. Queries perform no database access for this fence.

Each successful startup transition advances the registry revision. Removing either
configuration retires its keys while retaining history. Restarting with an unchanged
active key is allowed; rotation requires a higher epoch and fresh public material.
Removed or replaced material cannot return at any epoch or move between issuers
or authentication/permit purposes. Failed transitions leave snapshot and audit
unchanged and refuse startup. Tests exercise actual process startup, SQLite restart,
retirement, fresh replacement and write failure.

This history does not prove live provider/app freshness, fence rollback of the
whole DB backup, or activate permit RPC. Distributed floors and restore protection remain required.

### Durable scope revision floors (unreleased)

The same startup transaction retains `(issuer, service, audience)` identity epochs
and minimum profile revisions, including removed scopes. A lower minimum revision
or a different identity epoch refuses startup and rolls back key history and audit
together. Identity-epoch migration is currently refused; an explicit validated
migration protocol remains to be implemented. History is bounded to 4,096 scopes.
Compiled request-time verification still uses only memory. This persists declared
floors, not the latest observed provider revision or live revocation state.

Validation: 54 workspace tests passed with `--test-threads=1`, and strict all-target
Clippy passed. The preceding parallel run had a transient owner-lock reacquisition
failure in the existing restart test; the owner now explicitly unlocks after SQLite closes to prevent fork-inherited
file descriptions from extending the lock. A deterministic child-inheritance
regression covers this case. The new scope-floor test passed in both runs.

After the ownership fix, all 55 workspace tests passed in normal parallel execution
and strict all-target Clippy passed. The child regression closes unrelated inherited
descriptors so it cannot prolong concurrent tests’ listeners.

## Signed application generation (unreleased)

ServiceTrust now requires the canonical `<base>:service:<profile>:app:<generation>`
epoch. Legacy profile-only receipts, zero/noncanonical app generations, wrong
base or profile revision are refused even when signed. `CheckedService` exposes
the authenticated application generation for subsequent native owner validation.
The actual Hopae captured-proof issuer adopts the same contract. Generation
parsing is not a live freshness check; owner revalidation remains required before
permit dispatch, and operating releases are unchanged by this source increment.

## Native live-validation client (unreleased)

`authentication_live::Client` establishes a persistent HTTPS gRPC channel with
explicit CA, server name and client identity. It accepts only an already verified
CheckedService plus its exact receipt bytes, checks the receipt SHA-256, and
queries Hopae ValidateService with the native request digest. Admission is bounded
to 128 simultaneous requests, encoded messages to 2 KiB and replies to 64 bytes.
RPC timeout is capped by the original receipt deadline and one second. Refusal,
outage, mismatched correlation/expiry, clock rollback or elapsed-time expiry
returns no observation; no fallback or acceptance cache is provided.

The opaque observation binds the exact receipt hash and original expiry and uses
monotonic elapsed time on subsequent checks. It is not a permission or durable
owner lease. Server startup resources and actual cross-process client qualification are
implemented below; permit dispatch and final remote owner fences remain open. This library
increment does not change operating listeners or deployments.

## Live-client startup resources (unreleased)

`--authentication-live <file>` requires `--authentication-trust` and loads a
reference-only JSON document: `issuer_ref`, HTTPS `address`, `server_name`,
`ca`, `certificate`, `key` file paths and `token_env`. The issuer must exist in
the compiled trust. Unknown/inline-secret fields are refused; document size is
16 KiB and each TLS file is bounded to 128 KiB. Temporary credential and file
buffers are zeroized. Loading and authenticated TLS connection complete before
DB opening and listener activation; failure reports a generic error. Status
exposes only `authentication_live_configured`.

This initial configuration binds one issuer endpoint. Mixed-provider authentication
behind that Hopae issuer remains supported; multi-issuer endpoint selection is
future work. Loading the client does not activate a permit RPC. Actual successful Hopae/Pumgye client lifecycle qualification is recorded below;
permit integration remains open.
The operating deployment is unchanged.

## Actual Hopae/Pumgye live-client qualification (unreleased)

`examples/hopae_live_qualification.rs` runs the production Pumgye Client against
an actual isolated Hopae executable using the portable
[receipt fixture](https://github.com/ziozzang/hopae/blob/main/tools/service_receipt_smoke.py)
with `--live-validation`. Persistent channels passed signed issuance/local trust
verification/live validation, cached unexpired receipt refusal after signed profile
CAS removal, restoration with a new revision, and authority outage refusal after
terminating the owned Hopae process while a fresh receipt remained locally valid.
Caller/issuer/service/audience/server-name/key/epoch refusals also passed.

This run used current debug executables, ephemeral TLS/signing keys and synthetic
profiles only. No operating credentials, data or listeners were used. Strict
workspace/all-target Clippy passed. Static release, actual Pumgye server permit
endpoint, distributed freshness/restore and Kubernetes live-client gates remain.

## Live observation plus native resource Allow (unreleased)

`authorization::authorize_live_resource_then` requires an opaque native live
observation bound to the exact checked receipt, in addition to the immutable policy
and mandatory current-owner fence. Every admission/final boundary checks the
observation; all internal clock reads share rollback detection. Wrong-receipt
observations, expired evidence or retired owners never reach the private callback.
The actual Hopae/Pumgye fixture now evaluates a synthetic native resource catalog
with the observed identity and returns only the owner-defined class after Allow.

That fixture uses an explicitly guard-optional synthetic policy and one immutable
local policy owner. It does not qualify Sumunjang evidence or distributed route/
projection ownership. The Pumgye server currently has no native readers for those
three revision owners. Permit activation must connect these owners; request-supplied
revision numbers or an unconditional current callback must not substitute for them.
No permit endpoint or operating deployment was enabled by this increment.

## Native Sumunjang observation client (unreleased)

`network_live::Client` uses persistent mandatory mTLS, collector credentials,
128-request admission and 128/64-byte encode/decode limits. It accepts only
well-formed Enforce/Allow, exact correlation, nonzero safe revision at or above
the configured/in-process floor and TTL in 1..5000 ms. Observation validity is
capped at one second starting before RPC; elapsed monotonic time includes network
work. IP mismatch, observe, deny, unavailable, malformed reply, rollback, expiry
and transport failure produce no evidence. Newer valid refusals advance the
process-local floor and invalidate older Allow observations too.

TLS channel construction is statically shared with the Hopae live client. The
opaque observation carries IP/revision/expiry; it is not a signed network receipt
or a distributed lease. Startup/configuration, actual Sumunjang/Pumgye wire
qualification, durable floor/backbone replication and permit integration remain
open. Neither endpoint nor deployment is activated by this library increment.

## Actual Sumunjang/Pumgye client qualification (unreleased)

The owned `examples/sumunjang_live_qualification.rs` entrypoint passed against
an actual Sumunjang debug executable through its existing portable gRPC fixture.
Persistent mTLS exercised Enforce Allow, IP binding, block removal/new revision,
reblocking/new refusal retiring the previous observation, observe rejection,
collector/admin separation, TLS server-name rejection and revision-floor refusal.
The parent fixture also checks malformed/oversized input, client-certificate
refusal, native parity and supervised listener handover. Strict all-target Clippy
passed. The example uses only the fixture’s loopback plaintext management adapter
for owned policy mutations; native decisions use mTLS. No operating data is used.

```sh
cargo build -p pumgye-server --example sumunjang_live_qualification
# Run in the Sumunjang repository with grpcio/grpcio-tools installed:
python tools/grpc_smoke.py --binary target/debug/sumunjang \
  --hangang-client /qualified/pumgye/examples/sumunjang_live_qualification
```

The fixture’s legacy `--hangang-client` option accepts this compatible native
qualification executable. These are debug process tests, not static-release,
startup-resource, distributed floor/restore or permit endpoint qualification.

## Network startup resources (unreleased)

`--network-live <file>` loads reference-only JSON with HTTPS `address`,
`server_name`, `ca`, `certificate`, `key` paths and `token_env`. Unknown and inline
secret fields are rejected. The document is bounded to 16 KiB, TLS files to
128 KiB each, and temporary buffers are zeroized. Mandatory mTLS connection is
established before opening the DB/listeners; failures expose a generic error.
Status reports only `network_live_configured`. Inspection/observation-only modes
cannot load this owning client. Missing credentials are tested with the actual
binary on an occupied listener, proving refusal before DB creation or binding.

This loads the client, not a permit endpoint. Network revision floors remain
process-local; durable restore/fleet epochs and combined final owner checks remain
open. Existing operating deployments are unchanged.

## Combined native identity/network gate (unreleased)

`authorize_combined_resource_then` requires checked identity plus opaque Hopae
and Sumunjang live observations. Its `NativeResourceRequest` contains only
resource/action/IP: caller-supplied assurance, subject, service, class, Guard
verdict and network expiry are absent. The native gate derives EnforcedAllow
and deadline from the accepted Sumunjang observation, checks exact IP and both
observations before/after private work, and retains rollback detection and the
mandatory additional-owner fence. Tests qualify a guard-required catalog Allow,
wrong-IP refusal before work and candidate discard after a network revision
advance during work. The synthetic authentication observation constructor is
compiled only under Rust `cfg(test)` and is absent from ordinary/release builds.

All 62 workspace tests and strict all-target Clippy passed. This is a server
library boundary; the request endpoint, real three-authority combined process
qualification, route/projection owners, distributed freshness and signed permit
activation still need integration. Production remains unchanged.

## Authenticated resource decision endpoint (unreleased)

`POST /v1/resource/authenticated-decision` requires the decision credential and
all three native resources: authentication trust, Hopae live validation and
Sumunjang live network. The bounded 4 KiB, unknown-field-refusing JSON contains
`request_id`, policy `minimum_revision`, `resource`, `action`, `ip`, signed
`context`, exact `receipt` bytes and the enforcement-derived `request_sha256`.
Raw classification, separate identity/AAL or Guard verdict/deadline fields are
not accepted. The receipt is verified locally, Sumunjang is queried, and Hopae
live ownership is validated before combined resource evaluation. Exact captured
policy/health/Kubernetes lease are fenced across awaits and after private work.

Replies carry correlation, policy/network revisions, Allow boolean and TTL zero.
Missing resources, transport errors or owner retirement never yield Allow;
ordinary native-policy denial yields Allow false. Tests cover admin-role refusal,
missing-resource unavailability and spoofed Guard-field rejection. The authenticated
enforcement caller still owns the bound request and client IP. This endpoint is
a decision observation, not a signed permit or upstream credential. Actual
three-authority positive endpoint qualification, gRPC equivalent, route/plan
owner integration and production rollout remain open.

## Actual three-authority endpoint qualification (unreleased)

`tools/authenticated_resource_smoke.py` owns ephemeral TLS/issuer keys, profiles,
private databases and actual Hopae, Sumunjang and Pumgye debug processes. The
Pumgye startup paths establish both native mTLS clients; a real service receipt
is posted to the authenticated resource endpoint. A guard-required native catalog
Allow passed, Sumunjang block/removal caused refusal/restoration, and profile
withdrawal/restoration advanced the identity generation. A cached unexpired
receipt was directly posted to Pumgye after withdrawal and refused. A fresh
receipt was directly posted after the owned Hopae process was terminated and
also refused. Seven caller/key/scope/TLS trust refusal cases passed. Strict
workspace/all-target Clippy passed.

```sh
python3 tools/authenticated_resource_smoke.py \
  --server /qualified/hopae --sumunjang /qualified/sumunjang \
  --pumgye /qualified/pumgye \
  --client target/debug/examples/hopae_live_qualification --live-validation
```

Only owned loopback management/decision adapters use HTTP; the inter-authority
queries use mTLS. No operating data or credentials are used. Static releases,
Kubernetes combined endpoint, Hangang request dispatch, gRPC equivalent and
signed permit/route/projection ownership remain separate gates.

## Static three-authority candidates — 2026-10-15

The same actual endpoint fixture passed with all three server executables and
the qualification client compiled for `x86_64-unknown-linux-musl`. Each ELF was
independently checked for absence of INTERP. Network/identity withdrawal and
restoration, cached proof refusal, authority-outage endpoint refusal and seven
trust refusals passed. Sumunjang static mTLS and Pumgye static resource-catalog
regressions also passed. Exact source revisions and artifact SHA-256 are in
[the public candidate report](qualification/three-authority-static.json).

These are unreleased source candidates retaining the preceding version strings;
existing signed tags/assets are unchanged. New versioning, signing/publication,
Kubernetes combined-endpoint qualification and operating rollout are subsequent
gates. No operational data/configuration changed during these owned tests.

## Kubernetes qualification client support — 2026-10-15

The owned example accepts an explicit identity epoch/IP and mTLS HTTPS Pumgye
endpoint, while retaining the isolated local fixture defaults. The static client
passed against the actual signed Pumgye 0.1.5/Hopae 0.0.7/Sumunjang 0.3.5
K3s Pods: public trust/resources were injected into the Pumgye Pod and the
authenticated endpoint returned native Allow after inter-authority mTLS Service
DNS queries. Actual browser/module and ordinary revocation/restart/outage world
gates also passed. Strict all-target Clippy passed for the example changes.

This Kubernetes endpoint step proves positive admission only; receipt-specific
withdrawal/outage was qualified in the local static three-authority fixture.
Signed permits, production Hangang dispatch and distributed restore/fleet
fences remain open. Server release assets are unchanged by this example update.

## Typed authenticated resource gRPC adapter (unreleased)

The mandatory-mTLS `AuthenticatedResourceAuthorization/Decide` service shares
the HTTP endpoint's exact native evaluation function. Its protobuf request uses
Hopae's canonical generated `AuthenticationReceiptContext` via build-time schema
export and extern-path mapping; no duplicate context schema or request-time JSON
parse is used. Packed IP, native resource/action, exact receipt and expected
request hash remain bounded. Decision-role authentication and shared admission
precede context conversion; decoding/encoding limits are 4 KiB/128 bytes. Replies
carry correlation, policy/network revisions, Allow/Deny and cache TTL zero.

Tests cover real mTLS service registration, admin-role refusal, invalid/missing
context, unavailable resources and existing resource-channel regressions. All
64 workspace tests and strict all-target Clippy passed. The actual three-authority
HTTP Allow/revocation/outage fixture passed again after evaluation extraction.
The gRPC positive three-authority path, Hangang client/dispatch integration and
signed permit remain subsequent gates; operating releases are unchanged.
